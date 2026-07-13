"""
VAPT Multi-Agent System — Multi-Provider LLM Client

Supports multiple AI providers with automatic fallback:
  1. OpenAI (GPT-4o, GPT-4-turbo, GPT-3.5-turbo)
  2. Anthropic (Claude 3.5 Sonnet, Claude 3 Opus)
  3. Google Gemini (gemini-1.5-pro, gemini-1.5-flash)
  4. Ollama (local: llama3, mistral, codellama, deepseek-coder)
  5. Azure OpenAI
  6. Groq (llama-3.1-70b, mixtral-8x7b)
  7. Together AI
  8. Any OpenAI-compatible endpoint

Features:
  - Provider chaining: if provider 1 fails, auto-fallback to provider 2, etc.
  - Structured JSON output with retry/repair
  - Token counting and cost estimation
  - Rate limiting per provider
  - Caching of repeated prompts (optional)
  - Streaming support for dashboard display

Usage:
    from tools.llm_client import LLMClient, LLMProvider

    client = LLMClient(config)
    result = await client.analyze("Find vulnerabilities in this response...", provider="openai")
"""

import asyncio
import hashlib
import json
import os
import re
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from loguru import logger

from core.llm_budget import budget_prompt


_GLOBAL_RATE_WINDOWS: dict[str, list[float]] = {}
_GLOBAL_RATE_LOCK = threading.Lock()
_GLOBAL_PROVIDER_COOLDOWNS: dict[str, tuple[float, str]] = {}


def _bearer_token(value: str) -> str:
    """Normalize pasted API keys, including an accidental Bearer prefix."""
    token = (value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token

# Task categories for model routing. Triage-class tasks go to the smaller/faster
# model (analysis_model, e.g. gemma); reasoning/report tasks go to the stronger
# model (report_model, e.g. qwen). Unknown tasks use the provider's own model.
_TRIAGE_TASKS = {"triage", "classify", "classification", "dedup", "categorize", "fast"}
_REASON_TASKS = {
    "reason", "reasoning", "remediation", "report", "summary", "exec_summary",
    "cve", "cwe", "analysis",
}


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    AZURE = "azure"
    GROQ = "groq"
    TOGETHER = "together"
    OPENAI_COMPAT = "openai_compat"  # vLLM, text-generation-webui, etc.
    HTTP_BASIC_CHAT = "http_basic_chat"  # Basic Auth /chat endpoint returning message.content


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""
    content: str
    provider: str
    model: str
    tokens_prompt: int = 0
    tokens_completion: int = 0
    duration_ms: float = 0
    cached: bool = False
    error: Optional[str] = None

    def json_content(self) -> Optional[dict]:
        """Try to parse response content as JSON."""
        if not self.content:
            return None
        # Try direct parse
        try:
            return json.loads(self.content)
        except json.JSONDecodeError:
            pass
        # Try extracting JSON from markdown code block
        match = re.search(r'```(?:json)?\s*([\s\S]*?)```', self.content)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        # Try finding top-level JSON object
        match = re.search(r'\{[\s\S]*\}', self.content)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None


@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider."""
    provider: LLMProvider
    model: str
    api_key_env: str = ""
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 4096
    max_rpm: int = 40
    temperature: float = 0.3
    timeout: int = 120
    enabled: bool = True
    verify_ssl: bool = True
    chat_path: str = "/chat"
    models_path: str = "/models"
    # Provider-specific
    organization_id: str = ""  # OpenAI org
    project_id: str = ""       # Azure project
    deployment_id: str = ""    # Azure deployment


class LLMClient:
    """Multi-provider LLM client with automatic fallback and structured output."""

    def __init__(self, config: Any = None):
        """
        Initialize LLM client from AppConfig or standalone.

        Args:
            config: AppConfig instance (reads LLM section), or None for defaults.
        """
        self._providers: dict[str, ProviderConfig] = {}
        self._fallback_chain: list[str] = []
        self._cache: dict[str, LLMResponse] = {}
        self._rate_limits: dict[str, list[float]] = {}
        self._request_counts: dict[str, int] = {}

        # Runtime overlay FIRST: persisted frontend-configured LLM settings
        # (provider/model/base_url/api_key/fallbacks/toggles) take precedence
        # over config.yaml + env, so the model is never hardcoded. Idempotent
        # and shared across API + worker containers via the data volume.
        if config:
            from core.runtime_config import apply_runtime_llm_overlay
            apply_runtime_llm_overlay(config)

        # enabled / allow_fallbacks: prefer the (now-overlaid) config value,
        # else fall back to the VAPT_LLM_* env vars.
        self._enabled = self._resolve_flag(config, "enabled", "VAPT_LLM_ENABLED", default=False)
        self._allow_fallbacks = self._resolve_flag(config, "allow_fallbacks", "VAPT_LLM_ALLOW_FALLBACKS", default=False)
        # Task→model routing: small/fast model for triage, stronger model for
        # reasoning/reporting. Populated from config (analysis_model/report_model).
        self._analysis_model: str = ""
        self._report_model: str = ""
        self._review_model: str = ""

        if config:
            self._load_from_config(config)
        else:
            self._load_defaults()

    @staticmethod
    def _env_truthy(name: str, default: bool = False) -> bool:
        value = os.environ.get(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _resolve_flag(config: Any, attr: str, env_name: str, default: bool) -> bool:
        """Precedence: config.llm.<attr> (if not None) > env var > default.

        Lets the frontend toggle ``enabled`` / ``allow_fallbacks`` at runtime
        while still honouring the legacy VAPT_LLM_* env vars.
        """
        if config is not None:
            val = getattr(getattr(config, "llm", None), attr, None)
            if val is not None:
                return bool(val)
        return LLMClient._env_truthy(env_name, default)

    @staticmethod
    def _provider_key(pc: "ProviderConfig") -> str:
        """Unique registry key: ``"<provider>:<model>"``.

        Required so multiple models from the SAME provider (e.g. several
        Ollama-served models: qwen2.5:32b, qwen2.5:14b, gemma) can coexist in
        the fallback chain instead of collapsing to a single entry.
        """
        return f"{pc.provider.value}:{pc.model}"

    def _resolve_provider_key(self, provider: Optional[str]) -> Optional[str]:
        """Map a bare provider name (e.g. ``"openai"``) to a registry key.

        Callers may still pass a bare provider name; this resolves it to the
        first matching ``"<provider>:<model>"`` key so explicit-provider use
        keeps working under the new keying.
        """
        if not provider:
            return None
        if provider in self._providers:
            return provider
        matches = [k for k in self._fallback_chain if k.split(":", 1)[0] == provider]
        return matches[0] if matches else provider

    def _load_from_config(self, config: Any) -> None:
        """Load provider configs from AppConfig LLM section."""
        llm = config.llm

        # Task routing models (default to the primary model when unset).
        self._analysis_model = getattr(llm, "analysis_model", "") or llm.model
        self._report_model = getattr(llm, "report_model", "") or llm.model
        self._review_model = getattr(llm, "review_model", "") or self._analysis_model

        # Primary provider. Registered under "<provider>:<model>" so that the
        # fallback chain can hold several models from the same provider.
        primary = ProviderConfig(
            provider=LLMProvider(llm.provider),
            model=llm.model,
            api_key_env=llm.api_key_env,
            api_key=getattr(llm, "api_key", ""),
            base_url=getattr(llm, "base_url", ""),
            verify_ssl=getattr(llm, "verify_ssl", True),
            max_tokens=llm.max_tokens,
            max_rpm=getattr(llm, "max_rpm", 40),
            temperature=llm.temperature,
            enabled=True,
        )
        primary_key = self._provider_key(primary)
        self._providers[primary_key] = primary
        self._fallback_chain.append(primary_key)

        # Load additional providers from config if present
        extra_providers = getattr(llm, "fallback_providers", None)
        if extra_providers and isinstance(extra_providers, list):
            for prov_cfg in extra_providers:
                if isinstance(prov_cfg, dict):
                    name = prov_cfg.get("provider", "")
                    model = prov_cfg.get("model", "default")
                    key = f"{name}:{model}"
                    if name and key not in self._providers:
                        pc = ProviderConfig(
                            provider=LLMProvider(name),
                            model=model,
                            api_key_env=prov_cfg.get("api_key_env", ""),
                            api_key=prov_cfg.get("api_key", ""),
                            base_url=prov_cfg.get("base_url", ""),
                            max_tokens=prov_cfg.get("max_tokens", 4096),
                            max_rpm=int(prov_cfg.get("max_rpm", 40)),
                            temperature=prov_cfg.get("temperature", 0.3),
                            enabled=prov_cfg.get("enabled", True),
                            verify_ssl=prov_cfg.get("verify_ssl", True),
                            chat_path=prov_cfg.get("chat_path", "/chat"),
                            models_path=prov_cfg.get("models_path", "/models"),
                            organization_id=prov_cfg.get("organization_id", ""),
                            project_id=prov_cfg.get("project_id", ""),
                            deployment_id=prov_cfg.get("deployment_id", ""),
                        )
                        self._providers[key] = pc
                        self._fallback_chain.append(key)

        # Always add an Ollama fallback (local, free) if none is configured.
        if not any(k.split(":", 1)[0] == "ollama" for k in self._fallback_chain):
            pc = ProviderConfig(
                provider=LLMProvider.OLLAMA,
                model="llama3",
                base_url="http://localhost:11434",
                enabled=True,
            )
            self._providers[self._provider_key(pc)] = pc
            self._fallback_chain.append(self._provider_key(pc))

    def _load_defaults(self) -> None:
        """Load sensible defaults when no config provided."""
        self._analysis_model = "gpt-4o"
        self._report_model = "gpt-4o"
        self._review_model = "gpt-4o"
        self._providers["openai"] = ProviderConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-4o",
            api_key_env="OPENAI_API_KEY",
            max_tokens=4096,
            temperature=0.3,
            enabled=True,
        )
        self._providers["ollama"] = ProviderConfig(
            provider=LLMProvider.OLLAMA,
            model="llama3",
            base_url="http://localhost:11434",
            enabled=True,
        )
        self._fallback_chain = ["openai", "ollama"]

    @staticmethod
    def _strip_endpoint_path(base_url: str, suffixes: tuple[str, ...]) -> str:
        """Accept either a provider base URL or a full endpoint URL."""
        raw = (base_url or "").rstrip("/")
        if not raw:
            return ""
        parsed = urlparse(raw)
        path = parsed.path.rstrip("/")
        for suffix in suffixes:
            suffix = suffix.rstrip("/")
            if path == suffix or path.endswith(suffix):
                new_path = path[: -len(suffix)].rstrip("/")
                return urlunparse(parsed._replace(path=new_path, params="", query="", fragment="")).rstrip("/")
        return raw

    @classmethod
    def _normalise_openai_compat_base(cls, base_url: str) -> str:
        return cls._strip_endpoint_path(
            base_url,
            ("/v1/chat/completions", "/v1/completions", "/v1/models", "/v1"),
        )

    @classmethod
    def _normalise_ollama_base(cls, base_url: str) -> str:
        return cls._strip_endpoint_path(base_url, ("/api/generate", "/api/chat", "/api/tags"))

    @classmethod
    def _normalise_basic_chat_base(cls, base_url: str) -> str:
        return cls._strip_endpoint_path(base_url, ("/chat", "/models"))

    def add_provider(self, config: ProviderConfig) -> None:
        """Add or override a provider configuration."""
        key = self._provider_key(config)
        self._providers[key] = config
        if key not in self._fallback_chain:
            self._fallback_chain.append(key)

    def get_available_providers(self) -> list[str]:
        """Return list of providers that have API keys configured."""
        if not self._enabled:
            return []
        available = []
        provider_names = self._fallback_chain if self._allow_fallbacks else self._fallback_chain[:1]
        for name in provider_names:
            pc = self._providers.get(name)
            if pc is None:
                continue
            if not pc.enabled:
                continue
            if pc.provider == LLMProvider.OLLAMA:
                # Ollama doesn't need an API key
                available.append(name)
            elif pc.provider == LLMProvider.OPENAI_COMPAT and pc.base_url:
                available.append(name)
            elif pc.provider == LLMProvider.HTTP_BASIC_CHAT and pc.base_url:
                if pc.api_key or os.environ.get(pc.api_key_env, ""):
                    available.append(name)
            elif pc.api_key or os.environ.get(pc.api_key_env, ""):
                available.append(name)
        return available

    def _role_model(self, task: str) -> str:
        """Return the operator-selected model for a task role."""
        t = task.lower().strip()
        if t == "dual_review":
            return self._review_model
        if t in _TRIAGE_TASKS and self._analysis_model:
            return self._analysis_model
        if t in _REASON_TASKS and self._report_model:
            return self._report_model
        return ""

    def _provider_for_model(self, model: str) -> Optional[str]:
        """Resolve a role model to the endpoint that actually serves it."""
        return next((key for key in self._fallback_chain if self._providers[key].model == model), None)

    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        provider: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        use_fallback: bool = True,
        task: str = "",
    ) -> LLMResponse:
        """Send a prompt to an LLM and get a response.

        Args:
            prompt:           The user prompt.
            system_prompt:    Optional system prompt for context.
            provider:         Specific provider to use (or None for fallback chain).
            model:            Override model name.
            temperature:      Override temperature.
            max_tokens:       Override max tokens.
            json_mode:        Request JSON output format.
            use_fallback:     Whether to try fallback providers on failure.

        Returns:
            LLMResponse with standardized content.
        """
        if not self._enabled:
            return LLMResponse(
                content="",
                provider=provider or "none",
                model=model or "none",
                error="LLM disabled. Set VAPT_LLM_ENABLED=true to enable AI enrichment.",
            )

        role_model = model or self._role_model(task)
        cache_material = json.dumps({
            "provider": provider, "model": role_model, "task": task,
            "system": system_prompt, "prompt": prompt, "temperature": temperature,
            "max_tokens": max_tokens, "json_mode": json_mode,
        }, sort_keys=True)
        cache_key = hashlib.sha256(cache_material.encode("utf-8")).hexdigest()
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            cached.cached = True
            return cached

        # Determine provider order
        if provider:
            providers_to_try = [self._resolve_provider_key(provider) or provider]
        else:
            base_chain = list(
                self._fallback_chain
                if use_fallback and self._allow_fallbacks
                else self._fallback_chain[:1]
            )
            role_provider = self._provider_for_model(role_model) if role_model else None
            if role_provider:
                providers_to_try = [role_provider]
                if use_fallback and self._allow_fallbacks:
                    providers_to_try.extend(p for p in base_chain if p != role_provider)
            else:
                providers_to_try = base_chain

        last_error = None
        for prov_name in providers_to_try:
            pc = self._providers.get(prov_name)
            if not pc or not pc.enabled:
                last_error = f"Provider not configured or disabled: {prov_name}"
                continue

            # Check rate limit
            rate_key = f"{pc.provider.value}:{pc.base_url.rstrip('/') or pc.provider.value}"
            cooldown = _GLOBAL_PROVIDER_COOLDOWNS.get(rate_key)
            if cooldown and cooldown[0] > time.time():
                last_error = f"Provider circuit open: {cooldown[1]}"
                continue
            if cooldown:
                _GLOBAL_PROVIDER_COOLDOWNS.pop(rate_key, None)
            if not self._reserve_rate_limit(rate_key, pc.max_rpm):
                last_error = f"Rate limit reached for {prov_name} ({pc.max_rpm} requests/minute)"
                continue

            # Check API key availability
            if pc.provider not in {LLMProvider.OLLAMA, LLMProvider.OPENAI_COMPAT}:
                api_key = _bearer_token(pc.api_key or os.environ.get(pc.api_key_env, ""))
                if not api_key:
                    continue

            # Resolve model (explicit override > task routing > provider default)
            # A role model is used only on the endpoint configured to serve it.
            # During failover each endpoint receives its own known-good model.
            effective_model = role_model if role_model and pc.model == role_model else pc.model
            effective_temp = temperature if temperature is not None else pc.temperature
            effective_max = max_tokens or pc.max_tokens

            # Budget the prompt against the model's context window so small local
            # models (qwen/gemma) never silently overflow. Trims only if needed.
            budgeted_prompt, budget_meta = budget_prompt(
                prompt,
                system_prompt=system_prompt,
                model=effective_model,
                reserved_output=effective_max,
                explicit_ctx=getattr(pc, "context_window", None),
            )

            try:
                response = await self._call_provider(
                    pc=pc,
                    prompt=budgeted_prompt,
                    system_prompt=system_prompt,
                    model=effective_model,
                    temperature=effective_temp,
                    max_tokens=effective_max,
                    json_mode=json_mode,
                )

                if response and not response.error and response.content.strip():
                    self._cache[cache_key] = response
                    return response
                else:
                    last_error = response.error if response and response.error else "Empty response"
                    error_lower = str(last_error).lower()
                    if "http 401" in error_lower or "http 403" in error_lower:
                        _GLOBAL_PROVIDER_COOLDOWNS[rate_key] = (time.time() + 300, str(last_error)[:300])
                    elif "http 429" in error_lower or "rate limit" in error_lower:
                        _GLOBAL_PROVIDER_COOLDOWNS[rate_key] = (time.time() + 60, str(last_error)[:300])
                    logger.warning(
                        "LLM call failed provider={provider} model={model}: {error}",
                        provider=pc.provider.value,
                        model=effective_model,
                        error=last_error,
                    )

            except Exception as exc:
                last_error = str(exc)
                continue

        return LLMResponse(
            content="",
            provider=provider or "none",
            model=model or "none",
            error=f"All providers failed. Last error: {last_error}",
        )

    async def analyze(
        self,
        prompt: str,
        context: str = "",
        provider: Optional[str] = None,
        task: str = "analysis",
    ) -> Optional[dict]:
        """Convenience method: send a prompt and parse JSON response.

        Args:
            prompt:   Analysis request.
            context:  Additional context (findings, URLs, etc.).
            provider: Specific provider to use.

        Returns:
            Parsed JSON dict, or None on failure.
        """
        full_prompt = prompt
        if context:
            full_prompt = f"{prompt}\n\nContext:\n{context}"

        system = (
            "You are a senior VAPT engineer, security architect, and evidence-first report reviewer. "
            "Always respond in valid JSON format only. Base every claim on supplied tool output, "
            "HTTP evidence, asset metadata, or explicitly named assumptions. Do not invent scans, "
            "tools, CVEs, ports, buckets, exploitability, or impact that are not present in the evidence. "
            "Separate confirmed findings from suspected leads, false-positive risks, and missing coverage. "
            "For every finding include severity, confidence, affected asset, evidence, business impact, "
            "remediation, validation status, and the exact next verification step. If evidence is weak, "
            "say what tool or check is required instead of overstating the result."
        )

        response = await self.complete(
            prompt=full_prompt,
            system_prompt=system,
            provider=provider,
            json_mode=True,
            task=task,
        )

        parsed = response.json_content()
        if parsed is not None:
            return parsed

        if response.content:
            repair_prompt = (
                "Convert the following model output into valid JSON only. "
                "Do not add new facts, findings, CVEs, targets, ports, or tools. "
                "If the content cannot support a finding, return an empty object with "
                "a 'notes' array explaining why.\n\n"
                f"Original output:\n{response.content[:6000]}"
            )
            repaired = await self.complete(
                prompt=repair_prompt,
                system_prompt="Return valid JSON only. No markdown. No prose outside JSON.",
                provider=provider,
                json_mode=True,
                use_fallback=False,
            )
            return repaired.json_content()

        return None

    async def _call_provider(
        self,
        pc: ProviderConfig,
        prompt: str,
        system_prompt: str,
        model: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> LLMResponse:
        """Route to the correct provider implementation."""
        start = time.time()

        if pc.provider == LLMProvider.OPENAI:
            result = await self._call_openai(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.ANTHROPIC:
            result = await self._call_anthropic(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.GEMINI:
            result = await self._call_gemini(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.OLLAMA:
            result = await self._call_ollama(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.AZURE:
            result = await self._call_azure(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.GROQ:
            result = await self._call_groq(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.TOGETHER:
            result = await self._call_together(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.OPENAI_COMPAT:
            result = await self._call_openai_compat(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        elif pc.provider == LLMProvider.HTTP_BASIC_CHAT:
            result = await self._call_http_basic_chat(pc, prompt, system_prompt, model, temperature, max_tokens, json_mode)
        else:
            result = LLMResponse(content="", provider=pc.provider.value, model=model, error=f"Unknown provider: {pc.provider}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # ────────────────────────────────────────────────────────────────
    # Provider Implementations
    # ────────────────────────────────────────────────────────────────

    async def _call_openai(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                           model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """OpenAI API (GPT-4o, GPT-4-turbo, GPT-3.5-turbo)."""
        try:
            from openai import AsyncOpenAI
        except ImportError:
            return LLMResponse(content="", provider="openai", model=model, error="openai package not installed")

        api_key = _bearer_token(pc.api_key or os.environ.get(pc.api_key_env, ""))
        client = AsyncOpenAI(api_key=api_key, organization=pc.organization_id or None)

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tok,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            response = await client.chat.completions.create(**kwargs)
            msg = response.choices[0].message
            usage = response.usage
            return LLMResponse(
                content=msg.content or "",
                provider="openai",
                model=response.model,
                tokens_prompt=usage.prompt_tokens if usage else 0,
                tokens_completion=usage.completion_tokens if usage else 0,
            )
        except Exception as e:
            return LLMResponse(content="", provider="openai", model=model, error=str(e))

    async def _call_anthropic(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                              model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """Anthropic Claude API (Claude 3.5 Sonnet, Claude 3 Opus)."""
        try:
            import httpx
        except ImportError:
            return LLMResponse(content="", provider="anthropic", model=model, error="httpx not installed")

        api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
        if not api_key:
            return LLMResponse(content="", provider="anthropic", model=model, error="ANTHROPIC_API_KEY not set")

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tok,
            "temperature": temp,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            body["system"] = system_prompt

        try:
            async with httpx.AsyncClient(timeout=pc.timeout) as client:
                resp = await client.post("https://api.anthropic.com/v1/messages", headers=headers, json=body)
                if resp.status_code != 200:
                    return LLMResponse(content="", provider="anthropic", model=model, error=f"HTTP {resp.status_code}: {resp.text[:200]}")

                data = resp.json()
                content_blocks = data.get("content", [])
                text = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
                usage = data.get("usage", {})

                return LLMResponse(
                    content=text,
                    provider="anthropic",
                    model=data.get("model", model),
                    tokens_prompt=usage.get("input_tokens", 0),
                    tokens_completion=usage.get("output_tokens", 0),
                )
        except Exception as e:
            return LLMResponse(content="", provider="anthropic", model=model, error=str(e))

    async def _call_gemini(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                           model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """Google Gemini API (gemini-1.5-pro, gemini-1.5-flash)."""
        try:
            import httpx
        except ImportError:
            return LLMResponse(content="", provider="gemini", model=model, error="httpx not installed")

        api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
        if not api_key:
            return LLMResponse(content="", provider="gemini", model=model, error="GEMINI_API_KEY not set")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

        parts = []
        if system_prompt:
            parts.append({"text": f"System instructions: {system_prompt}\n\n"})
        parts.append({"text": prompt})

        body = {
            "contents": [{"parts": parts}],
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": max_tok,
                "responseMimeType": "application/json" if json_mode else "text/plain",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=pc.timeout) as client:
                resp = await client.post(url, json=body)
                if resp.status_code != 200:
                    return LLMResponse(content="", provider="gemini", model=model, error=f"HTTP {resp.status_code}: {resp.text[:200]}")

                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    text = "".join(p.get("text", "") for p in parts)
                    usage = data.get("usageMetadata", {})

                    return LLMResponse(
                        content=text,
                        provider="gemini",
                        model=model,
                        tokens_prompt=usage.get("promptTokenCount", 0),
                        tokens_completion=usage.get("candidatesTokenCount", 0),
                    )

                return LLMResponse(content="", provider="gemini", model=model, error="No candidates in response")
        except Exception as e:
            return LLMResponse(content="", provider="gemini", model=model, error=str(e))

    async def _call_ollama(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                           model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """Ollama local LLM (llama3, mistral, codellama, deepseek-coder, etc.)."""
        try:
            import httpx
        except ImportError:
            return LLMResponse(content="", provider="ollama", model=model, error="httpx not installed")

        base_url = pc.base_url or "http://localhost:11434"
        base_url = self._normalise_ollama_base(base_url)

        body: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temp,
                "num_predict": max_tok,
            },
        }
        if system_prompt:
            body["system"] = system_prompt
        if json_mode:
            body["format"] = "json"

        try:
            async with httpx.AsyncClient(timeout=pc.timeout) as client:
                # Check if Ollama is running
                try:
                    await client.get(f"{base_url}/api/tags", timeout=5)
                except Exception:
                    return LLMResponse(content="", provider="ollama", model=model, error="Ollama not running — start with: ollama serve")

                resp = await client.post(f"{base_url}/api/generate", json=body, timeout=pc.timeout)
                if resp.status_code != 200:
                    return LLMResponse(content="", provider="ollama", model=model, error=f"HTTP {resp.status_code}: {resp.text[:200]}")

                data = resp.json()
                return LLMResponse(
                    content=data.get("response", ""),
                    provider="ollama",
                    model=data.get("model", model),
                    tokens_prompt=data.get("prompt_eval_count", 0),
                    tokens_completion=data.get("eval_count", 0),
                )
        except Exception as e:
            return LLMResponse(content="", provider="ollama", model=model, error=str(e))

    async def _call_azure(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                          model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """Azure OpenAI Service."""
        try:
            from openai import AsyncAzureOpenAI
        except ImportError:
            return LLMResponse(content="", provider="azure", model=model, error="openai package not installed")

        api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
        if not api_key or not pc.base_url:
            return LLMResponse(content="", provider="azure", model=model, error="AZURE_OPENAI_API_KEY and base_url required")

        deployment = pc.deployment_id or model

        try:
            client = AsyncAzureOpenAI(
                api_key=api_key,
                api_version="2024-02-01",
                azure_endpoint=pc.base_url,
            )

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs: dict[str, Any] = {
                "model": deployment,
                "messages": messages,
                "temperature": temp,
                "max_tokens": max_tok,
            }
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}

            response = await client.chat.completions.create(**kwargs)
            msg = response.choices[0].message
            usage = response.usage

            return LLMResponse(
                content=msg.content or "",
                provider="azure",
                model=response.model,
                tokens_prompt=usage.prompt_tokens if usage else 0,
                tokens_completion=usage.completion_tokens if usage else 0,
            )
        except Exception as e:
            return LLMResponse(content="", provider="azure", model=model, error=str(e))

    async def _call_groq(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                         model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """Groq API (llama-3.1-70b, mixtral-8x7b — ultra-fast inference)."""
        try:
            import httpx
        except ImportError:
            return LLMResponse(content="", provider="groq", model=model, error="httpx not installed")

        api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
        if not api_key:
            return LLMResponse(content="", provider="groq", model=model, error="GROQ_API_KEY not set")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tok,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        try:
            async with httpx.AsyncClient(timeout=pc.timeout) as client:
                resp = await client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=body)
                if resp.status_code != 200:
                    return LLMResponse(content="", provider="groq", model=model, error=f"HTTP {resp.status_code}: {resp.text[:200]}")

                data = resp.json()
                msg = data.get("choices", [{}])[0].get("message", {})
                usage = data.get("usage", {})

                return LLMResponse(
                    content=msg.get("content", ""),
                    provider="groq",
                    model=data.get("model", model),
                    tokens_prompt=usage.get("prompt_tokens", 0),
                    tokens_completion=usage.get("completion_tokens", 0),
                )
        except Exception as e:
            return LLMResponse(content="", provider="groq", model=model, error=str(e))

    async def _call_together(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                             model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """Together AI API (open-source models hosted)."""
        try:
            import httpx
        except ImportError:
            return LLMResponse(content="", provider="together", model=model, error="httpx not installed")

        api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
        if not api_key:
            return LLMResponse(content="", provider="together", model=model, error="TOGETHER_API_KEY not set")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tok,
        }

        try:
            async with httpx.AsyncClient(timeout=pc.timeout) as client:
                resp = await client.post("https://api.together.xyz/v1/chat/completions", headers=headers, json=body)
                if resp.status_code != 200:
                    return LLMResponse(content="", provider="together", model=model, error=f"HTTP {resp.status_code}: {resp.text[:200]}")

                data = resp.json()
                msg = data.get("choices", [{}])[0].get("message", {})
                usage = data.get("usage", {})

                return LLMResponse(
                    content=msg.get("content", ""),
                    provider="together",
                    model=data.get("model", model),
                    tokens_prompt=usage.get("prompt_tokens", 0),
                    tokens_completion=usage.get("completion_tokens", 0),
                )
        except Exception as e:
            return LLMResponse(content="", provider="together", model=model, error=str(e))

    async def _call_openai_compat(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                                  model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """Any OpenAI-compatible API (vLLM, text-generation-webui, LM Studio, etc.)."""
        try:
            import httpx
        except ImportError:
            return LLMResponse(content="", provider="openai_compat", model=model, error="httpx not installed")

        if not pc.base_url:
            return LLMResponse(content="", provider="openai_compat", model=model, error="base_url required for openai_compat")

        base_url = self._normalise_openai_compat_base(pc.base_url)

        headers = {
            "Content-Type": "application/json",
        }
        api_key = _bearer_token(pc.api_key or os.environ.get(pc.api_key_env, ""))
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tok,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        try:
            async with httpx.AsyncClient(timeout=pc.timeout, verify=pc.verify_ssl) as client:
                resp = await client.post(f"{base_url}/v1/chat/completions", headers=headers, json=body)
                if resp.status_code in (404, 405):
                    completion_body = {
                        "model": model,
                        "prompt": f"{system_prompt}\n\n{prompt}" if system_prompt else prompt,
                        "temperature": temp,
                        "max_tokens": max_tok,
                    }
                    resp = await client.post(f"{base_url}/v1/completions", headers=headers, json=completion_body)
                if resp.status_code != 200:
                    return LLMResponse(content="", provider="openai_compat", model=model, error=f"HTTP {resp.status_code}: {resp.text[:200]}")

                data = resp.json()
                choice = data.get("choices", [{}])[0]
                msg = choice.get("message", {})
                usage = data.get("usage", {})
                content = msg.get("content", "") if isinstance(msg, dict) else ""
                if not content:
                    content = choice.get("text", "")

                return LLMResponse(
                    content=content,
                    provider="openai_compat",
                    model=data.get("model", model),
                    tokens_prompt=usage.get("prompt_tokens", 0),
                    tokens_completion=usage.get("completion_tokens", 0),
                )
        except Exception as e:
            return LLMResponse(content="", provider="openai_compat", model=model, error=str(e))

    async def _call_http_basic_chat(self, pc: ProviderConfig, prompt: str, system_prompt: str,
                                    model: str, temp: float, max_tok: int, json_mode: bool) -> LLMResponse:
        """HTTP Basic Auth chat API with an Ollama-like response shape.

        Expected request:
            POST /chat {"model": "...", "messages": [{"role": "user", "content": "..."}]}

        Expected response:
            {"message": {"role": "assistant", "content": "..."}, ...}
        """
        try:
            import httpx
        except ImportError:
            return LLMResponse(content="", provider="http_basic_chat", model=model, error="httpx not installed")

        if not pc.base_url:
            return LLMResponse(content="", provider="http_basic_chat", model=model, error="base_url required")

        auth_value = pc.api_key or os.environ.get(pc.api_key_env, "")
        if not auth_value or ":" not in auth_value:
            return LLMResponse(
                content="",
                provider="http_basic_chat",
                model=model,
                error=f"{pc.api_key_env or 'api_key'} must be set as 'username:password'",
            )
        username, password = auth_value.split(":", 1)

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tok,
        }
        if json_mode:
            body["format"] = "json"

        base_url = self._normalise_basic_chat_base(pc.base_url)
        chat_path = pc.chat_path if pc.chat_path.startswith("/") else f"/{pc.chat_path}"
        models_path = pc.models_path if pc.models_path.startswith("/") else f"/{pc.models_path}"

        try:
            async with httpx.AsyncClient(timeout=pc.timeout, verify=pc.verify_ssl) as client:
                models_resp = await client.get(f"{base_url}{models_path}", auth=(username, password))
                if models_resp.status_code != 200:
                    return LLMResponse(
                        content="",
                        provider="http_basic_chat",
                        model=model,
                        error=f"models HTTP {models_resp.status_code}: {models_resp.text[:200]}",
                    )

                resp = await client.post(f"{base_url}{chat_path}", auth=(username, password), json=body)
                if resp.status_code != 200:
                    return LLMResponse(
                        content="",
                        provider="http_basic_chat",
                        model=model,
                        error=f"chat HTTP {resp.status_code}: {resp.text[:200]}",
                    )

                data = resp.json()
                message = data.get("message", {}) if isinstance(data, dict) else {}
                return LLMResponse(
                    content=message.get("content", "") if isinstance(message, dict) else "",
                    provider="http_basic_chat",
                    model=data.get("model", model) if isinstance(data, dict) else model,
                    tokens_prompt=data.get("prompt_eval_count", 0) if isinstance(data, dict) else 0,
                    tokens_completion=data.get("eval_count", 0) if isinstance(data, dict) else 0,
                )
        except Exception as e:
            return LLMResponse(content="", provider="http_basic_chat", model=model, error=str(e))

    # ────────────────────────────────────────────────────────────────
    # Rate Limiting & Tracking
    # ────────────────────────────────────────────────────────────────

    def _reserve_rate_limit(self, provider: str, max_rpm: int = 40) -> bool:
        """Atomically reserve one request in a process-wide rolling window."""
        now = time.time()
        with _GLOBAL_RATE_LOCK:
            window = [t for t in _GLOBAL_RATE_WINDOWS.get(provider, []) if now - t < 60]
            if len(window) >= max_rpm:
                _GLOBAL_RATE_WINDOWS[provider] = window
                return False
            window.append(now)
            _GLOBAL_RATE_WINDOWS[provider] = window
        self._rate_limits[provider] = list(window)
        self._request_counts[provider] = self._request_counts.get(provider, 0) + 1
        return True

    def _track_request(self, provider: str) -> None:
        """Backward-compatible no-op; requests are recorded before dispatch."""

    def get_stats(self) -> dict[str, int]:
        """Return request counts per provider."""
        return dict(self._request_counts)

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._cache.clear()
