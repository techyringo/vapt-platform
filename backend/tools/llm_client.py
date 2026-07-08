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
import json
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


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
    temperature: float = 0.3
    timeout: int = 120
    enabled: bool = True
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
        self._enabled = self._env_truthy("VAPT_LLM_ENABLED", default=False)
        self._allow_fallbacks = self._env_truthy("VAPT_LLM_ALLOW_FALLBACKS", default=False)

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

    def _load_from_config(self, config: Any) -> None:
        """Load provider configs from AppConfig LLM section."""
        llm = config.llm

        # Primary provider
        primary = ProviderConfig(
            provider=LLMProvider(llm.provider),
            model=llm.model,
            api_key_env=llm.api_key_env,
            base_url=getattr(llm, "base_url", ""),
            max_tokens=llm.max_tokens,
            temperature=llm.temperature,
            enabled=True,
        )
        self._providers[llm.provider] = primary
        self._fallback_chain.append(llm.provider)

        # Load additional providers from config if present
        extra_providers = getattr(llm, "fallback_providers", None)
        if extra_providers and isinstance(extra_providers, list):
            for prov_cfg in extra_providers:
                if isinstance(prov_cfg, dict):
                    name = prov_cfg.get("provider", "")
                    if name and name not in self._providers:
                        pc = ProviderConfig(
                            provider=LLMProvider(name),
                            model=prov_cfg.get("model", "default"),
                            api_key_env=prov_cfg.get("api_key_env", ""),
                            api_key=prov_cfg.get("api_key", ""),
                            base_url=prov_cfg.get("base_url", ""),
                            max_tokens=prov_cfg.get("max_tokens", 4096),
                            temperature=prov_cfg.get("temperature", 0.3),
                            enabled=prov_cfg.get("enabled", True),
                            organization_id=prov_cfg.get("organization_id", ""),
                            project_id=prov_cfg.get("project_id", ""),
                            deployment_id=prov_cfg.get("deployment_id", ""),
                        )
                        self._providers[name] = pc
                        self._fallback_chain.append(name)

        # Always add Ollama as last fallback (local, free)
        if "ollama" not in self._providers:
            self._providers["ollama"] = ProviderConfig(
                provider=LLMProvider.OLLAMA,
                model="llama3",
                base_url="http://localhost:11434",
                enabled=True,
            )
            self._fallback_chain.append("ollama")

    def _load_defaults(self) -> None:
        """Load sensible defaults when no config provided."""
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

    def add_provider(self, config: ProviderConfig) -> None:
        """Add or override a provider configuration."""
        self._providers[config.provider.value] = config
        if config.provider.value not in self._fallback_chain:
            self._fallback_chain.append(config.provider.value)

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
            elif pc.api_key or os.environ.get(pc.api_key_env, ""):
                available.append(name)
        return available

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

        # Check cache
        cache_key = f"{provider}:{model}:{prompt[:500]}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            cached.cached = True
            return cached

        # Determine provider order
        if provider:
            providers_to_try = [provider]
        else:
            providers_to_try = (
                self._fallback_chain
                if use_fallback and self._allow_fallbacks
                else self._fallback_chain[:1]
            )

        last_error = None
        for prov_name in providers_to_try:
            pc = self._providers.get(prov_name)
            if not pc or not pc.enabled:
                continue

            # Check rate limit
            if not self._check_rate_limit(prov_name):
                continue

            # Check API key availability
            if pc.provider not in {LLMProvider.OLLAMA, LLMProvider.OPENAI_COMPAT}:
                api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
                if not api_key:
                    continue

            # Resolve model
            effective_model = model or pc.model
            effective_temp = temperature if temperature is not None else pc.temperature
            effective_max = max_tokens or pc.max_tokens

            try:
                response = await self._call_provider(
                    pc=pc,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    model=effective_model,
                    temperature=effective_temp,
                    max_tokens=effective_max,
                    json_mode=json_mode,
                )

                if response and not response.error:
                    self._cache[cache_key] = response
                    self._track_request(prov_name)
                    return response
                else:
                    last_error = response.error if response else "No response"

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

        api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
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

        headers = {
            "Content-Type": "application/json",
        }
        api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
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
            async with httpx.AsyncClient(timeout=pc.timeout) as client:
                resp = await client.post(f"{pc.base_url}/v1/chat/completions", headers=headers, json=body)
                if resp.status_code != 200:
                    return LLMResponse(content="", provider="openai_compat", model=model, error=f"HTTP {resp.status_code}: {resp.text[:200]}")

                data = resp.json()
                msg = data.get("choices", [{}])[0].get("message", {})
                usage = data.get("usage", {})

                return LLMResponse(
                    content=msg.get("content", ""),
                    provider="openai_compat",
                    model=data.get("model", model),
                    tokens_prompt=usage.get("prompt_tokens", 0),
                    tokens_completion=usage.get("completion_tokens", 0),
                )
        except Exception as e:
            return LLMResponse(content="", provider="openai_compat", model=model, error=str(e))

    # ────────────────────────────────────────────────────────────────
    # Rate Limiting & Tracking
    # ────────────────────────────────────────────────────────────────

    def _check_rate_limit(self, provider: str, max_rpm: int = 60) -> bool:
        """Check if we're within rate limits for a provider."""
        now = time.time()
        window = self._rate_limits.setdefault(provider, [])
        # Clean old entries (older than 60 seconds)
        self._rate_limits[provider] = [t for t in window if now - t < 60]
        return len(self._rate_limits[provider]) < max_rpm

    def _track_request(self, provider: str) -> None:
        """Record a request for rate limiting."""
        self._rate_limits.setdefault(provider, []).append(time.time())
        self._request_counts[provider] = self._request_counts.get(provider, 0) + 1

    def get_stats(self) -> dict[str, int]:
        """Return request counts per provider."""
        return dict(self._request_counts)

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._cache.clear()
