"""
VAPT Platform — LLM Context-Window Budgeting (Phase 1, local-first AI)

Local models (qwen, gemma) have far smaller context windows than GPT-4/Claude.
The codebase previously truncated evidence with hardcoded slices (`[:2000]`,
`[:6000]`) which silently drops evidence and can still overflow a small window.

This module makes trimming **window-aware**:
  * ``context_window_for`` — best-known context length for a model (static table +
    a cache primed by an optional live Ollama probe).
  * ``budget_prompt`` — trim a prompt to fit ``ctx - reserved_output`` tokens using
    a HEAD+TAIL strategy, so both the task framing (start) and the JSON-format
    instructions (end) survive while the bulky evidence in the middle is sampled.

Token estimation is a deliberately cheap ~chars/4 heuristic — good enough for
budgeting without pulling in a tokenizer per model.
"""

from __future__ import annotations

from typing import Any, Optional

from loguru import logger

CHARS_PER_TOKEN = 4
DEFAULT_CONTEXT = 8192
# Reserve headroom below the true window for prompt-format overhead + safety.
SAFETY_FRACTION = 0.92

# Substring → context window (tokens). First match wins; order longest/specific first.
KNOWN_CONTEXT_WINDOWS: list[tuple[str, int]] = [
    ("qwen2.5", 32768), ("qwen2", 32768), ("qwen", 32768),
    ("gemma2", 8192), ("gemma", 8192),
    ("llama3.1", 131072), ("llama-3.1", 131072), ("llama3", 8192), ("llama", 8192),
    ("mixtral", 32768), ("mistral", 32768),
    ("deepseek", 16384),
    ("phi3", 128000), ("phi", 4096),
    ("gpt-4o", 128000), ("gpt-4-turbo", 128000), ("gpt-4", 8192), ("gpt-3.5", 16384),
    ("claude", 200000),
    ("gemini-1.5", 1000000), ("gemini", 32768),
]

# Runtime cache of model(lowercased) → context window, primed by probes.
_ctx_cache: dict[str, int] = {}


def estimate_tokens(text: str) -> int:
    """Cheap token estimate (~chars/4). Never returns negative."""
    if not text:
        return 0
    return len(text) // CHARS_PER_TOKEN + 1


def context_window_for(model: str, explicit: Optional[int] = None) -> int:
    """Best-known context window (tokens) for a model name."""
    if explicit and explicit > 0:
        return explicit
    key = (model or "").lower().strip()
    if not key:
        return DEFAULT_CONTEXT
    if key in _ctx_cache:
        return _ctx_cache[key]
    for frag, ctx in KNOWN_CONTEXT_WINDOWS:
        if frag in key:
            return ctx
    return DEFAULT_CONTEXT


async def probe_ollama_context(model: str, base_url: str = "http://localhost:11434") -> Optional[int]:
    """Ask a live Ollama server for a model's real context length and cache it.

    Best-effort: returns None (and logs at debug) if Ollama is unreachable or the
    field is absent. Intended to be called once at scan warm-up.
    """
    if not model:
        return None
    try:
        import httpx

        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(f"{base_url.rstrip('/')}/api/show", json={"name": model})
            if resp.status_code != 200:
                return None
            info = (resp.json() or {}).get("model_info", {}) or {}
            # e.g. "qwen2.context_length", "gemma2.context_length"
            for key, value in info.items():
                if key.endswith("context_length") and isinstance(value, int) and value > 0:
                    _ctx_cache[model.lower().strip()] = value
                    logger.info("[llm_budget] {model} context window = {n} tokens (probed)",
                                model=model, n=value)
                    return value
    except Exception as exc:
        logger.debug("[llm_budget] Ollama context probe failed for {m}: {e}", m=model, e=exc)
    return None


def _head_tail_trim(text: str, max_tokens: int) -> str:
    """Keep the head (task framing) and tail (output-format instructions),
    dropping the bulky middle with an explicit marker."""
    max_chars = max(64, max_tokens * CHARS_PER_TOKEN)
    if len(text) <= max_chars:
        return text
    marker = "\n\n…[evidence trimmed to fit model context window]…\n\n"
    keep = max_chars - len(marker)
    if keep <= 0:
        return text[:max_chars]
    head = int(keep * 0.6)
    tail = keep - head
    return text[:head] + marker + text[-tail:]


def budget_prompt(
    prompt: str,
    system_prompt: str = "",
    model: str = "",
    *,
    reserved_output: int = 512,
    explicit_ctx: Optional[int] = None,
) -> tuple[str, dict[str, Any]]:
    """Return (possibly-trimmed prompt, meta). Trims only when it would overflow.

    meta = {ctx, prompt_tokens, available_tokens, trimmed}.
    """
    ctx = int(context_window_for(model, explicit_ctx) * SAFETY_FRACTION)
    system_tokens = estimate_tokens(system_prompt)
    available = max(128, ctx - reserved_output - system_tokens)
    prompt_tokens = estimate_tokens(prompt)

    meta = {
        "ctx": ctx,
        "prompt_tokens": prompt_tokens,
        "available_tokens": available,
        "trimmed": False,
    }
    if prompt_tokens <= available:
        return prompt, meta

    trimmed = _head_tail_trim(prompt, available)
    meta["trimmed"] = True
    meta["kept_tokens"] = estimate_tokens(trimmed)
    logger.warning(
        "[llm_budget] Prompt {pt} tok > {avail} avail for '{model}' — trimmed to fit window",
        pt=prompt_tokens, avail=available, model=model or "?",
    )
    return trimmed, meta


def fit_evidence(evidence: str, max_tokens: int) -> str:
    """Trim a single evidence blob to a token budget (head+tail preserved)."""
    if estimate_tokens(evidence) <= max_tokens:
        return evidence
    return _head_tail_trim(evidence, max_tokens)
