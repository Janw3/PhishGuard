"""Optional LLM-written explanations for model highlights (Phase 3, layer C).

Off by default. The curated templates always stay the fallback: if the LLM is
switched off, slow, unreachable, refuses, or answers outside the UX rules, the
template is shown instead. An LLM can never break or delay an analysis for long.

Providers (chosen in backend/.env, models freely swappable):
  LLM_PROVIDER=openai     any OpenAI-compatible API, called with the standard library:
                          Ollama (local, default URL), LM Studio, OpenAI, Mistral, Groq, OpenRouter ...
  LLM_PROVIDER=anthropic  Claude via the official `anthropic` SDK

A local model (Ollama) is the default endpoint; any other host is an explicit opt-in and logged at startup.

Only MODEL highlights that would otherwise get the generic fallback text are
rewritten. Rule highlights already have curated, reviewed explanations.
"""

import json
import logging
import re
import time
import urllib.error
import urllib.request
from typing import Protocol
from urllib.parse import urlsplit

logger = logging.getLogger("uvicorn.error")

SYSTEM_PROMPT = (
    "You explain phishing warning signs to non-technical email users. "
    "You get one highlighted phrase from an email, the kind of signal it is, and a short excerpt around it. "
    "Write ONE or TWO short sentences in plain English, at most 40 words in total. "
    "The first sentence MUST start with 'This is an indicator of'. "
    "Say what the phrase suggests and what the reader can check. "
    "Never claim certainty: do not say the email IS a scam or IS phishing. "
    "No jargon, no lists, no quotes, no markdown. Output only the explanation."
)

MAX_CONTEXT_CHARS = 300
MAX_EXPLANATION_CHARS = 320
# A failed call (timeout, provider down) is retried after this many seconds, not on every
# request. The first call to a local model often times out while the model is still loading.
RETRY_AFTER_SECONDS = 60
_CERTAINTY = re.compile(
    r"\b(this is (a )?(scam|phishing|fraud)|definitely|certainly|guaranteed|100 ?%|without (a )?doubt)\b",
    re.IGNORECASE,
)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama"}

# Used when LLM_MODEL is empty.
DEFAULT_MODELS = {"openai": "llama3.2:3b", "anthropic": "claude-opus-5-5"}

# Claude models that accept the server-side refusal fallback (`fallbacks: "default"`).
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}


class ExplanationWriter(Protocol):
    name: str  # shown to the user, e.g. "llama3.2:3b"

    def complete(self, system: str, prompt: str) -> str | None: ...


def build_prompt(feature: str, category: str, context: str) -> str:
    return f"Signal type: {category}\nHighlighted phrase: {feature}\nExcerpt: {context[:MAX_CONTEXT_CHARS]}"


def context_around(text: str, start: int, end: int) -> str:
    """The sentence (or ~150 characters on each side) around a highlight."""
    left = max(text.rfind(".", 0, start), text.rfind("\n", 0, start)) + 1
    right_candidates = [i for i in (text.find(".", end), text.find("\n", end)) if i != -1]
    right = min(right_candidates) + 1 if right_candidates else len(text)
    left, right = max(left, start - 150), min(right, end + 150)
    return " ".join(text[left:right].split())


def validate(text: str | None) -> str | None:
    """Accept only answers that follow the UX rules; anything else falls back to the template."""
    if not text:
        return None
    text = " ".join(text.strip().strip('"').split())
    # Small models tend to add a third sentence; keep the first two instead of discarding all.
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", text) if s]
    text = " ".join(sentences[:2])
    if (
        not text.startswith("This is an indicator of")
        or len(text) > MAX_EXPLANATION_CHARS
        or _CERTAINTY.search(text)
        or any(mark in text for mark in ("*", "#", "`"))  # markdown
    ):
        return None
    return text


class LLMExplainer:
    """Rewrites generic model-highlight explanations; caches per (category, phrase)."""

    def __init__(self, writer: ExplanationWriter, max_cache: int = 2000) -> None:
        self.writer = writer
        self.max_cache = max_cache
        self._cache: dict[tuple[str, str], str | None] = {}
        self._failed_at: dict[tuple[str, str], float] = {}  # when a call last failed, per phrase

    def explain(self, feature: str, category: str, context: str) -> str | None:
        key = (category, feature.lower())
        if key in self._cache:
            return self._cache[key]
        if time.monotonic() - self._failed_at.get(key, float("-inf")) < RETRY_AFTER_SECONDS:
            return None  # failed recently: don't hammer a broken provider
        try:
            answer = self.writer.complete(SYSTEM_PROMPT, build_prompt(feature, category, context))
        except Exception:  # any provider failure: fall back to the template
            logger.warning("LLM explanation failed for '%s'; using the template.", feature, exc_info=True)
            answer = None
        if answer is None:  # no answer at all (timeout, error, refusal): try again later
            self._failed_at[key] = time.monotonic()
            return None
        if len(self._cache) >= self.max_cache:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = validate(answer)  # an answer that breaks the rules stays rejected
        return self._cache[key]


# --------------------------------------------------------------------------- providers


class OpenAICompatibleWriter:
    """POST {base_url}/chat/completions. Works with Ollama, LM Studio, OpenAI, Mistral, Groq, OpenRouter, ..."""

    def __init__(self, model: str, base_url: str, api_key: str = "", timeout: float = 15.0) -> None:
        self.name = model
        self.model = model
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.timeout = timeout

    def complete(self, system: str, prompt: str) -> str | None:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "max_tokens": 200,
            "temperature": 0.2,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            logger.warning("LLM endpoint %s not usable: %s", self.url, error)
            return None
        choices = data.get("choices") or []
        return choices[0].get("message", {}).get("content") if choices else None


class AnthropicWriter:
    """Claude via the official SDK. The API key comes from LLM_API_KEY or ANTHROPIC_API_KEY."""

    def __init__(self, model: str, api_key: str = "", timeout: float = 15.0, client=None) -> None:
        self.name = model
        self.model = model
        if client is None:
            import anthropic  # only imported when this provider is used

            client = anthropic.Anthropic(api_key=api_key or None, timeout=timeout, max_retries=1)
        self.client = client

    def complete(self, system: str, prompt: str) -> str | None:
        import anthropic

        kwargs = {}
        if self.model in _FALLBACK_MODELS:
            # Server-side fallback: if a safety classifier declines, the API re-runs the
            # request on a suitable fallback model inside the same call.
            kwargs = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system,
                # A short, simple task: low effort keeps it fast and cheap.
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": prompt}],
                **kwargs,
            )
        except anthropic.RateLimitError:
            logger.warning("Anthropic rate limit reached; using the template.")
            return None
        except anthropic.APIStatusError as error:
            logger.warning("Anthropic API error %s: %s", error.status_code, error.message)
            return None
        except anthropic.APIConnectionError:
            logger.warning("Anthropic API not reachable; using the template.")
            return None
        if response.stop_reason == "refusal":
            return None
        return next((block.text for block in response.content if block.type == "text"), None)


def is_local(base_url: str) -> bool:
    return (urlsplit(base_url).hostname or "") in _LOCAL_HOSTS


def build_explainer(provider: str, model: str, base_url: str, api_key: str, timeout: float) -> LLMExplainer | None:
    """The configured explainer, or None if LLM explanations are off."""
    provider = provider.strip().lower()
    if provider in ("", "none", "off"):
        return None
    model = model.strip() or DEFAULT_MODELS.get(provider, "")
    if provider == "openai":
        writer = OpenAICompatibleWriter(model, base_url, api_key, timeout)
        where = base_url
        external = not is_local(base_url)
    elif provider == "anthropic":
        writer = AnthropicWriter(model, api_key, timeout)
        where, external = "api.anthropic.com", True
    else:
        raise ValueError(f"Unknown LLM_PROVIDER '{provider}'. Use none, openai or anthropic.")
    if external:
        logger.warning(
            "LLM explanations use an EXTERNAL service (%s): highlighted phrases and short excerpts "
            "of analyzed emails are sent there.",
            where,
        )
    else:
        logger.info("LLM explanations use a local model (%s at %s).", model, where)
    return LLMExplainer(writer)
