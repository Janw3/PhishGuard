"""LLM explanations: validation, caching, fallback, providers. No real LLM is called."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from core.analysis import add_llm_explanations
from core.explainer import FALLBACK_EXPLANATION
from core.llm_explanations import (
    RETRY_AFTER_SECONDS,
    AnthropicWriter,
    LLMExplainer,
    OpenAICompatibleWriter,
    build_explainer,
    build_prompt,
    context_around,
    validate,
)

GOOD = "This is an indicator of a money lure. Check whether you really expect a payment from this sender."


# --------------------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "answer",
    [
        GOOD,
        f'"{GOOD}"',  # quotes are stripped
        "This is an indicator of urgency.",
    ],
)
def test_valid_answers_are_accepted(answer):
    assert validate(answer).startswith("This is an indicator of")


def test_extra_sentences_are_cut_to_two():
    answer = "This is an indicator of urgency. Check the sender. Small models like to add more."
    assert validate(answer) == "This is an indicator of urgency. Check the sender."


@pytest.mark.parametrize(
    "answer",
    [
        None,
        "",
        "Be careful, this looks like phishing.",  # wrong opening
        "This is an indicator of fraud. This is a scam.",  # claims certainty
        "This is an indicator of fraud, definitely.",  # claims certainty
        "This is an indicator of **urgency**.",  # markdown
        "This is an indicator of " + "very " * 80 + "long text.",  # too long
    ],
)
def test_answers_breaking_the_ux_rules_are_rejected(answer):
    assert validate(answer) is None


def test_prompt_contains_only_phrase_category_and_short_excerpt():
    prompt = build_prompt("wire", "model", "x" * 1000)
    assert "Highlighted phrase: wire" in prompt and "Signal type: model" in prompt
    assert len(prompt) < 400  # never the whole email


def test_context_is_the_surrounding_sentence():
    text = "Hello Anna. Please send the fee by wire transfer today. Thanks, Tom."
    start = text.index("wire")
    assert context_around(text, start, start + 4) == "Please send the fee by wire transfer today."


# --------------------------------------------------------------------------- explainer


class FakeWriter:
    name = "fake-model"

    def __init__(self, answer=GOOD, fail=False):
        self.answer, self.fail, self.calls = answer, fail, 0

    def complete(self, system, prompt):
        self.calls += 1
        if self.fail:
            raise RuntimeError("provider down")
        return self.answer


def test_results_are_cached_per_category_and_phrase():
    writer = FakeWriter()
    llm = LLMExplainer(writer)
    assert llm.explain("Wire", "model", "ctx") == GOOD
    assert llm.explain("wire", "model", "other ctx") == GOOD
    assert writer.calls == 1


def test_provider_failure_is_not_retried_at_once():
    writer = FakeWriter(fail=True)
    llm = LLMExplainer(writer)
    assert llm.explain("wire", "model", "ctx") is None
    assert llm.explain("wire", "model", "ctx") is None
    assert writer.calls == 1  # a broken provider is not hammered for the same phrase


def test_provider_failure_is_retried_later(monkeypatch):
    # e.g. the first call to a local model times out while the model is still loading
    clock = [1000.0]
    monkeypatch.setattr("core.llm_explanations.time.monotonic", lambda: clock[0])
    writer = FakeWriter(fail=True)
    llm = LLMExplainer(writer)
    assert llm.explain("wire", "model", "ctx") is None
    writer.fail = False
    clock[0] += RETRY_AFTER_SECONDS + 1
    assert llm.explain("wire", "model", "ctx") == GOOD
    assert writer.calls == 2


def test_writer_returning_nothing_counts_as_failure():
    writer = FakeWriter(answer=None)
    llm = LLMExplainer(writer)
    assert llm.explain("wire", "model", "ctx") is None
    writer.answer = GOOD
    assert llm.explain("wire", "model", "ctx") is None  # still inside the retry wait
    assert writer.calls == 1


def reason(source, explanation, start=0, end=4, feature="wire"):
    return {"id": "r", "feature": feature, "explanation": explanation, "impact": 0.1,
            "start": start, "end": end, "source": source, "category": "model" if source == "model" else "money"}  # fmt: skip


def test_only_generic_model_explanations_are_rewritten():
    llm = LLMExplainer(FakeWriter())
    reasons = add_llm_explanations(
        [reason("model", FALLBACK_EXPLANATION), reason("rule", "curated text"), reason("model", "curated model text")],
        "wire money now",
        llm,
    )
    assert reasons[0]["explanation"] == GOOD and reasons[0]["explanation_by"] == "fake-model"
    assert reasons[1]["explanation"] == "curated text" and reasons[1]["explanation_by"] is None
    assert reasons[2]["explanation"] == "curated model text"


def test_invalid_llm_answer_keeps_the_template():
    llm = LLMExplainer(FakeWriter(answer="Definitely a scam!"))
    reasons = add_llm_explanations([reason("model", FALLBACK_EXPLANATION)], "wire money", llm)
    assert reasons[0]["explanation"] == FALLBACK_EXPLANATION and reasons[0]["explanation_by"] is None


def test_without_llm_nothing_changes():
    reasons = add_llm_explanations([reason("model", FALLBACK_EXPLANATION)], "wire money", None)
    assert reasons[0]["explanation"] == FALLBACK_EXPLANATION and reasons[0]["explanation_by"] is None


# --------------------------------------------------------------------------- providers


def test_build_explainer_off_by_default_and_rejects_unknown():
    assert build_explainer("none", "", "", "", 5) is None
    with pytest.raises(ValueError):
        build_explainer("something", "", "", "", 5)


def test_provider_default_models():
    assert build_explainer("openai", "", "http://localhost:11434/v1", "", 5).writer.name == "llama3.2:3b"


@pytest.fixture
def fake_openai_server():
    """A tiny local server that answers like the OpenAI chat completions API."""
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received["path"] = self.path
            received["auth"] = self.headers.get("Authorization")
            received["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            payload = json.dumps({"choices": [{"message": {"role": "assistant", "content": GOOD}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/v1", received
    server.shutdown()


def test_openai_compatible_writer(fake_openai_server):
    base_url, received = fake_openai_server
    writer = OpenAICompatibleWriter("llama3.2:3b", base_url, api_key="secret", timeout=5)
    assert writer.complete("sys", "prompt") == GOOD
    assert received["path"] == "/v1/chat/completions"
    assert received["auth"] == "Bearer secret"
    assert received["body"]["model"] == "llama3.2:3b"
    assert received["body"]["messages"][0] == {"role": "system", "content": "sys"}


def test_openai_compatible_writer_unreachable_returns_none():
    writer = OpenAICompatibleWriter("m", "http://127.0.0.1:9/v1", timeout=1)  # nothing listens on port 9
    assert writer.complete("sys", "prompt") is None


class FakeAnthropicClient:
    def __init__(self, stop_reason="end_turn"):
        self.kwargs = None
        self.stop_reason = stop_reason
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.kwargs = kwargs
        return SimpleNamespace(stop_reason=self.stop_reason, content=[SimpleNamespace(type="text", text=GOOD)])


def test_anthropic_writer_sends_low_effort_and_fallbacks_for_supported_models():
    client = FakeAnthropicClient()
    writer = AnthropicWriter("claude-opus-5-5", client=client)
    assert writer.complete("sys", "prompt") == GOOD
    assert client.kwargs["model"] == "claude-opus-5-5"
    assert client.kwargs["output_config"] == {"effort": "low"}
    assert client.kwargs["fallbacks"] == "default"
    assert client.kwargs["betas"] == ["server-side-fallback-2026-07-01"]


def test_anthropic_writer_omits_fallbacks_for_other_models():
    client = FakeAnthropicClient()
    AnthropicWriter("claude-haiku-5-5", client=client).complete("sys", "prompt")
    assert "fallbacks" not in client.kwargs


def test_anthropic_refusal_falls_back_to_template():
    writer = AnthropicWriter("claude-opus-5-5", client=FakeAnthropicClient(stop_reason="refusal"))
    assert writer.complete("sys", "prompt") is None
