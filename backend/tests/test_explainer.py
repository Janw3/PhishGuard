"""Highlight positions must index into the exact text the UI displays."""

import pytest

from app.demo_emails import load_emails
from core.explainer import (
    FALLBACK_EXPLANATION,
    explain,
    find_position,
    get_explanation,
    is_meaningful,
    merge_adjacent,
)
from tests.conftest import RAW_PHISHING_EMAIL, requires_models

# Fewer LIME samples than in production keeps the tests fast.
NUM_SAMPLES = 500


def test_find_position_is_case_insensitive_and_points_into_original():
    text = "Please CLICK here"
    start, end = find_position(text, "click")
    assert text[start:end] == "CLICK"


def test_find_position_returns_minus_one_when_missing():
    assert find_position("hello", "click") == (-1, -1)


def test_find_position_matches_whole_words_only():
    text = "Your access is limited. Fix it now."
    start, end = find_position(text, "it")
    assert text[start:end] == "it" and start == text.index(" it ") + 1


@pytest.mark.parametrize("word", ["it", "the", "email", "Account", "please", "information", "42", "ok"])
def test_generic_words_are_not_meaningful(word):
    assert not is_meaningful(word)


@pytest.mark.parametrize("word", ["verify", "password", "lottery", "PayPal", "suspended", "wire"])
def test_specific_words_are_meaningful(word):
    assert is_meaningful(word)


def test_get_explanation_matches_whole_words():
    assert get_explanation("processing fee") != FALLBACK_EXPLANATION
    assert get_explanation("feedback") == FALLBACK_EXPLANATION  # contains "fee", but is not "fee"


def model_reason(text, word, impact):
    start, end = find_position(text, word)
    return {
        "id": word,
        "feature": word,
        "explanation": "",
        "impact": impact,
        "start": start,
        "end": end,
        "source": "model",
        "category": "model",
    }


def test_adjacent_features_merge_into_one_phrase():
    text = "Please send the processing fee by wire transfer today."
    reasons = [model_reason(text, w, 0.1) for w in ["processing", "fee", "wire", "transfer"]]
    merged = merge_adjacent(text, reasons)
    assert [r["feature"] for r in merged] == ["processing fee", "wire transfer"]
    assert merged[0]["impact"] == pytest.approx(0.2)
    assert all(text[r["start"] : r["end"]] == r["feature"] for r in merged)
    assert merged[1]["explanation"] != FALLBACK_EXPLANATION  # curated text for "wire transfer"


def test_features_far_apart_stay_separate():
    text = "Verify now. Later we talk about the password."
    reasons = [model_reason(text, w, 0.1) for w in ["Verify", "password"]]
    assert len(merge_adjacent(text, reasons)) == 2


@requires_models
def test_model_highlights_contain_no_generic_words(classifiers):
    for clf in classifiers.values():
        for email in load_emails():
            for r in explain(email["body"], clf, num_features=20, num_samples=NUM_SAMPLES):
                for word in r["feature"].split():
                    assert is_meaningful(word.strip(",.;:'\"-")), (clf.name, r["feature"])


def assert_reasons_match_text(text: str, reasons: list[dict]) -> None:
    for r in reasons:
        assert 0 <= r["start"] < r["end"] <= len(text)
        assert text[r["start"] : r["end"]].lower() == r["feature"].lower()
        assert type(r["impact"]) is float
        assert type(r["start"]) is int and type(r["end"]) is int


@requires_models
def test_offsets_match_raw_text_with_capitals_and_newlines(classifiers):
    for clf in classifiers.values():
        reasons = explain(RAW_PHISHING_EMAIL, clf, num_features=10, num_samples=NUM_SAMPLES)
        assert reasons, clf.name
        assert_reasons_match_text(RAW_PHISHING_EMAIL, reasons)


@requires_models
def test_offsets_match_demo_emails(classifiers):
    clf = next(iter(classifiers.values()))
    for email in load_emails():
        reasons = explain(email["body"], clf, num_features=10, num_samples=NUM_SAMPLES)
        assert_reasons_match_text(email["body"], reasons)


@requires_models
def test_explanations_are_deterministic(classifiers):
    clf = next(iter(classifiers.values()))
    first = explain(RAW_PHISHING_EMAIL, clf, num_features=10, num_samples=NUM_SAMPLES)
    second = explain(RAW_PHISHING_EMAIL, clf, num_features=10, num_samples=NUM_SAMPLES)
    strip_ids = lambda rs: [{k: v for k, v in r.items() if k != "id"} for r in rs]  # noqa: E731
    assert strip_ids(first) == strip_ids(second)
