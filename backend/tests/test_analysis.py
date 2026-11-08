import numpy as np
import pytest

from app.schemas import AnalysisResponse
from core.analysis import (
    MAX_HIGHLIGHTS,
    MAX_PER_CATEGORY,
    MAX_RULE_HIGHLIGHTS,
    analyze,
    merge_reasons,
    risk_level,
)


@pytest.mark.parametrize(
    ("p", "expected"),
    [(0.0, "low"), (0.49, "low"), (0.5, "medium"), (0.79, "medium"), (0.8, "high"), (1.0, "high")],
)
def test_risk_level_is_lowercase_and_uses_thresholds(p, expected):
    assert risk_level(p) == expected


class FixedClassifier:
    """Stand-in model that always returns the same probability, no training needed."""

    def __init__(self, p_phishing: float) -> None:
        self.name = "fixed"
        self.p = p_phishing

    def predict_proba(self, texts):
        return np.array([[1 - self.p, self.p] for _ in texts])


@pytest.mark.parametrize(
    ("p", "uncertain"),
    [(0.1, False), (0.39, False), (0.4, True), (0.5, True), (0.6, True), (0.61, False), (0.95, False)],
)
def test_uncertain_band(p, uncertain):
    result = analyze("some text here", FixedClassifier(p), uncertain_band=(0.4, 0.6), num_features=3)
    assert result["uncertain"] is uncertain


def test_legitimate_result_is_valid_contract():
    result = analyze("hello team", FixedClassifier(0.2))
    assert result["label"] == "legitimate"
    assert result["reasons"] == []
    assert result["confidence"] == pytest.approx(0.8)
    AnalysisResponse(**result)


def test_numpy_values_are_cast_to_python_types():
    result = analyze("hello team", FixedClassifier(np.float64(0.3)))
    assert type(result["confidence"]) is float
    assert type(result["phishing_probability"]) is float
    assert type(result["rule_score"]) is float


# --------------------------------------------------------------------------- rules + model

STRONG = "Dear Customer, verify your identity within 24 hours at http://www.paypa1.com/login"


def test_strong_rules_make_a_legitimate_verdict_uncertain_and_medium():
    result = analyze(STRONG, FixedClassifier(0.1))
    assert result["label"] == "legitimate"  # the model still decides the label
    assert result["uncertain"] is True
    assert result["risk"] == "medium"  # raised, but never to high against the model
    assert result["rule_score"] >= 0.8
    AnalysisResponse(**result)


def test_weak_rules_do_not_change_a_legitimate_verdict():
    result = analyze("Please click here to see the agenda.", FixedClassifier(0.1))
    assert result["uncertain"] is False
    assert result["risk"] == "low"
    assert [r["category"] for r in result["reasons"]] == ["call_to_action"]  # still highlighted


def test_rules_can_raise_risk_of_a_phishing_verdict():
    result = analyze(STRONG, FixedClassifier(0.55), num_features=3)
    assert result["label"] == "phishing"
    assert result["risk"] == "high"  # model alone would be "medium"


def test_rule_reasons_come_first_and_point_into_the_text():
    result = analyze(STRONG, FixedClassifier(0.9), num_features=5)
    sources = [r["source"] for r in result["reasons"]]
    assert sources == sorted(sources, key=lambda s: s != "rule")  # all rules before any model reason
    for r in result["reasons"]:
        assert STRONG[r["start"] : r["end"]] == r["feature"] or r["source"] == "model"
    AnalysisResponse(**result)


def test_sender_signals_are_returned_separately():
    result = analyze("hello", FixedClassifier(0.1), sender="PayPal <help@gmail.com>")
    assert [s["category"] for s in result["sender_signals"]] == ["sender"]
    assert result["reasons"] == []


# --------------------------------------------------------------------------- merging


def reason(start, end, source="rule", category="x", impact=0.5):
    return {
        "id": f"{start}",
        "feature": "f",
        "explanation": "e",
        "impact": impact,
        "start": start,
        "end": end,
        "source": source,
        "category": category,
    }


def test_merge_drops_model_reasons_that_overlap_rules():
    merged = merge_reasons([reason(0, 10)], [reason(5, 8, "model"), reason(20, 25, "model")])
    assert [(r["start"], r["source"]) for r in merged] == [(0, "rule"), (20, "model")]


def test_merge_keeps_slots_for_the_model():
    rules = [reason(i * 10, i * 10 + 5, category=f"c{i}") for i in range(10)]
    model = [reason(200 + i * 10, 200 + i * 10 + 5, source="model", category="model") for i in range(5)]
    merged = merge_reasons(rules, model)
    assert len(merged) == MAX_HIGHLIGHTS
    assert sum(r["source"] == "rule" for r in merged) == MAX_RULE_HIGHLIGHTS
    assert sum(r["source"] == "model" for r in merged) == MAX_HIGHLIGHTS - MAX_RULE_HIGHLIGHTS


def test_free_model_slots_are_filled_with_rules():
    rules = [reason(i * 10, i * 10 + 5, category=f"c{i}") for i in range(10)]
    merged = merge_reasons(rules, [])
    assert len(merged) == MAX_HIGHLIGHTS and all(r["source"] == "rule" for r in merged)


def test_merge_limits_per_category_and_in_total():
    rules = [reason(i * 10, i * 10 + 5, category="urgency") for i in range(5)]
    rules += [reason(100 + i * 10, 100 + i * 10 + 5, category=f"c{i}") for i in range(10)]
    merged = merge_reasons(rules, [])
    assert len(merged) == MAX_HIGHLIGHTS
    assert sum(r["category"] == "urgency" for r in merged) == MAX_PER_CATEGORY
