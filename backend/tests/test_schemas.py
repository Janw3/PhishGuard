import pytest
from pydantic import ValidationError

from app.schemas import AnalysisResponse, EmailRequest

VALID = {
    "label": "phishing",
    "risk": "high",
    "confidence": 0.9,
    "phishing_probability": 0.9,
    "rule_score": 0.5,
    "uncertain": False,
    "model": "random_forest",
    "reasons": [
        {
            "id": "reason_1",
            "feature": "click",
            "explanation": "...",
            "impact": 0.1,
            "start": 0,
            "end": 5,
            "source": "model",
            "category": "model",
        }
    ],
    "sender_signals": [
        {"id": "sender_1", "feature": "paypa1.com", "category": "sender", "explanation": "...", "severity": 0.9}
    ],
}


@pytest.mark.parametrize("source", ["Rule", "lime", ""])
def test_reason_source_must_be_rule_or_model(source):
    reason = {**VALID["reasons"][0], "source": source}
    with pytest.raises(ValidationError):
        AnalysisResponse(**{**VALID, "reasons": [reason]})


def test_valid_response_is_accepted():
    assert AnalysisResponse(**VALID).risk == "high"


@pytest.mark.parametrize("risk", ["High", "HIGH", "critical", ""])
def test_risk_must_be_lowercase_contract_value(risk):
    with pytest.raises(ValidationError):
        AnalysisResponse(**{**VALID, "risk": risk})


@pytest.mark.parametrize("label", ["Phishing Email", "safe", "uncertain"])
def test_label_must_be_contract_value(label):
    with pytest.raises(ValidationError):
        AnalysisResponse(**{**VALID, "label": label})


def test_request_model_and_sender_are_optional():
    assert EmailRequest(content="hi").model is None
    assert EmailRequest(content="hi").sender is None
    assert EmailRequest(content="hi", model="logistic_regression").model == "logistic_regression"
