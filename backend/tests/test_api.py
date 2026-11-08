"""API tests that call the route functions directly.

FastAPI's TestClient would need the extra `httpx` dependency, so these tests
call the functions behind the routes and validate the results against the
response models instead.
"""

import pytest
from fastapi import HTTPException

from app.schemas import AnalysisResponse, EmailRequest, ModelInfo
from tests.conftest import RAW_PHISHING_EMAIL, requires_models

pytestmark = requires_models


@pytest.fixture(scope="module")
def api():
    from app import main  # imported lazily: loading it loads all models

    return main


def test_models_endpoint_lists_models_with_one_default(api):
    models = [ModelInfo(**m) for m in api.list_models()]
    assert len(models) >= 2
    assert sum(m.default for m in models) == 1


def test_analyze_uses_requested_model(api):
    name = "logistic_regression"
    result = AnalysisResponse(**api.analyze(EmailRequest(content=RAW_PHISHING_EMAIL, model=name)))
    assert result.model == name
    assert result.label == "phishing"
    for r in result.reasons:
        assert RAW_PHISHING_EMAIL[r.start : r.end].lower() == r.feature.lower()


def test_analyze_unknown_model_is_rejected(api):
    with pytest.raises(HTTPException) as exc:
        api.analyze(EmailRequest(content="hi", model="does_not_exist"))
    assert exc.value.status_code == 422


def test_demo_emails_endpoint(api):
    emails = api.get_emails()
    assert emails and all({"id", "body", "subject"} <= e.keys() for e in emails)
