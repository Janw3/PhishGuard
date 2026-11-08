"""Shared test fixtures.

Model-dependent tests are skipped (not failed) when no trained models exist,
e.g. on a fresh clone. Train them with: python -m scripts.train
"""

import pytest

from app.config import ARTIFACTS_DIR
from core.classifiers import load_registry

HAS_MODELS = any(ARTIFACTS_DIR.glob("*.pkl"))
requires_models = pytest.mark.skipif(
    not HAS_MODELS, reason="no trained models in artifacts/ (run python -m scripts.train)"
)

# Formatted like a real email: capitals, punctuation, line breaks.
RAW_PHISHING_EMAIL = (
    "Dear Customer,\n\n"
    "Your account has been SUSPENDED. Click here immediately to verify your password "
    "and credit card details.\n"
    "Failure to act within 24 hours will result in termination."
)


@pytest.fixture(scope="session")
def classifiers():
    if not HAS_MODELS:
        pytest.skip("no trained models in artifacts/")
    return load_registry(ARTIFACTS_DIR)
