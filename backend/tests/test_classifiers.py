"""Smoke tests that run against every trained model."""

import numpy as np

from tests.conftest import RAW_PHISHING_EMAIL, requires_models

pytestmark = requires_models


def test_registry_has_at_least_two_models(classifiers):
    assert len(classifiers) >= 2


def test_every_model_returns_valid_probabilities(classifiers):
    texts = [RAW_PHISHING_EMAIL, "hi team , the meeting moved to 3 pm . thanks"]
    for name, clf in classifiers.items():
        proba = clf.predict_proba(texts)
        assert proba.shape == (2, 2), name
        assert np.allclose(proba.sum(axis=1), 1.0), name
        assert ((proba >= 0) & (proba <= 1)).all(), name


def test_formatting_does_not_change_prediction(classifiers):
    """normalize() runs inside predict_proba, so raw and tokenized text agree."""
    tokenized = "your account has been suspended . click here immediately ."
    raw = "Your account has been SUSPENDED.\nClick here immediately."
    for name, clf in classifiers.items():
        a, b = clf.predict_proba([tokenized, raw])[:, 1]
        assert abs(a - b) < 1e-9, name
