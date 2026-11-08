"""Model abstraction and registry.

Every model the API offers implements the small `Classifier` protocol, so the
rest of the code (analysis, LIME, tests) does not care whether it is a
scikit-learn pipeline today or a transformer later.
"""

from pathlib import Path
from typing import Protocol

import joblib
import numpy as np

from core.preprocessing import normalize


class Classifier(Protocol):
    name: str

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        """Return an array of shape (n, 2): [P(legitimate), P(phishing)] per text."""
        ...


class SklearnTextClassifier:
    """Wraps a trained scikit-learn text pipeline (e.g. TF-IDF + classifier).

    Normalization happens here, inside predict_proba, so callers (and LIME)
    can pass the original text.
    """

    def __init__(self, name: str, pipeline) -> None:
        self.name = name
        self.pipeline = pipeline

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        return self.pipeline.predict_proba([normalize(t) for t in texts])


def load_registry(artifacts_dir: Path) -> dict[str, Classifier]:
    """Load every <name>.pkl in artifacts_dir as a classifier called <name>."""
    return {
        path.stem: SklearnTextClassifier(path.stem, joblib.load(path)) for path in sorted(artifacts_dir.glob("*.pkl"))
    }
