"""Pretrained Hugging Face models behind the same Classifier interface.

Each model is pinned to an exact revision (commit) on the Hub, so results stay
reproducible even if the author updates the model. Weights are downloaded on
first use into the Hugging Face cache (outside the repo) and never committed.

The models are loaded lazily: the API starts fast, and only the first request
to a pretrained model waits for loading (and, the very first time, the download).
"""

import threading
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class PretrainedSpec:
    repo_id: str
    revision: str
    # Output indices that mean "phishing". All other outputs count as legitimate.
    phishing_labels: tuple[int, ...]
    license: str
    note: str


PRETRAINED: dict[str, PretrainedSpec] = {
    "cybersectony_distilbert": PretrainedSpec(
        repo_id="cybersectony/phishing-email-detection-distilbert_v2.4.1",
        revision="6724dec17360ab1f6450553f1d950404f66a5dde",
        phishing_labels=(1, 3),
        license="apache-2.0",
        note="Trained on cybersectony/PhishingEmailDetectionv2.0, which may overlap our corpora "
        "(scores on our data can be optimistic).",
    ),
    "dima806_distilbert": PretrainedSpec(
        repo_id="dima806/phishing-email-detection",
        revision="310a5602280486e01dd60e37230980cfcc327b41",
        # config.json: 0 "SAVE EMAIL", 1 "PHISHING EMAIL"
        phishing_labels=(1,),
        license="apache-2.0",
        note="Training data not documented.",
    ),
}


def to_binary(probabilities: np.ndarray, phishing_labels: tuple[int, ...]) -> np.ndarray:
    """Collapse a model's class probabilities into [P(legitimate), P(phishing)] per row."""
    p_phishing = probabilities[:, list(phishing_labels)].sum(axis=1)
    return np.column_stack([1.0 - p_phishing, p_phishing])


def _logsumexp(x: np.ndarray) -> np.ndarray:
    m = x.max(axis=1, keepdims=True)
    return (m + np.log(np.exp(x - m).sum(axis=1, keepdims=True)))[:, 0]


def log_odds_from_logits(logits: np.ndarray, phishing_labels: tuple[int, ...]) -> np.ndarray:
    """log(sum of exp(phishing logits)) - log(sum of exp(other logits)), per row."""
    phishing = list(phishing_labels)
    others = [i for i in range(logits.shape[1]) if i not in phishing_labels]
    return _logsumexp(logits[:, phishing]) - _logsumexp(logits[:, others])


class HuggingFaceClassifier:
    """A Hugging Face sequence-classification model as a Classifier.

    It gets the RAW text (no normalize()): transformers have their own tokenizer
    and were trained on normal text with capitals and punctuation.
    """

    # Highlights for transformers come from word occlusion (core/occlusion.py),
    # which uses phishing_log_odds. This is only the fallback if LIME is used.
    explain_samples = 200
    max_length = 512
    batch_size = 16

    def __init__(self, name: str, spec: PretrainedSpec) -> None:
        self.name = name
        self.spec = spec
        self._model = None
        self._tokenizer = None
        # Startup preloading and the first request may try to load at the same
        # time; the lock makes the second one wait instead of loading twice.
        self._lock = threading.Lock()

    def _load(self) -> None:
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:  # loaded by another thread while we waited
                return
            # Imported here so the backend starts without loading torch when no
            # pretrained model is used.
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            tokenizer = AutoTokenizer.from_pretrained(self.spec.repo_id, revision=self.spec.revision)
            model = AutoModelForSequenceClassification.from_pretrained(
                self.spec.repo_id, revision=self.spec.revision, use_safetensors=True
            )
            model.eval()
            # Assign only when fully ready: other threads check `_model` without the lock.
            self._tokenizer = tokenizer
            self._model = model

    def _logits(self, texts: list[str]) -> np.ndarray:
        import torch

        self._load()
        batches = []
        with torch.no_grad():
            for i in range(0, len(texts), self.batch_size):
                inputs = self._tokenizer(
                    list(texts[i : i + self.batch_size]),
                    truncation=True,
                    max_length=self.max_length,
                    padding=True,
                    return_tensors="pt",
                )
                batches.append(self._model(**inputs).logits.numpy())
        return np.vstack(batches)

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        logits = self._logits(texts)
        exp = np.exp(logits - logits.max(axis=1, keepdims=True))  # softmax, numerically stable
        return to_binary(exp / exp.sum(axis=1, keepdims=True), self.spec.phishing_labels)

    def phishing_log_odds(self, texts: list[str]) -> np.ndarray:
        """log(P(phishing) / P(legitimate)) per text, computed from the raw logits.

        Unlike the probability, this does not saturate: when the model is 99.99%
        sure, removing one word barely changes the probability, but the log-odds
        still change clearly. That makes it the right measure for occlusion.
        """
        return log_odds_from_logits(self._logits(texts), self.spec.phishing_labels)


def load_pretrained(names: list[str]) -> dict[str, HuggingFaceClassifier]:
    unknown = [n for n in names if n not in PRETRAINED]
    if unknown:
        raise ValueError(f"Unknown pretrained model(s) {unknown}. Known: {sorted(PRETRAINED)}")
    return {name: HuggingFaceClassifier(name, PRETRAINED[name]) for name in names}
