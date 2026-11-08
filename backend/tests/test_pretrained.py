"""Pretrained models: label mapping always; real inference only if the model is already cached.

Real inference needs the weights (~270 MB each) in the Hugging Face cache. They
are downloaded on first use by the API or by scripts.evaluate; the tests never
download anything themselves.
"""

import numpy as np
import pytest

from core.pretrained import PRETRAINED, load_pretrained, to_binary


def test_to_binary_sums_all_phishing_outputs():
    probabilities = np.array([[0.1, 0.2, 0.3, 0.4], [0.7, 0.1, 0.2, 0.0]])
    binary = to_binary(probabilities, (1, 3))
    assert binary == pytest.approx(np.array([[0.4, 0.6], [0.9, 0.1]]))


def test_to_binary_two_classes():
    assert to_binary(np.array([[0.25, 0.75]]), (1,)) == pytest.approx(np.array([[0.25, 0.75]]))


def test_unknown_pretrained_model_is_rejected():
    with pytest.raises(ValueError):
        load_pretrained(["does_not_exist"])


def test_loading_is_lazy():
    classifiers = load_pretrained(list(PRETRAINED))
    assert all(c._model is None for c in classifiers.values())


def test_every_spec_is_pinned_to_a_commit():
    for spec in PRETRAINED.values():
        assert len(spec.revision) == 40


def is_cached(name: str) -> bool:
    from huggingface_hub import try_to_load_from_cache

    spec = PRETRAINED[name]
    path = try_to_load_from_cache(spec.repo_id, "model.safetensors", revision=spec.revision)
    return isinstance(path, str)


@pytest.mark.parametrize("name", sorted(PRETRAINED))
def test_cached_pretrained_model_gives_valid_probabilities(name):
    if not is_cached(name):
        pytest.skip(f"{name} not downloaded yet")
    clf = load_pretrained([name])[name]
    proba = clf.predict_proba(
        [
            "Dear customer, verify your password now at http://paypa1.com/login or your account will be closed.",
            "Hi Anna, the meeting moved to 3 pm. See you there, Tom",
        ]
    )
    assert proba.shape == (2, 2)
    assert np.allclose(proba.sum(axis=1), 1.0)


def test_concurrent_first_use_loads_only_once(monkeypatch):
    """Startup preloading and a request may hit an unloaded model at the same time."""
    import threading
    import time

    clf = load_pretrained(["dima806_distilbert"])["dima806_distilbert"]
    calls = []

    class FakeAuto:
        @staticmethod
        def from_pretrained(*args, **kwargs):
            calls.append(1)
            time.sleep(0.05)
            return FakeModel()

    class FakeModel:
        def eval(self):
            return self

    import transformers

    monkeypatch.setattr(transformers, "AutoTokenizer", FakeAuto)
    monkeypatch.setattr(transformers, "AutoModelForSequenceClassification", FakeAuto)
    threads = [threading.Thread(target=clf._load) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 2  # one tokenizer + one model, not four of each
