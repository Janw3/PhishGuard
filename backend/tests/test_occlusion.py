"""Word occlusion with a fake transformer (no downloads needed)."""

import numpy as np
import pytest

from core.analysis import analyze, model_highlights
from core.occlusion import candidate_words, explain_by_occlusion, without_word
from core.pretrained import log_odds_from_logits


class KeywordModel:
    """Fake model: every occurrence of a keyword adds its weight to the log-odds."""

    name = "fake_transformer"
    weights = {"lottery": 3.0, "processing": 1.5, "fee": 1.5, "winner": 2.0, "tom": -1.0}

    def phishing_log_odds(self, texts):
        return np.array(
            [
                sum(w * t.lower().split().count(k) for k, w in self.weights.items()) - 2.0
                for t in (text.replace(",", " ").replace(".", " ") for text in texts)
            ]
        )

    def predict_proba(self, texts):
        p = 1 / (1 + np.exp(-self.phishing_log_odds(texts)))
        return np.column_stack([1 - p, p])


TEXT = "Dear winner, you won the lottery. Please pay the processing fee today. Regards, Tom"


def test_candidate_words_skip_generic_words_and_repeats():
    words = candidate_words("It is the lottery, the LOTTERY and the email winner.")
    assert words == ["lottery", "winner"]


def test_without_word_removes_whole_words_only():
    assert without_word("fee feedback Fee", "fee") == " feedback "


def test_occlusion_finds_the_words_that_drive_the_score():
    reasons = explain_by_occlusion(TEXT, KeywordModel(), num_features=10)
    features = [r["feature"] for r in reasons]
    assert features[0] == "lottery"  # strongest word first
    assert "processing fee" in features  # adjacent words merged into one phrase
    assert "Tom" not in features  # pushes towards legitimate: not highlighted
    for r in reasons:
        assert TEXT[r["start"] : r["end"]] == r["feature"]
        assert r["source"] == "model"


def test_occlusion_is_deterministic():
    first = explain_by_occlusion(TEXT, KeywordModel(), 10)
    second = explain_by_occlusion(TEXT, KeywordModel(), 10)
    strip = lambda rs: [{k: v for k, v in r.items() if k != "id"} for r in rs]  # noqa: E731
    assert strip(first) == strip(second)


def test_no_candidates_no_highlights():
    assert explain_by_occlusion("It is the one.", KeywordModel(), 10) == []


def test_analysis_uses_occlusion_for_models_with_log_odds():
    reasons = model_highlights(TEXT, KeywordModel(), 10)
    assert reasons and reasons[0]["feature"] == "lottery"
    result = analyze(TEXT, KeywordModel())
    assert result["label"] == "phishing"
    assert any(r["source"] == "model" for r in result["reasons"])


def test_log_odds_from_logits():
    logits = np.array([[0.0, 2.0, 0.0, 2.0], [1.0, -1.0, 1.0, -1.0]])
    log_odds = log_odds_from_logits(logits, (1, 3))
    assert log_odds == pytest.approx([2.0, -2.0])
