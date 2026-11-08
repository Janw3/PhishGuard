"""Word occlusion: model highlights for transformers (Phase 3, layer B).

Idea: remove one word (every occurrence of it) from the email and classify
again. The more the phishing score drops, the more that word pushed the model
towards "phishing".

Why not LIME for transformers?
  - LIME needs hundreds of random samples; with a transformer on CPU that is
    slow, and with few samples (200) the result is noisy.
  - Occlusion is deterministic (no random sampling) and needs only one model
    call per candidate word, batched.
  - It measures the change in LOG-ODDS, which does not saturate: when the model
    is 99.99% sure, the probability barely moves, but the log-odds still do.

Only meaningful words are tried (same filter as for LIME), so filler words like
"it" or "please" are never highlighted. The output has the same format as
core.explainer.explain, so the rest of the code does not care which one ran.
"""

import re
import uuid
from typing import Protocol

import numpy as np

from core.explainer import MIN_RELATIVE_WEIGHT, find_position, get_explanation, is_meaningful, merge_adjacent

# Upper bound on candidate words per email: keeps one analysis around 1-3 s on CPU.
MAX_CANDIDATES = 60
_WORD = re.compile(r"\b[A-Za-z][A-Za-z'-]*[A-Za-z]\b")


class LogOddsClassifier(Protocol):
    name: str

    def phishing_log_odds(self, texts: list[str]) -> np.ndarray: ...


def candidate_words(text: str, limit: int = MAX_CANDIDATES) -> list[str]:
    """Distinct meaningful words in order of first appearance (case-insensitive)."""
    seen: dict[str, None] = {}
    for match in _WORD.finditer(text):
        word = match.group(0)
        if word.lower() not in seen and is_meaningful(word):
            seen[word.lower()] = None
            if len(seen) >= limit:
                break
    return list(seen)


def without_word(text: str, word: str) -> str:
    """The text with every whole-word occurrence of word removed."""
    return re.sub(r"\b" + re.escape(word) + r"\b", "", text, flags=re.IGNORECASE)


def explain_by_occlusion(text: str, classifier: LogOddsClassifier, num_features: int) -> list[dict]:
    words = candidate_words(text)
    if not words:
        return []
    scores = classifier.phishing_log_odds([text] + [without_word(text, w) for w in words])
    drops = scores[0] - scores[1:]  # positive = removing the word makes the email look less like phishing

    positive = [(w, float(d)) for w, d in zip(words, drops, strict=True) if d > 0]
    if not positive:
        return []
    strongest = max(d for _, d in positive)
    positive.sort(key=lambda x: -x[1])

    reasons = []
    for word, drop in positive[:num_features]:
        if drop < MIN_RELATIVE_WEIGHT * strongest:
            continue
        start, end = find_position(text, word)
        if start == -1:
            continue
        reasons.append(
            {
                "id": f"reason_{uuid.uuid4().hex[:8]}",
                "feature": text[start:end],
                "explanation": get_explanation(word),
                # Scaled to roughly the same range as LIME weights, so the tooltip's
                # "x% influence" stays comparable: a drop of 1 log-odds unit ~ 10%.
                "impact": drop / 10,
                "start": int(start),
                "end": int(end),
                "source": "model",
                "category": "model",
            }
        )

    reasons = merge_adjacent(text, reasons)
    reasons.sort(key=lambda r: -r["impact"])
    return reasons
