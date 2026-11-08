"""Text normalization shared by training and inference.

The training corpus is lowercase and tokenized: punctuation is separated by
spaces and contractions are split ("don't" -> "do n't", "son's" -> "son 's").
`normalize` brings raw email text into the same shape.

Use it ONLY on the text the model sees (inside predict_proba). The UI and LIME
keep the original text, so highlight offsets still point into what is shown.
"""

import re

_NEGATION = re.compile(r"n't\b")
_CLITIC = re.compile(r"'(s|re|ve|ll|d|m)\b")
# Any character that is not a letter/digit/underscore, whitespace, apostrophe or hyphen.
_PUNCTUATION = re.compile(r"([^\w\s'-])")


def normalize(text: str) -> str:
    """Lowercase, split off punctuation and contractions, collapse whitespace.

    The function is idempotent: normalize(normalize(x)) == normalize(x).
    """
    text = text.lower()
    text = _NEGATION.sub(" n't", text)
    text = _CLITIC.sub(r" '\1", text)
    text = _PUNCTUATION.sub(r" \1 ", text)
    return " ".join(text.split())
