"""Is this email English? PhishGuard only analyzes English emails.

All models were trained on English emails, and the rules and explanations are
English. On other languages the verdict would look confident without being
trustworthy, so the API refuses them instead of guessing.

Method (no extra dependency): count very common function words ("the", "and",
"der", "und", ...). English text has about 30-50% common English words;
German, Dutch, French or Portuguese text has under ~12%. An email counts as
English if it has at least MIN_ENGLISH_SHARE common English words AND more of
them than of any other listed language. Mixed content (code, URLs, numbers)
lowers the share, which is why the threshold is well below typical prose.
"""

import re

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

MIN_ENGLISH_SHARE = 0.08
MIN_WORDS = 5  # shorter texts cannot be judged and are accepted

# Frequent function words of languages seen in real phishing. Words that are
# also English ("a", "no", "do", "as", "in", ...) are left out on purpose.
OTHER_LANGUAGES = {
    "German": {"der", "das", "und", "ist", "nicht", "sie", "ihr", "ihre", "wir", "mit", "für", "auf", "dem",
               "ein", "eine", "zu", "von", "bitte", "sind", "wird", "haben", "ihnen", "oder", "bei", "jetzt",
               "keine", "kein", "nur", "noch", "hier", "auch", "einen", "ihren", "werden", "kann", "ohne",
               "sich", "über", "zum", "zur", "heute", "dein", "deine"},
    "Dutch": {"het", "een", "van", "ik", "je", "jij", "niet", "op", "met", "voor", "zijn", "wij", "uw",
              "jouw", "deze", "naar", "ook", "wordt", "uit", "bij"},
    "French": {"le", "les", "et", "est", "pas", "vous", "votre", "nous", "des", "une", "pour", "sur",
               "avec", "dans", "ce", "cette", "du", "au", "vos", "sont"},
    "Portuguese/Spanish": {"os", "não", "você", "seu", "sua", "nós", "um", "uma", "para", "com", "em",
                           "na", "da", "que", "el", "los", "las", "es", "usted", "sus", "del", "por"},
}  # fmt: skip

_WORD = re.compile(r"[^\W\d_]+")


def language_shares(text: str) -> dict[str, float]:
    words = _WORD.findall(text.lower())
    if not words:
        return {}
    shares = {"English": sum(w in ENGLISH_STOP_WORDS for w in words) / len(words)}
    for language, vocabulary in OTHER_LANGUAGES.items():
        shares[language] = sum(w in vocabulary for w in words) / len(words)
    return shares


def is_english(text: str) -> bool:
    if len(_WORD.findall(text)) < MIN_WORDS:
        return True
    shares = language_shares(text)
    english = shares.pop("English")
    return english >= MIN_ENGLISH_SHARE and english >= max(shares.values())


def detected_language(text: str) -> str:
    """Best guess for messages ('English', 'German', ...); 'unknown' if nothing matches."""
    shares = language_shares(text)
    if not shares or max(shares.values()) == 0:
        return "unknown"
    return max(shares, key=shares.get)
