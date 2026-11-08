import pytest

from core.preprocessing import normalize


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Click HERE now!", "click here now !"),
        ("Don't wait", "do n't wait"),
        ("your son's account", "your son 's account"),
        ("line one\nline two\r\n\tline three", "line one line two line three"),
        ("e.g. this", "e . g . this"),
        ("thought-provoking", "thought-provoking"),
        ("", ""),
    ],
)
def test_normalize_matches_training_style(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize(
    "text",
    ["Don't CLICK here!\nYour son's account.", "www.paypa1.com/login?x=1", "do n't click ."],
)
def test_normalize_is_idempotent(text):
    once = normalize(text)
    assert normalize(once) == once
