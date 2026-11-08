import pytest

from core.signals import (
    detect_signals,
    find_link_signals,
    find_sender_signals,
    find_text_signals,
    impersonated_brand,
    levenshtein,
    registered_domain,
    rule_score,
)

PHISHING = (
    "Dear Customer,\n"
    "Your account has been SUSPENDED. Please verify your identity and enter your password "
    "within 24 hours: http://www.paypa1-secure.com/login\n"
    "Pay the processing fee of $1,500 by wire transfer."
)


def categories(signals):
    return {s.category for s in signals}


def test_every_signal_points_into_the_original_text():
    for s in find_text_signals(PHISHING) + find_link_signals(PHISHING):
        assert PHISHING[s.start : s.end] == s.feature


@pytest.mark.parametrize(
    ("text", "category", "feature"),
    [
        ("Please verify your account today", "credentials", "verify your account"),
        ("Enter your Password below", "credentials", "Password"),
        ("We need your credit card number", "financial_data", "credit card number"),
        ("Your access has been suspended", "threat", "suspended"),
        ("Respond within 48 hours", "urgency", "within 48 hours"),
        ("Join the lottery today", "prize", "lottery"),
        ("Great news, you have won!", "prize", "you have won"),
        ("Send it by Western Union", "money", "Western Union"),
        ("A fee of $2,000 applies.", "money", "$2,000"),
        ("Dear Valued Customer, hello", "generic_greeting", "Dear Valued Customer"),
        ("Click here to continue", "call_to_action", "Click here"),
    ],
)
def test_text_rules(text, category, feature):
    matches = [s for s in find_text_signals(text) if s.category == category]
    assert [s.feature for s in matches] == [feature]


def test_harmless_email_has_no_signals():
    text = "Hi Anna, lunch at 12 tomorrow? The slides are on the team drive. Cheers, Tom"
    assert detect_signals(text, "Tom <tom@example.org>") == ([], [])


def test_words_inside_other_words_do_not_match():
    assert find_text_signals("The prizewinning passwordless design is unrestricted.") == []


# --------------------------------------------------------------------------- domains


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("mail.paypal.com", "paypal.com"),
        ("paypal.com", "paypal.com"),
        ("shop.amazon.co.uk", "amazon.co.uk"),
    ],
)
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


def test_levenshtein():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypall", "paypal") == 1
    assert levenshtein("kitten", "sitting") == 3


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("paypal.com", None),
        ("www.paypal.com", None),
        ("googleapis.com", None),
        ("purchase-info.com", None),  # "chase" inside another word is not Chase
        ("appleseed.org", None),
        ("paypa1.com", ("paypal", "lookalike")),
        ("paypall.com", ("paypal", "lookalike")),
        ("rnicrosoft.com", ("microsoft", "lookalike")),
        ("paypal-security.com", ("paypal", "brand_misuse")),
        ("paypal.com.evil.net", ("paypal", "brand_misuse")),
        ("paypalsecurity.com", ("paypal", "brand_misuse")),
    ],
)
def test_impersonated_brand(host, expected):
    assert impersonated_brand(host) == expected


@pytest.mark.parametrize(
    ("text", "severity"),
    [
        ("Go to http://192.168.0.1/login now", 0.8),
        ("Visit www.paypa1.com today", 0.9),
        ("Visit https://paypal-help.com today", 0.8),
        ("See bit.ly/abc123", 0.4),
        ("Open http://xn--80ak6aa92e.com", 0.7),  # punycode only
        ("Open http://xn--pypal-4ve.com", 0.9),  # punycode AND looks like "paypal": the stronger wins
    ],
)
def test_link_signals(text, severity):
    signals = find_link_signals(text)
    assert max(s.severity for s in signals) == severity
    for s in signals:
        assert text[s.start : s.end] == s.feature


def test_official_link_and_trailing_punctuation():
    assert find_link_signals("Log in at https://www.paypal.com.") == []
    text = "Go to http://192.168.0.1/x."
    assert find_link_signals(text)[0].feature == "http://192.168.0.1/x"


# --------------------------------------------------------------------------- sender


@pytest.mark.parametrize(
    "sender",
    [
        "security@paypa1-support.com",
        "PayPal <service@paypal-alerts.net>",
        "PayPal Service <help@gmail.com>",
        "Bank of America <alerts@boa-secure.net>",
    ],
)
def test_suspicious_senders(sender):
    signals = find_sender_signals(sender)
    assert len(signals) == 1 and signals[0].category == "sender"
    assert signals[0].start == -1


@pytest.mark.parametrize(
    "sender", ["service@paypal.com", "PayPal <service@mail.paypal.com>", "rick@enron.com", "", None, "not an address"]
)
def test_harmless_senders(sender):
    assert find_sender_signals(sender) == []


# --------------------------------------------------------------------------- score


def test_rule_score_counts_strongest_signal_per_category_once():
    one = find_text_signals("Your account is suspended.")
    many = find_text_signals("Suspended. Suspended. Suspended. Suspended.")
    assert rule_score(one) == pytest.approx(rule_score(many)) == pytest.approx(0.5)


def test_rule_score_combines_categories():
    signals = find_text_signals("Verify your identity within 24 hours")  # 0.7 and 0.4
    assert rule_score(signals) == pytest.approx(1 - 0.3 * 0.6)


def test_rule_score_of_nothing_is_zero():
    assert rule_score([]) == 0.0


def test_full_phishing_example_is_strong():
    text_signals, sender_signals = detect_signals(PHISHING, "PayPal <alert@paypa1-support.com>")
    assert {"credentials", "threat", "urgency", "money", "generic_greeting", "link"} <= categories(text_signals)
    assert categories(sender_signals) == {"sender"}
    assert rule_score(text_signals + sender_signals) > 0.99
