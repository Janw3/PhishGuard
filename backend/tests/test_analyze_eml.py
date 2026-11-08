"""POST /analyze-eml and the two checks that need a full email: link targets and Reply-To."""

from email.message import EmailMessage

import pytest
from fastapi import HTTPException

from app.schemas import EmlAnalysisResponse
from core.email_parser import Link, parse_eml
from core.signals import find_anchor_signals, find_reply_to_signals, find_sender_signals
from tests.conftest import requires_models

HTML = (
    "<p>Dear customer,</p>"
    '<p>Please confirm your details at <a href="http://login-check.example.net/x">www.paypal.com</a>.</p>'
    '<p>Or use <a href="http://192.168.0.7/login">our secure portal</a>.</p>'
    '<p>Questions? <a href="mailto:help@example.net">Write to us</a>.</p>'
)


def make_eml(html: str = HTML, sender: str = "PayPal <service@paypal.com>", reply_to: str | None = None) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = "Account check"
    msg["From"] = sender
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(html, subtype="html")
    return bytes(msg)


# --------------------------------------------------------------------------- parser


def test_parser_collects_visible_text_and_target_of_each_link():
    email = parse_eml(make_eml())
    assert Link("www.paypal.com", "http://login-check.example.net/x") in email.anchors
    assert Link("our secure portal", "http://192.168.0.7/login") in email.anchors


# --------------------------------------------------------------------------- link targets


def test_link_text_showing_another_domain_is_flagged():
    email = parse_eml(make_eml())
    signals = find_anchor_signals(email.body, email.anchors)
    mismatch = [s for s in signals if "shows 'paypal.com'" in s.explanation]
    assert len(mismatch) == 1
    s = mismatch[0]
    assert email.body[s.start : s.end] == "www.paypal.com"  # highlight sits on the visible text
    assert "example.net" in s.explanation


def test_hidden_target_gets_the_normal_link_checks():
    email = parse_eml(make_eml())
    signals = find_anchor_signals(email.body, email.anchors)
    ip = [s for s in signals if s.feature == "our secure portal"]
    assert ip and ip[0].severity == 0.8  # bare IP address behind harmless-looking text


def test_honest_links_and_mailto_are_not_flagged():
    body = "Visit www.example.org or write to us."
    anchors = [Link("www.example.org", "https://www.example.org/start"), Link("write to us", "mailto:a@b.example")]
    assert find_anchor_signals(body, anchors) == []


def test_outlook_safe_links_are_unwrapped_before_checking():
    wrapped = "https://eur01.safelinks.protection.outlook.com/?url=http%3A%2F%2F192.168.0.7%2Flogin&data=1"
    signals = find_anchor_signals("Open portal", [Link("portal", wrapped)])
    assert [s.severity for s in signals] == [0.8]


# --------------------------------------------------------------------------- Reply-To


def test_reply_to_free_mail_while_sender_claims_a_company():
    signals = find_reply_to_signals("Bank <service@bank.example>", "bank.support@gmail.com")
    assert len(signals) == 1 and signals[0].severity == 0.8


def test_reply_to_other_domain_is_a_weaker_signal():
    signals = find_reply_to_signals("Anna <anna@example.org>", "dev@lists.example.com")
    assert len(signals) == 1 and signals[0].severity == 0.6


@pytest.mark.parametrize(
    ("sender", "reply_to"),
    [
        ("Anna <anna@example.org>", "anna@mail.example.org"),  # same registered domain
        ("Anna <anna@example.org>", None),
        ("anna@gmail.com", "anna.backup@gmail.com"),  # both free mail
    ],
)
def test_no_reply_to_signal(sender, reply_to):
    assert find_reply_to_signals(sender, reply_to) == []


def test_sender_signals_include_reply_to():
    signals = find_sender_signals("PayPal <service@paypal.com>", "paypal.help@gmail.com")
    assert [s.severity for s in signals] == [0.8]


# --------------------------------------------------------------------------- endpoint


@pytest.fixture(scope="module")
def api():
    from app import main

    return main


@requires_models
def test_analyze_eml_returns_parsed_email_and_valid_offsets(api):
    raw = make_eml(reply_to="paypal.help@gmail.com")
    result = EmlAnalysisResponse(**api.analyze_eml_bytes(raw, model="logistic_regression"))
    assert result.email.subject == "Account check"
    assert result.email.reply_to == "paypal.help@gmail.com"
    for r in result.reasons:
        assert result.email.body[r.start : r.end].lower() == r.feature.lower()
    assert any(r.source == "rule" and "shows 'paypal.com'" in r.explanation for r in result.reasons)
    assert any("redirected reply" in s.explanation for s in result.sender_signals)


@requires_models
@pytest.mark.parametrize(("raw", "status"), [(b"", 422), (b"Subject: x\n\n   ", 422)])
def test_analyze_eml_rejects_unusable_input(api, raw, status):
    with pytest.raises(HTTPException) as exc:
        api.analyze_eml_bytes(raw, model="logistic_regression")
    assert exc.value.status_code == status


@requires_models
def test_analyze_eml_rejects_too_large_files(api, monkeypatch):
    monkeypatch.setattr(api, "MAX_EML_BYTES", 10)
    with pytest.raises(HTTPException) as exc:
        api.analyze_eml_bytes(make_eml(), model="logistic_regression")
    assert exc.value.status_code == 413


def test_analyze_content_has_a_size_limit():
    from pydantic import ValidationError

    from app.schemas import MAX_CONTENT_CHARS, EmailRequest

    with pytest.raises(ValidationError):
        EmailRequest(content="x" * (MAX_CONTENT_CHARS + 1))
