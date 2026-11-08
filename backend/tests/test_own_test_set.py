"""Email parsing, anonymization and the own-test-set evaluation helpers (no network, no real emails)."""

from email.message import EmailMessage

import numpy as np
import pytest

from core.email_parser import html_to_text, parse_eml, parse_txt
from scripts.anonymize_emails import anonymize, anonymize_text, clean_url, to_txt
from scripts.evaluate_own import load_test_set, summarize, wilson_interval
from scripts.fetch_phishing_pot import email_date


def make_eml(plain: str | None = None, html: str | None = None) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = "Your account"
    msg["From"] = "PayPal Service <alerts@paypa1-support.com>"
    msg["Reply-To"] = "help@other.example"
    msg["Date"] = "Tue, 04 Nov 2025 10:00:00 +0000"
    if plain is not None:
        msg.set_content(plain)
    if html is not None:
        if plain is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    return bytes(msg)


# --------------------------------------------------------------------------- parsing


def test_parse_eml_prefers_html_because_that_is_what_readers_see():
    email = parse_eml(make_eml(plain="Hello plain", html="<p>Hello <b>html</b></p>"))
    assert email.body == "Hello html"


def test_parse_eml_uses_plain_text_without_html():
    email = parse_eml(make_eml(plain="Hello plain"))
    assert email.body == "Hello plain"
    assert email.anchors == []
    assert email.subject == "Your account"
    assert email.sender == "PayPal Service <alerts@paypa1-support.com>"
    assert email.reply_to == "help@other.example"


def test_parse_eml_falls_back_to_html_and_collects_links():
    html = '<html><head><style>p{}</style></head><body><p>Verify <a href="http://paypa1.com/x">here</a></p><p>Thanks</p></body></html>'
    email = parse_eml(make_eml(html=html))
    assert email.body == "Verify here\n\nThanks"
    assert email.links == ["http://paypa1.com/x"]


def test_html_to_text_skips_scripts():
    text, _ = html_to_text("<script>var x=1;</script><div>Visible</div>")
    assert text == "Visible"


def test_parse_txt_reads_optional_headers():
    email = parse_txt("Subject: Hi\nFrom: Tom <tom@example.com>\n\nBody line 1\nBody line 2")
    assert (email.subject, email.sender, email.body) == ("Hi", "Tom <tom@example.com>", "Body line 1\nBody line 2")
    assert parse_txt("Only a body").body == "Only a body"


def test_email_date():
    assert email_date(make_eml(plain="x")).year == 2025
    assert email_date(b"Subject: no date\n\nbody") is None


# --------------------------------------------------------------------------- anonymization


def test_personal_terms_and_addresses_are_removed():
    text = "Hi Jan Weller, write to jan.w@example.com or call +49 151 2345 6789. IBAN DE89 3704 0044 0532 0130 00"
    result = anonymize_text(text, ["Jan Weller"])
    assert "Jan Weller" not in result and "jan.w" not in result
    assert "user@example.com" in result
    assert "[NUMBER]" in result and "[IBAN]" in result


def test_money_amounts_and_short_numbers_stay():
    assert anonymize_text("Pay $1,500 within 24 hours, ref 42.", []) == "Pay $1,500 within 24 hours, ref 42."


def test_clean_url_keeps_domain_drops_tracking():
    assert clean_url("https://paypa1.com/login/a8F3kd92Jd83kdLq0?user=jan&id=7#x") == "https://paypa1.com/login/[TOKEN]"
    assert clean_url("http://example.com/help/contact") == "http://example.com/help/contact"


def test_clean_url_unwraps_outlook_safe_links():
    wrapped = (
        "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1.com%2Flogin%3Fid%3D42"
        "&data=05%7C01&reserved=0"
    )
    assert clean_url(wrapped) == "https://paypa1.com/login"


def test_clean_url_survives_malformed_urls():
    assert clean_url("http://[bad.host.example]/x?id=1") == "http://[bad.host.example]/x"


def test_honeypot_address_is_always_redacted():
    from scripts.anonymize_emails import load_personal_terms

    terms = load_personal_terms(path=__import__("pathlib").Path("does-not-exist.txt"))
    assert anonymize_text("phishing@pot your parcel", terms) == "[REDACTED] your parcel"


def test_parser_repairs_wrongly_declared_charset():
    raw = (
        b"Subject: Test\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n"
        + "Große Prämien".encode("cp1252")
    )
    assert parse_eml(raw).body == "Große Prämien"


def test_parser_reads_raw_utf8_and_encoded_headers():
    raw = "Subject: Commande confirmée\nFrom: =?utf-8?q?Caf=C3=A9_M=C3=BCller?= <a@b.example>\n\nHallo".encode()
    email = parse_eml(raw)
    assert email.subject == "Commande confirmée"
    assert email.sender == "Café Müller <a@b.example>"


def test_display_name_kept_for_phishing_removed_for_legitimate():
    email = parse_eml(make_eml(plain="Hello"))
    assert anonymize(email, "phishing", []).sender == "PayPal Service <user@paypa1-support.com>"
    assert anonymize(email, "legitimate", []).sender == "Sender <user@paypa1-support.com>"


def test_round_trip_through_txt():
    email = anonymize(parse_eml(make_eml(plain="Body")), "phishing", [])
    again = parse_txt(to_txt(email))
    assert (again.subject, again.sender, again.body) == (email.subject, email.sender, email.body)


# --------------------------------------------------------------------------- evaluation


def test_wilson_interval_contains_the_rate_and_stays_in_bounds():
    low, high = wilson_interval(45, 50)
    assert low < 0.9 < high
    assert wilson_interval(0, 10)[0] == 0.0
    assert wilson_interval(10, 10)[1] == pytest.approx(1.0)


def test_small_samples_give_wide_intervals():
    small = wilson_interval(9, 10)
    large = wilson_interval(900, 1000)
    assert (small[1] - small[0]) > 3 * (large[1] - large[0])


def test_summarize_counts_errors():
    y = np.array([1, 1, 1, 0, 0])
    flagged = np.array([True, True, False, True, False])
    s = summarize(y, flagged)
    assert s["missed phishing (FN)"] == 1 and s["false alarms (FP)"] == 1
    assert s["phishing recall [95% CI]"].startswith("0.67")


def test_load_test_set_uses_folder_as_label(tmp_path):
    (tmp_path / "phishing").mkdir()
    (tmp_path / "legitimate").mkdir()
    (tmp_path / "phishing" / "a.txt").write_text("Subject: Win\nFrom: x@y.com\n\nYou won", encoding="utf-8")
    (tmp_path / "legitimate" / "b.txt").write_text("Subject: Lunch\n\nAt 12?", encoding="utf-8")
    df = load_test_set(tmp_path)
    assert sorted(df["label"]) == [0, 1]
    assert df.loc[df["label"] == 1, "text"].item() == "Win\n\nYou won"


# --------------------------------------------------------------------------- mailing lists


def test_months_back_crosses_year_boundary():
    from datetime import UTC, datetime

    from scripts.fetch_mailing_lists import months_back

    assert months_back(3, datetime(2026, 2, 15, tzinfo=UTC)) == ["2026-01", "2025-12", "2025-11"]


def test_messages_from_mbox_splits_messages():
    from scripts.fetch_mailing_lists import messages_from_mbox

    mbox = (
        b"From a@example.org  Thu Oct  1 07:30:18 2026\nSubject: One\n\nFirst body\n\n"
        b"From b@example.org  Thu Oct  2 07:30:18 2026\nSubject: Two\n\nSecond body\n"
    )
    messages = messages_from_mbox(mbox)
    assert len(messages) == 2
    assert parse_eml(messages[1]).subject == "Two"


def test_is_usable_checks_date_and_body_length():
    from scripts.fetch_mailing_lists import is_usable

    long_body = "This is a normal mailing list message with enough text to be a useful test email. " * 2
    recent = f"Date: Tue, 06 Oct 2026 10:00:00 +0000\nSubject: Hi\n\n{long_body}".encode()
    old = f"Date: Tue, 06 Oct 2020 10:00:00 +0000\nSubject: Hi\n\n{long_body}".encode()
    short = b"Date: Tue, 06 Oct 2026 10:00:00 +0000\nSubject: Hi\n\n+1"
    assert is_usable(recent)
    assert not is_usable(old)
    assert not is_usable(short)
