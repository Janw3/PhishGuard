"""English-only gate: core/language.py and its use in both endpoints."""

import pytest
from fastapi import HTTPException

from app.demo_emails import load_emails
from app.schemas import EmailRequest
from core.language import detected_language, is_english
from tests.conftest import requires_models

ENGLISH = "Your account has been suspended. Please verify your identity within 24 hours to restore access."
GERMAN = "Ihr Konto wurde gesperrt. Bitte bestätigen Sie jetzt Ihre Daten, sonst wird es nicht wieder freigegeben."
DUTCH = "Uw account is geblokkeerd. Klik op de link en vul je gegevens in voor het einde van de dag."
FRENCH = "Votre compte est suspendu. Cliquez sur le lien pour confirmer vos informations avec nous."
PORTUGUESE = "Sua fatura digital está atrasada. Para evitar o bloqueio, pague com o código que você recebeu."
CODE_HEAVY = (
    "I tried the patch with mod_proxy and the config below, the build still fails:\n"
    "ProxyPass /app http://127.0.0.1:8080/app\nLoadModule proxy_module modules/mod_proxy.so\n"
    "Any idea what is missing? The error log shows AH01144 on every request."
)


@pytest.mark.parametrize("text", [ENGLISH, CODE_HEAVY])
def test_english_texts_pass(text):
    assert is_english(text)


@pytest.mark.parametrize(("text", "language"), [(GERMAN, "German"), (DUTCH, "Dutch"), (FRENCH, "French")])
def test_other_languages_are_detected(text, language):
    assert not is_english(text)
    assert detected_language(text) == language


def test_portuguese_is_rejected():
    assert not is_english(PORTUGUESE)


def test_very_short_texts_are_accepted():
    assert is_english("Danke!")


def test_all_demo_emails_are_english():
    assert all(is_english(e["body"]) for e in load_emails())


@pytest.fixture(scope="module")
def api():
    from app import main

    return main


@requires_models
def test_analyze_rejects_non_english_with_a_clear_error(api):
    with pytest.raises(HTTPException) as exc:
        api.analyze(EmailRequest(content=GERMAN, model="logistic_regression"))
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "unsupported_language"
    assert exc.value.detail["language"] == "German"
    assert "only analyzes English" in exc.value.detail["message"]


@requires_models
def test_analyze_eml_rejects_non_english(api):
    raw = f"Subject: Rechnung\nContent-Type: text/plain; charset=utf-8\n\n{GERMAN}".encode()
    with pytest.raises(HTTPException) as exc:
        api.analyze_eml_bytes(raw, model="logistic_regression")
    assert exc.value.detail["error"] == "unsupported_language"
