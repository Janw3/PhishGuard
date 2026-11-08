import pytest
from pydantic import ValidationError

from app.config import Settings


def test_defaults():
    s = Settings(_env_file=None)
    assert s.default_model == "cybersectony_distilbert"
    assert s.uncertain_low == 0.4


def test_env_variables_override_defaults(monkeypatch):
    monkeypatch.setenv("DEFAULT_MODEL", "logistic_regression")
    monkeypatch.setenv("UNCERTAIN_HIGH", "0.7")
    s = Settings(_env_file=None)
    assert s.default_model == "logistic_regression"
    assert s.uncertain_high == 0.7


def test_env_file_is_read(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DEFAULT_MODEL=dima806_distilbert\nPRETRAINED_MODELS=\n", encoding="utf-8")
    s = Settings(_env_file=env)
    assert s.default_model == "dima806_distilbert"
    assert s.pretrained_models == ""


def test_invalid_number_fails_early(monkeypatch):
    monkeypatch.setenv("UNCERTAIN_LOW", "abc")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
