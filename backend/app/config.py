"""Central backend configuration.

Values come from (highest priority first):
  1. environment variables
  2. backend/.env   (copy .env.example; never committed)
  3. the defaults below

pydantic-settings reads and type-checks them, so a typo like
UNCERTAIN_LOW=abc fails at startup instead of somewhere later.

Paths are built relative to this file, so the backend works no matter which
directory it is started from and on both Linux and Windows.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    data_dir: Path = BACKEND_DIR / "data"
    # Output of scripts/prepare_data.py.
    prepared_data_path: Path = BACKEND_DIR / "data" / "prepared.csv"
    # Every <name>.pkl in this folder is a selectable trained model called <name>.
    artifacts_dir: Path = BACKEND_DIR / "artifacts"
    # Evaluation results from scripts/prepare_data, evaluate and evaluate_own (not committed).
    reports_dir: Path = BACKEND_DIR.parent / "reports"

    # Model used when a request does not name one. Any name from GET /models,
    # e.g. logistic_regression, random_forest, cybersectony_distilbert, dima806_distilbert.
    # Default: the pretrained DistilBERT, which generalizes best to unseen email collections.
    default_model: str = "cybersectony_distilbert"
    # Load the default model in the background at startup, so the first analysis is fast.
    preload_default_model: bool = True
    # Pretrained Hugging Face models to offer (comma-separated names from core/pretrained.py).
    # Empty string = none. They are downloaded on first use into the Hugging Face cache.
    pretrained_models: str = "cybersectony_distilbert,dima806_distilbert"

    # Optional LLM-written explanations for model highlights (core/llm_explanations.py).
    # none = templates only (default); openai = any OpenAI-compatible API (Ollama, OpenAI, ...);
    # anthropic = Claude via the official SDK. Model and endpoint are freely swappable.
    llm_provider: str = "none"
    llm_model: str = ""  # empty = provider default (openai: llama3.2:3b via Ollama, anthropic: claude-opus-5-5)
    llm_base_url: str = "http://localhost:11434/v1"  # Ollama's OpenAI-compatible endpoint
    llm_api_key: str = ""  # never commit; for anthropic, ANTHROPIC_API_KEY also works
    llm_timeout: float = 15.0

    # Comma-separated list of frontend origins that may call the API.
    cors_origins: str = "http://localhost:5173"
    # Also allowed: a frontend on this machine on any port. Vite moves to 5174, 5175, ...
    # when 5173 is taken (e.g. by Docker). Empty string = only CORS_ORIGINS.
    cors_origin_regex: str = r"http://(localhost|127\.0\.0\.1)(:\d+)?"

    # Phishing probabilities inside this band are reported as "uncertain".
    uncertain_low: float = 0.4
    uncertain_high: float = 0.6


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


settings = Settings()

# Module-level names, so the rest of the code can keep importing them directly.
DATA_DIR = settings.data_dir
PREPARED_DATA_PATH = settings.prepared_data_path
ARTIFACTS_DIR = settings.artifacts_dir
REPORTS_DIR = settings.reports_dir
DEFAULT_MODEL = settings.default_model
PRELOAD_DEFAULT_MODEL = settings.preload_default_model
LLM_PROVIDER = settings.llm_provider
LLM_MODEL = settings.llm_model
LLM_BASE_URL = settings.llm_base_url
LLM_API_KEY = settings.llm_api_key
LLM_TIMEOUT = settings.llm_timeout
PRETRAINED_MODELS = _split(settings.pretrained_models)
CORS_ORIGINS = _split(settings.cors_origins)
CORS_ORIGIN_REGEX = settings.cors_origin_regex or None
UNCERTAIN_LOW = settings.uncertain_low
UNCERTAIN_HIGH = settings.uncertain_high
