import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from app import demo_emails
from app.config import (
    ARTIFACTS_DIR,
    CORS_ORIGIN_REGEX,
    CORS_ORIGINS,
    DEFAULT_MODEL,
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_MODEL,
    LLM_PROVIDER,
    LLM_TIMEOUT,
    PRELOAD_DEFAULT_MODEL,
    PRETRAINED_MODELS,
    UNCERTAIN_HIGH,
    UNCERTAIN_LOW,
)
from app.schemas import (
    MAX_CONTENT_CHARS,
    MAX_EML_BYTES,
    AnalysisResponse,
    EmailRequest,
    EmlAnalysisResponse,
    ModelInfo,
)
from core.analysis import analyze as analyze_email
from core.classifiers import load_registry
from core.email_parser import parse_eml
from core.language import detected_language, is_english
from core.llm_explanations import build_explainer
from core.pretrained import load_pretrained

# Trained models (artifacts/*.pkl) load at startup. Pretrained models are only
# registered here and load on their first request.
classifiers = {**load_registry(ARTIFACTS_DIR), **load_pretrained(PRETRAINED_MODELS)}
if not classifiers:
    raise RuntimeError(
        f"No models found in {ARTIFACTS_DIR} and no PRETRAINED_MODELS set. Train one with: python -m scripts.train"
    )
# Fail loudly on a typo in DEFAULT_MODEL instead of silently using another model.
if DEFAULT_MODEL not in classifiers:
    raise RuntimeError(f"DEFAULT_MODEL '{DEFAULT_MODEL}' is not available. Choose one of: {sorted(classifiers)}")
default_model = DEFAULT_MODEL

# Optional LLM-written explanations (off unless LLM_PROVIDER is set in backend/.env).
llm_explainer = build_explainer(LLM_PROVIDER, LLM_MODEL, LLM_BASE_URL, LLM_API_KEY, LLM_TIMEOUT)

# uvicorn's own logger: its output already appears in the server log (and `docker compose logs`).
logger = logging.getLogger("uvicorn.error")


def _warm_up(name: str) -> None:
    """Load the model and run it once, so the first real request is fast."""
    try:
        classifiers[name].predict_proba(["Warm-up request."])
        logger.info("Default model '%s' is ready.", name)
    except Exception:  # e.g. no internet for the first download: requests will retry the load
        logger.exception("Preloading model '%s' failed; it will be loaded on the first request.", name)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # A background thread: the API is reachable at once; requests arriving during
    # the load simply wait for it (the classifier guards loading with a lock).
    if PRELOAD_DEFAULT_MODEL:
        threading.Thread(target=_warm_up, args=(default_model,), daemon=True).start()
    yield


app = FastAPI(title="PhishGuard API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_methods=["*"],
    allow_headers=["*"],
)


# The routes are plain `def` instead of `async def`: classification and LIME are
# CPU-heavy, and FastAPI runs plain functions in a thread pool, so one slow
# analysis does not block every other request.


@app.get("/emails")
def get_emails():
    return demo_emails.load_emails()


@app.get("/models", response_model=list[ModelInfo])
def list_models():
    return [{"name": name, "default": name == default_model} for name in classifiers]


def get_classifier(model_name: str | None):
    name = model_name or default_model
    classifier = classifiers.get(name)
    if classifier is None:
        raise HTTPException(status_code=422, detail=f"Unknown model '{name}'. Available: {sorted(classifiers)}")
    return classifier


def require_english(text: str) -> None:
    """PhishGuard only analyzes English emails (models, rules and explanations are English)."""
    if not is_english(text):
        language = detected_language(text)
        hint = f" This email looks {language}." if language not in ("English", "unknown") else ""
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unsupported_language",
                "language": language,
                "message": f"PhishGuard only analyzes English emails.{hint}",
            },
        )


@app.post("/analyze", response_model=AnalysisResponse)
def analyze(request: EmailRequest):
    require_english(request.content)
    return analyze_email(
        request.content,
        get_classifier(request.model),
        sender=request.sender,
        uncertain_band=(UNCERTAIN_LOW, UNCERTAIN_HIGH),
        llm=llm_explainer,
    )


def analyze_eml_bytes(raw: bytes, model: str | None = None) -> dict:
    """Parse a raw .eml file and analyze it with the full context (sender, Reply-To, HTML links)."""
    if not raw:
        raise HTTPException(status_code=422, detail="Empty request body. Send the .eml file as the body.")
    if len(raw) > MAX_EML_BYTES:
        raise HTTPException(status_code=413, detail=f"Email too large (max {MAX_EML_BYTES // 1_000_000} MB).")
    classifier = get_classifier(model)
    email = parse_eml(raw)
    if not email.body.strip():
        raise HTTPException(status_code=422, detail="No readable text found in this email.")
    require_english(f"{email.subject}\n\n{email.body}")
    body = email.body[:MAX_CONTENT_CHARS]
    result = analyze_email(
        body,
        classifier,
        sender=email.sender,
        reply_to=email.reply_to,
        anchors=email.anchors,
        uncertain_band=(UNCERTAIN_LOW, UNCERTAIN_HIGH),
        llm=llm_explainer,
    )
    result["email"] = {"subject": email.subject, "sender": email.sender, "reply_to": email.reply_to, "body": body}
    return result


@app.post(
    "/analyze-eml",
    response_model=EmlAnalysisResponse,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"message/rfc822": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
async def analyze_eml(request: Request, model: str | None = None):
    """Analyze a complete email file. Send the raw .eml as the request body, e.g.
    `curl -X POST --data-binary @mail.eml http://localhost:8000/analyze-eml`.

    Compared to /analyze this also checks the Reply-To header and the real
    targets behind HTML links. Reason offsets refer to `email.body` in the response.
    """
    # Reading the body needs `async`; the heavy analysis then runs in the thread pool
    # (like the plain `def` routes), so it does not block other requests.
    raw = await request.body()
    return await run_in_threadpool(analyze_eml_bytes, raw, model)


@app.post("/simulate-incoming")
def simulate_incoming():
    return {
        "id": 99,
        "from": "security-alert@paypa1-verify.com",
        "subject": "Your account has been compromised",
        "preview": "We have detected suspicious login activity on your account...",
        "time": "Now",
        "body": "dear account user we have detected suspicious login activity on your account from an unrecognized device . your account has been temporarily suspended to protect your information . to restore access please click here immediately and verify your identity by providing your password and credit card details . failure to act within the next 2 hours will result in permanent account termination . paypal security team",
        "label": "Phishing Email",
    }
