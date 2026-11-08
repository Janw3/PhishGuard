# PhishGuard API
# Build:  docker build -t phishguard-backend backend
# Usually started via docker-compose.yml in the repository root.

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Pretrained models are downloaded here on first use (a Docker volume in compose).
    HF_HOME=/hf-cache

WORKDIR /app

# Dependencies first, so code changes do not reinstall them (Docker layer cache).
# The CPU-only torch build is much smaller than the default one with CUDA.
COPY requirements.txt .
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu \
 && pip install -r requirements.txt

# Only what the API needs at runtime. Trained models (artifacts/) are mounted, not copied.
COPY app ./app
COPY core ./core

# Run as a normal user instead of root.
RUN useradd --create-home phishguard && mkdir -p /hf-cache /app/artifacts \
 && chown phishguard /hf-cache /app/artifacts
USER phishguard

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/models')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
