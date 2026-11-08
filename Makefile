# Common tasks. Run `make help` for the list.
# Works with GNU make on Linux and on Windows (Git Bash / MSYS).
#
# The backend Python is found automatically in backend/.venv or backend/venv
# (Linux and Windows layouts). Override with:  make test PYTHON=/path/to/python

PYTHON ?= $(shell cd backend && for p in .venv/bin/python venv/bin/python .venv/Scripts/python.exe venv/Scripts/python.exe; do [ -x "$$p" ] && echo "$$p" && break; done)

.PHONY: help install data train evaluate test lint format check run run-backend run-frontend stop

help:
	@echo "make install       install backend (dev) and frontend dependencies"
	@echo "make data          merge the Zenodo CSVs in backend/data/ into prepared.csv"
	@echo "make train         train the TF-IDF models into backend/artifacts/"
	@echo "make evaluate      write reports/model_comparison.md"
	@echo "make test          run the backend tests"
	@echo "make lint          ruff + eslint"
	@echo "make format        auto-format the backend code"
	@echo "make check         lint + tests + frontend build (what CI runs)"
	@echo "make run           start everything with Docker (http://localhost:5173)"
	@echo "make run-backend   start the API locally with auto-reload"
	@echo "make run-frontend  start the Vite dev server"
	@echo "make stop          stop the Docker containers"

install:
	cd backend && $(PYTHON) -m pip install -r requirements-dev.txt
	cd frontend && npm ci

data:
	cd backend && $(PYTHON) -m scripts.prepare_data

train:
	cd backend && $(PYTHON) -m scripts.train

evaluate:
	cd backend && $(PYTHON) -m scripts.evaluate

test:
	cd backend && $(PYTHON) -m pytest

lint:
	cd backend && $(PYTHON) -m ruff check . && $(PYTHON) -m ruff format --check .
	cd frontend && npm run lint

format:
	cd backend && $(PYTHON) -m ruff format . && $(PYTHON) -m ruff check . --fix

check: lint test
	cd frontend && npm run build

run:
	docker compose up --build

run-backend:
	cd backend && $(PYTHON) -m uvicorn app.main:app --reload

run-frontend:
	cd frontend && npm run dev

stop:
	docker compose down
