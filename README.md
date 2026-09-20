# Ad Risk Control System

An educational, rule-based advertisement risk scoring API built with FastAPI and SQLite. It evaluates synthetic ad events and returns an `ALLOW`, `REVIEW`, or `BLOCK` decision.

> This is a personal project using synthetic data. It is not a production fraud-detection model.

## Features

- Risk scoring for ad clicks and impressions
- Duplicate-click detection
- Device click velocity detection
- IP velocity detection across users
- Auditable event history
- Deterministic decisions that are easy to test
- Docker support and GitHub Actions CI

## Architecture

```text
Client -> FastAPI risk API -> Rule evaluator -> SQLite event store
                                      |
                                      -> ALLOW / REVIEW / BLOCK
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open the interactive API documentation at http://127.0.0.1:8000/docs.

## Run with Docker

```bash
docker compose up --build
```

## Example request

```bash
curl -X POST http://127.0.0.1:8000/v1/risk/evaluate \\
  -H 'Content-Type: application/json' \\
  -d '{
    "user_id": "user-1",
    "device_id": "device-1",
    "ip_address": "203.0.113.10",
    "ad_id": "ad-1",
    "event_type": "click"
  }'
```

## Test

```bash
pytest -q
```

## Resume description

> Built a FastAPI-based advertisement risk-control service with deterministic rules for duplicate clicks, device velocity, and IP velocity; added SQLite indexing, Docker deployment, API tests, and CI automation.

