"""Advertisement risk scoring service.

This project uses synthetic events and deterministic rules. It is intended as
an educational demonstration of a risk-control API, not a production model.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field


DB_PATH = os.getenv("RISK_DB_PATH", "risk.db")


class Decision(str, Enum):
    allow = "ALLOW"
    review = "REVIEW"
    block = "BLOCK"


class AdEvent(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    ip_address: str = Field(min_length=7, max_length=45)
    ad_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(default="click", pattern="^(click|impression)$")
    event_time: datetime | None = None


class RiskResponse(BaseModel):
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str]
    evaluated_at: datetime


class Rule(BaseModel):
    name: str
    description: str
    points: int


RULES = [
    Rule(name="rapid_clicks", description="Many clicks from one device in a short window", points=30),
    Rule(name="duplicate_click", description="Repeated click for the same user, ad, and device", points=40),
    Rule(name="ip_velocity", description="Many users sharing one IP in a short window", points=20),
    Rule(name="suspicious_test_ip", description="Reserved documentation/test IP address", points=25),
]


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                ad_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_time TEXT NOT NULL
            )"""
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_time ON events(device_id, event_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_time ON events(ip_address, event_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_identity ON events(user_id, device_id, ad_id, event_type)")


def normalize_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def evaluate_event(event: AdEvent) -> RiskResponse:
    event_time = normalize_time(event.event_time)
    window_start = event_time - timedelta(minutes=1)
    reasons: list[str] = []
    score = 0

    with connect() as conn:
        recent_device = conn.execute(
            "SELECT COUNT(*) FROM events WHERE device_id=? AND event_type='click' AND event_time BETWEEN ? AND ?",
            (event.device_id, window_start.isoformat(), event_time.isoformat()),
        ).fetchone()[0]
        duplicate = conn.execute(
            "SELECT COUNT(*) FROM events WHERE user_id=? AND device_id=? AND ad_id=? AND event_type='click'",
            (event.user_id, event.device_id, event.ad_id),
        ).fetchone()[0]
        recent_ip_users = conn.execute(
            "SELECT COUNT(DISTINCT user_id) FROM events WHERE ip_address=? AND event_time BETWEEN ? AND ?",
            (event.ip_address, window_start.isoformat(), event_time.isoformat()),
        ).fetchone()[0]

        if recent_device >= 5:
            score += 30
            reasons.append("rapid_clicks")
        if duplicate >= 1:
            score += 40
            reasons.append("duplicate_click")
        if recent_ip_users >= 5:
            score += 20
            reasons.append("ip_velocity")
        if event.ip_address in {"192.0.2.1", "198.51.100.1", "203.0.113.1"}:
            score += 25
            reasons.append("suspicious_test_ip")

        score = min(score, 100)
        decision = Decision.block if score >= 70 else Decision.review if score >= 40 else Decision.allow

        conn.execute(
            "INSERT INTO events(user_id, device_id, ip_address, ad_id, event_type, event_time) VALUES (?, ?, ?, ?, ?, ?)",
            (event.user_id, event.device_id, event.ip_address, event.ad_id, event.event_type, event_time.isoformat()),
        )

    return RiskResponse(decision=decision, risk_score=score, reasons=reasons, evaluated_at=event_time)


app = FastAPI(title="Ad Risk Control System", version="1.0.0")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/rules", response_model=list[Rule])
def list_rules() -> list[Rule]:
    return RULES


@app.post("/v1/risk/evaluate", response_model=RiskResponse)
def evaluate(event: AdEvent) -> RiskResponse:
    return evaluate_event(event)


@app.get("/v1/events")
def list_events(limit: int = Query(default=20, ge=1, le=100)) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


@app.delete("/v1/events")
def clear_events() -> dict[str, int]:
    with connect() as conn:
        result = conn.execute("DELETE FROM events")
    return {"deleted": result.rowcount}
