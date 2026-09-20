import importlib

from fastapi.testclient import TestClient


def make_client(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    monkeypatch.setenv("RISK_DB_PATH", str(db))
    import app.main as main
    main = importlib.reload(main)
    main.init_db()
    return TestClient(main.app)


def payload(**overrides):
    value = {
        "user_id": "user-1",
        "device_id": "device-1",
        "ip_address": "203.0.113.10",
        "ad_id": "ad-1",
        "event_type": "click",
        "event_time": "2026-01-01T12:00:00Z",
    }
    value.update(overrides)
    return value


def test_health_and_rules(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.get("/health").json() == {"status": "ok"}
    assert len(client.get("/v1/rules").json()) == 4


def test_first_event_is_allowed(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.post("/v1/risk/evaluate", json=payload())
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["risk_score"] == 0


def test_duplicate_click_goes_to_review(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/v1/risk/evaluate", json=payload())
    response = client.post("/v1/risk/evaluate", json=payload())
    assert response.json()["decision"] == "REVIEW"
    assert "duplicate_click" in response.json()["reasons"]


def test_rapid_clicks_are_blocked_after_multiple_signals(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    for i in range(6):
        response = client.post("/v1/risk/evaluate", json=payload())
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["risk_score"] == 70
