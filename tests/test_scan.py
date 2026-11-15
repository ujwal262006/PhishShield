"""Integration tests for scanning and scan history."""
from app.models import Scan


def _login(client, user):
    return client.post("/api/auth/login", json={
        "username": user.username, "password": "Passw0rd!"})


def test_scan_requires_auth(client):
    resp = client.post("/api/scan", json={"url": "https://example.com"})
    assert resp.status_code == 401


def test_scan_creates_record(client, user, app):
    _login(client, user)
    resp = client.post("/api/scan", json={"url": "http://192.0.2.10/login"})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["classification"] in {"SAFE", "SUSPICIOUS", "HIGH RISK", "CRITICAL"}
    assert 0 <= data["risk_score"] <= 100
    assert len(data["integrity_hash"]) == 64
    with app.app_context():
        assert Scan.query.count() == 1


def test_scan_invalid_url_rejected(client, user):
    _login(client, user)
    resp = client.post("/api/scan", json={"url": "not-a-url"})
    assert resp.status_code == 400


def test_scan_empty_url_rejected(client, user):
    _login(client, user)
    resp = client.post("/api/scan", json={"url": ""})
    assert resp.status_code == 400


def test_scan_history_lists_own_scans(client, user):
    _login(client, user)
    client.post("/api/scan", json={"url": "https://example.com"})
    client.post("/api/scan", json={"url": "http://192.0.2.10/login"})
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert len(resp.get_json()["scans"]) == 2


def test_user_cannot_view_other_users_scan(client, make_user):
    # User A creates a scan.
    a = make_user(username="alice", email="alice@example.test", password="Passw0rd!")
    _login(client, a)
    scan_resp = client.post("/api/scan", json={"url": "https://example.com"})
    scan_id = scan_resp.get_json()["id"]
    client.post("/api/auth/logout")

    # User B logs in and tries to access A's scan.
    b = make_user(username="bob", email="bob@example.test", password="Passw0rd!")
    _login(client, b)
    resp = client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 403


def test_dashboard_stats(client, user):
    _login(client, user)
    client.post("/api/scan", json={"url": "https://example.com"})
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 1
