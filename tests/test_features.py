"""Integration tests for upgrade features: settings, exports, compare,
user management, system health, and security headers."""
from app.models import ROLE_ADMIN, ROLE_USER, Scan, User


def _login(client, u, pw):
    return client.post("/api/auth/login", json={"username": u, "password": pw})


def _make_scan(client):
    """Create one scan for the logged-in user; return its id."""
    client.post("/api/scan", json={"url": "http://192.0.2.10/login-verify"})
    return client.get("/api/scans").get_json()["scans"][0]["id"]


# ---- Settings / password change ----
def test_settings_page_requires_auth(client):
    resp = client.get("/settings")
    assert resp.status_code in (302, 401)  # redirect to login for browser


def test_settings_page_ok(client, user):
    _login(client, user.username, "Passw0rd!")
    assert client.get("/settings").status_code == 200


def test_change_password_success(client, user, app):
    _login(client, user.username, "Passw0rd!")
    resp = client.post("/settings/password", data={
        "current_password": "Passw0rd!",
        "new_password": "NewPass1!",
        "confirm_password": "NewPass1!",
    }, follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        u = User.query.filter_by(username=user.username).first()
        assert u.check_password("NewPass1!")


def test_change_password_wrong_current(client, user, app):
    _login(client, user.username, "Passw0rd!")
    client.post("/settings/password", data={
        "current_password": "WrongPass1!",
        "new_password": "NewPass1!",
        "confirm_password": "NewPass1!",
    }, follow_redirects=True)
    with app.app_context():
        u = User.query.filter_by(username=user.username).first()
        assert u.check_password("Passw0rd!")  # unchanged


def test_change_password_weak_rejected(client, user, app):
    _login(client, user.username, "Passw0rd!")
    client.post("/settings/password", data={
        "current_password": "Passw0rd!",
        "new_password": "weak",
        "confirm_password": "weak",
    }, follow_redirects=True)
    with app.app_context():
        u = User.query.filter_by(username=user.username).first()
        assert u.check_password("Passw0rd!")  # unchanged


# ---- Exports ----
def test_export_scan_json(client, user):
    _login(client, user.username, "Passw0rd!")
    sid = _make_scan(client)
    resp = client.get(f"/scan/{sid}/export.json")
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    assert resp.get_json()["id"] == sid


def test_export_history_csv(client, user):
    _login(client, user.username, "Passw0rd!")
    _make_scan(client)
    resp = client.get("/history/export.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["Content-Type"]
    assert b"scan_id" in resp.data


def test_export_json_ownership_enforced(client, make_user):
    a = make_user(username="alice", email="a@x.test", password="Passw0rd!")
    _login(client, a.username, "Passw0rd!")
    sid = _make_scan(client)
    client.post("/api/auth/logout")
    b = make_user(username="bob", email="b@x.test", password="Passw0rd!")
    _login(client, b.username, "Passw0rd!")
    assert client.get(f"/scan/{sid}/export.json").status_code == 403


# ---- Scan comparison ----
def test_compare_two_scans(client, user):
    _login(client, user.username, "Passw0rd!")
    client.post("/api/scan", json={"url": "https://example.com"})
    client.post("/api/scan", json={"url": "http://192.0.2.10/login-verify"})
    scans = client.get("/api/scans").get_json()["scans"]
    a, b = scans[0]["id"], scans[1]["id"]
    resp = client.get(f"/compare?a={a}&b={b}")
    assert resp.status_code == 200


# ---- Admin user management ----
def test_admin_toggle_user_active(client, admin, make_user, app):
    target = make_user(username="target", email="t@x.test", password="Passw0rd!")
    _login(client, admin.username, "Adm1n@Pass!")
    client.post(f"/admin/users/{target.id}/toggle-active", follow_redirects=True)
    with app.app_context():
        assert User.query.filter_by(username="target").first().is_active is False


def test_admin_change_user_role(client, admin, make_user, app):
    target = make_user(username="promote", email="p@x.test", password="Passw0rd!")
    _login(client, admin.username, "Adm1n@Pass!")
    client.post(f"/admin/users/{target.id}/role", data={"role": "ADMIN"},
                follow_redirects=True)
    with app.app_context():
        assert User.query.filter_by(username="promote").first().role == ROLE_ADMIN


def test_admin_cannot_toggle_self(client, admin, app):
    _login(client, admin.username, "Adm1n@Pass!")
    client.post(f"/admin/users/{admin.id}/toggle-active", follow_redirects=True)
    with app.app_context():
        assert User.query.filter_by(username=admin.username).first().is_active is True


def test_user_cannot_manage_users(client, user, admin):
    _login(client, user.username, "Passw0rd!")
    resp = client.post(f"/admin/users/{admin.id}/toggle-active")
    assert resp.status_code == 403


# ---- System health (admin only) ----
def test_system_health_admin_only(client, user):
    _login(client, user.username, "Passw0rd!")
    assert client.get("/admin/system-health").status_code == 403


def test_system_health_ok_for_admin(client, admin):
    _login(client, admin.username, "Adm1n@Pass!")
    assert client.get("/admin/system-health").status_code == 200


# ---- Informational pages ----
def test_insights_page_public(client):
    assert client.get("/insights").status_code == 200


def test_methodology_page_public(client):
    assert client.get("/methodology").status_code == 200


# ---- Security headers ----
def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert "Permissions-Policy" in resp.headers
