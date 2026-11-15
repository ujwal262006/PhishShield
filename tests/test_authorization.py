"""Integration tests for RBAC / authorization."""


def _login(client, u, pw):
    return client.post("/api/auth/login", json={"username": u, "password": pw})


def test_admin_endpoints_require_auth(client):
    for path in ("/api/admin/stats", "/api/admin/users",
                 "/api/admin/scans", "/api/admin/security-events"):
        assert client.get(path).status_code == 401


def test_regular_user_forbidden_from_admin(client, user):
    _login(client, user.username, "Passw0rd!")
    assert client.get("/api/admin/stats").status_code == 403
    assert client.get("/api/admin/users").status_code == 403


def test_admin_can_access_admin_endpoints(client, admin):
    _login(client, admin.username, "Adm1n@Pass!")
    assert client.get("/api/admin/stats").status_code == 200
    assert client.get("/api/admin/users").status_code == 200
    assert client.get("/api/admin/scans").status_code == 200
    assert client.get("/api/admin/security-events").status_code == 200


def test_admin_can_view_all_scans(client, admin, make_user):
    # A normal user creates a scan.
    normal = make_user(username="normal", email="n@example.test",
                       password="Passw0rd!")
    _login(client, normal.username, "Passw0rd!")
    sid = client.post("/api/scan",
                      json={"url": "https://example.com"}).get_json()["id"]
    client.post("/api/auth/logout")

    # Admin can view that user's scan detail.
    _login(client, admin.username, "Adm1n@Pass!")
    assert client.get(f"/api/scans/{sid}").status_code == 200


def test_admin_html_dashboard_accessible(client, admin):
    _login(client, admin.username, "Adm1n@Pass!")
    resp = client.get("/admin")
    assert resp.status_code == 200


def test_user_html_admin_forbidden(client, user):
    _login(client, user.username, "Passw0rd!")
    resp = client.get("/admin")
    assert resp.status_code == 403
