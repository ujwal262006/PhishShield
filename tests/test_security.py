"""Security-focused tests: rate limiting, injection-style input, validation."""
import pytest

from app import create_app
from app.extensions import db as _db
from app.models import ROLE_USER, User
from app.utils.rate_limit import reset_rate_limits


# A dedicated app with rate limiting ENABLED (the default testing config
# disables it so it does not interfere with the broader suite).
@pytest.fixture()
def rl_app():
    app = create_app("testing")
    app.config["RATELIMIT_ENABLED"] = True
    with app.app_context():
        _db.create_all()
        reset_rate_limits()
        yield app
        _db.session.remove()
        _db.drop_all()
        reset_rate_limits()


@pytest.fixture()
def rl_client(rl_app):
    return rl_app.test_client()


def test_login_rate_limited(rl_client):
    # Login bucket is 10 / 5 min. The 11th attempt should be blocked with 429.
    codes = []
    for _ in range(12):
        r = rl_client.post("/api/auth/login",
                           json={"username": "ghost", "password": "Nope1!aa"})
        codes.append(r.status_code)
    assert 429 in codes


def test_rate_limit_disabled_by_default(client):
    # Default testing config disables rate limiting; many calls stay allowed.
    for _ in range(15):
        r = client.post("/api/auth/login",
                        json={"username": "ghost", "password": "Nope1!aa"})
        assert r.status_code != 429


import re


# ---- CSP nonce hardening ----
def test_csp_uses_nonce_not_unsafe_inline_for_scripts(client):
    resp = client.get("/")
    csp = resp.headers.get("Content-Security-Policy", "")
    script_src = csp.split("style-src")[0]
    assert "'unsafe-inline'" not in script_src
    assert re.search(r"script-src[^;]*'nonce-[A-Za-z0-9_-]+'", csp)


def test_csp_nonce_matches_script_tags(client):
    resp = client.get("/")
    csp = resp.headers.get("Content-Security-Policy", "")
    m = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
    assert m is not None
    assert ('nonce="%s"' % m.group(1)).encode() in resp.data


def test_csp_nonce_changes_per_request(client):
    def nonce_of(resp):
        return re.search(r"'nonce-([A-Za-z0-9_-]+)'",
                         resp.headers["Content-Security-Policy"]).group(1)
    assert nonce_of(client.get("/")) != nonce_of(client.get("/"))


# ---- Injection-style inputs are handled safely (ORM + validation) ----
def test_sql_injection_style_username_login(client):
    resp = client.post("/api/auth/login", json={
        "username": "admin' OR '1'='1", "password": "x"})
    # Rejected as invalid credentials, never executes injected SQL.
    assert resp.status_code == 401


def test_sql_injection_style_registration_rejected(client):
    resp = client.post("/api/auth/register", json={
        "username": "a';DROP TABLE users;--",
        "email": "x@y.test", "password": "Passw0rd!"})
    # Username validation rejects the payload characters.
    assert resp.status_code == 400


def test_xss_payload_in_url_is_escaped(client, user):
    client.post("/api/auth/login", json={
        "username": user.username, "password": "Passw0rd!"})
    payload = "https://example.com/<script>alert(1)</script>"
    resp = client.post("/api/scan", json={"url": payload})
    # Accepted as a string; when rendered it is escaped by Jinja autoescape.
    assert resp.status_code in (201, 400)
    if resp.status_code == 201:
        sid = resp.get_json()["id"]
        page = client.get(f"/scan/{sid}")
        assert b"<script>alert(1)</script>" not in page.data


def test_oversized_url_rejected(client, user):
    client.post("/api/auth/login", json={
        "username": user.username, "password": "Passw0rd!"})
    resp = client.post("/api/scan", json={"url": "https://example.com/" + "a" * 5000})
    assert resp.status_code == 400


def test_users_table_still_exists_after_injection_attempt(client, app):
    client.post("/api/auth/register", json={
        "username": "a';DROP TABLE users;--",
        "email": "x@y.test", "password": "Passw0rd!"})
    # The ORM parameterizes queries, so the table is intact and usable.
    with app.app_context():
        u = User(username="stillhere", email="s@h.test", role=ROLE_USER)
        u.set_password("Passw0rd!")
        _db.session.add(u)
        _db.session.commit()
        assert User.query.filter_by(username="stillhere").first() is not None
