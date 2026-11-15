"""Integration tests for authentication: register, login, logout, password policy."""
from app.models import User
from app.utils.validators import validate_password


# ---- Password policy (unit) ----
def test_password_policy_requires_length():
    assert validate_password("Aa1!") is not None


def test_password_policy_requires_upper():
    assert validate_password("password1!") is not None


def test_password_policy_requires_special():
    assert validate_password("Password1") is not None


def test_password_policy_accepts_strong():
    assert validate_password("Passw0rd!") is None


# ---- Registration ----
def test_register_success(client):
    resp = client.post("/api/auth/register", json={
        "username": "newuser", "email": "new@example.test",
        "password": "Passw0rd!"})
    assert resp.status_code == 201
    assert resp.get_json()["user"]["username"] == "newuser"


def test_register_weak_password_rejected(client):
    resp = client.post("/api/auth/register", json={
        "username": "weak", "email": "weak@example.test", "password": "weak"})
    assert resp.status_code == 400


def test_register_duplicate_username(client, user):
    resp = client.post("/api/auth/register", json={
        "username": user.username, "email": "other@example.test",
        "password": "Passw0rd!"})
    assert resp.status_code == 400


def test_password_is_hashed_not_plaintext(client, app):
    client.post("/api/auth/register", json={
        "username": "hashme", "email": "hashme@example.test",
        "password": "Passw0rd!"})
    with app.app_context():
        u = User.query.filter_by(username="hashme").first()
        assert u.password_hash != "Passw0rd!"
        assert u.check_password("Passw0rd!") is True


# ---- Login / logout ----
def test_login_success(client, user):
    resp = client.post("/api/auth/login", json={
        "username": user.username, "password": "Passw0rd!"})
    assert resp.status_code == 200


def test_login_wrong_password(client, user):
    resp = client.post("/api/auth/login", json={
        "username": user.username, "password": "WrongPass1!"})
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/api/auth/login", json={
        "username": "ghost", "password": "Passw0rd!"})
    assert resp.status_code == 401


def test_me_requires_auth(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_me_after_login(client, user):
    client.post("/api/auth/login", json={
        "username": user.username, "password": "Passw0rd!"})
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.get_json()["user"]["username"] == user.username


def test_logout(client, user):
    client.post("/api/auth/login", json={
        "username": user.username, "password": "Passw0rd!"})
    resp = client.post("/api/auth/logout")
    assert resp.status_code == 200
    # After logout, protected endpoint should reject.
    assert client.get("/api/auth/me").status_code == 401


def test_account_lockout_after_failures(client, user, app):
    # Testing config sets MAX_FAILED_LOGINS = 3.
    for _ in range(3):
        client.post("/api/auth/login", json={
            "username": user.username, "password": "WrongPass1!"})
    # Even the correct password is refused while locked.
    resp = client.post("/api/auth/login", json={
        "username": user.username, "password": "Passw0rd!"})
    assert resp.status_code == 401
