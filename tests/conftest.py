"""Shared pytest fixtures for PhishShield tests."""
import pytest

from app import create_app
from app.extensions import db as _db
from app.models import ROLE_ADMIN, ROLE_USER, User


@pytest.fixture()
def app():
    app = create_app("testing")
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def make_user(app):
    """Factory to create a user directly in the database."""
    def _make(username="tester", email="tester@example.test",
              password="Passw0rd!", role=ROLE_USER):
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        _db.session.add(user)
        _db.session.commit()
        return user
    return _make


@pytest.fixture()
def user(make_user):
    return make_user()


@pytest.fixture()
def admin(make_user):
    return make_user(username="admin", email="admin@example.test",
                     password="Adm1n@Pass!", role=ROLE_ADMIN)


def login(client, username, password):
    return client.post("/api/auth/login",
                        json={"username": username, "password": password})
