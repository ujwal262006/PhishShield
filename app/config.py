"""Central application configuration.

Security note: secrets are read from environment variables (via a local .env
file in development). No production secret is hardcoded in source.
"""
from __future__ import annotations

import os
import secrets


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class BaseConfig:
    """Configuration shared across all environments."""

    # If SECRET_KEY is not provided, fall back to a random per-process value.
    # This keeps development running but means sessions reset on restart, which
    # is a deliberate reminder to set a real SECRET_KEY.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Secure session / cookie configuration ---
    SESSION_COOKIE_HTTPONLY = True          # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE = "Lax"         # basic CSRF mitigation for cookies
    SESSION_COOKIE_SECURE = False           # set True behind HTTPS in production
    PERMANENT_SESSION_LIFETIME = 60 * 60    # 1 hour session lifetime (seconds)

    # --- Application / security policy knobs ---
    MAX_URL_LENGTH = 2048                    # reject absurdly long input
    MAX_FAILED_LOGINS = 5                    # lock threshold for an account
    ACCOUNT_LOCK_SECONDS = 15 * 60           # temporary lock window

    # --- Redirect checking safety (disabled by default) ---
    ENABLE_REDIRECT_CHECK = _env_bool("ENABLE_REDIRECT_CHECK", False)
    REDIRECT_ALLOWLIST = {"example.com", "www.example.com", "localhost"}

    # --- Rate limiting (simple in-memory, single-process) ---
    RATELIMIT_ENABLED = True
    RATELIMIT_LOGIN = (10, 300)       # 10 attempts / 5 minutes
    RATELIMIT_REGISTER = (5, 600)     # 5 registrations / 10 minutes
    RATELIMIT_SCAN = (30, 60)         # 30 scans / minute

    @staticmethod
    def init_app(app):  # pragma: no cover - hook for future extension
        pass


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///phishshield.db"
    )


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    # In-memory database keeps tests isolated and fast.
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False   # disable CSRF token checks inside the test client
    MAX_FAILED_LOGINS = 3      # smaller threshold makes lockout tests quick
    RATELIMIT_ENABLED = False  # keep rate limits out of the way of most tests


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///phishshield.db"
    )


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(name: str | None = None):
    """Return the config class for the given environment name."""
    env = (name or os.environ.get("FLASK_ENV") or "development").lower()
    return CONFIG_MAP.get(env, DevelopmentConfig)
