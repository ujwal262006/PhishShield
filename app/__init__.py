"""PhishShield application factory.

PhishShield - An Explainable Phishing Detection and Risk Assessment System.
Educational, defensive cybersecurity PBL project.
"""
from __future__ import annotations

import os
import secrets

from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request

from app.config import get_config
from app.extensions import csrf, db, login_manager

load_dotenv()  # load .env in development; no-op if the file is absent


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(config_name))

    # Ensure the instance folder (for the SQLite file) exists.
    os.makedirs(app.instance_path, exist_ok=True)

    # Point relative SQLite URIs at the instance folder.
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if uri.startswith("sqlite:///") and ":memory:" not in uri:
        db_name = uri.replace("sqlite:///", "")
        if not os.path.isabs(db_name):
            app.config["SQLALCHEMY_DATABASE_URI"] = (
                "sqlite:///" + os.path.join(app.instance_path, db_name)
            )

    # Initialize extensions.
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Import models so SQLAlchemy is aware of them, then register the loader.
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id: str):
        return db.session.get(User, int(user_id))

    # Register blueprints.
    from app.routes.admin import admin_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.main import main_bp
    from app.routes.scan import scan_bp
    from app.routes.settings import settings_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(settings_bp)

    # Exempt JSON API endpoints from CSRF token checks. These are stateless
    # JSON calls (used by tests and programmatic clients); CSRF protection
    # still applies to all browser HTML form submissions.
    _exempt_api_from_csrf(app)

    _register_error_handlers(app)
    _register_security_headers(app)
    _register_context(app)

    # Create tables automatically for the local SQLite database.
    with app.app_context():
        db.create_all()

    return app


def _exempt_api_from_csrf(app: Flask) -> None:
    """Exempt all /api/ view functions from CSRF protection."""
    for endpoint, view in app.view_functions.items():
        rule_paths = [r.rule for r in app.url_map.iter_rules(endpoint)]
        if any(path.startswith("/api/") for path in rule_paths):
            csrf.exempt(view)


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


def _register_error_handlers(app: Flask) -> None:
    """User-friendly error responses that never leak stack traces."""

    def handle(status: int, message: str):
        if _wants_json():
            return jsonify({"error": message}), status
        return render_template("error.html", code=status, message=message), status

    @app.errorhandler(400)
    def bad_request(_e):
        return handle(400, "The request could not be understood.")

    @app.errorhandler(401)
    def unauthorized(_e):
        return handle(401, "Authentication is required to access this resource.")

    @app.errorhandler(403)
    def forbidden(_e):
        return handle(403, "You do not have permission to access this resource.")

    @app.errorhandler(404)
    def not_found(_e):
        return handle(404, "The requested resource was not found.")

    @app.errorhandler(429)
    def too_many_requests(_e):
        return handle(429, "Too many requests. Please slow down and try again shortly.")

    @app.errorhandler(500)
    def server_error(_e):
        # Roll back any half-finished transaction to keep the session usable.
        db.session.rollback()
        return handle(500, "An unexpected error occurred. Please try again.")


def _register_context(app: Flask) -> None:
    """Inject shared values (product identity, version, CSP nonce) into templates."""
    from app.version import (
        PHISHSHIELD_NAME,
        PHISHSHIELD_TAGLINE,
        PHISHSHIELD_VERSION,
    )

    @app.before_request
    def _generate_csp_nonce():
        # A fresh per-request nonce lets us drop 'unsafe-inline' from script-src.
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def inject_globals():
        return {
            "APP_NAME": PHISHSHIELD_NAME,
            "APP_TAGLINE": PHISHSHIELD_TAGLINE,
            "APP_VERSION": PHISHSHIELD_VERSION,
            "csp_nonce": getattr(g, "csp_nonce", ""),
        }


def _register_security_headers(app: Flask) -> None:
    """Attach sensible HTTP security headers to every response."""

    @app.after_request
    def set_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Disable powerful browser features the app does not use.
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), usb=(), payment=()"
        )
        # Scripts are locked down with a per-request nonce (no 'unsafe-inline'),
        # plus the Chart.js CDN. Styles still allow 'unsafe-inline' because the
        # templates use inline style attributes (nonces do not apply to those).
        # frame-ancestors 'none' complements X-Frame-Options against clickjacking.
        nonce = getattr(g, "csp_nonce", "")
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response
