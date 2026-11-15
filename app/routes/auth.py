"""Authentication routes: register, login, logout, and JSON API equivalents.

Supports both HTML form flows (for the UI) and JSON API endpoints (for tests
and programmatic access). Passwords are always hashed via Werkzeug.
"""
from __future__ import annotations

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.utils.decorators import login_required_api
from app.models import (
    EVENT_ACCOUNT_LOCKED,
    EVENT_LOGIN_FAILED,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGOUT,
    EVENT_REGISTER,
    ROLE_USER,
    User,
)
from app.utils.rate_limit import rate_limit
from app.utils.security_logger import log_event
from app.utils.validators import validate_email, validate_password, validate_username

auth_bp = Blueprint("auth", __name__)


def _login_limit(view):
    return rate_limit("login", 10, 300)(view)


def _register_limit(view):
    return rate_limit("register", 5, 600)(view)


def _register_core(username: str, email: str, password: str) -> tuple[User | None, str | None]:
    """Validate and create a user. Returns (user, error_message)."""
    username = (username or "").strip()
    email = (email or "").strip().lower()

    for error in (
        validate_username(username),
        validate_email(email),
        validate_password(password or ""),
    ):
        if error:
            return None, error

    if User.query.filter_by(username=username).first():
        return None, "That username is already taken."
    if User.query.filter_by(email=email).first():
        return None, "That email is already registered."

    user = User(username=username, email=email, role=ROLE_USER)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    log_event(EVENT_REGISTER, user_id=user.id,
              description=f"User '{username}' registered.")
    return user, None


# ---------------------------------------------------------------------------
# HTML form routes
# ---------------------------------------------------------------------------
@auth_bp.route("/register", methods=["GET", "POST"])
@_register_limit
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.user_dashboard"))

    if request.method == "POST":
        user, error = _register_core(
            request.form.get("username"),
            request.form.get("email"),
            request.form.get("password"),
        )
        if error:
            flash(error, "danger")
            return render_template("register.html",
                                   username=request.form.get("username", ""),
                                   email=request.form.get("email", ""))
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@_login_limit
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.user_dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user, error = _authenticate(username, password)
        if error:
            flash(error, "danger")
            return render_template("login.html", username=username)
        login_user(user)
        flash(f"Welcome back, {user.username}.", "success")
        next_url = request.args.get("next")
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("dashboard.user_dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    uid = current_user.id
    logout_user()
    log_event(EVENT_LOGOUT, user_id=uid, description="User logged out.")
    flash("You have been logged out.", "info")
    return redirect(url_for("main.index"))


def _authenticate(username: str, password: str) -> tuple[User | None, str | None]:
    """Shared login logic with failed-login tracking and lockout."""
    from flask import current_app

    generic_error = "Invalid username or password."
    user = User.query.filter_by(username=username).first()

    if user is None:
        log_event(EVENT_LOGIN_FAILED, description=f"Unknown username '{username}'.")
        return None, generic_error

    if not user.is_active:
        return None, "This account is disabled."

    if user.is_locked():
        log_event(EVENT_ACCOUNT_LOCKED, user_id=user.id,
                  description="Login attempt on a locked account.")
        return None, ("This account is temporarily locked due to repeated "
                      "failed logins. Please try again later.")

    if not user.check_password(password):
        max_attempts = current_app.config["MAX_FAILED_LOGINS"]
        lock_seconds = current_app.config["ACCOUNT_LOCK_SECONDS"]
        user.register_failed_login(max_attempts, lock_seconds)
        db.session.commit()
        log_event(EVENT_LOGIN_FAILED, user_id=user.id,
                  description="Incorrect password.",
                  metadata={"failed_logins": user.failed_logins})
        if user.is_locked():
            log_event(EVENT_ACCOUNT_LOCKED, user_id=user.id,
                      description="Account locked after repeated failures.")
        return None, generic_error

    # Success: reset counters.
    user.reset_failed_logins()
    db.session.commit()
    log_event(EVENT_LOGIN_SUCCESS, user_id=user.id,
              description=f"User '{username}' logged in.")
    return user, None


# ---------------------------------------------------------------------------
# JSON API routes
# ---------------------------------------------------------------------------
@auth_bp.route("/api/auth/register", methods=["POST"])
@_register_limit
def api_register():
    data = request.get_json(silent=True) or {}
    user, error = _register_core(
        data.get("username"), data.get("email"), data.get("password")
    )
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"message": "registered", "user": user.to_dict()}), 201


@auth_bp.route("/api/auth/login", methods=["POST"])
@_login_limit
def api_login():
    data = request.get_json(silent=True) or {}
    user, error = _authenticate(
        (data.get("username") or "").strip(), data.get("password") or ""
    )
    if error:
        return jsonify({"error": error}), 401
    login_user(user)
    return jsonify({"message": "logged in", "user": user.to_dict()}), 200


@auth_bp.route("/api/auth/logout", methods=["POST"])
@login_required_api
def api_logout():
    uid = current_user.id
    logout_user()
    log_event(EVENT_LOGOUT, user_id=uid, description="User logged out (API).")
    return jsonify({"message": "logged out"}), 200


@auth_bp.route("/api/auth/me", methods=["GET"])
@login_required_api
def api_me():
    return jsonify({"user": current_user.to_dict()}), 200
