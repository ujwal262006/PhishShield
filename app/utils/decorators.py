"""Authorization decorators for role-based access control (RBAC)."""
from __future__ import annotations

from functools import wraps

from flask import abort, jsonify, request
from flask_login import current_user

from app.models import EVENT_UNAUTHORIZED, ROLE_ADMIN
from app.utils.security_logger import log_event


def _wants_json() -> bool:
    """True when the request appears to be an API/JSON call."""
    if request.path.startswith("/api/"):
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


def _deny(status: int, message: str):
    user_id = current_user.id if current_user.is_authenticated else None
    log_event(
        EVENT_UNAUTHORIZED,
        user_id=user_id,
        description=message,
        metadata={"path": request.path, "method": request.method},
    )
    if _wants_json():
        return jsonify({"error": message}), status
    abort(status)


def login_required_api(view):
    """Like flask_login.login_required but returns 401 JSON for API calls."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return _deny(401, "Authentication required.")
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    """Require an authenticated ADMIN user (401 if anonymous, 403 if not admin)."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return _deny(401, "Authentication required.")
        if current_user.role != ROLE_ADMIN:
            return _deny(403, "Administrator privileges required.")
        return view(*args, **kwargs)

    return wrapper
