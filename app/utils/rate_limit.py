"""Lightweight in-memory rate limiting.

This is a simple, dependency-free fixed-window limiter suitable for a local /
single-process academic prototype. It protects against obvious abuse (e.g.
rapid login or scan flooding) but is NOT a distributed, production-grade rate
limiter. Limitations are documented in SECURITY.md.

Design:
- Keyed by (bucket_name, client_identifier), where the identifier is the
  authenticated user id when available, otherwise the remote IP address.
- Fixed time window; counter resets when the window elapses.
- Disabled automatically when app.config['RATELIMIT_ENABLED'] is False (tests).
"""
from __future__ import annotations

import threading
import time
from functools import wraps

from flask import current_app, jsonify, render_template, request
from flask_login import current_user

# Module-level store: { key: (window_start_epoch, count) }
_store: dict[str, tuple[float, int]] = {}
_lock = threading.Lock()


def _client_id() -> str:
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    # request.remote_addr can be None in odd test setups; fall back gracefully.
    return f"ip:{request.remote_addr or 'unknown'}"


def _hit(bucket: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    """Register a hit. Returns (allowed, seconds_until_reset)."""
    key = f"{bucket}:{_client_id()}"
    now = time.time()
    with _lock:
        window_start, count = _store.get(key, (now, 0))
        if now - window_start >= window_seconds:
            # Window elapsed: reset.
            window_start, count = now, 0
        count += 1
        _store[key] = (window_start, count)
        retry_after = int(window_seconds - (now - window_start))
        return count <= limit, max(retry_after, 1)


def rate_limit(bucket: str, limit: int, window_seconds: int):
    """Decorator enforcing a fixed-window rate limit on a view.

    On limit exceed: 429 JSON for API paths, otherwise a rendered 429 page.
    """

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not current_app.config.get("RATELIMIT_ENABLED", True):
                return view(*args, **kwargs)

            allowed, retry_after = _hit(bucket, limit, window_seconds)
            if not allowed:
                message = ("Too many requests. Please slow down and try again "
                           "in a moment.")
                wants_json = request.path.startswith("/api/") or (
                    "application/json" in request.headers.get("Accept", "")
                    and "text/html" not in request.headers.get("Accept", "")
                )
                if wants_json:
                    resp = jsonify({"error": message, "retry_after": retry_after})
                    resp.status_code = 429
                else:
                    resp = current_app.make_response(
                        (render_template("error.html", code=429, message=message), 429)
                    )
                resp.headers["Retry-After"] = str(retry_after)
                return resp
            return view(*args, **kwargs)

        return wrapper

    return decorator


def reset_rate_limits() -> None:
    """Clear all counters (useful for tests)."""
    with _lock:
        _store.clear()
