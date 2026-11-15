"""Input validation helpers for registration and authentication."""
from __future__ import annotations

import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

PASSWORD_MIN_LENGTH = 8


def validate_username(username: str) -> str | None:
    """Return an error message if invalid, else None."""
    if not username:
        return "Username is required."
    if not USERNAME_RE.match(username):
        return ("Username must be 3-32 characters using letters, numbers, "
                "or underscores.")
    return None


def validate_email(email: str) -> str | None:
    if not email:
        return "Email is required."
    if len(email) > 120 or not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return None


def validate_password(password: str) -> str | None:
    """Enforce the password policy: length + upper + lower + digit + special."""
    if not password:
        return "Password is required."
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character."
    return None


# --- Request-parameter bounding (defensive input handling) ---
MAX_SEARCH_LENGTH = 200


def clamp_page(value, default: int = 1) -> int:
    """Coerce a page number to a sane positive integer."""
    try:
        page = int(value)
    except (TypeError, ValueError):
        return default
    return page if page >= 1 else default


def clamp_per_page(value, default: int = 10, maximum: int = 100) -> int:
    """Coerce a per-page size into the range [1, maximum]."""
    try:
        per_page = int(value)
    except (TypeError, ValueError):
        return default
    if per_page < 1:
        return default
    return min(per_page, maximum)


def clean_search(value) -> str:
    """Trim and bound a free-text search parameter."""
    text = (value or "").strip()
    return text[:MAX_SEARCH_LENGTH]
