"""Application-level security event logging helper.

Records auth and scan events into the SecurityEvent table. Never logs
passwords, session tokens, or other credentials.
"""
from __future__ import annotations

import json

from app.extensions import db
from app.models import SecurityEvent

# Keys that must never be persisted in event metadata.
_FORBIDDEN_KEYS = {"password", "passwd", "pwd", "token", "secret",
                   "password_hash", "authorization", "cookie"}


def _sanitize(metadata: dict | None) -> str | None:
    if not metadata:
        return None
    safe = {k: v for k, v in metadata.items() if k.lower() not in _FORBIDDEN_KEYS}
    return json.dumps(safe)


def log_event(
    event_type: str,
    user_id: int | None = None,
    description: str | None = None,
    metadata: dict | None = None,
    commit: bool = True,
) -> SecurityEvent:
    """Persist a security event. Metadata is sanitized of sensitive keys.

    Set ``commit=False`` to batch several events into one transaction; the
    caller is then responsible for committing the session.
    """
    event = SecurityEvent(
        event_type=event_type,
        user_id=user_id,
        description=description,
        event_metadata=_sanitize(metadata),
    )
    db.session.add(event)
    if commit:
        db.session.commit()
    return event
