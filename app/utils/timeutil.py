"""Time helpers.

Centralizes UTC "now" so we do not scatter the deprecated ``datetime.utcnow``
across the codebase. We store naive UTC datetimes (consistent with the existing
schema) but derive them from a timezone-aware source.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime (tz-aware source)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
