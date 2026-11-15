"""SecurityEvent model for application-level security logging.

Records auth and scan events. Never stores passwords, tokens, or credentials.
"""
from __future__ import annotations

import json

from app.extensions import db
from app.utils.timeutil import utcnow

# Event type constants.
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILED = "LOGIN_FAILED"
EVENT_LOGOUT = "LOGOUT"
EVENT_REGISTER = "REGISTER"
EVENT_SCAN = "SCAN"
EVENT_HIGH_RISK = "HIGH_RISK_DETECTED"
EVENT_CRITICAL_RISK = "CRITICAL_RISK_DETECTED"
EVENT_UNAUTHORIZED = "UNAUTHORIZED_ACCESS"
EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, index=True
    )
    event_type = db.Column(db.String(32), nullable=False, index=True)
    description = db.Column(db.String(255), nullable=True)
    event_metadata = db.Column(db.Text, nullable=True)  # JSON string, no secrets
    created_at = db.Column(
        db.DateTime, nullable=False, default=utcnow, index=True
    )

    @property
    def metadata_dict(self) -> dict:
        try:
            return json.loads(self.event_metadata or "{}")
        except (ValueError, TypeError):
            return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "description": self.description,
            "metadata": self.metadata_dict,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SecurityEvent {self.event_type} user={self.user_id}>"
