"""Scan model storing the result of a URL risk assessment."""
from __future__ import annotations

import json

from app.extensions import db
from app.utils.timeutil import utcnow

# Classification constants shared by the risk engine and templates.
CLASS_SAFE = "SAFE"
CLASS_SUSPICIOUS = "SUSPICIOUS"
CLASS_HIGH = "HIGH RISK"
CLASS_CRITICAL = "CRITICAL"


class Scan(db.Model):
    __tablename__ = "scans"
    # Composite index speeds the common "my scans, newest first" query.
    __table_args__ = (
        db.Index("ix_scans_user_created", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    url = db.Column(db.String(2048), nullable=False)
    hostname = db.Column(db.String(255), nullable=True, index=True)
    protocol = db.Column(db.String(16), nullable=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0, index=True)
    classification = db.Column(db.String(16), nullable=False, index=True)
    # Detected indicators stored as a JSON string (SQLite has no native JSON).
    indicators_json = db.Column(db.Text, nullable=False, default="[]")
    recommendation = db.Column(db.Text, nullable=True)
    # Educational SHA-256 integrity hash of the normalized URL.
    integrity_hash = db.Column(db.String(64), nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=utcnow, index=True
    )

    @property
    def indicators(self) -> list:
        try:
            return json.loads(self.indicators_json or "[]")
        except (ValueError, TypeError):
            return []

    @indicators.setter
    def indicators(self, value: list) -> None:
        self.indicators_json = json.dumps(value or [])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url": self.url,
            "hostname": self.hostname,
            "protocol": self.protocol,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "indicators": self.indicators,
            "recommendation": self.recommendation,
            "integrity_hash": self.integrity_hash,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scan {self.id} {self.classification} {self.risk_score}>"
