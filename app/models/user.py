"""User model with secure password storage and role-based access control."""
from __future__ import annotations

from datetime import timedelta

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.utils.timeutil import utcnow

# Role constants keep RBAC checks consistent across the codebase.
ROLE_ADMIN = "ADMIN"
ROLE_USER = "USER"
VALID_ROLES = {ROLE_ADMIN, ROLE_USER}


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    # Only the salted hash is stored; the plaintext password never touches disk.
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(16), nullable=False, default=ROLE_USER)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    # Account-protection fields (failed-login tracking / temporary lockout).
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    scans = db.relationship(
        "Scan", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    # --- Password handling (delegated to Werkzeug, never custom crypto) ---
    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # --- Role helpers ---
    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    # --- Account lock helpers ---
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        if utcnow() >= self.locked_until:
            return False
        return True

    def register_failed_login(self, max_attempts: int, lock_seconds: int) -> None:
        self.failed_logins += 1
        if self.failed_logins >= max_attempts:
            self.locked_until = utcnow() + timedelta(seconds=lock_seconds)

    def reset_failed_logins(self) -> None:
        self.failed_logins = 0
        self.locked_until = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.username} ({self.role})>"
