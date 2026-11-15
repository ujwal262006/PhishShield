"""Database models package."""
from app.models.scan import (
    CLASS_CRITICAL,
    CLASS_HIGH,
    CLASS_SAFE,
    CLASS_SUSPICIOUS,
    Scan,
)
from app.models.security_event import (
    EVENT_ACCOUNT_LOCKED,
    EVENT_CRITICAL_RISK,
    EVENT_HIGH_RISK,
    EVENT_LOGIN_FAILED,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGOUT,
    EVENT_REGISTER,
    EVENT_SCAN,
    EVENT_UNAUTHORIZED,
    SecurityEvent,
)
from app.models.user import ROLE_ADMIN, ROLE_USER, VALID_ROLES, User

__all__ = [
    "User",
    "Scan",
    "SecurityEvent",
    "ROLE_ADMIN",
    "ROLE_USER",
    "VALID_ROLES",
    "CLASS_SAFE",
    "CLASS_SUSPICIOUS",
    "CLASS_HIGH",
    "CLASS_CRITICAL",
    "EVENT_LOGIN_SUCCESS",
    "EVENT_LOGIN_FAILED",
    "EVENT_LOGOUT",
    "EVENT_REGISTER",
    "EVENT_SCAN",
    "EVENT_HIGH_RISK",
    "EVENT_CRITICAL_RISK",
    "EVENT_UNAUTHORIZED",
    "EVENT_ACCOUNT_LOCKED",
]
