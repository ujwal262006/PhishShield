"""Seed the database with clearly-marked DEMO DATA.

Creates an admin account, a demo user, and several synthetic scans using
reserved/documentation domains and localhost-safe examples.

Run from the project root:
    python -m scripts.seed_demo_data

Demo credentials are read from environment variables (see .env.example) so no
insecure password is hardcoded in application source.
"""
from __future__ import annotations

import os
import sys

# Allow running as a plain script (python scripts/seed_demo_data.py).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import ROLE_ADMIN, ROLE_USER, Scan, User  # noqa: E402
from app.services.risk_engine import analyze_url, build_scan  # noqa: E402
from app.utils.security_logger import log_event  # noqa: E402
from app.models import EVENT_SCAN  # noqa: E402

# --- DEMO DATA: synthetic / reserved URLs safe for local testing ---
DEMO_URLS = [
    "https://example.com",
    "https://github.com/login",
    "http://example.com/login",
    "http://192.0.2.10/login",
    "http://secure-login-verify.example.test/account/confirm",
    "http://paypa1-secure-login.example.test/verify",
    "https://g00gle-account-update.example.test/signin",
    "http://example.com/search?q=1&ref=2&utm=3&sid=4&x=5",
    "https://微软.example.test/login",  # will be handled as unicode host
    "http://xn--e1afmkfd.example.test/verify-account-now-secure-login",
]


def get_or_create_user(username_env, email_env, password_env, role, defaults):
    username = os.environ.get(username_env, defaults["username"])
    email = os.environ.get(email_env, defaults["email"])
    password = os.environ.get(password_env, defaults["password"])

    user = User.query.filter_by(username=username).first()
    if user:
        print(f"  - user '{username}' already exists (skipping)")
        return user, password

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f"  - created {role} '{username}'")
    return user, password


def seed():
    app = create_app()
    with app.app_context():
        db.create_all()
        print("Seeding DEMO DATA...")

        admin, admin_pw = get_or_create_user(
            "SEED_ADMIN_USERNAME", "SEED_ADMIN_EMAIL", "SEED_ADMIN_PASSWORD",
            ROLE_ADMIN,
            {"username": "admin", "email": "admin@phishshield.test",
             "password": "Admin@12345"},
        )
        student, student_pw = get_or_create_user(
            "SEED_USER_USERNAME", "SEED_USER_EMAIL", "SEED_USER_PASSWORD",
            ROLE_USER,
            {"username": "student", "email": "student@phishshield.test",
             "password": "Student@12345"},
        )

        # Only seed scans if the demo user has none yet.
        if Scan.query.filter_by(user_id=student.id).count() == 0:
            print("  - creating demo scans for the student user")
            for url in DEMO_URLS:
                try:
                    result = analyze_url(url)
                except Exception as exc:  # noqa: BLE001 - demo resilience
                    print(f"    (skipped {url}: {exc})")
                    continue
                db.session.add(build_scan(student.id, result))
            db.session.commit()

            for scan in Scan.query.filter_by(user_id=student.id).all():
                log_event(EVENT_SCAN, user_id=student.id,
                          description=f"[DEMO] Scanned {scan.hostname}",
                          metadata={"classification": scan.classification})
        else:
            print("  - demo scans already present (skipping)")

        print("\nDemo data ready.")
        print("=" * 48)
        print("DEMO CREDENTIALS (development only):")
        print(f"  ADMIN  -> username: {admin.username}  password: {admin_pw}")
        print(f"  USER   -> username: {student.username}  password: {student_pw}")
        print("=" * 48)


if __name__ == "__main__":
    seed()
