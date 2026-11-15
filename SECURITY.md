# PhishShield - Security Design

PhishShield is a defensive, educational project. It also follows secure-development
practices in its own implementation. This document summarizes those decisions.

## 1. Threat model

**Assets:** user accounts, scan history, security event log, application integrity.

**In-scope threats:**
- Credential compromise (weak passwords, brute force).
- Unauthorized access to admin functions or other users' data.
- Injection attacks (SQL injection, XSS).
- CSRF on state-changing form submissions.
- Sensitive data leakage (passwords, secrets in logs or the repo).

**Out of scope (by design):** PhishShield never visits, scrapes, or attacks target
websites. It analyzes the submitted URL string only. There is no exploitation, credential
harvesting, malware, or offensive scanning capability.

## 2. Authentication

- Registration enforces a password policy: minimum 8 characters, with uppercase,
  lowercase, digit, and special character (`app/utils/validators.py`).
- Passwords are hashed with **Werkzeug** `generate_password_hash` (PBKDF2 with a salt).
  We never implement custom cryptographic password hashing.
- Plaintext passwords are never stored, logged, or returned by any endpoint.
- **Failed-login tracking:** after a configurable number of failures
  (`MAX_FAILED_LOGINS`), the account is temporarily locked (`ACCOUNT_LOCK_SECONDS`).
- Login uses a generic "Invalid username or password" message to avoid user enumeration.

## 3. Authorization (RBAC)

- Two roles: `USER` and `ADMIN` (`app/models/user.py`).
- Decorators in `app/utils/decorators.py`:
  - `login_required_api` → 401 JSON for unauthenticated API calls.
  - `admin_required` → 401 if anonymous, 403 if authenticated but not admin.
- Users can only view their **own** scans; admins may view all. Cross-user access returns
  403 (verified by tests).
- Every denied request is recorded as an `UNAUTHORIZED_ACCESS` security event.

## 4. Session and cookie security

- `SESSION_COOKIE_HTTPONLY = True` (JavaScript cannot read the session cookie).
- `SESSION_COOKIE_SAMESITE = "Lax"` (basic CSRF mitigation).
- `SESSION_COOKIE_SECURE = True` in production (HTTPS only).
- `PERMANENT_SESSION_LIFETIME` limits session duration.

## 5. Input validation

- All input is validated **server-side**; client-side checks are convenience only.
- URLs are validated for scheme, hostname, and length before analysis
  (`app/services/url_analyzer.py`), and rejected with user-friendly messages.
- Maximum URL length (2048) prevents resource-exhaustion via oversized input.

## 6. Injection defenses

- **SQL injection:** all database access uses the SQLAlchemy ORM with parameterized
  queries. No string-built SQL is used anywhere.
- **XSS:** Jinja2 autoescaping is on by default; user-supplied values (URLs, usernames)
  are escaped in templates. A restrictive Content-Security-Policy header is also set.

## 7. CSRF protection

- Flask-WTF `CSRFProtect` is enabled globally. Every HTML form includes a CSRF token.
- Stateless JSON API endpoints under `/api/` are explicitly exempted (they are intended
  for programmatic clients and tests, and do not rely on ambient browser cookies for CSRF).

## 8. HTTP security headers

Set on every response (`app/__init__.py`):

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` disabling geolocation, microphone, camera, USB, and payment.
- `Content-Security-Policy` restricting scripts/styles to self + the Chart.js CDN,
  with `frame-ancestors 'none'`, `base-uri 'self'`, and `form-action 'self'`.

## 8a. Rate limiting

A simple in-memory, fixed-window limiter (`app/utils/rate_limit.py`) protects
login, registration, and scanning against obvious abuse. It is keyed by user id
(or IP for anonymous requests) and returns HTTP 429 with `Retry-After` when
exceeded. **Limitation:** it is single-process/in-memory and is disabled under the
testing config; a multi-process deployment would require a shared store.

## 9. Secrets management

- `SECRET_KEY` and demo credentials are read from environment variables / `.env`.
- `.env` is git-ignored; only `.env.example` (with placeholders) is committed.
- No production secret is hardcoded in source.

## 10. Secure logging

- Security events are logged to the `SecurityEvent` table.
- The logger sanitizes forbidden keys (`password`, `token`, `secret`, etc.) from metadata
  (`app/utils/security_logger.py`). Passwords and tokens are never logged.

## 11. Error handling

- Custom handlers for 400/401/403/404/500 return friendly messages and never expose
  stack traces to users. On 500, the database session is rolled back.

## 12. Cryptographic hashing (integrity)

- SHA-256 is used to fingerprint the normalized scanned URL (`app/services/integrity.py`).
- This demonstrates the **Integrity** pillar of the CIA triad. It is explicitly documented
  that **hashing is not encryption** and is not reversible.

## 13. Known limitations

- Heuristic detection can produce false positives / negatives.
- Rate limiting is in-memory and single-process (not distributed).
- No MFA yet (architecture is MFA-ready).
- SQLite is suitable for a local/educational deployment, not high-concurrency production.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for a STRIDE-style threat model.
