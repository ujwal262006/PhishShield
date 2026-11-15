# PhishShield — Threat Model

A lightweight, STRIDE-informed threat model for the PhishShield application
itself (not the URLs it analyzes).

## Assets

- User accounts and credentials (password hashes).
- Users' scan history and results.
- The security event log.
- Application and database integrity.
- Admin-only functions and data.

## Threat actors

- Unauthenticated external users.
- Authenticated users attempting to access others' data or admin functions.
- Automated abuse (credential guessing, scan flooding).

## Attack surfaces

- HTML forms (login, register, scan, settings, admin actions).
- JSON API endpoints under `/api/`.
- Query/pagination/search parameters.
- Submitted URLs (treated as untrusted strings).

## STRIDE analysis

| Category | Threat | Mitigation |
|----------|--------|------------|
| **Spoofing** | Credential theft / impersonation | Werkzeug password hashing; generic login errors; session cookie HttpOnly + SameSite; account lockout after repeated failures |
| **Tampering** | Modifying data via forms/params | CSRF protection on HTML forms; server-side validation; ORM-parameterized queries; SHA-256 integrity fingerprint on scans |
| **Repudiation** | Denying actions | Security event log records logins, scans, high/critical detections, unauthorized attempts, password/role/status changes |
| **Information disclosure** | Leaking secrets or other users' data | Ownership checks on scans/exports; RBAC on admin routes; secrets from env only; logger strips password/token/secret keys; system-health page omits sensitive data; no stack traces to users |
| **Denial of service** | Login/scan flooding | In-memory rate limiting on login/register/scan; max URL length; bounded pagination/search |
| **Elevation of privilege** | User accessing admin functions | `admin_required` decorator (401 anonymous / 403 non-admin); self-role/self-status change blocked; unauthorized attempts logged |

## Injection & XSS specifics

- **SQL injection:** all DB access uses the SQLAlchemy ORM with parameterized
  queries. Tested with injection-style inputs (`test_security.py`).
- **XSS:** Jinja2 autoescaping is on; user-supplied values (URLs, usernames) are
  escaped; a restrictive CSP with `frame-ancestors 'none'` is applied. Tested by
  confirming a `<script>` payload in a URL is not rendered unescaped.

## Out of scope (by design)

PhishShield never visits, scrapes, or attacks the URLs it analyzes. It has no
offensive capability: no exploitation, credential harvesting, malware, page
cloning, or scanning of external systems. Analysis is string-based only.

## Residual risks

- Heuristic detection yields false positives/negatives.
- Rate limiting is single-process and in-memory (not distributed).
- SQLite suits a local/educational deployment, not high-concurrency production.
- No MFA yet (architecture is MFA-ready; listed in future scope).
