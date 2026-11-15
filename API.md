# PhishShield - API Documentation

Base URL (development): `http://127.0.0.1:5000`

All API endpoints accept and return JSON. Authentication uses the session cookie
established by `/api/auth/login`. API endpoints are CSRF-exempt (intended for
programmatic clients); the HTML UI uses CSRF-protected forms.

Status codes:
`200` OK · `201` Created · `400` Bad Request · `401` Unauthorized · `403` Forbidden ·
`404` Not Found.

---

## Authentication

### POST /api/auth/register
Create a new user (role `USER`).

Request:
```json
{ "username": "student2", "email": "s2@example.test", "password": "Passw0rd!" }
```
Responses: `201` `{ "message": "registered", "user": { ... } }` ·
`400` `{ "error": "<validation message>" }`

Password policy: min 8 chars, at least one uppercase, lowercase, digit, and special char.

### POST /api/auth/login
```json
{ "username": "student", "password": "Student@12345" }
```
Responses: `200` `{ "message": "logged in", "user": { ... } }` ·
`401` `{ "error": "Invalid username or password." }`

Repeated failures temporarily lock the account.

### POST /api/auth/logout
Auth: user. Response `200` `{ "message": "logged out" }` (401 if not logged in).

### GET /api/auth/me
Auth: user. Response `200` `{ "user": { "id", "username", "email", "role", ... } }`.

---

## Scanning

### POST /api/scan
Auth: user. Analyze a URL (string-only; never fetches the target).

Request:
```json
{ "url": "http://192.0.2.10/login-verify" }
```
Response `201`:
```json
{
  "id": 12,
  "user_id": 2,
  "url": "http://192.0.2.10/login-verify",
  "hostname": "192.0.2.10",
  "protocol": "http",
  "risk_score": 65,
  "classification": "HIGH RISK",
  "indicators": [
    {
      "key": "ip_hostname",
      "name": "IP Address Used as Hostname",
      "severity": "HIGH",
      "points": 20,
      "explanation": "The URL uses a raw IP address instead of a conventional domain name..."
    }
  ],
  "recommendation": "Avoid interacting with this URL...",
  "integrity_hash": "<64-char SHA-256 hex>",
  "created_at": "2026-08-29T12:00:00"
}
```
Errors: `400` `{ "error": "The URL is empty." }` and similar validation messages.

### GET /api/scans
Auth: user. Returns the current user's scans: `{ "scans": [ ... ] }`.

### GET /api/scans/&lt;id&gt;
Auth: user. Returns a single scan. `403` if the scan belongs to another user (admins may
view any). `404` if not found.

---

## Dashboard

### GET /api/dashboard/stats
Auth: user. Personal statistics:
```json
{ "total": 11, "safe": 3, "suspicious": 4, "high_risk": 2, "critical": 2 }
```

---

## Admin (role ADMIN required)

All admin endpoints return `401` if anonymous and `403` if authenticated as a non-admin.

### GET /api/admin/stats
```json
{
  "total_scans": 127, "safe": 82, "suspicious": 25, "high_risk": 13, "critical": 7,
  "total_users": 4,
  "top_indicators": [ { "name": "Suspicious Keyword(s)", "count": 40 } ]
}
```

### GET /api/admin/users
`{ "users": [ { "id", "username", "email", "role", "is_active", "created_at" } ] }`

### GET /api/admin/scans
`{ "scans": [ ... ] }` — all scans across all users.

### GET /api/admin/security-events
`{ "events": [ { "id", "event_type", "user_id", "description", "metadata", "created_at" } ] }`

---

## Example: curl flow

```bash
# Register
curl -c cookies.txt -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","email":"demo@example.test","password":"Passw0rd!"}'

# Login (stores session cookie)
curl -c cookies.txt -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"Passw0rd!"}'

# Scan a URL (reuse cookie)
curl -b cookies.txt -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"http://192.0.2.10/login-verify"}'
```

---

## v0.2.0 additions

The upgrade is primarily UI-driven (HTML routes). The JSON API above is unchanged
and backward-compatible. New HTML routes (session-authenticated, CSRF-protected
forms) include:

### Scanning & reporting
- `GET /scan/<id>/export.json` — download a single scan report as JSON
  (ownership enforced; admins may access any).
- `GET /history/export.csv` — download the current user's scan history as CSV
  (no passwords, tokens, or hashes of other users).
- `GET /compare?a=<id>&b=<id>` — compare two of the user's scans (score delta,
  classification change, indicators added/removed).
- `POST /demo` — populate history with labelled synthetic examples (demo mode).

### Account
- `GET /settings` — account settings page.
- `POST /settings/password` — change password (requires current password; enforces
  the password policy; logs a `PASSWORD_CHANGED` event with no password material).

### Informational
- `GET /insights` — detection-rule library.
- `GET /methodology` — risk-scoring methodology and weights.

### Admin (ADMIN role required; 401 anonymous / 403 non-admin)
- `GET /admin/scans/export.csv` — export all/filtered scan records as CSV.
- `POST /admin/users/<id>/toggle-active` — activate/deactivate a user
  (cannot target self; logs `USER_STATUS_CHANGED`).
- `POST /admin/users/<id>/role` — change a user's role
  (cannot target self; logs `USER_ROLE_CHANGED`).
- `GET /admin/system-health` — non-sensitive operational status (never exposes
  secrets, credentials, or sensitive filesystem paths).

### Rate limiting
`POST /api/auth/login`, `POST /api/auth/register`, and `POST /api/scan` (and their
HTML equivalents) are rate-limited. When exceeded they return **429** with a
`Retry-After` header (JSON body for API paths).

### Security notes
- All state-changing HTML forms include a CSRF token; JSON `/api/` endpoints are
  explicitly CSRF-exempt by design (documented in SECURITY.md).
- Exports never include passwords, hashes, tokens, or session data.
