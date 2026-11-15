# Testing Report

## How to run

```bat
pytest
```

## Summary

- **Total tests:** 73
- **Result:** 73 passed
- **Framework:** pytest 8.2 + Flask test client
- **Isolation:** each test runs against an in-memory SQLite database (testing config).

## Coverage by area

### Unit tests

| File | What it verifies |
|------|------------------|
| `test_url_analyzer.py` (20) | URL validation (empty, none, missing scheme, unsupported scheme, too long, no host); HTTPS/HTTP detection; IP hostname; suspicious keywords; subdomain count; URL length; `@` symbol; special chars; punycode; suspicious TLD; parameter count |
| `test_risk_engine.py` (13) | Classification bands (SAFE/SUSPICIOUS/HIGH/CRITICAL); score clamping to 0-100; non-negative score; safe HTTPS URL; IP+keyword scoring; keyword-point cap; indicators carry explanations/severity/points; recommendation + 64-char hash present; `@` flagged; high/critical classification |
| `test_domain_similarity.py` (12) | Levenshtein distance; normalized similarity range; exact trusted domain not flagged; look-alike flagged; unrelated not flagged; subdomain/www handling; SHA-256 length/determinism/sensitivity; verify_integrity; integrity_demo change detection |

### Integration tests

| File | What it verifies |
|------|------------------|
| `test_auth.py` (15) | Password policy; registration success/weak-reject/duplicate; password stored hashed (not plaintext); login success/wrong-password/unknown-user; `/me` requires auth; logout; account lockout after repeated failures |
| `test_scan.py` (7) | Scan requires auth; scan creates a DB record with valid score/class/hash; invalid & empty URLs rejected; history lists own scans; a user cannot view another user's scan (403); dashboard stats |
| `test_authorization.py` (6) | Admin endpoints require auth (401); regular user forbidden (403); admin can access admin endpoints; admin can view any user's scan; admin HTML dashboard accessible; user HTML admin forbidden |

## Edge cases covered

- Empty / `None` / malformed / oversized URLs.
- Unsupported protocols (e.g. `ftp://`).
- Keyword stuffing (score cap enforced).
- Cross-user data access attempts.
- Unauthenticated and under-privileged access to admin routes.
- Hash sensitivity to single-character changes.

## End-to-end verification (manual smoke test)

Against a running dev server with seeded data:

- `GET /health` → `{"status":"ok"}`
- `GET /` → 200
- Login as `student` → 200 (role USER)
- Scan `http://user@192.0.2.10/login-verify-secure-account` → 201, score 65, HIGH RISK,
  4 indicators, 64-char integrity hash
- `GET /api/scans` → 200
- `GET /api/admin/stats` as student → 403 (correctly forbidden)

## Notes

Deprecation warnings from `datetime.utcnow()` are informational only (Python 3.12+) and do
not affect behavior.
