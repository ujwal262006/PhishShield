# PhishShield — Final Release Report

**Release version:** 0.3.0 (release candidate)
**Product:** PhishShield — Explainable Phishing Detection & Risk Intelligence
**Nature:** Educational, defensive cybersecurity PBL project (undergraduate).

---

## 1. Principal-engineer review scorecard

Scores reflect the state **after** this review's fixes were applied. Every
category is now at or above 9; the two remaining sub-10s are documented, justified
limitations of a local academic prototype (not defects).

| Category | Score | Notes |
|----------|:-----:|-------|
| Visual polish | 9 | Cohesive design system, gauge/waterfall/forensics, consistent components. |
| Usability | 9 | Clear flows, command palette, demo mode, empty/loading states. |
| Accessibility | 9 | Semantic landmarks, focus-visible, ARIA on menus/dialogs, reduced-motion. Full WCAG audit needs manual AT testing. |
| Responsiveness | 9 | Fluid grids; sidebar collapses to an off-canvas drawer; no mobile h-scroll. |
| Security | 9 | Hashing, RBAC, CSRF, **CSP nonces (no unsafe-inline scripts)**, headers, rate limiting, ownership checks, sanitized logs. |
| Architecture | 9 | App factory, blueprints, Flask-independent services, shared helpers. |
| Correctness | 10 | 115 tests + 25-point live E2E all pass. |
| Performance | 9 | Single-query dashboard stats, single-commit scans, pagination, indexes. |
| Maintainability | 9 | Centralized time/version/scoring config, no dead/duplicated code, zero warnings. |
| Error handling | 9 | Branded 400/401/403/404/429/500; no stack traces; 500 rolls back the session. |
| Consistency | 9 | Shared layouts, badge/severity conventions, `active_nav` everywhere. |
| Academic demonstrability | 10 | Transparent methodology, insights library, waterfall, quiz, demo mode, docs. |

### Fixes made during this review
- **CSP nonce hardening** — removed `'unsafe-inline'` from `script-src`; per-request
  nonce applied to every script tag; removed all inline `onclick` handlers.
- Verified (and locked in with 3 new tests) that the nonce is present, matches the
  served tags, and rotates per request.

(Earlier review passes had already fixed the dashboard N+1 query, multi-commit
scans, deprecated `datetime.utcnow()`, duplicated scan-construction, and dead code.)

---

## 2. Features

- Rule-based, **explainable** URL risk engine (20+ string-only features; no network).
- Weighted, capped, normalized 0–100 scoring with four bands (SAFE/SUSPICIOUS/HIGH/CRITICAL).
- Typosquatting/look-alike detection (normalized Levenshtein vs. a trusted list).
- Advanced scan report: risk gauge, category breakdown, "why scored" waterfall, URL forensics.
- Auth (register/login/logout), password policy, hashing, failed-login lockout, **rate limiting**.
- **RBAC** (USER/ADMIN) with correct 401/403 and audit logging.
- Scan history (search, score filter, sort, pagination) + **scan comparison**.
- Exports: single-scan JSON, history CSV, admin all-scans CSV; print/PDF stylesheet.
- Admin SOC dashboard (metrics, trend, distribution, histogram, alerts), user management, system health.
- Account settings (profile, change password, theme).
- Security Insights (rule library), Risk Methodology, Awareness + Quiz, SHA-256 Integrity demo.
- Premium UI: design tokens, **dark/light themes**, app shell, **command palette (Ctrl/Cmd+K)**,
  toasts, modals, empty/loading states.
- JSON API alongside the HTML UI.

---

## 3. Architecture

```
app/
├── __init__.py     factory: blueprints, CSRF, error handlers, CSP nonce + headers, context
├── config.py       Base/Development/Testing/Production
├── version.py      PHISHSHIELD_VERSION = 0.3.0
├── extensions.py   db, login_manager, csrf
├── models/         User, Scan, SecurityEvent (SQLAlchemy / SQLite)
├── services/       url_analyzer, risk_engine (+ build_scan/breakdown/waterfall/forensics),
│                   domain_similarity, integrity, scoring_config
├── routes/         main, auth, scan, dashboard, admin, settings  (HTML + JSON API)
├── utils/          security_logger, decorators (RBAC), validators, rate_limit, timeutil
├── templates/      base.html (public) + shell.html (authed app shell) + pages
└── static/         css/style.css (design system), js/main.js (components)
```

The risk engine is Flask-independent and fully unit-tested. Security-relevant
concerns (auth, RBAC, logging, headers, rate limiting) are isolated in `utils/`.

---

## 4. Security posture

- **Passwords:** Werkzeug hashing (PBKDF2 + salt); never stored/logged/returned in plaintext.
- **Authorization:** `admin_required` / `login_required_api`; ownership checks on scans and exports; self-role/self-status changes blocked; denials logged.
- **CSRF:** Flask-WTF on all HTML forms; JSON `/api/` explicitly exempt (documented).
- **Content-Security-Policy:** `script-src 'self' 'nonce-<per-request>' cdn.jsdelivr.net` — **no `unsafe-inline` for scripts**; `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`.
- **Other headers:** `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`.
- **Injection/XSS:** ORM-parameterized queries; Jinja2 autoescape (verified a `<script>` payload is not rendered unescaped).
- **Rate limiting:** in-memory fixed-window on login/register/scan → 429 + `Retry-After`.
- **Logging:** security events sanitize forbidden keys (password/token/secret/…); System Health omits secrets.
- **Secrets:** from env/`.env` only; `.env` git-ignored.
- **Safety by design:** analyzes the URL string only — never visits, scrapes, or attacks targets.

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 5. Test results

Command: `pytest`

**Result: `115 passed` in ~30s, 0 warnings.**

| Suite | Focus |
|-------|-------|
| `test_url_analyzer.py` | validation, feature extraction |
| `test_risk_engine.py` | scoring, classification, clamping, keyword cap |
| `test_new_rules.py` | new rules + report helpers (breakdown/waterfall/forensics/catalog) |
| `test_domain_similarity.py` | Levenshtein, typosquatting, SHA-256 integrity |
| `test_auth.py` | register/login/logout, password policy, hashing, lockout |
| `test_scan.py` | scan create/history, cross-user 403, dashboard stats |
| `test_authorization.py` | RBAC 401/403, admin access |
| `test_features.py` | settings/password change, exports+ownership, compare, user mgmt, system health, headers |
| `test_security.py` | **CSP nonce (3)**, rate limiting, SQLi-style/XSS handling, oversized input |

---

## 6. QA results (live end-to-end, running server)

All 25 checks passed:

- USER login; USER blocked from `/admin` (403). ✔
- Scan CRITICAL (80) and SAFE (0) with correct classification. ✔
- Scan history page + API. ✔
- Export JSON (attachment) and CSV (no password field). ✔
- Settings page. ✔
- 404 branded error page. ✔
- No `password_hash` / `secret_key` in any served page. ✔
- ADMIN login; admin dashboard, all scans, security events, users, system health. ✔
- Security events log contains SCAN entries. ✔
- All routes reachable (insights, methodology, awareness, integrity, compare). ✔
- System Health exposes no secret key. ✔

CSP verified separately: nonce present in header, matches script tags, rotates per request.

**Verification method:** because this Windows terminal integration garbles stdout,
all command output was captured to files and read back; results above are read from
those files, not assumed.

---

## 7. Known limitations

- **Heuristic engine:** false positives/negatives possible; a score is a heuristic
  risk value out of 100, not a probability of maliciousness.
- **`style-src 'unsafe-inline'`** remains (templates use inline `style` attributes;
  nonces don't apply to inline style attributes). Scripts are fully locked down.
- **Rate limiting is in-memory/single-process** — a multi-process deployment needs a shared store.
- **No MFA** yet (architecture is MFA-ready).
- **SQLite** suits local/educational use, not high-concurrency production.
- Full **WCAG** conformance needs manual assistive-technology testing.

---

## 8. Future improvements

- CSP nonces/hashes for inline styles (or move all inline styles to classes) to drop `style-src 'unsafe-inline'`.
- HSTS when served over HTTPS; MFA (TOTP); distributed rate limiting; CAPTCHA.
- Configurable per-organization trusted-domain profiles.
- Optional, fully reproducible ML classifier trained on a public URL dataset.

---

## 9. Deployment instructions

> Windows `cmd`. On macOS/Linux use `python3` and `source .venv/bin/activate`.

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
:: set a strong key in .env:
python -c "import secrets; print(secrets.token_hex(32))"
python -m scripts.seed_demo_data
python run.py
```

Open <http://127.0.0.1:5000>. Run tests with `pytest`. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production-style guidance.

---

## 10. Demo instructions

Demo credentials (dev only, configurable via `.env`):

| Role | Username | Password |
|------|----------|----------|
| ADMIN | `admin` | `Admin@12345` |
| USER | `student` | `Student@12345` |

Full ~5-minute walkthrough in [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md): landing →
theme toggle → login → command palette → scan SAFE then CRITICAL → advanced report
(gauge/breakdown/waterfall/forensics) → export/print → history + compare → insights
→ methodology → integrity → awareness quiz → settings → admin SOC dashboard →
security events → user management → system health.

To reset the demo: stop the server, delete `instance/phishshield.db`, re-run
`python -m scripts.seed_demo_data`.

---

## 11. Verdict

PhishShield 0.3.0 is a polished, coherent, and defensible release candidate:
explainable by three undergraduates during a viva, yet presenting like a
professional security product. Correctness and demonstrability are verified;
security is hardened to the point that the only remaining relaxations are the
documented, low-risk `style-src` inline allowance and the single-process rate
limiter appropriate to a local prototype.
