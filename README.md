# PhishShield

### Explainable Phishing Detection & Risk Intelligence

> **v0.3.0** — a polished, production-style cybersecurity SaaS prototype built on
> the explainable rule-based core. See [CHANGELOG.md](CHANGELOG.md) for the upgrade
> summary, [docs/UPGRADE_AUDIT.md](docs/UPGRADE_AUDIT.md) for the pre-upgrade audit,
> and [FINAL_RELEASE_REPORT.md](FINAL_RELEASE_REPORT.md) for the release-candidate review.

PhishShield is a web-based, **rule-based phishing risk assessment system**. A user
submits a URL, and PhishShield analyzes the URL *string* using transparent security
rules, calculates a normalized risk score (0-100), classifies the URL, and clearly
explains **why** it was judged safe, suspicious, high-risk, or critical.

This is a **Computer and Cyber Security Fundamentals** Project-Based Learning (PBL)
project built for a 3-member undergraduate team. It is **educational and defensive**:
it never visits, attacks, clones, or harvests anything. All analysis is performed on the
URL string itself.

---

## 1. Project Overview

PhishShield demonstrates core cybersecurity concepts in a single, explainable
application: threat/risk assessment, authentication, access control, cryptographic
hashing, security logging, and cybercrime awareness.

## 2. Problem Statement

Phishing links trick users into trusting malicious destinations. Many detection tools
are black boxes that only output "safe" or "dangerous" without explanation. For a student
audience, that is neither educational nor trustworthy. PhishShield instead makes every
decision **transparent**: each risk point is tied to a named indicator with a plain-English
explanation.

## 3. Objectives

- Analyze a URL's structure for well-understood phishing indicators.
- Produce an explainable, weighted risk score normalized to 0-100.
- Classify URLs as SAFE / SUSPICIOUS / HIGH RISK / CRITICAL.
- Provide secure authentication, RBAC, and security event logging.
- Demonstrate cryptographic hashing (SHA-256) for integrity.
- Raise phishing awareness through an educational module.

## 4. Features

Core (explainable engine):
- **Rule-based URL analysis engine** (20+ features, string-only, no network calls).
- **Explainable weighted risk scoring** with a centralized, editable config.
- **Typosquatting / look-alike detection** via normalized Levenshtein similarity.

Security & access:
- **Secure authentication**: registration, login, logout, password policy, hashing,
  failed-login tracking, temporary account lockout, and **rate limiting**.
- **Role-based access control** (USER / ADMIN) with proper 401/403 responses.
- **Security event logging**; **CSRF**, security headers, input validation.
- **SHA-256 integrity demonstration** (hashing != encryption).

Experience:
- **Premium UI** with a design system, **dark/light themes**, app shell (sidebar +
  topbar), **command palette (Ctrl/Cmd+K)**, toasts, modals, empty/loading states.
- **Advanced scan report**: circular risk gauge, category risk-breakdown bars,
  "why this URL was scored" waterfall, and URL forensics view.
- **Scan history** with search, score filter, sorting, pagination, and **compare**.
- **Exports**: single-scan JSON, history CSV, admin all-scans CSV; **print/PDF**.
- **Admin SOC dashboard** (metrics, trend, distribution, histogram, alerts),
  **user management**, **security events**, and **System Health**.
- **Account settings** (profile, change password, theme).
- **Security Insights** (rule library), **Risk Methodology**, **Awareness quiz**,
  and a **Demo mode** for presentations.
- **JSON API** alongside the HTML UI.

## 5. System Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for diagrams and data flow. In short:

```
Flask app factory
 ├── models/      (User, Scan, SecurityEvent)  -> SQLite via SQLAlchemy
 ├── services/    (url_analyzer, risk_engine, domain_similarity, integrity, scoring_config)
 ├── routes/      (main, auth, scan, dashboard, admin) -> HTML + JSON API
 ├── utils/       (security_logger, RBAC decorators, validators)
 └── templates/ + static/  (dark cybersecurity UI, Chart.js)
```

The risk engine is fully independent of Flask so it can be unit-tested on its own.

## 6. Technology Stack

- **Backend:** Python 3.11+, Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF (CSRF),
  Werkzeug password hashing.
- **Frontend:** HTML5, CSS3, vanilla JavaScript, Chart.js (via CDN).
- **Database:** SQLite + SQLAlchemy ORM.
- **Testing:** pytest + Flask test client.

## 7. Installation

> Requires Python 3.11 or newer. Commands below use Windows `cmd`. On macOS/Linux,
> use `python3` and `source .venv/bin/activate`.

```bat
:: 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate

:: 2. Install dependencies
pip install -r requirements.txt
```

## 8. Configuration

```bat
:: Copy the example environment file and edit it
copy .env.example .env
```

Set a strong `SECRET_KEY` in `.env`:

```bat
python -c "import secrets; print(secrets.token_hex(32))"
```

`.env` is git-ignored and must never be committed. Demo seed credentials are read from
environment variables (see `.env.example`), so no insecure password is hardcoded in the
application source.

## 9. Database Setup

The SQLite database is created automatically on first run inside the `instance/` folder.
To populate it with demo data (recommended for the viva):

```bat
python -m scripts.seed_demo_data
```

## 10. Running the Project

```bat
python run.py
```

Then open <http://127.0.0.1:5000> in your browser.

## 11. Demo Credentials

Created by the seed script (development only; configurable via `.env`):

| Role  | Username  | Password        |
|-------|-----------|-----------------|
| ADMIN | `admin`   | `Admin@12345`   |
| USER  | `student` | `Student@12345` |

## 12. API Documentation

Full details in [API.md](API.md). Summary:

| Method | Endpoint                       | Auth   | Purpose                     |
|--------|--------------------------------|--------|-----------------------------|
| POST   | `/api/auth/register`           | -      | Register a new user         |
| POST   | `/api/auth/login`              | -      | Log in                      |
| POST   | `/api/auth/logout`             | user   | Log out                     |
| GET    | `/api/auth/me`                 | user   | Current user info           |
| POST   | `/api/scan`                    | user   | Analyze a URL               |
| GET    | `/api/scans`                   | user   | List own scans              |
| GET    | `/api/scans/<id>`              | user   | Scan detail (own/admin)     |
| GET    | `/api/dashboard/stats`         | user   | Personal statistics         |
| GET    | `/api/admin/stats`             | admin  | System statistics           |
| GET    | `/api/admin/users`             | admin  | All users                   |
| GET    | `/api/admin/scans`             | admin  | All scans                   |
| GET    | `/api/admin/security-events`   | admin  | Security event log          |

Selected HTML routes: `/dashboard`, `/scan`, `/scan/<id>`, `/scan/<id>/export.json`,
`/history`, `/history/export.csv`, `/compare`, `/demo`, `/settings`, `/insights`,
`/methodology`, `/awareness`, `/integrity`, and admin routes `/admin`,
`/admin/scans` (+ `/export.csv`), `/admin/security-events`, `/admin/users`
(+ `/toggle-active`, `/role`), `/admin/system-health`. Full details in
[API.md](API.md).

## 13. Risk-Scoring Methodology

Each detected indicator contributes a defined number of points, configured centrally in
`app/services/scoring_config.py`. Points are summed (suspicious-keyword points are capped
to avoid double-counting), then clamped to 0-100.

| Score  | Classification |
|--------|----------------|
| 0-29   | SAFE           |
| 30-59  | SUSPICIOUS     |
| 60-79  | HIGH RISK      |
| 80-100 | CRITICAL       |

Example indicator weights (fully editable): no HTTPS `+15`, IP hostname `+20`, suspicious
keyword `+5` each (capped), `@` symbol `+15`, punycode `+15`, typosquatting `+20`. See
`scoring_config.py` for the complete, commented list.

## 14. Security Considerations

See [SECURITY.md](SECURITY.md). Highlights: Werkzeug password hashing, session cookies with
HttpOnly/SameSite, CSRF protection on forms, RBAC decorators, server-side input validation,
ORM-parameterized queries (no raw SQL), output escaping via Jinja2 autoescape, HTTP security
headers, secrets via environment variables, and no password/credential logging.

## 15. Testing

```bat
pytest
```

112 tests cover URL validation/parsing, feature detection (incl. new rules),
risk scoring, classification, domain similarity, SHA-256 hashing, report helpers,
and integration flows (register/login/logout, authorization, scanning, history,
compare, exports, settings/password change, admin user management, system health),
plus security tests (rate limiting, injection-style input, XSS escaping, oversized
input, security headers).

**Result:** `115 passed` (73 original + 42 added during the upgrade & RC hardening).

## 16. Limitations

PhishShield is a **heuristic** system. It analyzes the URL string only and does **not**:

- fetch page content, follow redirects (disabled by default), or use threat-intelligence feeds;
- guarantee detection. It can produce **false positives** and **false negatives**.

A SAFE result is not a guarantee of safety; a CRITICAL result is not proof of malice.

## 17. Future Enhancements

- Optional, allowlisted redirect-chain inspection (safely sandboxed).
- Configurable per-organization trusted-domain lists.
- Multi-factor authentication (architecture is MFA-ready).
- CAPTCHA and distributed (shared-store) rate limiting.
- Optional, fully reproducible ML classifier trained on a public URL dataset.

Delivered in v0.2.0: premium UI + dark/light, command palette, advanced report,
exports (JSON/CSV/print), scan comparison, admin SOC dashboard, user management,
system health, settings/password change, awareness quiz, and in-app rate limiting.

## 18. Team-Member Responsibilities

| Member | Focus | Responsibilities |
|--------|-------|------------------|
| **Member 1** | Phishing Detection & Risk Engine | URL parser, feature extraction, detection rules, risk scoring, domain similarity, analysis tests |
| **Member 2** | Authentication, Authorization & Backend | Database, registration/login, password hashing, RBAC, API, sessions, backend security |
| **Member 3** | Frontend, Dashboard & Security Analytics | UI, scanner/result pages, dashboards, scan history, charts, awareness module, frontend testing |

All three members contribute to integration and documentation.

## 19. Academic Disclaimer

> **PhishShield is an educational URL risk-assessment system. Its results are heuristic and
> should not be treated as definitive proof that a website is malicious or safe.** Heuristic
> indicators can produce false positives and false negatives. Always verify links
> independently before entering sensitive information.

## 20. Syllabus Mapping

See [docs/module-description.md](docs/module-description.md) for a full mapping of each
module to the Computer and Cyber Security Fundamentals syllabus concepts.

## 21. Documentation Index

- [ARCHITECTURE.md](ARCHITECTURE.md) — components, data flow, ER diagram.
- [SECURITY.md](SECURITY.md) — security design and controls.
- [API.md](API.md) — endpoint reference.
- [CHANGELOG.md](CHANGELOG.md) — version history.
- [docs/UPGRADE_AUDIT.md](docs/UPGRADE_AUDIT.md) — pre-upgrade audit.
- [docs/UI_DESIGN.md](docs/UI_DESIGN.md) — design system.
- [docs/RISK_METHODOLOGY.md](docs/RISK_METHODOLOGY.md) — scoring methodology.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — STRIDE threat model.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — setup and deployment.
- [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md) — faculty walkthrough.
- Also: project-overview, module-description, testing-report, demo-scenarios,
  future-scope under `docs/`.
