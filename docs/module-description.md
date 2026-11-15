# Module Description & Syllabus Mapping

## Modules

| Module | Location | Description |
|--------|----------|-------------|
| A. Authentication | `routes/auth.py`, `models/user.py`, `utils/validators.py` | Registration, login, logout, password policy, hashing, failed-login lockout |
| B. URL Analysis Engine | `services/url_analyzer.py` | String-only feature extraction (18+ features) |
| C. Explainable Risk Scoring | `services/risk_engine.py`, `services/scoring_config.py` | Weighted, capped, normalized scoring + classification + explanations |
| D. Trusted Domain / Typosquatting | `services/domain_similarity.py` | Levenshtein-based look-alike detection vs. trusted list |
| E. Scan System | `routes/scan.py` | Validate → analyze → score → explain → store → display |
| F. Scan History | `routes/scan.py`, `models/scan.py` | Per-user history with search/filter/pagination; admin sees all |
| G. Admin Dashboard | `routes/admin.py` | System stats, charts, most-common indicators, alerts |
| H. Security Logging | `utils/security_logger.py`, `models/security_event.py` | Auth/scan events; sensitive keys sanitized |
| I. Cryptographic Integrity | `services/integrity.py`, `routes/main.py` | SHA-256 hashing demo (integrity, not encryption) |
| J. Security Awareness | `templates/awareness.html` | "How to Identify a Phishing URL" education |

## Mapping to Computer & Cyber Security Fundamentals syllabus

| Syllabus concept | Where it is demonstrated |
|------------------|--------------------------|
| Security threats & vulnerabilities | URL analysis engine (Module B) — detects phishing indicators |
| Risk assessment | Risk engine (Module C) — weighted scoring and classification |
| Confidentiality, Integrity, Availability (CIA) | Confidentiality: password hashing + session security; Integrity: SHA-256 demo (Module I); Availability: input limits, error handling, lockout |
| Authentication | Login/registration system (Module A) |
| Password security | Password policy + Werkzeug hashing (Module A) |
| Access control | Route protection and ownership checks (Modules E/F) |
| Role-based access control | `admin_required` / role checks (RBAC, Module G) |
| Cryptographic hashing | SHA-256 integrity demonstration (Module I) |
| Cybercrime awareness | Phishing analysis + awareness page (Modules B, J) |
| Secure computing practices | Security-awareness module + secure-development practices (SECURITY.md) |

## Concept → Module quick reference

```
Threat / Vulnerability / Risk  -> Risk Engine (C)
Authentication                 -> Login system (A)
Access Control / RBAC          -> Decorators + role checks (G)
Cryptography (hashing)         -> SHA-256 integrity demo (I)
Cybercrime                     -> Phishing analysis (B)
Secure Computing               -> Awareness module (J) + secure dev
```


## v0.2.0 upgrade modules

| Module | Location | Description |
|--------|----------|-------------|
| Design system & app shell | `static/css/style.css`, `static/js/main.js`, `templates/base.html`, `templates/shell.html` | Tokens, dark/light theme, sidebar+topbar, command palette, toasts, modals |
| Advanced report | `services/risk_engine.py` (`risk_breakdown`, `waterfall`, `url_forensics`), `templates/result.html` | Gauge, breakdown bars, waterfall, forensics |
| Reporting & exports | `routes/scan.py`, `routes/admin.py` | JSON/CSV exports, print stylesheet, scan comparison |
| Rule library & methodology | `services/risk_engine.py` (`indicator_catalog`, `methodology_table`), `templates/insights.html`, `templates/methodology.html` | Transparent rules and weights |
| Account settings | `routes/settings.py`, `templates/settings.html` | Profile, password change, theme |
| Admin analytics & ops | `routes/admin.py`, `templates/admin_dashboard.html`, `templates/system_health.html` | SOC dashboard, user management, system health |
| Rate limiting | `utils/rate_limit.py` | Login/register/scan abuse protection |

These reinforce the same syllabus concepts: access control (settings, admin ops),
secure computing (rate limiting, headers, exports without secrets), and risk
assessment transparency (methodology, insights).
