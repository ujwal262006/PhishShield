# PhishShield — Upgrade Audit (Phase 0)

This document records the audit of the existing codebase performed **before** any
upgrade work, the baseline test result, and the planned upgrade phases.

## Baseline verification

- Test suite run before changes: **73 passed** (74 deprecation warnings, all from
  `datetime.utcnow()` on Python 3.13 — informational only).
- The application starts, seeds, and serves as documented.

## Current architecture (as-built)

```
app/
├── __init__.py        app factory, CSRF-exempt /api/, error handlers, security headers
├── config.py          Base/Development/Testing/Production configs
├── extensions.py      db, login_manager, csrf
├── models/            User, Scan, SecurityEvent (SQLAlchemy over SQLite)
├── routes/            main, auth, scan, dashboard, admin (HTML + JSON API)
├── services/          url_analyzer, risk_engine, domain_similarity, integrity, scoring_config
├── utils/             security_logger, decorators (RBAC), validators
├── templates/         base + 14 pages
└── static/            css/style.css, js/main.js
```

The risk engine is Flask-independent and unit-testable — a strong existing design.

## Existing strengths (preserve these)

1. **Explainable rule-based engine** with a centralized, editable `scoring_config.py`.
   Every point maps to a named indicator with a plain-English explanation.
2. **Clean separation of concerns**: services vs. routes vs. models vs. utils.
3. **Secure auth fundamentals**: Werkzeug hashing, failed-login lockout, generic error
   messages, no plaintext storage.
4. **RBAC** via decorators returning correct 401/403 and logging unauthorized attempts.
5. **Security logging** with sensitive-key sanitization.
6. **String-only URL analysis** — no network calls, safe by design.
7. **Good test coverage** across unit and integration layers.

## Identified weaknesses / opportunities

| # | Area | Finding | Planned action |
|---|------|---------|----------------|
| 1 | Frontend | Single flat `style.css`, no design tokens, no theming, navbar-only shell | New design-token system, dark/light mode, app shell (sidebar + topbar) |
| 2 | UX | No toasts, empty states, loading states, command palette, modals | Add lightweight, dependency-free components |
| 3 | Scanner/Result | Result page is basic; no gauge, waterfall, or URL forensics | Rebuild result as a professional security report |
| 4 | Analytics | No time-series or SOC-style admin dashboard | Add scans-over-time + richer admin dashboard |
| 5 | Reporting | No export (JSON/CSV), no print stylesheet, no scan comparison | Add exports, print CSS, comparison view |
| 6 | Admin | No user activate/deactivate/role change, no system health | Add user management actions + system health page |
| 7 | Account | No settings page or password-change flow | Add settings + change password (policy-enforced, logged) |
| 8 | Rate limiting | None on login/register/scan | Add simple in-memory rate limiter (documented limitation) |
| 9 | Security headers | Missing `Permissions-Policy`; uses `X-Frame-Options` only | Add `Permissions-Policy` + `frame-ancestors` in CSP |
| 10 | Error pages | Generic single template; no 429 handler | Branded error pages + 429 handler |
| 11 | Versioning | No version constant or changelog | Add `PHISHSHIELD_VERSION` + `CHANGELOG.md` |
| 12 | Risk engine | A few explainable rules could be added (userinfo, port, path depth, mixed-script, repeated separators, encoded chars) | Add rules, each with name/severity/points/explanation/test |
| 13 | Validation | Search/pagination params not bounded | Clamp pagination, bound search length |
| 14 | Accessibility | Limited focus states, few ARIA labels | Add focus-visible, ARIA, reduced-motion, semantic landmarks |
| 15 | DB indexes | Reasonable; add composite index for (user_id, created_at) | Add index to speed history queries |

## Migration risks & mitigations

- **Risk:** CSP tightening breaks Chart.js or inline scripts. **Mitigation:** keep the
  jsdelivr allowance, test every page after header changes.
- **Risk:** Template rewrites break existing HTML-route tests
  (`test_authorization` checks `/admin` returns 200/403). **Mitigation:** preserve route
  names, status codes, and required context keys; run tests after each phase.
- **Risk:** New risk rules change scores and break `test_risk_engine` expectations.
  **Mitigation:** add rules conservatively; keep `https://example.com` SAFE and existing
  thresholds; update tests only when behavior intentionally changes, never to force green.
- **Risk:** Rate limiting interferes with the test client. **Mitigation:** disable rate
  limiting under the testing config.

## Upgrade phases

0. Audit (this document).
1. Architecture & security hardening (version, config, headers, validation, rate-limit base).
2. Design system (tokens, dark/light, components).
3. Landing page + application shell + command palette.
4. Scanner + advanced result (gauge, waterfall, forensics).
5. Dashboards + analytics.
6. History + reporting + exports + comparison.
7. Admin (events, user management, system health).
8. Settings + notifications + Security Insights + awareness quiz.
9. Security hardening finalization + error pages.
10. Testing (keep 73 green, add new).
11. Documentation.
12. Final QA + completion report.

## Guiding constraints

- Do not replace the explainable engine with a black box.
- No offensive capability; analysis remains string-based.
- Keep it explainable by three undergraduate students.
- Preserve the 73-test baseline; extend, don't delete.
