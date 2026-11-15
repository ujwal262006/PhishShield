# Changelog

All notable changes to PhishShield are documented here.

## [0.3.0] — Release candidate (hardening & cleanup)

Final principal-engineer review pass. 115 tests pass (112 + 3 new CSP tests).

### Security
- **CSP nonces**: `script-src` now uses a per-request `'nonce-...'` and no longer
  allows `'unsafe-inline'`. A fresh nonce is generated per request and applied to
  every `<script>` tag (inline and CDN). All inline `onclick` handlers were removed
  and replaced with delegated event listeners.

### Performance
- User dashboard stats now use a single grouped SQL aggregate instead of loading
  all scans twice.
- A scan and its security events are now written in a **single transaction**
  (`log_event(..., commit=False)`), instead of up to four commits per scan.

### Maintainability
- Centralized `utcnow()` (`app/utils/timeutil.py`) — removed all deprecated
  `datetime.utcnow()` usage; the test suite now runs with **zero warnings**.
- Extracted `build_scan()` in the risk engine; the scan route and seed script now
  share it (removed duplicated model-construction logic).
- Removed dead code (`_is_json_request`) and orphaned CSS; landing hero moved from
  inline styles to design-system classes.

## [0.2.0] — Production-style SaaS upgrade

## [0.2.0] — Production-style SaaS upgrade

A major UI/UX, security, and analytics upgrade of the working 0.1.0 academic app.
All 73 original tests still pass; 39 new tests were added (112 total).

### Added
- **Design system** with CSS design tokens and polished **dark/light themes**
  (persisted + system-preference detection).
- **Application shell** for authenticated users: sidebar + topbar, user menu,
  active-nav state, responsive collapse.
- **Command palette** (Ctrl/Cmd+K) for keyboard navigation.
- **Premium landing page** with hero, product preview, and explainer sections.
- **Advanced scan report**: circular risk gauge, category risk-breakdown bars,
  "why this URL was scored" waterfall, and a URL forensics view.
- **Security Insights** page (detection-rule library) and **Risk Methodology**
  page (weights + rationale + pipeline).
- **Scan history upgrade**: score filter, sorting, CSV export, empty states.
- **Scan comparison** view (score delta, classification change, indicator diff).
- **Exports**: single-scan JSON, history CSV, admin all-scans CSV; print stylesheet.
- **Admin SOC dashboard**: metrics, scans-over-time trend, risk distribution,
  score histogram, top indicators, recent alerts.
- **User management** (activate/deactivate, change role) with confirmation dialogs.
- **System Health** admin page (non-sensitive status only).
- **Account settings** with policy-enforced password change (logged, no secrets).
- **Awareness quiz** (interactive Quick Check).
- **Demo mode** that loads labelled synthetic examples.
- **Toasts, modals, empty states, loading states** across the app.
- New explainable risk rules with tests: userinfo component, non-standard port,
  deep path, repeated/traversal separators.
- **Rate limiting** (in-memory) on login, registration, and scanning.
- New docs: `UPGRADE_AUDIT.md`, `UI_DESIGN.md`, `RISK_METHODOLOGY.md`,
  `THREAT_MODEL.md`, `DEPLOYMENT.md`, `DEMO_GUIDE.md`, and this changelog.
- `PHISHSHIELD_VERSION` constant (`app/version.py`).

### Changed
- Hardened HTTP security headers: added `Permissions-Policy`, CSP `frame-ancestors 'none'`,
  `base-uri`, and `form-action`.
- Bounded pagination/search parameters server-side.
- Added a composite index on `(user_id, created_at)` for faster history queries.
- Branded error pages for 400/401/403/404/429/500.

### Preserved
- The explainable, rule-based risk engine remains the core (no black-box ML added).
- String-only URL analysis — the app never visits or attacks target sites.
- All original authentication, RBAC, logging, and integrity behavior.

## [0.1.0] — Initial academic release
- Flask app, SQLite, auth + RBAC, rule-based URL analysis, explainable risk
  scoring, typosquatting detection, scan history, admin dashboard, security
  logging, SHA-256 integrity demo, awareness page, JSON API, 73 tests, docs.
