# Future Scope

Ideas for extending PhishShield beyond the current PBL scope. None are required for the
project to be complete; they are documented for viva discussion and future teams.

## Detection

- **Allowlisted redirect inspection** — optionally follow redirect chains, but only to a
  strict allowlist, in a sandbox, without submitting credentials or executing JavaScript.
- **Configurable trusted-domain profiles** — per-organization lists loaded from a file.
- **Extended indicators** — homograph detection tables, brand keyword dictionaries,
  shortened-URL awareness (without resolving them).

## Machine learning (optional, only if fully reproducible)

- Train a transparent classifier (e.g. logistic regression / decision tree) on a public
  URL dataset, with a documented pipeline and evaluation metrics. Kept optional because a
  rule-based system is more explainable for a viva.

## Product features

- Exportable PDF/CSV scan reports.
- Bulk URL scanning from an uploaded list.
- Email/webhook alerts for CRITICAL detections.
- User-configurable scoring weights via the admin UI.

## Security hardening

- Rate limiting and CAPTCHA on authentication endpoints.
- Two-factor authentication (TOTP).
- Audit-log export and retention policies.
- Move from SQLite to a networked database for multi-user deployments.

## Operations

- Dockerfile and CI pipeline running the test suite on each push.
- Structured logging and metrics.
