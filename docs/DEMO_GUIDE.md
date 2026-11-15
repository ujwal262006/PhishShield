# PhishShield — Demo Guide (Faculty Presentation)

A ~5-minute walkthrough of the upgraded PhishShield.

## Setup (once)

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -m scripts.seed_demo_data
python run.py
```

Open <http://127.0.0.1:5000>.

| Role | Username | Password |
|------|----------|----------|
| ADMIN | `admin` | `Admin@12345` |
| USER | `student` | `Student@12345` |

## Walkthrough

1. **Landing page** — Hero "Know the risk before you click", product preview, and
   the four risk bands. Toggle **dark/light** in the navbar.
2. **Login** as `student`.
3. **App shell** — point out the sidebar, topbar, and press **Ctrl+K** to open the
   **command palette**; jump to the Scanner.
4. **Scan a SAFE URL** — `https://example.com`. Show the gauge (low score) and the
   empty indicator list.
5. **Demo mode** (optional) — on the Scanner, click **Load demo data** to populate
   four labelled examples (SAFE → CRITICAL).
6. **Scan a CRITICAL URL** —
   `http://user@192.0.2.10/login-verify-secure-account-update/confirm.php`.
7. **Advanced report** — walk through the **gauge**, **risk breakdown** bars,
   the **"why this URL was scored" waterfall**, and the **URL forensics** tree.
8. **Expand an indicator** to show its severity, points, explanation, and action.
9. **Export** the report as **JSON**, or **Print/PDF** (print stylesheet).
10. **History** — demonstrate search, min-score filter, sorting, and **Compare
    scans** (score delta + indicator diff). Export **CSV**.
11. **Security Insights** — the detection-rule library.
12. **Risk Methodology** — the transparent weights table and pipeline.
13. **Integrity Check** — hash a URL, change one character, show a completely
    different hash. Emphasize hashing ≠ encryption.
14. **Awareness** — take one or two questions of the **Quick Check** quiz.
15. **Settings** — show profile, theme options, and the change-password form.
16. **Log in as `admin`** — the **SOC dashboard**: metrics, scans-over-time trend,
    risk distribution, score histogram, top indicators, recent alerts.
17. **Security Events** — severity-badged log; note passwords/tokens are never logged.
18. **Users** — activate/deactivate and change a role (confirmation dialog appears).
19. **System Health** — non-sensitive operational status and app version.

## Talking points

- "Every point is explainable — open Risk Methodology to justify any number."
- "We never visit the URL; analysis is string-only, so it is safe to run."
- "Auth, RBAC, CSRF, rate limiting, security headers, and logging are all in place."

## Reset the demo

Stop the server, delete `instance/phishshield.db`, then re-run
`python -m scripts.seed_demo_data`.
