# Demo Scenarios (5-Minute Faculty Walkthrough)

## Setup (once, before the demo)

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -m scripts.seed_demo_data
python run.py
```

Open <http://127.0.0.1:5000>.

Demo credentials:

| Role  | Username  | Password        |
|-------|-----------|-----------------|
| ADMIN | `admin`   | `Admin@12345`   |
| USER  | `student` | `Student@12345` |

## 5-minute flow

1. **Landing page** — Open PhishShield. Point out the subtitle, the four risk bands, and
   the disclaimer that results are heuristic.
2. **Login** — Log in as `student`.
3. **User dashboard** — Show the stat cards and the risk-distribution doughnut chart.
4. **Scan a SAFE URL** — Go to *Scan URL*, submit `https://example.com`. Show the SAFE
   result, the low score, and the empty/short indicator list.
5. **Scan a suspicious URL** — Submit
   `http://secure-login-verify.example.test/account/confirm`.
6. **Show risk indicators** — Point to each detected indicator with its severity.
7. **Show risk-score calculation** — Note the score ring and how points add up (open
   `app/services/scoring_config.py` if asked to justify the weights).
8. **Show explanations** — Read one or two plain-English explanations.
9. **Scan a CRITICAL URL** — Submit
   `http://user@192.0.2.10/login-verify-secure-account-update/confirm.php` to show a
   HIGH RISK / CRITICAL result.
10. **Scan history** — Open *History*; demonstrate search and the classification filter.
11. **Login as admin** — Log out, log in as `admin`.
12. **System statistics** — Show the admin dashboard: totals, chart, and most-common
    indicators.
13. **Security events** — Open *Security Events*; show logged logins, scans, and any
    high/critical detections.
14. **SHA-256 integrity** — Open *Integrity*; hash a URL, then change one character and
    show the completely different hash. Emphasize hashing != encryption.
15. **Awareness page** — Finish on *Awareness* to highlight the educational angle.

## Suggested talking points

- "Every point in the score is explainable — nothing is a black box."
- "We never visit the URL; we analyze the string, which keeps the tool safe to run."
- "Passwords are hashed, admins and users are separated by RBAC, and every security-relevant
  action is logged."

## Safe demo URLs

| URL | Expected |
|-----|----------|
| `https://example.com` | SAFE |
| `https://github.com/login` | SAFE / low |
| `http://example.com/login` | SUSPICIOUS |
| `http://192.0.2.10/login` | SUSPICIOUS / HIGH |
| `http://secure-login-verify.example.test/account/confirm` | HIGH RISK |
| `http://user@192.0.2.10/login-verify-secure-account-update/confirm.php` | HIGH / CRITICAL |
| `https://g00gle-account-update.example.test/signin` | typosquatting flagged |

All use reserved/documentation domains (`example.*`, `192.0.2.0/24`) or `.test`.
