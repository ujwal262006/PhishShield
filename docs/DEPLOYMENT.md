# PhishShield — Deployment Guide

PhishShield is designed to run **locally** for academic/demo use. SQLite is
appropriate for this local/educational prototype. It is **not** presented as
enterprise production infrastructure.

## Development setup

> Windows `cmd` shown. On macOS/Linux use `python3` and `source .venv/bin/activate`.

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Generate a strong secret key and put it in `.env`:

```bat
python -c "import secrets; print(secrets.token_hex(32))"
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SECRET_KEY` | Session signing key (required in production) |
| `FLASK_ENV` | `development` \| `testing` \| `production` |
| `DATABASE_URL` | Optional DB URI (defaults to SQLite in `instance/`) |
| `ENABLE_REDIRECT_CHECK` | Keep `false` (redirect checking is off by design) |
| `SEED_*` | Demo seed credentials used only by the seed script |

`.env` is git-ignored; only `.env.example` (placeholders) is committed. No
production secret is hardcoded in source.

## Database initialization

Tables are created automatically on first run inside `instance/`. To load demo
data:

```bat
python -m scripts.seed_demo_data
```

## Running

```bat
python run.py
```

Open <http://127.0.0.1:5000>.

## Running tests

```bat
pytest
```

## Production-style configuration (guidance)

If deployed beyond local use:

- Set `FLASK_ENV=production` and a strong `SECRET_KEY`.
- Serve behind a WSGI server (e.g. `waitress` on Windows, `gunicorn` on Linux)
  and a reverse proxy that terminates HTTPS.
- With HTTPS, `SESSION_COOKIE_SECURE` is enabled by the production config.
- Consider migrating from SQLite to a networked database for concurrency.
- Rate limiting here is single-process/in-memory; a multi-process deployment
  would need a shared store (documented limitation).

## Security checklist before sharing

- `.env` is not committed.
- `SECRET_KEY` is set to a strong random value.
- Demo credentials changed if the instance is reachable by others.
- Debug mode off in production.
