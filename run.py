"""Entry point for running the PhishShield development server.

Usage:
    python run.py

The database (SQLite) is created automatically on first run inside instance/.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug is controlled by the selected config (FLASK_ENV).
    app.run(host="127.0.0.1", port=5000)
