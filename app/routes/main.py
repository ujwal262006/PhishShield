"""Public and informational pages (landing, awareness, integrity demo)."""
from __future__ import annotations

from flask import Blueprint, render_template, request
from flask_login import current_user

from app.services.integrity import integrity_demo

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/awareness")
def awareness():
    """Security-awareness / 'How to identify a phishing URL' page."""
    active_nav = "awareness" if current_user.is_authenticated else ""
    return render_template("awareness.html", active_nav=active_nav)


@main_bp.route("/insights")
def insights():
    """Security Indicator Library: explains every detection rule."""
    from app.services.risk_engine import indicator_catalog
    active_nav = "insights" if current_user.is_authenticated else ""
    return render_template("insights.html", indicators=indicator_catalog(),
                           active_nav=active_nav)


@main_bp.route("/methodology")
def methodology():
    """Transparent risk-scoring methodology (weights + rationale)."""
    from app.services.risk_engine import methodology_table
    active_nav = "methodology" if current_user.is_authenticated else ""
    return render_template("methodology.html", rows=methodology_table(),
                           active_nav=active_nav)


@main_bp.route("/integrity", methods=["GET", "POST"])
def integrity():
    """Educational SHA-256 integrity demonstration (hashing != encryption)."""
    demo = None
    if request.method == "POST":
        original = (request.form.get("original") or "").strip()
        modified = (request.form.get("modified") or "").strip()
        if not modified:
            # If no modified value is supplied, tamper with one character to
            # illustrate hash sensitivity.
            modified = (original + "X") if original else "X"
        demo = integrity_demo(original, modified)
    active_nav = "integrity" if current_user.is_authenticated else ""
    return render_template("integrity.html", demo=demo, user=current_user,
                           active_nav=active_nav)


@main_bp.route("/health")
def health():
    return {"status": "ok", "service": "PhishShield"}
