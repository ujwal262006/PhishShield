"""User dashboard routes and per-user statistics."""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template
from flask_login import current_user, login_required

from app.extensions import db
from app.models import (
    CLASS_CRITICAL,
    CLASS_HIGH,
    CLASS_SAFE,
    CLASS_SUSPICIOUS,
    Scan,
)
from app.utils.decorators import login_required_api

dashboard_bp = Blueprint("dashboard", __name__)


def _user_stats(user_id: int) -> dict:
    """Aggregate a user's scan stats with a single grouped SQL query."""
    rows = (
        db.session.query(Scan.classification, db.func.count(Scan.id),
                         db.func.coalesce(db.func.sum(Scan.risk_score), 0))
        .filter(Scan.user_id == user_id)
        .group_by(Scan.classification)
        .all()
    )
    counts = {CLASS_SAFE: 0, CLASS_SUSPICIOUS: 0, CLASS_HIGH: 0, CLASS_CRITICAL: 0}
    total = 0
    score_sum = 0
    for classification, count, subtotal in rows:
        total += count
        score_sum += int(subtotal or 0)
        if classification in counts:
            counts[classification] += count
    return {
        "total": total,
        "safe": counts[CLASS_SAFE],
        "suspicious": counts[CLASS_SUSPICIOUS],
        "high_risk": counts[CLASS_HIGH],
        "critical": counts[CLASS_CRITICAL],
        "avg_score": round(score_sum / total) if total else 0,
    }


@dashboard_bp.route("/dashboard")
@login_required
def user_dashboard():
    stats = _user_stats(current_user.id)
    recent = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(6)
        .all()
    )
    return render_template("dashboard.html", stats=stats, recent=recent,
                           avg_score=stats["avg_score"], active_nav="dashboard")


@dashboard_bp.route("/api/dashboard/stats")
@login_required_api
def api_dashboard_stats():
    return jsonify(_user_stats(current_user.id)), 200
