"""Administrative routes: system stats, all scans, security events, users.

Every route is protected by the admin_required RBAC decorator.
"""
from __future__ import annotations

from collections import Counter

from flask import Blueprint, jsonify, render_template, request

from app.extensions import db
from app.models import (
    CLASS_CRITICAL,
    CLASS_HIGH,
    CLASS_SAFE,
    CLASS_SUSPICIOUS,
    Scan,
    SecurityEvent,
    User,
)
from app.utils.decorators import admin_required

admin_bp = Blueprint("admin", __name__)


def _system_stats() -> dict:
    scans = Scan.query.all()
    counts = {CLASS_SAFE: 0, CLASS_SUSPICIOUS: 0, CLASS_HIGH: 0, CLASS_CRITICAL: 0}
    indicator_counter: Counter = Counter()

    for scan in scans:
        if scan.classification in counts:
            counts[scan.classification] += 1
        for ind in scan.indicators:
            indicator_counter[ind.get("name", "Unknown")] += 1

    top_indicators = [
        {"name": name, "count": count}
        for name, count in indicator_counter.most_common(5)
    ]

    return {
        "total_scans": len(scans),
        "safe": counts[CLASS_SAFE],
        "suspicious": counts[CLASS_SUSPICIOUS],
        "high_risk": counts[CLASS_HIGH],
        "critical": counts[CLASS_CRITICAL],
        "total_users": User.query.count(),
        "top_indicators": top_indicators,
    }


# ---------------------------------------------------------------------------
# HTML routes
# ---------------------------------------------------------------------------
def _scans_over_time(days: int = 14) -> dict:
    """Return per-day scan counts for the last `days` days (SOC trend chart)."""
    from datetime import datetime, timedelta

    from app.utils.timeutil import utcnow

    today = utcnow().date()
    start = today - timedelta(days=days - 1)
    buckets = {(start + timedelta(days=i)).isoformat(): 0 for i in range(days)}

    recent = Scan.query.filter(Scan.created_at >= datetime(start.year, start.month, start.day)).all()
    for scan in recent:
        key = scan.created_at.date().isoformat()
        if key in buckets:
            buckets[key] += 1
    return {"labels": list(buckets.keys()), "counts": list(buckets.values())}


def _score_distribution() -> list[int]:
    """Histogram of risk scores in 10-point bins (0-9, ..., 90-100)."""
    bins = [0] * 10
    for scan in Scan.query.all():
        idx = min(scan.risk_score // 10, 9)
        bins[idx] += 1
    return bins


@admin_bp.route("/admin")
@admin_required
def admin_dashboard():
    stats = _system_stats()
    stats["total_events"] = SecurityEvent.query.count()
    recent_alerts = (
        Scan.query.filter(Scan.classification.in_([CLASS_HIGH, CLASS_CRITICAL]))
        .order_by(Scan.created_at.desc())
        .limit(8)
        .all()
    )
    return render_template("admin_dashboard.html", stats=stats,
                           recent_alerts=recent_alerts,
                           trend=_scans_over_time(),
                           score_dist=_score_distribution(),
                           active_nav="admin_dashboard")


@admin_bp.route("/admin/scans")
@admin_required
def admin_scans():
    page = request.args.get("page", 1, type=int)
    query_text = (request.args.get("q") or "").strip()
    classification = (request.args.get("classification") or "").strip()

    query = Scan.query
    if query_text:
        query = query.filter(Scan.url.ilike(f"%{query_text}%"))
    if classification:
        query = query.filter_by(classification=classification)

    pagination = query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )
    return render_template("admin_scans.html", pagination=pagination,
                           q=query_text, classification=classification,
                           active_nav="admin_scans")


@admin_bp.route("/admin/scans/export.csv")
@admin_required
def admin_scans_export():
    """Export scan records (optionally filtered) as CSV. No sensitive fields."""
    import csv
    import io

    from flask import Response, request

    query_text = (request.args.get("q") or "").strip()
    classification = (request.args.get("classification") or "").strip()
    query = Scan.query
    if query_text:
        query = query.filter(Scan.url.ilike(f"%{query_text}%"))
    if classification:
        query = query.filter_by(classification=classification)
    rows = query.order_by(Scan.created_at.desc()).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["scan_id", "user_id", "created_at", "url", "hostname",
                     "protocol", "risk_score", "classification"])
    for s in rows:
        writer.writerow([s.id, s.user_id, s.created_at.isoformat(), s.url,
                         s.hostname, s.protocol, s.risk_score, s.classification])
    return Response(
        buffer.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishshield_all_scans.csv"},
    )


@admin_bp.route("/admin/security-events")
@admin_required
def admin_security_events():
    page = request.args.get("page", 1, type=int)
    event_type = (request.args.get("event_type") or "").strip()

    query = SecurityEvent.query
    if event_type:
        query = query.filter_by(event_type=event_type)

    pagination = query.order_by(SecurityEvent.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template("admin_events.html", pagination=pagination,
                           event_type=event_type, active_nav="admin_events")


@admin_bp.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.asc()).all()
    return render_template("admin_users.html", users=users, active_nav="admin_users")


@admin_bp.route("/admin/system-health")
@admin_required
def system_health():
    health = _system_health()
    return render_template("system_health.html", health=health,
                           active_nav="admin_health")


def _system_health() -> dict:
    """Collect non-sensitive operational status for the health page."""
    import os
    import platform
    import sys

    from flask import current_app

    from app.version import PHISHSHIELD_VERSION

    # Database connectivity check.
    db_status = "connected"
    db_size_kb = None
    try:
        db.session.execute(db.text("SELECT 1"))
        uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
        if uri.startswith("sqlite:///") and ":memory:" not in uri:
            path = uri.replace("sqlite:///", "")
            if os.path.exists(path):
                db_size_kb = round(os.path.getsize(path) / 1024, 1)
    except Exception:  # noqa: BLE001 - health check must never crash the page
        db_status = "error"

    return {
        "app_status": "online",
        "db_status": db_status,
        "db_size_kb": db_size_kb,
        "environment": current_app.config.get("ENV")
        or os.environ.get("FLASK_ENV", "development"),
        "debug": bool(current_app.debug),
        "python_version": platform.python_version(),
        "flask_version": _pkg_version("flask"),
        "app_version": PHISHSHIELD_VERSION,
        "total_users": User.query.count(),
        "total_scans": Scan.query.count(),
        "total_events": SecurityEvent.query.count(),
        "rate_limiting": current_app.config.get("RATELIMIT_ENABLED", True),
    }


def _pkg_version(name: str) -> str:
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------------------
# Admin user-management actions
# ---------------------------------------------------------------------------
@admin_bp.route("/admin/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_user_active(user_id: int):
    from flask import flash, redirect, url_for
    from flask_login import current_user

    from app.utils.security_logger import log_event

    user = db.session.get(User, user_id)
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for("admin.admin_users"))
    if user.id == current_user.id:
        flash("You cannot change your own account status.", "warning")
        return redirect(url_for("admin.admin_users"))

    user.is_active = not user.is_active
    db.session.commit()
    state = "activated" if user.is_active else "deactivated"
    log_event("USER_STATUS_CHANGED", user_id=current_user.id,
              description=f"Admin {state} user '{user.username}'.",
              metadata={"target_user_id": user.id, "state": state})
    flash(f"User '{user.username}' {state}.", "success")
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_user_role(user_id: int):
    from flask import flash, redirect, request, url_for
    from flask_login import current_user

    from app.models import VALID_ROLES
    from app.utils.security_logger import log_event

    user = db.session.get(User, user_id)
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for("admin.admin_users"))
    if user.id == current_user.id:
        flash("You cannot change your own role.", "warning")
        return redirect(url_for("admin.admin_users"))

    new_role = (request.form.get("role") or "").strip().upper()
    if new_role not in VALID_ROLES:
        flash("Invalid role.", "danger")
        return redirect(url_for("admin.admin_users"))

    old_role = user.role
    user.role = new_role
    db.session.commit()
    log_event("USER_ROLE_CHANGED", user_id=current_user.id,
              description=f"Admin changed role of '{user.username}' "
                          f"from {old_role} to {new_role}.",
              metadata={"target_user_id": user.id, "new_role": new_role})
    flash(f"Role for '{user.username}' updated to {new_role}.", "success")
    return redirect(url_for("admin.admin_users"))


# ---------------------------------------------------------------------------
# JSON API routes
# ---------------------------------------------------------------------------
@admin_bp.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    return jsonify(_system_stats()), 200


@admin_bp.route("/api/admin/users")
@admin_required
def api_admin_users():
    users = User.query.order_by(User.created_at.asc()).all()
    return jsonify({"users": [u.to_dict() for u in users]}), 200


@admin_bp.route("/api/admin/scans")
@admin_required
def api_admin_scans():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return jsonify({"scans": [s.to_dict() for s in scans]}), 200


@admin_bp.route("/api/admin/security-events")
@admin_required
def api_admin_events():
    events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).all()
    return jsonify({"events": [e.to_dict() for e in events]}), 200
