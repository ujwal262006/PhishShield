"""User account settings: profile, password change, theme, session info."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import SecurityEvent
from app.utils.security_logger import log_event
from app.utils.validators import validate_password

settings_bp = Blueprint("settings", __name__)

EVENT_PASSWORD_CHANGE = "PASSWORD_CHANGED"


@settings_bp.route("/settings")
@login_required
def settings_page():
    # Recent security events for this user (session/activity context).
    recent_events = (
        SecurityEvent.query.filter_by(user_id=current_user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(8)
        .all()
    )
    return render_template("settings.html", active_nav="settings",
                           recent_events=recent_events)


@settings_bp.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""

    if not current_user.check_password(current):
        flash("Your current password is incorrect.", "danger")
        return redirect(url_for("settings.settings_page"))

    error = validate_password(new)
    if error:
        flash(error, "danger")
        return redirect(url_for("settings.settings_page"))

    if new != confirm:
        flash("The new passwords do not match.", "danger")
        return redirect(url_for("settings.settings_page"))

    if current_user.check_password(new):
        flash("The new password must be different from the current one.", "warning")
        return redirect(url_for("settings.settings_page"))

    current_user.set_password(new)
    db.session.commit()
    # Log the change WITHOUT any password material.
    log_event(EVENT_PASSWORD_CHANGE, user_id=current_user.id,
              description="Password changed via settings.")
    flash("Password changed successfully.", "success")
    return redirect(url_for("settings.settings_page"))
