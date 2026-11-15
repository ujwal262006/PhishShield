"""Scan routes: URL scanner UI, scan history, and JSON scan API."""
from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.models import (
    CLASS_CRITICAL,
    CLASS_HIGH,
    EVENT_CRITICAL_RISK,
    EVENT_HIGH_RISK,
    EVENT_SCAN,
    ROLE_ADMIN,
    Scan,
)
from app.services.risk_engine import (
    analyze_url,
    build_scan,
    risk_breakdown,
    url_forensics,
    waterfall,
)
from app.services.url_analyzer import URLValidationError
from app.utils.decorators import login_required_api
from app.utils.rate_limit import rate_limit
from app.utils.security_logger import log_event
from app.utils.validators import clamp_page, clean_search

scan_bp = Blueprint("scan", __name__)


def _scan_limit(view):
    return rate_limit("scan", 30, 60)(view)


def _persist_scan(url: str) -> Scan:
    """Run analysis, store the result, and log security events.

    All database writes (the scan row plus its security events) are committed in
    a single transaction so a scan costs one commit rather than several.
    """
    result = analyze_url(url)  # raises URLValidationError on bad input

    scan = build_scan(current_user.id, result)
    db.session.add(scan)

    log_event(EVENT_SCAN, user_id=current_user.id,
              description=f"Scanned {result['hostname']}",
              metadata={"classification": result["classification"],
                        "score": result["score"]},
              commit=False)

    if result["classification"] == CLASS_CRITICAL:
        log_event(EVENT_CRITICAL_RISK, user_id=current_user.id,
                  description=f"Critical-risk URL detected: {result['hostname']}",
                  metadata={"score": result["score"]}, commit=False)
    elif result["classification"] == CLASS_HIGH:
        log_event(EVENT_HIGH_RISK, user_id=current_user.id,
                  description=f"High-risk URL detected: {result['hostname']}",
                  metadata={"score": result["score"]}, commit=False)

    db.session.commit()
    return scan


# ---------------------------------------------------------------------------
# HTML routes
# ---------------------------------------------------------------------------
def _result_context(scan: Scan) -> dict:
    """Build the rich context for the professional result/report page."""
    indicators = scan.indicators
    return {
        "scan": scan,
        "breakdown": risk_breakdown(indicators),
        "waterfall": waterfall(indicators),
        "forensics": url_forensics(scan.url),
        "active_nav": "scanner",
    }


def _recent_scans(limit: int = 5):
    return (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )


@scan_bp.route("/scan", methods=["GET", "POST"])
@login_required
@_scan_limit
def scanner():
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            scan = _persist_scan(url)
        except URLValidationError as exc:
            flash(str(exc), "danger")
            return render_template("scanner.html", submitted=url,
                                   recent=_recent_scans(), active_nav="scanner")
        return render_template("result.html", **_result_context(scan))
    return render_template("scanner.html", recent=_recent_scans(),
                           active_nav="scanner")


@scan_bp.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)
    # Users may only view their own scans; admins may view any.
    if scan.user_id != current_user.id and current_user.role != ROLE_ADMIN:
        abort(403)
    return render_template("result.html", **_result_context(scan))


@scan_bp.route("/history")
@login_required
def history():
    page = clamp_page(request.args.get("page"))
    query_text = clean_search(request.args.get("q"))
    classification = clean_search(request.args.get("classification"))
    min_score = request.args.get("min_score", type=int)
    sort = (request.args.get("sort") or "newest").strip()

    query = Scan.query.filter_by(user_id=current_user.id)
    if query_text:
        query = query.filter(Scan.url.ilike(f"%{query_text}%"))
    if classification:
        query = query.filter_by(classification=classification)
    if min_score is not None:
        min_score = max(0, min(100, min_score))
        query = query.filter(Scan.risk_score >= min_score)

    sort_map = {
        "newest": Scan.created_at.desc(),
        "oldest": Scan.created_at.asc(),
        "score_high": Scan.risk_score.desc(),
        "score_low": Scan.risk_score.asc(),
    }
    query = query.order_by(sort_map.get(sort, Scan.created_at.desc()))

    pagination = query.paginate(page=page, per_page=10, error_out=False)
    return render_template("history.html", pagination=pagination,
                           q=query_text, classification=classification,
                           min_score=min_score or "", sort=sort,
                           active_nav="history")


# ---------------------------------------------------------------------------
# JSON API routes
# ---------------------------------------------------------------------------
@scan_bp.route("/api/scan", methods=["POST"])
@login_required_api
@_scan_limit
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    try:
        scan = _persist_scan(url)
    except URLValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(scan.to_dict()), 201


@scan_bp.route("/api/scans", methods=["GET"])
@login_required_api
def api_scans():
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return jsonify({"scans": [s.to_dict() for s in scans]}), 200


@scan_bp.route("/api/scans/<int:scan_id>", methods=["GET"])
@login_required_api
def api_scan_detail(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404
    if scan.user_id != current_user.id and current_user.role != ROLE_ADMIN:
        return jsonify({"error": "Forbidden."}), 403
    return jsonify(scan.to_dict()), 200


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------
@scan_bp.route("/scan/<int:scan_id>/export.json")
@login_required
def export_json(scan_id: int):
    """Download a single scan report as JSON (ownership enforced)."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)
    if scan.user_id != current_user.id and current_user.role != ROLE_ADMIN:
        abort(403)
    payload = jsonify(scan.to_dict())
    payload.headers["Content-Disposition"] = (
        f"attachment; filename=phishshield_scan_{scan.id}.json"
    )
    return payload


# Clearly-labelled synthetic demo URLs (reserved/documentation domains only).
_DEMO_URLS = [
    "https://example.com",                                              # SAFE
    "http://example.com/login",                                         # SUSPICIOUS
    "http://192.0.2.10/login-verify",                                   # HIGH
    "http://user@192.0.2.10/login-verify-secure-account-update/confirm.php",  # CRITICAL
]


@scan_bp.route("/demo", methods=["POST"])
@login_required
def demo_mode():
    """Populate the current user's history with labelled synthetic examples.

    For faculty presentation only. Uses reserved/documentation domains; performs
    no network activity.
    """
    created = 0
    for url in _DEMO_URLS:
        try:
            _persist_scan(url)
            created += 1
        except URLValidationError:
            continue
    flash(f"Demo mode: created {created} synthetic example scans.", "success")
    return redirect(url_for("scan.history"))


@scan_bp.route("/compare")
@login_required
def compare():
    """Compare two scans: score/classification diff and indicator changes."""
    a_id = request.args.get("a", type=int)
    b_id = request.args.get("b", type=int)

    def _load(scan_id):
        if scan_id is None:
            return None
        s = db.session.get(Scan, scan_id)
        if s is None:
            return None
        if s.user_id != current_user.id and current_user.role != ROLE_ADMIN:
            abort(403)
        return s

    scan_a = _load(a_id)
    scan_b = _load(b_id)

    # Options for the selection dropdowns (the user's own scans).
    options = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
    )

    diff = None
    if scan_a and scan_b:
        a_keys = {i["key"]: i for i in scan_a.indicators}
        b_keys = {i["key"]: i for i in scan_b.indicators}
        added = [b_keys[k] for k in b_keys if k not in a_keys]
        removed = [a_keys[k] for k in a_keys if k not in b_keys]
        shared = [k for k in a_keys if k in b_keys]
        diff = {
            "score_delta": scan_b.risk_score - scan_a.risk_score,
            "class_changed": scan_a.classification != scan_b.classification,
            "added": added,
            "removed": removed,
            "shared": [a_keys[k] for k in shared],
        }

    return render_template("compare.html", scan_a=scan_a, scan_b=scan_b,
                           options=options, diff=diff, active_nav="history")


@scan_bp.route("/history/export.csv")
@login_required
def export_history_csv():
    """Download the current user's scan history as CSV (no sensitive fields)."""
    import csv
    import io

    from flask import Response

    rows = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["scan_id", "created_at", "url", "hostname", "protocol",
                     "risk_score", "classification", "integrity_hash"])
    for s in rows:
        writer.writerow([s.id, s.created_at.isoformat(), s.url, s.hostname,
                         s.protocol, s.risk_score, s.classification,
                         s.integrity_hash])
    return Response(
        buffer.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishshield_history.csv"},
    )
