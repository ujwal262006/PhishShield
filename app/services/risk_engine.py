"""Explainable, rule-based risk engine.

Pipeline:
    analyze_url(url)
      -> validate_url()
      -> extract_features()
      -> evaluate_rules(features)         # build indicator list + points
      -> calculate_score() / normalize()  # sum, cap keywords, clamp 0-100
      -> classify_risk()
      -> generate_explanation()
      -> return result dict

This module is intentionally independent of Flask so it can be unit-tested on
its own. It performs no network activity.
"""
from __future__ import annotations

from app.services import scoring_config as cfg
from app.services.domain_similarity import check_typosquatting
from app.services.integrity import sha256_hash
from app.services.url_analyzer import extract_features, validate_url


def _indicator(key: str, points: int, severity: str, extra: str = "") -> dict:
    """Build a single indicator entry with its explanation."""
    explanation = cfg.EXPLANATIONS.get(key, "")
    if extra:
        explanation = f"{explanation} {extra}".strip()
    return {
        "key": key,
        "name": _INDICATOR_NAMES.get(key, key),
        "severity": severity,
        "points": points,
        "explanation": explanation,
    }


_INDICATOR_NAMES = {
    "no_https": "Insecure Protocol (no HTTPS)",
    "ip_hostname": "IP Address Used as Hostname",
    "suspicious_keyword": "Suspicious Keyword(s)",
    "excessive_subdomains": "Excessive Subdomains",
    "long_url": "Unusually Long URL",
    "suspicious_tld": "Suspicious Top-Level Domain",
    "at_symbol": "'@' Symbol in URL",
    "excessive_hyphens": "Excessive Hyphens in Hostname",
    "suspicious_path": "Suspicious Path Pattern",
    "url_encoding": "URL Encoding / Obfuscation",
    "punycode": "Punycode / IDN Hostname",
    "typosquatting": "Possible Typosquatting",
    "special_characters": "Excessive Special Characters",
    "long_domain": "Unusually Long Domain",
    "many_parameters": "Many Query Parameters",
    "userinfo": "Userinfo Component in URL",
    "suspicious_port": "Non-standard Network Port",
    "deep_path": "Unusually Deep URL Path",
    "repeated_separators": "Repeated / Traversal Separators",
}


# Why an attacker might use each indicator, and the defender's guidance.
# Used by the Security Insights and Risk Methodology pages.
_INDICATOR_RATIONALE = {
    "no_https": "Attackers may skip HTTPS on quickly-built phishing pages, or rely "
                "on users not noticing the missing padlock.",
    "ip_hostname": "A raw IP hides the absence of a real, registered brand domain.",
    "suspicious_keyword": "Words like 'verify' or 'login' lend a fake page false "
                          "legitimacy and urgency.",
    "excessive_subdomains": "Long subdomain chains bury a trusted-looking name in "
                            "front of an untrusted registrable domain.",
    "long_url": "Length hides the true destination and discourages careful reading.",
    "suspicious_tld": "Low-cost or abuse-prone TLDs are popular for disposable "
                      "phishing infrastructure.",
    "at_symbol": "Everything before '@' is user-info; the real host is what follows, "
                 "so '@' can disguise the destination.",
    "excessive_hyphens": "Hyphenated look-alikes (secure-login-bank) imitate brands.",
    "suspicious_path": "Certain paths mimic admin/login endpoints or hint at hosted "
                       "executables.",
    "url_encoding": "Percent-encoding can obscure the true characters of a link.",
    "punycode": "IDN/punycode hostnames can render as look-alike Unicode brand names.",
    "typosquatting": "Look-alike domains rely on a glance mistaking them for the real "
                     "brand.",
    "special_characters": "Unusual character density often signals obfuscation.",
    "long_domain": "Overlong hostnames can smuggle a brand name into an untrusted domain.",
    "many_parameters": "Many parameters can carry redirect targets or tracking payloads.",
    "userinfo": "Text before '@' is user-info; attackers use it so the link looks "
                "like a trusted site while the real host is what follows.",
    "suspicious_port": "Unusual ports can point to ad-hoc servers rather than a "
                       "legitimate public website.",
    "deep_path": "Deep paths can bury a fake page beneath convincing-looking folders.",
    "repeated_separators": "Repeated or traversal separators are a classic "
                           "obfuscation and path-manipulation signal.",
}


def indicator_catalog() -> list[dict]:
    """Return the full list of detection rules for the Insights page."""
    catalog = []
    for key, name in _INDICATOR_NAMES.items():
        points, severity = cfg.WEIGHTS[key]
        catalog.append({
            "key": key,
            "name": name,
            "severity": severity,
            "points": points,
            "explanation": cfg.EXPLANATIONS.get(key, ""),
            "rationale": _INDICATOR_RATIONALE.get(key, ""),
        })
    # Sort HIGH severity first for a stronger presentation.
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(catalog, key=lambda c: (order.get(c["severity"], 3), -c["points"]))


def methodology_table() -> list[dict]:
    """Rows for the Risk Methodology page: feature, weight, reason, max."""
    rows = []
    for key, name in _INDICATOR_NAMES.items():
        points, severity = cfg.WEIGHTS[key]
        max_contribution = cfg.MAX_KEYWORD_POINTS if key == "suspicious_keyword" else points
        rows.append({
            "name": name,
            "weight": points,
            "severity": severity,
            "reason": _INDICATOR_RATIONALE.get(key, ""),
            "max": max_contribution,
        })
    return sorted(rows, key=lambda r: -r["weight"])


# Maps each indicator to a risk "category" used by the result-page breakdown bars.
_CATEGORY_OF = {
    "ip_hostname": "Domain Analysis",
    "typosquatting": "Domain Analysis",
    "punycode": "Domain Analysis",
    "long_domain": "Domain Analysis",
    "suspicious_tld": "Domain Analysis",
    "no_https": "Protocol Security",
    "url_encoding": "URL Structure",
    "long_url": "URL Structure",
    "many_parameters": "URL Structure",
    "special_characters": "URL Structure",
    "at_symbol": "URL Structure",
    "excessive_subdomains": "URL Structure",
    "excessive_hyphens": "URL Structure",
    "suspicious_path": "Suspicious Indicators",
    "suspicious_keyword": "Suspicious Indicators",
    "userinfo": "URL Structure",
    "suspicious_port": "URL Structure",
    "deep_path": "URL Structure",
    "repeated_separators": "URL Structure",
}

# Max points reasonably attributable to each category (for a 0-100% bar).
_CATEGORY_MAX = {
    "Domain Analysis": 40,
    "Protocol Security": 15,
    "URL Structure": 40,
    "Suspicious Indicators": 25,
}


def risk_breakdown(indicators: list[dict]) -> list[dict]:
    """Aggregate indicator points into category percentages for visualization.

    Percentages are clearly-labelled *normalized visualization values*, not
    probabilities. They show how much each category contributed relative to a
    sensible per-category maximum.
    """
    totals: dict[str, int] = {c: 0 for c in _CATEGORY_MAX}
    for ind in indicators:
        cat = _CATEGORY_OF.get(ind.get("key"), "Suspicious Indicators")
        totals[cat] += ind.get("points", 0)
    rows = []
    for cat, maximum in _CATEGORY_MAX.items():
        pct = min(100, round((totals[cat] / maximum) * 100)) if maximum else 0
        rows.append({"category": cat, "points": totals[cat], "percent": pct})
    return rows


def waterfall(indicators: list[dict]) -> dict:
    """Build a waterfall of point contributions plus the clamped total."""
    steps = [{"name": i["name"], "points": i["points"]} for i in indicators]
    raw_total = sum(i["points"] for i in indicators)
    return {"steps": steps, "raw_total": raw_total,
            "clamped_total": max(0, min(100, raw_total))}


def url_forensics(url: str) -> dict:
    """Parse a URL into its components for the forensics view (no network)."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    labels = [p for p in hostname.split(".") if p]
    subdomains = labels[:-2] if len(labels) > 2 else []
    return {
        "protocol": parsed.scheme or "",
        "hostname": hostname,
        "port": parsed.port,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "subdomains": subdomains,
        "domain_length": len(hostname),
        "url_length": len(url),
    }


def evaluate_rules(features: dict) -> list[dict]:
    """Turn extracted features into a list of scored indicators."""
    indicators: list[dict] = []

    def add(key: str, extra: str = ""):
        points, severity = cfg.WEIGHTS[key]
        indicators.append(_indicator(key, points, severity, extra))

    if not features["uses_https"]:
        add("no_https")

    if features["is_ip_hostname"]:
        add("ip_hostname")

    # Suspicious keywords: one indicator, points scaled by count but capped.
    if features["keyword_count"] > 0:
        per_hit, severity = cfg.WEIGHTS["suspicious_keyword"]
        raw = per_hit * features["keyword_count"]
        capped = min(raw, cfg.MAX_KEYWORD_POINTS)
        found = ", ".join(features["keyword_hits"])
        indicators.append(
            _indicator(
                "suspicious_keyword",
                capped,
                severity,
                extra=f"Detected term(s): {found}.",
            )
        )

    if features["subdomain_count"] > cfg.MAX_SUBDOMAINS:
        add("excessive_subdomains")

    if features["url_length"] > cfg.LONG_URL_THRESHOLD:
        add("long_url")

    if features["is_suspicious_tld"]:
        add("suspicious_tld", extra=f"TLD: .{features['tld']}.")

    if features["has_at_symbol"]:
        add("at_symbol")

    if features["hyphen_count"] > cfg.MAX_HYPHENS:
        add("excessive_hyphens")

    if features["path_pattern_hits"]:
        found = ", ".join(features["path_pattern_hits"])
        points, severity = cfg.WEIGHTS["suspicious_path"]
        indicators.append(
            _indicator("suspicious_path", points, severity,
                       extra=f"Pattern(s): {found}.")
        )

    if features["has_url_encoding"]:
        add("url_encoding")

    if features["is_punycode"]:
        add("punycode")

    if features["special_char_count"] > cfg.SPECIAL_CHAR_THRESHOLD:
        add("special_characters")

    if features["domain_length"] > cfg.LONG_DOMAIN_THRESHOLD:
        add("long_domain")

    if features["param_count"] > cfg.MANY_PARAMETERS_THRESHOLD:
        add("many_parameters")

    if features.get("has_userinfo"):
        add("userinfo")

    if features.get("suspicious_port"):
        add("suspicious_port",
            extra=f"Port {features.get('port')}.")

    if features.get("path_depth", 0) > cfg.DEEP_PATH_THRESHOLD:
        add("deep_path")

    if features.get("repeated_separators"):
        add("repeated_separators")

    # Typosquatting check (skip if the host is a raw IP).
    if not features["is_ip_hostname"] and features["hostname"]:
        result = check_typosquatting(features["hostname"])
        if result["is_typosquat"]:
            points, severity = cfg.WEIGHTS["typosquatting"]
            indicators.append(
                _indicator(
                    "typosquatting",
                    points,
                    severity,
                    extra=(
                        f"Resembles '{result['matched_domain']}' "
                        f"(similarity {result['similarity']})."
                    ),
                )
            )

    return indicators


def calculate_score(indicators: list[dict]) -> int:
    """Sum indicator points and clamp to the 0-100 range."""
    total = sum(item["points"] for item in indicators)
    return max(0, min(100, total))


def classify_risk(score: int) -> str:
    """Map a 0-100 score to a classification band."""
    for lower_bound, label in cfg.CLASSIFICATION_BANDS:
        if score >= lower_bound:
            return label
    return "SAFE"


def generate_recommendation(classification: str) -> str:
    return cfg.RECOMMENDATIONS.get(classification, cfg.RECOMMENDATIONS["SUSPICIOUS"])


def build_scan(user_id: int, result: dict):
    """Build (but do not persist) a Scan model from an analyze_url() result.

    Shared by the scan route and the seed script to avoid duplicated mapping
    logic. Import is local to keep this service Flask/model independent when
    imported for pure analysis.
    """
    from app.models import Scan

    scan = Scan(
        user_id=user_id,
        url=result["url"],
        hostname=result["hostname"],
        protocol=result["protocol"],
        risk_score=result["score"],
        classification=result["classification"],
        recommendation=result["recommendation"],
        integrity_hash=result["integrity_hash"],
    )
    scan.indicators = result["indicators"]
    return scan


def analyze_url(url: str) -> dict:
    """Full analysis pipeline. Raises URLValidationError on invalid input."""
    cleaned = validate_url(url)
    features = extract_features(cleaned)
    indicators = evaluate_rules(features)
    score = calculate_score(indicators)
    classification = classify_risk(score)
    recommendation = generate_recommendation(classification)

    # Educational integrity hash of the normalized URL.
    integrity = sha256_hash(cleaned)

    # Sort indicators by severity (HIGH first) then points for display.
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    indicators_sorted = sorted(
        indicators,
        key=lambda i: (severity_rank.get(i["severity"], 3), -i["points"]),
    )

    return {
        "url": cleaned,
        "hostname": features["hostname"],
        "protocol": features["protocol"],
        "score": score,
        "classification": classification,
        "indicators": indicators_sorted,
        "recommendation": recommendation,
        "integrity_hash": integrity,
        "features": features,
    }
