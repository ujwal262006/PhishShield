"""Unit tests for the risk-engine rules added during the upgrade."""
from app.services.risk_engine import (
    analyze_url,
    indicator_catalog,
    methodology_table,
    risk_breakdown,
    url_forensics,
    waterfall,
)
from app.services.url_analyzer import extract_features


# ---- New feature extraction ----
def test_userinfo_detected():
    f = extract_features("http://user:pass@evil.example.test/login")
    assert f["has_userinfo"] is True


def test_no_userinfo_on_plain_url():
    f = extract_features("https://example.com/path")
    assert f["has_userinfo"] is False


def test_suspicious_port_detected():
    f = extract_features("http://example.com:8080/login")
    assert f["suspicious_port"] is True


def test_standard_port_not_suspicious():
    f = extract_features("https://example.com")
    assert f["suspicious_port"] is False


def test_deep_path_depth():
    f = extract_features("http://example.com/a/b/c/d/e/f/g")
    assert f["path_depth"] >= 7


def test_repeated_separators_detected():
    f = extract_features("http://example.com/a//b/../c")
    assert f["repeated_separators"] is True


# ---- New rules contribute points ----
def test_userinfo_rule_flagged():
    result = analyze_url("http://user@evil.example.test/login")
    keys = {i["key"] for i in result["indicators"]}
    assert "userinfo" in keys


def test_suspicious_port_rule_flagged():
    result = analyze_url("http://example.com:8080/login")
    keys = {i["key"] for i in result["indicators"]}
    assert "suspicious_port" in keys


def test_safe_url_stays_safe_with_new_rules():
    # Regression guard: a clean URL must remain SAFE after adding rules.
    result = analyze_url("https://example.com")
    assert result["classification"] == "SAFE"
    assert result["score"] < 30


# ---- Report-support helpers ----
def test_risk_breakdown_categories():
    result = analyze_url("http://192.0.2.10/login-verify")
    rows = risk_breakdown(result["indicators"])
    cats = {r["category"] for r in rows}
    assert "Domain Analysis" in cats
    assert "Protocol Security" in cats
    for r in rows:
        assert 0 <= r["percent"] <= 100


def test_waterfall_totals_match_score():
    result = analyze_url("http://192.0.2.10/login-verify")
    wf = waterfall(result["indicators"])
    assert wf["clamped_total"] == result["score"]


def test_url_forensics_parses_components():
    fx = url_forensics("https://sub.example.com:8443/path/here?q=1#frag")
    assert fx["protocol"] == "https"
    assert fx["hostname"] == "sub.example.com"
    assert fx["port"] == 8443
    assert fx["path"] == "/path/here"
    assert fx["query"] == "q=1"
    assert fx["fragment"] == "frag"
    assert "sub" in fx["subdomains"]


def test_indicator_catalog_complete():
    catalog = indicator_catalog()
    assert len(catalog) >= 15
    for c in catalog:
        assert c["name"] and c["explanation"] and c["rationale"]
        assert c["severity"] in {"LOW", "MEDIUM", "HIGH"}


def test_methodology_table_sorted_desc():
    rows = methodology_table()
    weights = [r["weight"] for r in rows]
    assert weights == sorted(weights, reverse=True)
