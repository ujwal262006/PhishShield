"""Unit tests for the risk engine: scoring, classification, explanations."""
from app.services.risk_engine import (
    analyze_url,
    calculate_score,
    classify_risk,
    evaluate_rules,
)
from app.services.url_analyzer import extract_features


# ---- Classification bands ----
def test_classify_safe():
    assert classify_risk(0) == "SAFE"
    assert classify_risk(29) == "SAFE"


def test_classify_suspicious():
    assert classify_risk(30) == "SUSPICIOUS"
    assert classify_risk(59) == "SUSPICIOUS"


def test_classify_high():
    assert classify_risk(60) == "HIGH RISK"
    assert classify_risk(79) == "HIGH RISK"


def test_classify_critical():
    assert classify_risk(80) == "CRITICAL"
    assert classify_risk(100) == "CRITICAL"


# ---- Score normalization ----
def test_score_clamped_to_100():
    fake_indicators = [{"points": 60}, {"points": 60}, {"points": 60}]
    assert calculate_score(fake_indicators) == 100


def test_score_never_negative():
    assert calculate_score([]) == 0


# ---- Rule evaluation ----
def test_https_url_is_low_risk():
    result = analyze_url("https://example.com")
    assert result["classification"] == "SAFE"
    assert result["score"] < 30


def test_ip_and_keywords_raise_score():
    result = analyze_url("http://192.0.2.10/login/verify/account")
    assert result["score"] > 30
    keys = {i["key"] for i in result["indicators"]}
    assert "ip_hostname" in keys
    assert "no_https" in keys
    assert "suspicious_keyword" in keys


def test_keyword_points_are_capped():
    # Many keywords should not exceed the configured cap.
    features = extract_features(
        "http://example.com/login/verify/account/secure/update/confirm/password"
    )
    indicators = evaluate_rules(features)
    kw = next(i for i in indicators if i["key"] == "suspicious_keyword")
    assert kw["points"] <= 15


def test_indicators_have_explanations():
    result = analyze_url("http://192.0.2.10/login")
    for ind in result["indicators"]:
        assert ind["explanation"]
        assert ind["severity"] in {"LOW", "MEDIUM", "HIGH"}
        assert isinstance(ind["points"], int)


def test_result_contains_recommendation_and_hash():
    result = analyze_url("https://example.com")
    assert result["recommendation"]
    assert len(result["integrity_hash"]) == 64  # SHA-256 hex length


def test_at_symbol_flagged():
    result = analyze_url("http://user@evil.example.test/login")
    keys = {i["key"] for i in result["indicators"]}
    assert "at_symbol" in keys


def test_critical_url_classification():
    # A URL packed with high-severity indicators should reach HIGH/CRITICAL.
    result = analyze_url(
        "http://user@192.0.2.10/login-verify-secure-account-update/confirm.php"
    )
    assert result["score"] >= 60
    assert result["classification"] in {"HIGH RISK", "CRITICAL"}
