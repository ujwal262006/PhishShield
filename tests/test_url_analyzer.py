"""Unit tests for URL validation and feature extraction."""
import pytest

from app.services.url_analyzer import (
    URLValidationError,
    extract_features,
    validate_url,
)


# ---- Validation ----
def test_validate_accepts_https():
    assert validate_url("https://example.com") == "https://example.com"


def test_validate_strips_whitespace():
    assert validate_url("  https://example.com  ") == "https://example.com"


def test_validate_rejects_empty():
    with pytest.raises(URLValidationError):
        validate_url("")


def test_validate_rejects_none():
    with pytest.raises(URLValidationError):
        validate_url(None)


def test_validate_rejects_missing_scheme():
    with pytest.raises(URLValidationError):
        validate_url("example.com/login")


def test_validate_rejects_unsupported_scheme():
    with pytest.raises(URLValidationError):
        validate_url("ftp://example.com")


def test_validate_rejects_too_long():
    with pytest.raises(URLValidationError):
        validate_url("https://example.com/" + "a" * 3000)


def test_validate_rejects_no_host():
    with pytest.raises(URLValidationError):
        validate_url("https://")


# ---- Feature extraction ----
def test_https_detection():
    f = extract_features("https://example.com")
    assert f["uses_https"] is True
    assert f["protocol"] == "https"


def test_http_detection():
    f = extract_features("http://example.com")
    assert f["uses_https"] is False


def test_ip_hostname_detection():
    f = extract_features("http://192.0.2.10/login")
    assert f["is_ip_hostname"] is True


def test_domain_hostname_not_ip():
    f = extract_features("https://example.com")
    assert f["is_ip_hostname"] is False


def test_suspicious_keyword_detection():
    f = extract_features("http://example.com/login/verify")
    assert "login" in f["keyword_hits"]
    assert "verify" in f["keyword_hits"]
    assert f["keyword_count"] >= 2


def test_subdomain_count():
    f = extract_features("http://a.b.c.example.com")
    assert f["subdomain_count"] >= 2


def test_url_length():
    url = "https://example.com/" + "x" * 100
    f = extract_features(url)
    assert f["url_length"] == len(url)


def test_at_symbol_detection():
    f = extract_features("http://user@evil.example.test")
    assert f["has_at_symbol"] is True


def test_special_character_count():
    f = extract_features("http://example.com/a?b=1&c=2")
    assert f["special_char_count"] >= 0


def test_punycode_detection():
    f = extract_features("http://xn--e1afmkfd.example.test/login")
    assert f["is_punycode"] is True


def test_suspicious_tld_detection():
    f = extract_features("http://example.zip/login")
    assert f["is_suspicious_tld"] is True


def test_parameter_count():
    f = extract_features("http://example.com/?a=1&b=2&c=3")
    assert f["param_count"] == 3
