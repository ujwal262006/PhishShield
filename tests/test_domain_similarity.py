"""Unit tests for domain similarity / typosquatting and SHA-256 integrity."""
from app.services.domain_similarity import (
    check_typosquatting,
    levenshtein_distance,
    normalized_similarity,
)
from app.services.integrity import integrity_demo, sha256_hash, verify_integrity


# ---- Levenshtein ----
def test_levenshtein_identical():
    assert levenshtein_distance("google", "google") == 0


def test_levenshtein_single_edit():
    assert levenshtein_distance("google", "g00gle") == 2


def test_normalized_similarity_range():
    score = normalized_similarity("google.com", "g00gle.com")
    assert 0.0 <= score <= 1.0


# ---- Typosquatting ----
def test_exact_trusted_domain_not_flagged():
    result = check_typosquatting("google.com")
    assert result["is_typosquat"] is False
    assert result["exact_trusted"] is True


def test_lookalike_flagged():
    result = check_typosquatting("g00gle.com")
    assert result["is_typosquat"] is True
    assert result["matched_domain"] == "google.com"


def test_unrelated_domain_not_flagged():
    result = check_typosquatting("totally-different-site.test")
    assert result["is_typosquat"] is False


def test_subdomain_uses_registrable_part():
    # www prefix and subdomains should not defeat the comparison.
    result = check_typosquatting("www.paypa1.com")
    assert result["matched_domain"] == "paypal.com"


# ---- SHA-256 integrity ----
def test_sha256_length():
    assert len(sha256_hash("hello")) == 64


def test_sha256_deterministic():
    assert sha256_hash("abc") == sha256_hash("abc")


def test_sha256_changes_with_input():
    assert sha256_hash("abc") != sha256_hash("abd")


def test_verify_integrity():
    h = sha256_hash("phishshield")
    assert verify_integrity("phishshield", h) is True
    assert verify_integrity("PhishShield", h) is False


def test_integrity_demo_detects_change():
    demo = integrity_demo("https://example.com", "https://example.org")
    assert demo["changed"] is True
    assert demo["algorithm"] == "SHA-256"
