"""URL validation and feature extraction.

This module analyzes the URL *string* only. It never fetches, visits, or
executes the target. All detection is based on parsing and pattern matching.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlparse

from app.services import scoring_config as cfg

MAX_URL_LENGTH = 2048
SUPPORTED_SCHEMES = {"http", "https"}

# A permissive URL shape check; deeper validation happens in validate_url().
_URL_SHAPE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.IGNORECASE)
_SPECIAL_CHARS = set("!$%^*()[]{}|\\;:'\"<>,`~ ")


class URLValidationError(ValueError):
    """Raised when a submitted URL cannot be analyzed."""


def validate_url(url: str) -> str:
    """Validate and normalize a submitted URL string.

    Raises URLValidationError with a user-friendly message on invalid input.
    Returns the cleaned URL on success.
    """
    if url is None:
        raise URLValidationError("No URL was provided.")

    cleaned = url.strip()
    if not cleaned:
        raise URLValidationError("The URL is empty.")

    if len(cleaned) > MAX_URL_LENGTH:
        raise URLValidationError(
            f"The URL is too long (max {MAX_URL_LENGTH} characters)."
        )

    if not _URL_SHAPE.match(cleaned):
        raise URLValidationError(
            "The URL must start with a scheme such as http:// or https://."
        )

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
        raise URLValidationError(
            "Only http and https URLs are supported for analysis."
        )
    if not parsed.hostname:
        raise URLValidationError("The URL does not contain a valid hostname.")

    return cleaned


def _is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _count_subdomains(hostname: str) -> int:
    """Number of subdomain labels (excluding the registrable domain + TLD)."""
    host = hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    labels = [p for p in host.split(".") if p]
    # Registrable domain is assumed to be the last two labels.
    return max(0, len(labels) - 2)


def _is_punycode(hostname: str) -> bool:
    return "xn--" in (hostname or "").lower()


def extract_features(url: str) -> dict:
    """Extract security-relevant features from a validated URL string.

    Returns a flat dict of features consumed by the risk engine. This function
    performs NO network activity.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    decoded_url = unquote(url)

    keyword_hits = sorted(
        {kw for kw in cfg.SUSPICIOUS_KEYWORDS if kw in url.lower()}
    )

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    path_hits = sorted(
        {p for p in cfg.SUSPICIOUS_PATH_PATTERNS if p in url.lower()}
    )

    special_char_count = sum(1 for ch in url if ch in _SPECIAL_CHARS)
    param_count = len(parse_qs(query)) if query else 0

    # Userinfo component (user:pass@host) — often used to disguise the real host.
    has_userinfo = bool(parsed.username)
    # Non-standard port for the scheme can indicate an unusual service endpoint.
    default_port = 443 if scheme == "https" else 80
    port = parsed.port
    suspicious_port = port is not None and port != default_port
    # Deep path (many segments) is sometimes used to bury a fake login page.
    path_depth = len([seg for seg in path.split("/") if seg])
    # Repeated separators like "//" or ".." inside the path hint at obfuscation.
    repeated_separators = ("//" in path) or (".." in path)

    return {
        "url": url,
        "scheme": scheme,
        "protocol": scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "url_length": len(url),
        "domain_length": len(hostname),
        "uses_https": scheme == "https",
        "is_ip_hostname": _is_ip_hostname(hostname),
        "subdomain_count": _count_subdomains(hostname),
        "keyword_hits": keyword_hits,
        "keyword_count": len(keyword_hits),
        "tld": tld,
        "is_suspicious_tld": tld in cfg.SUSPICIOUS_TLDS,
        "has_at_symbol": "@" in url,
        "hyphen_count": hostname.count("-"),
        "path_pattern_hits": path_hits,
        "has_url_encoding": "%" in url and decoded_url != url,
        "is_punycode": _is_punycode(hostname),
        "special_char_count": special_char_count,
        "param_count": param_count,
        "has_userinfo": has_userinfo,
        "port": port,
        "suspicious_port": suspicious_port,
        "path_depth": path_depth,
        "repeated_separators": repeated_separators,
    }
