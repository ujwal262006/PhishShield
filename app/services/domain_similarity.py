"""Safe, local typosquatting / domain-similarity analysis.

This module performs pure string comparison against a small, configurable list
of trusted domains. It NEVER contacts, scrapes, or attacks any real website.
"""
from __future__ import annotations

from app.services.scoring_config import (
    TRUSTED_DOMAINS,
    TYPOSQUAT_SIMILARITY_THRESHOLD,
)


def levenshtein_distance(a: str, b: str) -> int:
    """Classic dynamic-programming Levenshtein (edit) distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (0 if ca == cb else 1)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def normalized_similarity(a: str, b: str) -> float:
    """Return a 0.0-1.0 similarity ratio (1.0 == identical strings)."""
    if not a and not b:
        return 1.0
    distance = levenshtein_distance(a, b)
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1.0 - (distance / longest)


def _registrable_part(hostname: str) -> str:
    """Best-effort extraction of the comparable domain label.

    We compare the second-level + TLD (e.g. 'paypa1.com'). This is a heuristic
    suitable for a student project, not a full public-suffix implementation.
    """
    host = (hostname or "").lower().strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def check_typosquatting(hostname: str, trusted_domains: list[str] | None = None) -> dict:
    """Compare a hostname against trusted domains for look-alike similarity.

    Returns a dict describing whether a *possible* similarity was detected. It
    deliberately avoids asserting that the URL is malicious.
    """
    trusted = trusted_domains if trusted_domains is not None else TRUSTED_DOMAINS
    candidate = _registrable_part(hostname)

    best_match = None
    best_score = 0.0
    for trusted_domain in trusted:
        trusted_domain = trusted_domain.lower()
        if candidate == trusted_domain:
            # Exact match to a trusted domain is NOT typosquatting.
            return {
                "is_typosquat": False,
                "matched_domain": trusted_domain,
                "similarity": 1.0,
                "exact_trusted": True,
            }
        score = normalized_similarity(candidate, trusted_domain)
        if score > best_score:
            best_score = score
            best_match = trusted_domain

    is_typosquat = (
        best_match is not None
        and best_score >= TYPOSQUAT_SIMILARITY_THRESHOLD
        and best_score < 1.0
    )
    return {
        "is_typosquat": is_typosquat,
        "matched_domain": best_match,
        "similarity": round(best_score, 3),
        "exact_trusted": False,
    }
