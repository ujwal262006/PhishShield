"""Educational cryptographic-integrity helper.

Demonstrates SHA-256 *hashing* (a one-way integrity function), NOT encryption.
Hashing is not reversible and does not hide data confidentially; it is used to
detect whether data has changed.
"""
from __future__ import annotations

import hashlib


def sha256_hash(text: str) -> str:
    """Return the hex SHA-256 digest of a UTF-8 string.

    Note: SHA-256 is a hash function. It is NOT encryption -- you cannot get the
    original input back from the digest. It is used here to fingerprint a scan
    so any change to the input produces a completely different hash.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_integrity(text: str, expected_hash: str) -> bool:
    """Return True if the SHA-256 hash of ``text`` matches ``expected_hash``."""
    return sha256_hash(text) == expected_hash


def integrity_demo(original: str, modified: str) -> dict:
    """Build a small demonstration payload showing hashing sensitivity.

    Changing even one character produces an entirely different digest, which
    illustrates how hashing supports the Integrity pillar of the CIA triad.
    """
    original_hash = sha256_hash(original)
    modified_hash = sha256_hash(modified)
    return {
        "original_input": original,
        "original_hash": original_hash,
        "modified_input": modified,
        "modified_hash": modified_hash,
        "changed": original_hash != modified_hash,
        "algorithm": "SHA-256",
        "note": "SHA-256 is a one-way hash for integrity, not encryption.",
    }
