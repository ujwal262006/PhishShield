"""Centralized, editable configuration for the rule-based risk engine.

All scoring weights, thresholds, and word lists live here so students can tune
the engine in a single place and explain every number during a viva.

IMPORTANT: PhishShield is a *rule-based risk assessment* system. These weights
are heuristics; they can produce false positives and false negatives.
"""
from __future__ import annotations

# --- Severity levels used for display and explanation ---
SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"

# --- Weighted points for each indicator (0-100 scale after normalization) ---
# Each key maps to (points, severity). Points are summed then capped at 100.
WEIGHTS = {
    "no_https": (15, SEV_MEDIUM),
    "ip_hostname": (20, SEV_HIGH),
    "suspicious_keyword": (5, SEV_MEDIUM),      # per keyword, capped below
    "excessive_subdomains": (10, SEV_MEDIUM),
    "long_url": (10, SEV_LOW),
    "suspicious_tld": (15, SEV_MEDIUM),
    "at_symbol": (15, SEV_HIGH),
    "excessive_hyphens": (5, SEV_LOW),
    "suspicious_path": (10, SEV_MEDIUM),
    "url_encoding": (5, SEV_LOW),
    "punycode": (15, SEV_HIGH),
    "typosquatting": (20, SEV_HIGH),
    "special_characters": (5, SEV_LOW),
    "long_domain": (5, SEV_LOW),
    "many_parameters": (5, SEV_LOW),
    "userinfo": (15, SEV_HIGH),
    "suspicious_port": (10, SEV_MEDIUM),
    "deep_path": (5, SEV_LOW),
    "repeated_separators": (5, SEV_LOW),
}

# Maximum total points that suspicious keywords can contribute (prevents a URL
# stuffed with keywords from dominating the score unfairly).
MAX_KEYWORD_POINTS = 15

# --- Thresholds for feature detection ---
LONG_URL_THRESHOLD = 75          # characters
LONG_DOMAIN_THRESHOLD = 30       # characters in the hostname
MAX_SUBDOMAINS = 3               # more than this is "excessive"
MAX_HYPHENS = 4                  # more than this in the hostname is suspicious
MANY_PARAMETERS_THRESHOLD = 4    # query parameters
SPECIAL_CHAR_THRESHOLD = 5       # count of unusual special chars in the URL
DEEP_PATH_THRESHOLD = 5          # more path segments than this is "deep"

# --- Classification bands (inclusive lower bound) ---
# 0-29 SAFE | 30-59 SUSPICIOUS | 60-79 HIGH RISK | 80-100 CRITICAL
CLASSIFICATION_BANDS = [
    (80, "CRITICAL"),
    (60, "HIGH RISK"),
    (30, "SUSPICIOUS"),
    (0, "SAFE"),
]

# --- Word / pattern lists ---
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "confirm", "password",
    "signin", "bank", "billing", "wallet", "webscr", "ebayisapi", "unlock",
    "suspend", "credential", "recover", "authenticate",
]

# TLDs frequently abused in phishing campaigns (heuristic list, editable).
SUSPICIOUS_TLDS = [
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "link", "top", "xin", "gdn", "click", "loan", "download",
]

SUSPICIOUS_PATH_PATTERNS = [
    "wp-admin", "signin", "login.php", "verify.php", "account-update",
    "secure-update", "confirm-identity", ".exe", ".scr", "cmd=",
]

# --- Trusted domains for the typosquatting / similarity check (editable) ---
TRUSTED_DOMAINS = [
    "example.com",
    "google.com",
    "microsoft.com",
    "github.com",
    "amazon.com",
    "apple.com",
    "paypal.com",
    "facebook.com",
    "netflix.com",
    "wikipedia.org",
]

# Similarity threshold: normalized Levenshtein similarity above this (but not an
# exact match) is flagged as *possible* typosquatting.
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.80

# --- Human-readable explanations per indicator ---
EXPLANATIONS = {
    "no_https": "The URL does not use HTTPS, so traffic may be transmitted "
                "without transport encryption and is easier to intercept or tamper with.",
    "ip_hostname": "The URL uses a raw IP address instead of a conventional "
                   "domain name, a technique often used to disguise the real destination.",
    "suspicious_keyword": "The URL contains terms commonly associated with "
                          "account-verification or credential-related pages used in phishing.",
    "excessive_subdomains": "The URL contains an unusually high number of "
                            "subdomains, which can be used to make a link look legitimate.",
    "long_url": "The URL is unusually long, which is sometimes used to hide the "
                "true destination or overwhelm a reader.",
    "suspicious_tld": "The top-level domain is one frequently abused in phishing "
                      "and low-reputation campaigns.",
    "at_symbol": "The URL contains an '@' symbol; everything before it is "
                 "treated as user info and the real host is what follows, a common trick.",
    "excessive_hyphens": "The hostname contains many hyphens, often seen in "
                         "look-alike domains imitating a brand.",
    "suspicious_path": "The URL path matches patterns often seen in phishing or "
                       "malware-hosting pages.",
    "url_encoding": "The URL contains percent-encoding that can be used to "
                    "obscure the true characters of the address.",
    "punycode": "The hostname uses punycode / IDN encoding, which can render as "
                "look-alike Unicode characters imitating a trusted brand.",
    "typosquatting": "The domain closely resembles a well-known trusted domain, "
                     "suggesting a possible typosquatting or look-alike attempt.",
    "special_characters": "The URL contains an unusual number of special "
                          "characters, which can indicate obfuscation.",
    "long_domain": "The hostname itself is unusually long, sometimes used to "
                   "bury a trusted brand name inside an untrusted domain.",
    "many_parameters": "The URL carries many query parameters, occasionally used "
                       "to smuggle redirect targets or tracking payloads.",
    "userinfo": "The URL contains a userinfo component (text before '@'), which "
                "can be used to make the link appear to point to a trusted site.",
    "suspicious_port": "The URL specifies a non-standard network port for its "
                       "protocol, which is unusual for legitimate public websites.",
    "deep_path": "The URL path is unusually deep, sometimes used to bury a fake "
                 "login page beneath many directories.",
    "repeated_separators": "The path contains repeated or traversal separators "
                           "(such as '//' or '..'), which can indicate obfuscation.",
}

# --- Recommended actions per classification ---
RECOMMENDATIONS = {
    "SAFE": "No strong risk indicators were found. Still verify the domain "
            "before entering sensitive information.",
    "SUSPICIOUS": "Treat this URL with caution. Do not enter credentials until "
                  "you have independently confirmed the site is legitimate.",
    "HIGH RISK": "Avoid interacting with this URL. Do not enter credentials or "
                 "personal information, and report it if it arrived unexpectedly.",
    "CRITICAL": "Do not visit this URL or enter any information. Delete the "
                "message it came from and report it to your security team.",
}
