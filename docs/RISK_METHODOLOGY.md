# PhishShield — Risk Methodology

PhishShield is a **transparent, rule-based** risk-assessment system. Every point
in a score maps to a named indicator with a plain-English explanation. There is
no black-box model.

## Pipeline

```
analyze_url(url)
  -> validate_url()          # scheme, hostname, length
  -> extract_features()      # 20+ string features, no network
  -> evaluate_rules()        # features -> scored indicators
  -> calculate_score()       # sum points, cap keywords, clamp 0-100
  -> classify_risk()         # map score to band
  -> generate_recommendation()
  -> return result
```

All logic lives in `app/services/` and is independent of Flask, so it is fully
unit-testable.

## Scoring

- Each indicator contributes a fixed number of points defined centrally in
  `app/services/scoring_config.py` (`WEIGHTS`).
- Suspicious keywords scale with count but are **capped** (`MAX_KEYWORD_POINTS`)
  to prevent keyword stuffing from dominating the score.
- The total is **clamped to 0–100**.

### Indicator weights (editable)

| Indicator | Severity | Weight | Category |
|-----------|----------|--------|----------|
| IP address as hostname | HIGH | 20 | Domain |
| Possible typosquatting | HIGH | 20 | Domain |
| "@" symbol | HIGH | 15 | URL structure |
| Userinfo component | HIGH | 15 | URL structure |
| Punycode / IDN hostname | HIGH | 15 | Domain |
| No HTTPS | MEDIUM | 15 | Protocol |
| Suspicious TLD | MEDIUM | 15 | Domain |
| Excessive subdomains | MEDIUM | 10 | URL structure |
| Suspicious path pattern | MEDIUM | 10 | Suspicious |
| Non-standard port | MEDIUM | 10 | URL structure |
| Long URL | LOW | 10 | URL structure |
| Suspicious keyword (each, capped) | MEDIUM | 5 (max 15) | Suspicious |
| Excessive hyphens | LOW | 5 | URL structure |
| URL encoding | LOW | 5 | URL structure |
| Excessive special characters | LOW | 5 | URL structure |
| Long domain | LOW | 5 | Domain |
| Many query parameters | LOW | 5 | URL structure |
| Deep URL path | LOW | 5 | URL structure |
| Repeated / traversal separators | LOW | 5 | URL structure |

Weights are heuristics; edit `scoring_config.py` to tune them. The live table is
also rendered at `/methodology`.

## Classification bands

| Score | Classification |
|-------|----------------|
| 0–29 | SAFE |
| 30–59 | SUSPICIOUS |
| 60–79 | HIGH RISK |
| 80–100 | CRITICAL |

## Important interpretation note

The score is a **heuristic risk score out of 100**, not a probability. A score of
82 means "82/100 heuristic risk", **not** "82% malicious". Heuristics produce
false positives and false negatives. A SAFE result is not a guarantee of safety;
a CRITICAL result is not proof of malice.

## Visualization values

The result page shows category "risk breakdown" percentages. These are
**normalized visualization values** (a category's summed points relative to a
sensible per-category maximum in `risk_breakdown()`), clearly labelled as such —
they are not probabilities.

## Typosquatting

`domain_similarity.py` compares the registrable domain against a small,
configurable trusted-domain list using normalized Levenshtein similarity. Above a
threshold (but not an exact match), it reports **"possible similarity"** — it
never asserts a domain is malicious. It performs pure string comparison and
contacts no external site.
