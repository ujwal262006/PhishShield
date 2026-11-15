# Project Overview

**PhishShield — An Explainable Phishing Detection and Risk Assessment System**

## What it is

A local, web-based application that accepts a URL and returns an explainable risk
assessment. It is a **rule-based** system: every point in the risk score maps to a named,
human-readable indicator. It is defensive and educational — it analyzes the URL string
only and never contacts the target site.

## Why it matters

Phishing remains one of the most common cybercrime vectors. Black-box detectors give a
verdict but no reasoning, which is unhelpful for learning. PhishShield's transparency makes
it ideal for teaching *how* phishing links are recognized.

## Core capabilities

1. URL validation and feature extraction (18+ features).
2. Explainable, weighted risk scoring normalized to 0-100.
3. Four-band classification: SAFE / SUSPICIOUS / HIGH RISK / CRITICAL.
4. Typosquatting detection against a configurable trusted-domain list.
5. Secure authentication with a password policy, hashing, and account lockout.
6. Role-based access control (USER / ADMIN).
7. Scan history with search, filtering, and pagination.
8. User and admin dashboards with charts.
9. Security event logging.
10. SHA-256 integrity demonstration.
11. Security-awareness education module.

## Non-goals (explicitly excluded)

- No real-world exploitation, malware, or credential harvesting.
- No cloning of phishing pages.
- No offensive scanning of external systems.
- No claim of perfect or guaranteed detection.

## Technology

Python 3.11+, Flask, SQLAlchemy + SQLite, Flask-Login, Flask-WTF, Werkzeug hashing,
vanilla JS + Chart.js, pytest.
