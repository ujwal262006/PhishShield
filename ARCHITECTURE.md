# PhishShield - Architecture

## High-level component diagram

```mermaid
graph TD
    Browser[User Browser] -->|HTML / JSON| Flask[Flask App Factory]

    subgraph App[PhishShield Application]
        Flask --> Routes[Routes / Blueprints]
        Routes --> Auth[auth.py]
        Routes --> Scan[scan.py]
        Routes --> Dash[dashboard.py]
        Routes --> Admin[admin.py]
        Routes --> Main[main.py]

        Auth --> Utils[utils: validators, decorators, security_logger]
        Scan --> Services[services]
        Dash --> Models
        Admin --> Models

        Services --> Analyzer[url_analyzer]
        Services --> Engine[risk_engine]
        Services --> Similarity[domain_similarity]
        Services --> Integrity[integrity SHA-256]
        Engine --> Config[scoring_config]

        Routes --> Models[(SQLAlchemy Models)]
    end

    Models --> DB[(SQLite: instance/phishshield.db)]
```

## Risk-engine data flow

```mermaid
flowchart LR
    A[analyze_url] --> B[validate_url]
    B --> C[extract_features]
    C --> D[evaluate_rules]
    D --> E[calculate_score]
    E --> F[classify_risk]
    F --> G[generate_recommendation]
    C --> H[sha256_hash integrity]
    G --> R[Result dict]
    H --> R
```

The engine is Flask-independent, so each stage is unit-testable in isolation.

## Scan request sequence

```mermaid
sequenceDiagram
    participant U as User
    participant R as scan route
    participant E as risk_engine
    participant DB as SQLite
    participant L as security_logger

    U->>R: POST /scan (url)
    R->>E: analyze_url(url)
    E-->>R: score, classification, indicators, hash
    R->>DB: INSERT Scan
    R->>L: log_event(SCAN [+ HIGH/CRITICAL])
    R-->>U: result page / JSON
```

## Module relationships

- **routes/** depend on **services/**, **models/**, and **utils/**.
- **services/risk_engine** composes **url_analyzer**, **domain_similarity**,
  **integrity**, and reads weights from **scoring_config**.
- **utils/decorators** enforce RBAC and log unauthorized attempts via
  **utils/security_logger**.
- All persistence goes through **models/** (SQLAlchemy) — no raw SQL anywhere.

## Database relationships (ER)

```mermaid
erDiagram
    USER ||--o{ SCAN : "creates"
    USER ||--o{ SECURITY_EVENT : "generates"

    USER {
        int id PK
        string username "unique"
        string email "unique"
        string password_hash
        string role "USER | ADMIN"
        bool is_active
        int failed_logins
        datetime locked_until
        datetime created_at
    }
    SCAN {
        int id PK
        int user_id FK
        string url
        string hostname
        string protocol
        int risk_score
        string classification
        text indicators_json
        text recommendation
        string integrity_hash "SHA-256"
        datetime created_at
    }
    SECURITY_EVENT {
        int id PK
        int user_id FK "nullable"
        string event_type
        string description
        text event_metadata "no secrets"
        datetime created_at
    }
```

## Request handling layers

1. **HTTP layer** — Flask blueprints, CSRF on forms, security headers, error handlers.
2. **Authorization layer** — `login_required` / `login_required_api` / `admin_required`.
3. **Domain layer** — services (analysis, scoring, similarity, hashing).
4. **Persistence layer** — SQLAlchemy models over SQLite.
