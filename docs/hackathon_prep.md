# DPDPA Compliance Self-Check — Hackathon Prep Kit
## Cyber Kavach Challenge 2026 | BSides Ahmedabad | 26-27 Sep

---

## 1. DEPENDENCIES

### Backend (requirements.txt)
```
fastapi==0.115.0
uvicorn[standard]==0.30.0
sqlalchemy==2.0.35
alembic==1.13.0
asyncpg==0.30.0
psycopg2-binary==2.9.9
python-dotenv==1.0.1
pydantic==2.9.0
pydantic-settings==2.5.0
httpx==0.27.0
google-generativeai==0.8.0
tree-sitter==0.23.0
tree-sitter-python==0.23.0
tree-sitter-javascript==0.23.0
tree-sitter-typescript==0.23.0
tree-sitter-java==0.23.0
tree-sitter-go==0.23.0
playwright==1.47.0
beautifulsoup4==4.12.3
lxml==5.3.0
numpy==1.26.4
scikit-learn==1.5.0
python-multipart==0.0.9
jinja2==3.1.4
weasyprint==62.0
pgvector==0.3.0
```

### Frontend (package.json deps)
```json
{
  "dependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "react-router-dom": "^7.0.0",
    "recharts": "^2.12.0",
    "axios": "^1.7.0",
    "tailwindcss": "^4.0.0",
    "@tailwindcss/vite": "^4.0.0",
    "lucide-react": "^0.400.0",
    "react-syntax-highlighter": "^15.5.0",
    "react-dropzone": "^14.2.0"
  },
  "devDependencies": {
    "vite": "^6.0.0",
    "@vitejs/plugin-react": "^4.3.0"
  }
}
```

### Docker
```
PostgreSQL 16 with pgvector extension
Python 3.11-slim
Node 22-alpine
```

---

## 2. PROJECT FILE STRUCTURE

```
dpdpa-reviewer/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI app, CORS, lifespan
│   │   ├── config.py                  # Settings from env vars
│   │   ├── database.py                # SQLAlchemy engine + session
│   │   │
│   │   ├── models/                    # SQLAlchemy models
│   │   │   ├── __init__.py
│   │   │   ├── scan.py                # Scan, ScanTarget
│   │   │   ├── finding.py             # Finding, FindingSeverity
│   │   │   ├── rule_result.py         # RuleResult per DPDP rule
│   │   │   ├── pii_field.py           # Detected PII fields
│   │   │   └── data_flow.py           # DataFlowEdge, FlowPath
│   │   │
│   │   ├── api/                       # Route handlers
│   │   │   ├── __init__.py
│   │   │   ├── scan.py                # POST /scan/web, POST /scan/code
│   │   │   ├── findings.py            # GET /scans/{id}/findings
│   │   │   ├── scorecard.py           # GET /scans/{id}/scorecard
│   │   │   └── health.py              # GET /health
│   │   │
│   │   ├── scanner/                   # Core scanning engines
│   │   │   ├── __init__.py
│   │   │   ├── web_scanner.py         # Playwright crawl + form analysis
│   │   │   └── code_scanner.py        # tree-sitter AST + PII detection
│   │   │
│   │   ├── context/                   # Data flow context engine
│   │   │   ├── __init__.py
│   │   │   ├── code_graph.py          # Call graph + dependency edges
│   │   │   ├── pii_flow.py            # PII source->transform->sink tracer
│   │   │   └── assembler.py           # Context packer for AI prompts
│   │   │
│   │   ├── rules/                     # DPDP rules engine (11 dimensions)
│   │   │   ├── __init__.py
│   │   │   ├── engine.py              # Run all rules, aggregate results
│   │   │   ├── r03_notice.py          # Rule 3: Notice
│   │   │   ├── r04_consent.py         # Rule 4: Consent
│   │   │   ├── r05_children.py        # Rule 5: Children's data
│   │   │   ├── r06_security.py        # Rule 6: Security safeguards
│   │   │   ├── r07_breach.py          # Rule 7: Breach notification
│   │   │   ├── r08_dpia.py            # Rule 8: DPIA
│   │   │   ├── r09_sdf.py             # Rule 9: SDF obligations
│   │   │   ├── r10_rights.py          # Rule 10: Data Principal rights
│   │   │   ├── r11_dpb.py             # Rule 11: DPB readiness
│   │   │   ├── r12_verification.py    # Rule 12: Compliance verification
│   │   │   └── retention.py           # s.8(7): Retention/erasure
│   │   │
│   │   ├── ai/                        # Gemini AI layer
│   │   │   ├── __init__.py
│   │   │   ├── gateway.py             # Gemini client wrapper
│   │   │   ├── embeddings.py          # text-embedding-004 for corpus
│   │   │   ├── grounded_analysis.py   # RAG: retrieve + generate
│   │   │   └── guardrail.py           # Citation + entailment check
│   │   │
│   │   ├── corpus/                    # DPDP statutory text
│   │   │   ├── __init__.py
│   │   │   ├── dpdp_act.py            # Act sections as structured data
│   │   │   ├── dpdp_rules.py          # Rules as structured data
│   │   │   ├── chunker.py             # Section -> citation-bearing chunks
│   │   │   └── indexer.py             # Embed + store in pgvector
│   │   │
│   │   ├── pii/                       # PII detection taxonomy
│   │   │   ├── __init__.py
│   │   │   ├── taxonomy.py            # Categories, sensitivity tiers
│   │   │   ├── indian_ids.py          # Aadhaar/PAN/GSTIN validators
│   │   │   └── field_classifier.py    # Field name -> PII category
│   │   │
│   │   └── scorecard/                 # Score computation + report
│   │       ├── __init__.py
│   │       ├── scorer.py              # Per-rule + overall scoring
│   │       └── report.py              # PDF generation
│   │
│   ├── alembic/                       # DB migrations
│   │   └── versions/
│   ├── alembic.ini
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── pages/
│   │   │   ├── Home.jsx               # Landing + scan input
│   │   │   ├── ScanResults.jsx        # Scorecard + findings
│   │   │   └── DataFlow.jsx           # Data flow visualization
│   │   ├── components/
│   │   │   ├── ScoreCard.jsx           # Radar chart + grades
│   │   │   ├── RuleStatus.jsx          # Per-rule compliance cards
│   │   │   ├── FindingsList.jsx        # Findings with citations
│   │   │   ├── DataFlowGraph.jsx       # PII flow visualization
│   │   │   ├── CodeViewer.jsx          # Code with highlighted lines
│   │   │   └── ScanForm.jsx            # URL or code upload input
│   │   └── api/
│   │       └── client.js               # Axios instance
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   └── Dockerfile
│
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## 3. DATABASE SCHEMA

```sql
-- Enable pgvector
CREATE EXTENSION IF NOT EXISTS vector;

-- Scans
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type VARCHAR(10) NOT NULL,        -- 'web' or 'code'
    target VARCHAR(1000) NOT NULL,          -- URL or repo name
    status VARCHAR(20) DEFAULT 'pending',   -- pending/scanning/complete/failed
    overall_score FLOAT,
    overall_grade VARCHAR(2),               -- A, B, C, D, F
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

-- Detected PII fields
CREATE TABLE pii_fields (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    file_path VARCHAR(500),
    line_number INTEGER,
    field_name VARCHAR(200),
    pii_category VARCHAR(50),              -- email, phone, aadhaar, pan, etc.
    sensitivity VARCHAR(20),               -- low, medium, high, critical
    context TEXT                            -- surrounding code snippet
);

-- Data flow edges
CREATE TABLE data_flow_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    source_file VARCHAR(500),
    source_line INTEGER,
    source_function VARCHAR(200),
    sink_file VARCHAR(500),
    sink_line INTEGER,
    sink_function VARCHAR(200),
    edge_type VARCHAR(30),                 -- call, import, data_pass, api_send, db_write
    pii_fields_involved TEXT[]             -- which PII crosses this edge
);

-- PII flow paths (end-to-end)
CREATE TABLE pii_flow_paths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    pii_category VARCHAR(50),
    source_description TEXT,               -- "User input at POST /register"
    transforms TEXT[],                     -- ["hashed in utils.py:34", "logged in middleware.py:12"]
    sink_description TEXT,                 -- "Stored plaintext in users.email column"
    has_consent_check BOOLEAN DEFAULT FALSE,
    has_encryption BOOLEAN DEFAULT FALSE,
    has_retention_policy BOOLEAN DEFAULT FALSE
);

-- Rule results (one per rule per scan)
CREATE TABLE rule_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    rule_id VARCHAR(10) NOT NULL,          -- R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, RET
    rule_name VARCHAR(100),
    status VARCHAR(20),                    -- compliant, gap, violation, not_applicable
    score FLOAT,                           -- 0.0 to 1.0
    evidence TEXT,                         -- what was found / not found
    dpdp_section VARCHAR(50),              -- s.5, s.6, s.8(5), etc.
    dpdp_rule VARCHAR(50)                  -- Rule 3, Rule 4, etc.
);

-- Individual findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    rule_id VARCHAR(10),
    severity VARCHAR(20),                  -- critical, high, medium, low, info
    file_path VARCHAR(500),
    line_number INTEGER,
    title TEXT,
    description TEXT,                      -- plain-English explanation
    citation TEXT,                         -- "DPDP Act s.8(5); Rules 2025 Rule 6"
    citation_text TEXT,                    -- actual quoted statutory text
    data_flow_context TEXT,                -- how this PII flows through the system
    suggested_fix TEXT,                    -- code suggestion
    ai_confidence FLOAT,                  -- 0.0 to 1.0
    guardrail_passed BOOLEAN DEFAULT TRUE
);

-- DPDP statutory corpus (for RAG)
CREATE TABLE dpdp_corpus (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(20),                    -- 'act' or 'rules'
    section_id VARCHAR(20),                -- 's.5', 's.6(1)', 'rule_3', etc.
    section_title VARCHAR(200),
    chunk_text TEXT,
    citation_label VARCHAR(100),           -- "DPDP Act 2023, Section 5"
    embedding vector(768)                  -- text-embedding-004 = 768 dims
);
```

---

## 4. API ENDPOINTS

```
POST /api/scan/web
  Body: { "url": "https://example.com/signup" }
  Response: { "scan_id": "uuid", "status": "scanning" }

POST /api/scan/code
  Body: multipart form with zip/tar of source code
  OR: { "github_url": "https://github.com/user/repo" }
  Response: { "scan_id": "uuid", "status": "scanning" }

GET /api/scans/{scan_id}
  Response: { scan metadata + status }

GET /api/scans/{scan_id}/scorecard
  Response: {
    "overall_score": 42.5,
    "overall_grade": "D",
    "rules": [
      { "rule_id": "R3", "name": "Notice", "score": 0.0, "status": "violation", ... },
      { "rule_id": "R4", "name": "Consent", "score": 0.5, "status": "gap", ... },
      ...
    ],
    "summary": { "total_findings": 12, "critical": 3, "high": 4, ... }
  }

GET /api/scans/{scan_id}/findings
  Response: [ array of findings with citations ]

GET /api/scans/{scan_id}/data-flows
  Response: [ array of PII flow paths ]

GET /api/scans/{scan_id}/report/pdf
  Response: PDF file download

GET /api/health
```

---

## 5. DPDP RULES-TO-CHECKS MAPPING

### Rule 3: Notice (DPDP Act s.5)
**What to check:**
- WEB: privacy notice/policy link exists on the page, visible before form submission
- WEB: notice contains itemized list of purposes
- WEB: DPO / grievance officer contact info present
- CODE: privacy notice template/page exists in codebase
- CODE: notice is shown before data collection (rendered before form, not after)

**Detection logic:**
- HTML: search for links containing "privacy", "policy", "notice"
- HTML: check if notice link appears before or within the form, not just footer
- AST: look for route handlers serving privacy policy
- AST: check render order (notice component before form component)

### Rule 4: Consent (DPDP Act s.6, s.7)
**What to check:**
- WEB: consent checkbox exists, is NOT pre-checked
- WEB: consent is granular (separate checkboxes per purpose)
- WEB: withdrawal mechanism exists (unsubscribe, manage preferences page)
- CODE: consent value is checked BEFORE data processing/storage
- CODE: consent record is stored (who consented, when, for what)
- CODE: consent withdrawal endpoint exists

**Detection logic:**
- HTML: find input[type=checkbox] near submit button, check "checked" attr absent
- HTML: count consent checkboxes (1 = not granular)
- AST: find if-statements checking consent/agreed/terms before DB writes
- AST: search for consent model/table in DB schemas
- AST: search for withdraw/revoke/unsubscribe routes

### Rule 5: Children's Data (DPDP Act s.9)
**What to check:**
- WEB: age gate / date of birth field exists
- WEB: if age < 18 detected, parental consent flow present
- CODE: age check logic before processing
- CODE: no behavioral tracking/monitoring for users flagged as children
- CODE: verifiable parental consent mechanism

**Detection logic:**
- HTML: find input fields for age, dob, date_of_birth, birthday
- AST: find conditionals comparing age < 18 or age < threshold
- AST: search for parental_consent, guardian, minor in models/routes
- AST: check analytics/tracking code for age-gated exclusion

### Rule 6: Security Safeguards (DPDP Act s.8(5))
**What to check:**
- CODE: PII fields are encrypted at rest (EncryptedType, pgcrypto, hashlib)
- CODE: HTTPS enforced (TLS/SSL config)
- CODE: access controls on PII endpoints (auth middleware)
- CODE: PII not logged in plaintext
- CODE: password hashing (bcrypt, argon2, scrypt)
- WEB: form submits over HTTPS
- WEB: security headers present (HSTS, CSP, X-Frame-Options)

**Detection logic:**
- AST: find Column/field definitions for PII, check if wrapped in encryption
- AST: search for logging calls that include PII variable names
- AST: find auth decorators/middleware on routes handling PII
- HTTP: check response headers for security headers
- HTTP: check form action URL is HTTPS

### Rule 7: Breach Notification (DPDP Act s.8(6))
**What to check:**
- CODE: breach notification mechanism exists
- CODE: breach model/table for recording incidents
- CODE: notification endpoint/function for DPB (72-hour requirement)
- CODE: notification to affected Data Principals

**Detection logic:**
- AST: search for breach, incident, notification in models/routes
- AST: search for email/SMS sending functions tied to breach events
- File search: look for incident response plan documents

### Rule 8: DPIA (Data Protection Impact Assessment)
**What to check:**
- CODE/DOCS: DPIA template or assessment present
- CODE: high-risk processing identified and flagged
- CODE: impact assessment for large-scale PII processing

**Detection logic:**
- File search: dpia, impact_assessment, risk_assessment files
- AST: comments/docstrings mentioning DPIA or impact assessment

### Rule 9: Significant Data Fiduciary (DPDP Act s.10)
**What to check:**
- CODE: Data Protection Officer role/model exists
- CODE: periodic audit mechanism
- CODE: algorithmic fairness checks if automated decisions on PII

**Detection logic:**
- AST: search for dpo, data_protection_officer in models/config
- AST: search for audit, audit_log tables/models
- AST: search for automated decision functions using PII

### Rule 10: Data Principal Rights (DPDP Act s.11-14)
**What to check:**
- CODE: access endpoint (user can see their data) -- s.11
- CODE: correction endpoint (user can fix their data) -- s.12
- CODE: erasure/deletion endpoint (right to be forgotten) -- s.13
- CODE: nomination mechanism (designate another person) -- s.14
- WEB: "My Data" or account settings page accessible

**Detection logic:**
- AST: find GET /me, /profile, /my-data routes
- AST: find PUT/PATCH routes for user profile correction
- AST: find DELETE /account or /my-data routes
- AST: find nominee, nomination in models
- HTML: find links to account/profile/data pages

### Rule 11: Data Protection Board Readiness
**What to check:**
- CODE: complaint/grievance mechanism
- CODE: reporting endpoint for DPB communication
- DOCS: compliance documentation structure

**Detection logic:**
- AST: search for complaint, grievance routes/models
- File search: compliance, dpb, board in filenames

### Rule 12: Compliance Verification
**What to check:**
- CODE: audit trail / logging of data processing
- CODE: evidence collection mechanism
- CODE: compliance status tracking
- CODE: documentation of processing activities (RoPA)

**Detection logic:**
- AST: audit_log, processing_log tables/models
- AST: decorator/middleware that logs data access
- File search: ropa, processing_activities, register

### s.8(7): Retention and Erasure
**What to check:**
- CODE: TTL / expiry on data (Redis TTL, DB column expires_at)
- CODE: scheduled deletion jobs (cron, celery tasks, cleanup)
- CODE: retention policy configuration
- CODE: no indefinite storage of PII without expiry

**Detection logic:**
- AST: find expires_at, ttl, retention_days, cleanup in models/config
- AST: find scheduled tasks/crons that delete old data
- AST: find PII columns WITHOUT any associated expiry/TTL
- If PII stored + no retention logic found = violation

---

## 6. GEMINI INTEGRATION

### Embedding model
- Model: `text-embedding-004`
- Dimensions: 768
- Use: embed DPDP corpus chunks + code snippets for similarity search

### Generation model
- Model: `gemini-2.5-flash` (fast, cheap for hackathon volume)
- Or: `gemini-2.5-pro` for final analysis pass
- Temperature: 0.1 (low creativity, high factuality)

### RAG prompt template
```
You are a DPDP Act 2023 compliance analyst. You have been given:
1. Code under analysis with file path and line numbers
2. Data flow context showing how personal data moves through the system
3. Relevant DPDP statutory provisions retrieved from the Act and Rules

For each compliance issue found, produce a JSON object:
{
  "file": "path/to/file.py",
  "line": 47,
  "title": "Short finding title",
  "description": "Plain-English explanation of the issue",
  "citation": "DPDP Act s.8(5); Rules 2025 Rule 6",
  "citation_text": "Exact quote from the provision",
  "data_flow": "How this PII flows: source -> transforms -> sink",
  "severity": "critical|high|medium|low",
  "suggested_fix": "Code suggestion to resolve",
  "rule_id": "R6"
}

RULES:
- Only cite sections that appear in the provided statutory text
- Never fabricate a section number or quote
- If unsure, say "requires manual review" rather than guessing
- The verdict (compliant/gap/violation) is determined by the rules engine, not by you
- You provide explanation and citation only
```

### Guardrail check
After Gemini generates findings:
1. Extract every citation (e.g., "s.8(5)")
2. Check it exists in the provided corpus chunks
3. Extract the quoted text
4. Check the quote actually appears in the corpus (fuzzy match > 0.85)
5. If citation fails: flag finding as `guardrail_passed = false`

---

## 7. .env.example

```env
# Database
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/dpdpa_reviewer

# Gemini AI
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.5-flash
GEMINI_EMBEDDING_MODEL=text-embedding-004

# App
APP_ENV=development
APP_PORT=8000
CORS_ORIGINS=http://localhost:5173

# Scanner
MAX_CRAWL_PAGES=10
MAX_UPLOAD_SIZE_MB=50
TREE_SITTER_LANGUAGES=python,javascript,typescript,java,go
```

---

## 8. 24-HOUR BUILD ORDER

### Day 1: Saturday (11:00 AM - 6:00 PM = 7 hours)

**Hour 1 (11:00-12:00): Scaffold**
- git init, .gitignore, .env.example, docker-compose.yml
- FastAPI app skeleton (main.py, config.py, database.py)
- React + Vite scaffold (npx create-vite)
- Install all deps
- FIRST COMMIT

**Hour 2 (12:00-13:00): Database + Models**
- docker-compose up (postgres with pgvector)
- SQLAlchemy models (scans, pii_fields, findings, rule_results, data_flow_edges, dpdp_corpus)
- Alembic init + first migration
- COMMIT

**13:00-14:00: LUNCH + mentor check-in**
- Show: running FastAPI + DB, explain architecture to mentor

**Hour 3-4 (14:00-16:00): Code Scanner**
- tree-sitter parser setup (Python + JS at minimum)
- PII taxonomy (field_classifier.py + indian_ids.py)
- AST walking: extract functions, classes, DB models, routes
- Data flow edge builder (call graph + imports)
- PII flow tracer (source -> transform -> sink)
- COMMIT

**Hour 5 (16:00-17:00): Web Scanner**
- Playwright page crawl
- Form field extraction
- Consent checkbox detection
- Privacy notice link finder
- Security header check
- COMMIT

**Hour 6-7 (17:00-18:00): Rules Engine**
- rules/engine.py (orchestrator)
- Implement R3 (notice), R4 (consent), R6 (security), R10 (rights), retention
- These 5 are the most demo-able rules
- COMMIT at Day 1 checkpoint

### Day 2: Sunday (9:30 AM - 12:30 PM = 3 hours)

**Hour 8 (9:30-10:30): Remaining Rules + Gemini RAG**
- Implement R5, R7, R8, R9, R11, R12
- DPDP corpus (dpdp_act.py + dpdp_rules.py with actual statutory text)
- Embed corpus into pgvector
- Gemini grounded analysis function
- Guardrail citation checker
- COMMIT

**Hour 9 (10:30-11:30): Scorecard + API**
- Scorer (per-rule + overall grade calculation)
- All API endpoints wired up
- End-to-end: URL -> scan -> findings -> scorecard working
- COMMIT

**Hour 10 (11:30-12:15): React Dashboard**
- ScanForm (URL input + code upload)
- ScoreCard component (radar chart with Recharts)
- RuleStatus cards (11 dimensions with status badges)
- FindingsList with citations and code snippets
- COMMIT

**12:15-12:30: Final polish**
- README.md (as if open-sourcing: setup, tech stack, architecture, how to run)
- Final commit before code freeze
- COMMIT

### Demo prep (12:30-13:30 during lunch)
- Have a sample vulnerable form ready to scan live
- Have a sample Python project with DPDP violations ready
- Practice the demo flow: scan -> scorecard -> drill into findings -> show data flow

---

## 9. DEMO SCRIPT (for jury)

1. "Here's a signup form for a fictional Indian e-commerce site" -> paste URL
2. System crawls it, finds: no privacy notice, pre-checked consent, no age gate, no HTTPS
3. Scorecard appears: Overall Grade D, 35/100
4. Drill into Rule 4 (Consent): "Checkbox is pre-checked, violating s.6(1) free consent requirement"
5. Show the citation: exact text from the Act
6. Now switch to code scan: upload the backend code
7. System finds: Aadhaar stored plaintext, no deletion endpoint, analytics gets PII without consent
8. Show data flow: "Aadhaar enters at POST /kyc -> stored in Column(String) -> read by analytics service -> sent to third-party API"
9. Show suggested fix: EncryptedString wrapper
10. Show PDF report export

Key talking points for Q&A:
- "The verdict is deterministic. AI only explains and cites. It never decides compliance status."
- "Every citation is verified against the actual statutory text. Hallucinated citations are caught and flagged."
- "The context engine traces data flow across the entire codebase, not just individual files."
- "We score 11 dimensions covering the operative obligations, not just consent and retention, and we cite the notified 2025 Rules rather than the January draft."

---

## 10. SAMPLE VULNERABLE APP (for demo)

Create a small Flask/Express app with these intentional violations:
- Aadhaar number stored as plaintext String column
- No privacy notice page
- Consent checkbox is pre-checked (checked="checked")
- No age verification
- PII logged in plaintext (logging.info(f"User registered: {aadhaar}"))
- No deletion/erasure endpoint
- No encryption on PII fields
- Analytics endpoint sends PII to external API without consent check
- No breach notification mechanism
- No retention policy / TTL on user data

This gives you violations across all 11 scored dimensions for a complete demo.
