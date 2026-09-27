# DPDPA Compliance Self-Check Tool — Architecture Document

**Project:** DPDP Act 2023 Compliance Scorecard Generator
**Event:** Cyber Kavach Challenge 2026 | BSides Ahmedabad
**Stack:** Python 3.11 / FastAPI / PostgreSQL + pgvector / React 19 / Gemini AI

---

## 1. System Overview

The system accepts two types of input — a live web URL or application source code — and produces a compliance scorecard evaluated across 11 compliance dimensions that map onto the DPDP Act 2023 and the notified DPDP Rules 2025.

The architecture enforces a strict separation: **the compliance verdict is deterministic** (produced by rules and evidence). The AI layer produces explanation, statutory citation, and suggested remediation only. It never alters the verdict. This makes every output auditable.

```
┌─────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                          │
│                                                             │
│   ┌──────────────────┐      ┌──────────────────────────┐   │
│   │   Web Scanner    │      │     Code Scanner          │   │
│   │   (Playwright)   │      │     (tree-sitter AST)     │   │
│   └────────┬─────────┘      └────────────┬──────────────┘   │
└────────────┼─────────────────────────────┼──────────────────┘
             │                             │
             ▼                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     CONTEXT ENGINE                          │
│                                                             │
│   ┌──────────┐   ┌──────────────┐   ┌────────────────┐    │
│   │Code Graph│──▶│PII Flow Map  │──▶│Context Assembler│    │
│   └──────────┘   └──────────────┘   └───────┬────────┘    │
│                                              │              │
│   ┌──────────────────────────────────────────┴───────────┐ │
│   │        Semantic Index (pgvector on PostgreSQL)        │ │
│   └──────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                DPDP RULES ENGINE (11 dimensions)                 │
│                                                             │
│   R3:Notice  R4:Consent  R5:Children  R6:Security           │
│   R7:Breach  R8:DPIA     R9:SDF       R10:Rights            │
│   R11:DPB    R12:Verify  s.8(7):Retention                   │
│                                                             │
│   Output: per-rule status (compliant / gap / violation)     │
│           + evidence string + score 0.0-1.0                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              GROUNDED RAG LAYER (Gemini)                    │
│                                                             │
│   ┌────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│   │DPDP Corpus │─▶│ Retrieval     │─▶│ Gemini Generate  │ │
│   │(pgvector)  │  │ (top-k match) │  │ (constrained)    │ │
│   └────────────┘  └───────────────┘  └────────┬─────────┘ │
│                                                │           │
│   ┌────────────────────────────────────────────┴─────────┐ │
│   │           Faithfulness Guardrail                      │ │
│   │   Citation exists? Quote matches? Entailment holds?   │ │
│   └──────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     OUTPUT LAYER                            │
│                                                             │
│   ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│   │ Scorecard │ │ Findings │ │Data Flow │ │ PDF Report │ │
│   │ (grades)  │ │ (cited)  │ │  (visual)│ │ (export)   │ │
│   └───────────┘ └──────────┘ └──────────┘ └────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Layer Specifications

### 2.1 Input Layer

Two independent scanner modules produce a common intermediate representation consumed by the context engine.

#### Web Scanner (`backend/app/scanner/web_scanner.py`)

| Responsibility | Implementation |
|---|---|
| Page crawl | Playwright headless browser, max 10 pages from entry URL |
| Form extraction | Parse all `<form>` elements, extract input fields by name/type/id |
| Consent detection | Find checkboxes near submit buttons, check `checked` attribute absent |
| Privacy notice | Search for anchor tags containing "privacy", "policy", "notice" |
| Security headers | Read HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type) |
| Third-party scripts | Extract `<script src>` domains, flag external analytics/tracking |
| Cookie analysis | Read Set-Cookie headers, classify by name patterns |
| Age gate | Search for date-of-birth, age, birthday input fields |

**Output:** `WebScanResult` dataclass containing:
- `forms: list[FormInfo]` (fields, action URL, method)
- `consent_elements: list[ConsentInfo]` (checkbox state, label text)
- `privacy_notice: Optional[NoticeInfo]` (URL, position relative to forms)
- `security_headers: dict[str, str]`
- `third_party_scripts: list[ScriptInfo]`
- `cookies: list[CookieInfo]`

#### Code Scanner (`backend/app/scanner/code_scanner.py`)

| Responsibility | Implementation |
|---|---|
| AST parsing | tree-sitter for Python, JavaScript, TypeScript, Java, Go |
| Symbol extraction | Functions, classes, variables, imports, decorators |
| DB model detection | SQLAlchemy/Django/Sequelize/JPA model class patterns |
| Route extraction | FastAPI/Flask/Express/Spring route decorator patterns |
| PII field detection | Field name matched against PII taxonomy + Indian ID validators |
| Data flow edges | Function calls, imports, variable assignments across files |

**Output:** `CodeScanResult` dataclass containing:
- `files: list[FileInfo]` (path, language, AST)
- `symbols: list[SymbolInfo]` (functions, classes, with file:line)
- `db_models: list[ModelInfo]` (table name, columns with types)
- `routes: list[RouteInfo]` (method, path, handler function)
- `pii_fields: list[PIIField]` (field name, category, sensitivity, location)
- `data_flow_edges: list[DataFlowEdge]` (source -> sink with edge type)

---

### 2.2 Context Engine

The context engine builds a persistent understanding of the codebase that the rules engine and AI layer consume.

#### Code Graph (`backend/app/context/code_graph.py`)

A directed graph stored in PostgreSQL. Nodes are symbols (functions, classes, routes, models). Edges represent relationships.

**Edge types:**
| Type | Meaning | Example |
|---|---|---|
| `calls` | Function A calls function B | `register_user()` calls `save_to_db()` |
| `imports` | File A imports from file B | `routes.py` imports `models.User` |
| `data_pass` | Variable flows from function A to B | `email` passed as argument |
| `db_write` | Function writes to a DB model | `session.add(User(email=x))` |
| `db_read` | Function reads from a DB model | `User.query.filter_by(email=x)` |
| `api_send` | Function sends data to external API | `requests.post(analytics_url, data)` |
| `log_output` | Function logs data | `logger.info(f"user: {email}")` |

#### PII Flow Map (`backend/app/context/pii_flow.py`)

For each detected PII field, trace its complete lifecycle:

```
Source (where PII enters)
  → Transform (what happens to it: hash, encrypt, mask, log, nothing)
    → Sink (where it ends up: DB column, API call, log file, response body)
```

Each flow path records:
- Which PII category (email, aadhaar, pan, phone, name, address, dob)
- Whether consent is checked before processing
- Whether encryption/hashing is applied
- Whether a retention/TTL policy exists
- Whether it reaches a third party

#### Context Assembler (`backend/app/context/assembler.py`)

Packs the right context for each analysis task. For a given finding or rule check:

1. Identify the relevant code locations
2. Traverse the code graph: pull callers (2 hops upstream) and callees (2 hops downstream)
3. Pull all PII flow paths that pass through the relevant code
4. Retrieve similar code patterns from the semantic index
5. Pack into a structured context object for the AI prompt

This ensures the AI sees the full picture without receiving the entire codebase.

---

### 2.3 PII Detection (`backend/app/pii/`)

#### Taxonomy (`taxonomy.py`)

| Category | Sensitivity | DPDP Sections | Examples |
|---|---|---|---|
| `name` | medium | s.2(t), s.5 | first_name, last_name, full_name |
| `email` | medium | s.2(t), s.5 | email, email_address, user_email |
| `phone` | medium | s.2(t), s.5 | phone, mobile, contact_number |
| `aadhaar` | critical | s.2(t), s.8(5), s.9 | aadhaar, aadhaar_number, uid |
| `pan` | critical | s.2(t), s.8(5) | pan, pan_number, pan_card |
| `passport` | critical | s.2(t), s.8(5) | passport, passport_number |
| `voter_id` | high | s.2(t), s.8(5) | voter_id, epic_number |
| `gstin` | high | s.2(t) | gstin, gst_number |
| `dob` | high | s.2(t), s.9 | dob, date_of_birth, birthday |
| `address` | medium | s.2(t) | address, street, city, pincode |
| `ip_address` | low | s.2(t) | ip, ip_address, remote_addr |
| `financial` | critical | s.2(t), s.8(5) | bank_account, ifsc, credit_card |
| `biometric` | critical | s.2(t), s.8(5), s.10 | fingerprint, face_id, retina |
| `health` | critical | s.2(t), s.8(5) | diagnosis, medical_record, blood_group |
| `password` | critical | s.8(5) | password, passwd, secret, pin |

#### Indian ID Validators (`indian_ids.py`)

| ID Type | Validation | Pattern |
|---|---|---|
| Aadhaar | Verhoeff checksum (12 digits) | `[2-9]{1}[0-9]{11}` |
| PAN | Format + check character | `[A-Z]{5}[0-9]{4}[A-Z]{1}` |
| GSTIN | State code + PAN + entity + check | `[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}` |
| IFSC | Bank + branch code | `[A-Z]{4}0[A-Z0-9]{6}` |
| Passport | Series + number | `[A-Z]{1}[0-9]{7}` |
| Voter ID | State code + number | `[A-Z]{3}[0-9]{7}` |
| Card number | Luhn checksum | 13-19 digits passing Luhn |

#### Field Classifier (`field_classifier.py`)

Classification pipeline (in order, first match wins):
1. **Exact match** against known PII field names (lowercase normalized)
2. **Token match** against PII alias tokens (e.g., "usr_email" contains "email")
3. **Negative filter** rejects UI/config fields (e.g., "email_template", "phone_format", "name_label")
4. **Value validation** if a string literal is found nearby, run format validators

---

### 2.4 DPDP Rules Engine (`backend/app/rules/`)

The engine runs each rule checker against the scan results and context. Every rule checker is a pure function:

```python
def check(scan_result, context) -> RuleResult:
    """
    Returns:
        RuleResult(
            rule_id="R4",
            rule_name="Consent",
            status="gap",           # compliant | gap | violation | not_applicable
            score=0.5,              # 0.0 to 1.0
            evidence="Consent checkbox found but pre-checked",
            dpdp_section="s.6(1)",
            dpdp_rule="Rule 4"
        )
    """
```

#### Rule Orchestrator (`engine.py`)

```python
RULE_CHECKERS = [
    R03NoticeChecker,
    R04ConsentChecker,
    R05ChildrenChecker,
    R06SecurityChecker,
    R07BreachChecker,
    R08DPIAChecker,
    R09SDFChecker,
    R10RightsChecker,
    R11DPBChecker,
    R12VerificationChecker,
    RetentionChecker,
]

def run_all_rules(scan_result, context) -> list[RuleResult]:
    return [checker.check(scan_result, context) for checker in RULE_CHECKERS]
```

#### Rule Check Details

**R03 Notice Checker**
```
PASS if: privacy notice exists AND appears before data collection AND contains purpose list
GAP if:  notice exists but missing purpose list or DPO contact
FAIL if: no notice found at all
Section: DPDP Act s.5; Rules 2025 Rule 3
```

**R04 Consent Checker**
```
PASS if: consent mechanism + not pre-checked + granular + withdrawal exists + consent checked in code before processing
GAP if:  consent exists but not granular or no withdrawal mechanism
FAIL if: no consent mechanism OR pre-checked checkbox OR no server-side consent check
Section: DPDP Act s.6, s.7; Rules 2025 Rule 4
```

**R05 Children Checker**
```
PASS if: age gate + parental consent flow + no tracking for minors
GAP if:  age field exists but no parental consent logic
FAIL if: no age verification at all when collecting data
N/A if:  service explicitly adult-only with enforcement
Section: DPDP Act s.9; Rules 2025 Rule 5
```

**R06 Security Checker**
```
PASS if: PII encrypted at rest + HTTPS enforced + auth on PII endpoints + PII not logged plaintext + passwords hashed
GAP if:  some safeguards present but not all
FAIL if: PII stored plaintext OR no HTTPS OR PII in logs
Section: DPDP Act s.8(5); Rules 2025 Rule 6
```

**R07 Breach Checker**
```
PASS if: breach model/table + notification mechanism + 72hr timeline logic
GAP if:  breach model exists but no notification endpoint
FAIL if: no breach handling at all
Section: DPDP Act s.8(6); Rules 2025 Rule 7
```

**R08 DPIA Checker**
```
PASS if: DPIA document/assessment exists for high-risk processing
GAP if:  partial assessment or outdated
FAIL if: no DPIA at all when processing sensitive PII at scale
Section: Rules 2025 Rule 8
```

**R09 SDF Checker**
```
PASS if: DPO role defined + audit mechanism + algorithmic fairness checks
GAP if:  some SDF obligations met
FAIL if: none of the SDF obligations implemented
N/A if:  not a Significant Data Fiduciary
Section: DPDP Act s.10; Rules 2025 Rule 9
```

**R10 Rights Checker**
```
PASS if: access + correction + erasure + nomination endpoints all exist
GAP if:  some rights endpoints missing
FAIL if: no rights endpoints at all
Section: DPDP Act s.11-14; Rules 2025 Rule 10
```

**R11 DPB Checker**
```
PASS if: complaint/grievance mechanism + DPB reporting readiness
GAP if:  grievance exists but no DPB integration
FAIL if: no complaint mechanism
Section: Rules 2025 Rule 11
```

**R12 Verification Checker**
```
PASS if: audit trail + evidence collection + documentation of processing
GAP if:  partial logging
FAIL if: no audit trail
Section: Rules 2025 Rule 12
```

**Retention Checker**
```
PASS if: TTL/expiry on PII data + deletion jobs + retention policy config
GAP if:  some retention logic but not covering all PII
FAIL if: PII stored with no retention/expiry/deletion mechanism
Section: DPDP Act s.8(7)
```

---

### 2.5 Grounded RAG Layer (`backend/app/ai/`)

#### Statutory Corpus (`backend/app/corpus/`)

The DPDP Act 2023 and the notified DPDP Rules 2025 (23 rules) are structured as Python data:

```python
@dataclass
class StatutoryChunk:
    source: str             # "act" or "rules"
    section_id: str         # "s.6(1)" or "rule_4"
    section_title: str      # "Consent"
    text: str               # actual statutory text
    citation_label: str     # "DPDP Act 2023, Section 6(1)"
```

Chunks are embedded using Gemini `text-embedding-004` (768 dimensions) and stored in the `dpdp_corpus` table with pgvector.

#### Retrieval (`backend/app/ai/grounded_analysis.py`)

For each finding from the rules engine:

1. Embed the finding text
2. Query pgvector for top-5 most similar statutory chunks
3. Build a constrained prompt:

```
CONTEXT:
- Code: {file_path}:{line_number} — {code_snippet}
- Data flow: {pii_source} → {transforms} → {pii_sink}
- Rule result: {rule_id} {status} — {evidence}

STATUTORY PROVISIONS (use ONLY these for citations):
{retrieved_chunk_1.citation_label}: {retrieved_chunk_1.text}
{retrieved_chunk_2.citation_label}: {retrieved_chunk_2.text}
...

TASK: For the finding above, produce:
1. A plain-English explanation
2. The exact statutory citation from the provisions above
3. A direct quote from the cited provision
4. A suggested code fix

OUTPUT FORMAT: JSON
```

4. Call Gemini (temperature 0.1)
5. Parse structured response

#### Guardrail (`backend/app/ai/guardrail.py`)

Every AI-generated finding passes three checks before delivery:

| Check | Method | On failure |
|---|---|---|
| Citation exists | Verify `section_id` exists in corpus table | Mark `guardrail_passed = false` |
| Quote matches | Fuzzy match quoted text against corpus chunk (threshold > 0.85) | Strip the quote, flag for review |
| Entailment | Check if the claim logically follows from the provision (keyword overlap + negation check) | Add disclaimer "requires manual verification" |

Findings that fail the guardrail are still shown but visually marked as unverified.

---

### 2.6 Scorecard (`backend/app/scorecard/`)

#### Scoring Algorithm (`scorer.py`)

```
Per-rule score: 0.0 (violation) to 1.0 (compliant)
  - 1.0 = all checks pass
  - 0.5 = some checks pass (gap)
  - 0.0 = all checks fail (violation)
  - null = not applicable

Overall score = weighted average of applicable rule scores

Weights:
  R04 Consent:    15%  (core DPDP obligation)
  R06 Security:   15%  (highest penalty exposure)
  R03 Notice:     12%
  R10 Rights:     12%
  Retention:      10%
  R05 Children:   8%
  R07 Breach:     8%
  R08 DPIA:       5%
  R09 SDF:        5%
  R11 DPB:        5%
  R12 Verify:     5%

Grade mapping:
  90-100 = A (Compliant)
  75-89  = B (Substantially Compliant)
  50-74  = C (Partially Compliant)
  25-49  = D (Significant Gaps)
  0-24   = F (Non-Compliant)
```

---

### 2.7 Output Layer

#### API Response: Scorecard

```json
{
  "scan_id": "uuid",
  "scan_type": "code",
  "target": "sample-ecommerce-app",
  "overall_score": 35.0,
  "overall_grade": "D",
  "grade_label": "Significant Gaps",
  "rules": [
    {
      "rule_id": "R3",
      "name": "Notice",
      "dpdp_section": "s.5",
      "dpdp_rule": "Rule 3",
      "status": "violation",
      "score": 0.0,
      "evidence": "No privacy notice page found in codebase",
      "finding_count": 1
    }
  ],
  "summary": {
    "total_findings": 14,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 2,
    "pii_fields_detected": 8,
    "data_flow_paths_traced": 5
  }
}
```

#### API Response: Finding

```json
{
  "id": "uuid",
  "rule_id": "R6",
  "severity": "critical",
  "file": "models/user.py",
  "line": 47,
  "title": "Government ID stored without encryption",
  "description": "Aadhaar number is stored as a plaintext String column. Rule 6 requires encryption of personal data at rest. A plaintext column storing a government identifier does not satisfy this.",
  "citation": "DPDP Act 2023, Section 8(5); DPDP Rules 2025, Rule 6",
  "citation_text": "Every Data Fiduciary shall protect personal data in its possession or under its control by taking reasonable security safeguards to prevent personal data breach.",
  "data_flow": "Aadhaar enters at POST /api/kyc (routes.py:23) → stored as Column(String) in users table (models/user.py:47) → read by analytics report (reports.py:89) → sent to external API (integrations.py:34)",
  "suggested_fix": "aadhaar_number = Column(EncryptedType(String, key=settings.PII_ENCRYPTION_KEY))",
  "guardrail_passed": true,
  "ai_confidence": 0.95
}
```

#### React Frontend

| Component | Purpose |
|---|---|
| `ScanForm` | URL input field + file upload dropzone + scan button |
| `ScoreCard` | Radar chart (Recharts) showing 11 rule scores + overall grade badge |
| `RuleStatus` | Card per rule: name, section, status badge (green/amber/red), score bar |
| `FindingsList` | Sortable/filterable table of findings with severity badges and citations |
| `CodeViewer` | Syntax-highlighted code with the flagged line highlighted |
| `DataFlowGraph` | Visual flow: source → transforms → sink with PII labels |

---

## 3. Data Flow: End-to-End Request

```
User submits URL or uploads code
  │
  ▼
POST /api/scan/web  OR  POST /api/scan/code
  │
  ▼
Scanner runs (web_scanner.py or code_scanner.py)
  │  Produces: ScanResult with forms, PII fields, routes, models
  │
  ▼
Context Engine builds understanding
  │  code_graph.py: call graph + dependency edges
  │  pii_flow.py: trace each PII field source → transform → sink
  │  assembler.py: pack context for each analysis point
  │
  ▼
Rules Engine evaluates all 11 dimensions
  │  Each rule checker: scan_result + context → RuleResult
  │  Deterministic: no AI involved in verdict
  │
  ▼
Grounded RAG for each finding
  │  1. Embed finding text
  │  2. Retrieve top-5 statutory provisions from pgvector
  │  3. Gemini generates explanation + citation + fix
  │  4. Guardrail verifies citation and entailment
  │
  ▼
Scorecard computed
  │  Per-rule scores weighted → overall grade
  │
  ▼
Results stored in PostgreSQL
  │  scans + rule_results + findings + pii_fields + data_flow_edges
  │
  ▼
GET /api/scans/{id}/scorecard → React dashboard renders
```

---

## 4. Security Constraints

| Constraint | Implementation |
|---|---|
| No secrets in repo | All keys via env vars, `.env.example` committed, `.env` in `.gitignore` |
| Input validation | URL validated before crawl, file size capped at 50MB, zip bomb check |
| No real PII | Only synthetic/sample data used for demos |
| CORS restricted | `CORS_ORIGINS` env var, not `*` |
| SQL injection | SQLAlchemy parameterized queries only, no raw SQL |
| SSRF protection | Web scanner URL validated against private IP ranges before crawl |
| AI prompt injection | User input sanitized before inclusion in Gemini prompts |
| Rate limiting | Scanner endpoints rate-limited to prevent abuse |

---

## 5. Deployment

```yaml
# docker-compose.yml
services:
  db:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_DB: dpdpa_reviewer
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  backend:
    build: ./backend
    environment:
      DATABASE_URL: postgresql+asyncpg://postgres:${DB_PASSWORD}@db:5432/dpdpa_reviewer
      GEMINI_API_KEY: ${GEMINI_API_KEY}
    ports:
      - "8000:8000"
    depends_on:
      - db

  frontend:
    build: ./frontend
    ports:
      - "5173:80"
    depends_on:
      - backend

volumes:
  pgdata:
```

---

## 6. Judging Criteria Alignment

| Criterion (weight) | How this architecture addresses it |
|---|---|
| Technical Architecture (15%) | Clean layer separation, each module independently testable, no circular dependencies |
| AI/ML Rigour (15%) | Grounded RAG with citation verification, guardrail prevents hallucination, deterministic verdict |
| Explainability (10%) | Every finding shows: code location, data flow trace, statutory citation, quote from law |
| Regulatory Alignment (10%) | Every scored dimension mapped to named provisions of the Act and the notified Rules; every finding cites one |
| Scalability (10%) | Async FastAPI, pgvector scales to large corpus, tree-sitter handles big codebases |
| Impact (10%) | Self-check before DPDP enforcement deadline, catches violations before deployment |
| Innovation (10%) | Data flow context engine, cross-file PII tracing, AI-explains-but-never-decides pattern |
