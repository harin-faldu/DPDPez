# DPDPA Compliance Self-Check — Backend File & Module Guide

This document is a comprehensive, file-by-file reference for the backend codebase. It details **what each file does**, **how it works internally**, **what it is used for**, and **where it is called / imported**.

---

## 1. High-Level Flow Diagram

The backend pipeline follows a strict unidirectional data flow:

```
[HTTP Request]
       │
       ▼
app/api/scan.py  ──(starts background job)──▶  app/pipeline.py
                                                      │
       ┌──────────────────────────────────────────────┴──────────────────────────────────────────────┐
       ▼                                                                                              ▼
[Web Scan Pipeline]                                                                        [Code Scan Pipeline]
app/scanner/web_scanner.py                                                         app/scanner/code_scanner.py
  - Playwright Headless Chromium                                                     - Tree-sitter AST queries
  - Forms, inputs, cookies, headers                                                  - Routes, symbols, models, PII
       │                                                                                              │
       │                                                                                              ▼
       │                                                                             app/context/code_graph.py
       │                                                                             app/context/pii_flow.py
       │                                                                               - Trace Ingress -> Sinks
       │                                                                                              │
       └──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                      ▼
                                            app/rules/engine.py
                                   (Evaluates R03 – R12 Deterministically)
                                                      │
                                                      ▼
                                         app/context/assembler.py
                                   (Packs bounded prompt & evidence)
                                                      │
                                                      ▼
                                       app/ai/grounded_analysis.py
                                 ├── app/ai/retrieval.py (pgvector search)
                                 ├── app/ai/gateway.py (Gemini / DeepSeek)
                                 └── app/ai/guardrail.py (Quote verify)
                                                      │
                                                      ▼
                                          app/scorecard/scorer.py
                                     (Calculates Grade: A to F)
                                                      │
                                                      ▼
                                         PostgreSQL (app/models/)
                                                      │
                                                      ▼
                                          app/scorecard/report.py
                                            (WeasyPrint PDF)
```

---

## 2. Complete Request Lifecycle: ZIP Upload → Compliance Result

> This section traces a single real request step by step — from the user selecting a ZIP file in the frontend through every layer of the backend until the result appears on screen.

### Step 0 — User selects a ZIP and clicks "Scan"

The frontend sends a multipart HTTP request:
```
POST /api/scan/code
Content-Type: multipart/form-data
Body: file = myapp.zip
```

---

### Step 1 — [`api/scan.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/api/scan.py) — Request received and ZIP validated

**Handler:** `scan_code()` (line 60)

1. **File extension check**: Ensures suffix is `.zip`, `.gz`, `.tgz`, or `.tar`. Returns `400` otherwise.
2. **Unique scan ID minted**: `scan_id = uuid.uuid4()` — this is the ID the frontend will poll.
3. **Workspace created**: A dedicated directory is made at `workspace/<scan_id>/`.
4. **`_save_upload()`** streams the file to disk **1 MB at a time**:
   - Enforces `MAX_UPLOAD_SIZE_MB` (default 50 MB) limit to prevent memory exhaustion.
   - Any excess triggers `HTTP 413`.
5. **`_safe_extract()`** inspects every archive member *before* extracting:
   - Rejects absolute paths (`/etc/passwd`).
   - Rejects path-traversal members (`../../etc/shadow`).
   - Rejects symlinks and hard links in tar files.
   - Checks that total uncompressed size won't exceed 20× the upload limit (zip-bomb protection).
   - Extracts to `workspace/<scan_id>/src/`.
6. **`Scan` row created** in PostgreSQL with `status = PENDING`.
7. **Background task launched**: `asyncio.create_task(_run_code_task(scan_id, extract_root))`
8. **Response returned immediately** (HTTP 202):
   ```json
   { "scan_id": "abc123...", "status": "pending" }
   ```

> The HTTP request completes here. The frontend starts polling `GET /api/scan/{scan_id}` every few seconds.

---

### Step 2 — [`pipeline.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/pipeline.py) — `run_code_scan()` starts

Background task opens a new independent database session and calls `run_code_scan(db, scan_id, root_path)`:

1. **Status → `SCANNING`**: `scan.status = "scanning"`, committed to DB.
2. Calls `code_scanner.scan_directory(root_path)` → returns `CodeScanResult`.
3. Updates `scan.files_scanned = len(code_result.files)`.
4. Builds `CodeGraph(code_result)` — an in-memory directed call graph.
5. Calls `pii_flow.trace_flows(code_result, graph)` → returns `List[PIIFlowPathInfo]`.
6. Calls `rules_engine.run_all(code_result=code_result, flows=flows)` → returns `List[RuleVerdict]`.
7. Calls `_persist_code_evidence(db, scan, code_result, flows)` — saves raw PII fields and data flow edges to DB.
8. Calls `_finish(db, scan, verdicts, ...)` — kicks off the AI phase.

---

### Step 3 — [`scanner/code_scanner.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scanner/code_scanner.py) — Static AST Analysis

`scan_directory(root_path)` walks the extracted `src/` tree.

For each supported file (`.py`, `.js`, `.ts`, `.java`, `.go`):

1. **Language detected** by extension → correct Tree-sitter grammar loaded.
2. **CST built**: File content parsed into a Concrete Syntax Tree.
3. **S-expression queries** run against the tree to extract:
   - **Routes**: `@app.post("/register")`, `router.post("/signup")`, `@PostMapping("/user")`.
   - **Functions**: Names, parameters, return types.
   - **Call edges**: `create_user()` → `db.add(user)`.
   - **ORM models**: SQLAlchemy `class User(Base)`, Prisma `model User`, Django `class User(Model)`.
   - **PII fields**: Column names like `aadhaar`, `dob`, `pan_number` classified via `field_classifier.py`.
   - **Sinks**: `print(user.phone)`, `logger.info(aadhaar)`, third-party SDK calls (`sentry.capture`, `segment.track`).

Result: a `CodeScanResult` containing all routes, symbols, models, PII fields, and data flow edges.

---

### Step 4 — [`context/code_graph.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/context/code_graph.py) + [`context/pii_flow.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/context/pii_flow.py) — Graph & Data Flow Tracing

1. **`CodeGraph`** is built from the `CodeScanResult`:
   - Nodes: routes, functions, models, sinks.
   - Edges: call relationships (who calls whom, which route reaches which model).

2. **`pii_flow.trace_flows()`** walks the graph:
   - Finds all HTTP ingress routes that collect PII fields.
   - Performs BFS from each route through intermediate function calls.
   - Identifies where PII arrives: a database model (`users.aadhaar`) or an external sink (`logger`, third-party).
   - For each flow, records:
     - Whether a consent check exists in the call chain.
     - Whether encryption is applied before storage.
     - Whether a retention/expiry policy exists.
     - Whether data crosses a third-party boundary.

Result: `List[PIIFlowPathInfo]` — e.g. `"POST /register → create_user() → User.aadhaar → db.save() — no consent check"`.

---

### Step 5 — [`rules/engine.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/engine.py) — Deterministic Rule Evaluation

`run_all()` iterates over all 11 `RULE_CHECKERS` and calls `checker.check(code_result=..., flows=...)` on each.

Each rule checker returns a `RuleVerdict` with:
- **`status`**: `"compliant"` | `"gap"` | `"violation"` | `"not_applicable"`
- **`score`**: `0.0` to `1.0` (fraction of sub-checks that passed)
- **`checks`**: List of individual `RuleCheck` objects with `passed: bool` and `detail: str`
- **`evidence`**: Human-readable summary of what was found

Example — `r06_security.check()` evaluating PII flows:
```
Check 1: "Aadhaar field found in User model"           PASS (detected)
Check 2: "POST /register → User.aadhaar no encryption" FAIL
Check 3: "logger.info(user.aadhaar) — cleartext log"   FAIL
Check 4: "Secure cookie flag missing"                   FAIL

score = 1/4 = 0.25 → status = "gap"
```

All 11 verdicts collected. **No AI is involved at this stage. Verdicts are 100% deterministic.**

---

### Step 6 — [`pipeline.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/pipeline.py) `_finish()` — Persist Rule Results, Status → ANALYZING

1. Every `RuleVerdict` is saved as a `RuleResult` row in PostgreSQL (rule ID, status, score, weight, evidence).
2. `scan.status = "analyzing"` committed.
3. For every verdict that is **not** `COMPLIANT` or `NOT_APPLICABLE`, `_create_finding()` is triggered.

---

### Step 7 — [`context/assembler.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/context/assembler.py) — Build LLM Context

`assemble_for_verdict(verdict, scan_result, graph, flows)` produces a token-budgeted `AnalysisContext`:

- **Code snippet**: First failing check's file and line, capped at `MAX_SNIPPET_LINES = 60`.
- **Callers/callees**: Up to 8 callers and 8 callees of the offending function.
- **PII flows**: Up to 6 flow paths relevant to the verdict's topic.

This strict budgeting ensures the LLM sees only the most relevant signal and isn't distracted by unrelated code.

---

### Step 8 — [`ai/grounded_analysis.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/grounded_analysis.py) — Retrieve Provisions + Generate Explanation

`explain_verdict(db, verdict, context, restrict_section_ids)`:

**Stage 8a — [`ai/retrieval.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/retrieval.py) — Statutory RAG Search:**
- Generates a query embedding using `gemini-embedding-001` for the rule topic.
- Performs cosine similarity (`<=>`) search against `corpus_chunks` in PostgreSQL (pgvector).
- Optionally **pins retrieval** to specific section IDs (e.g. `["s.8(5)", "rule_6"]`) declared by each rule checker via `RETRIEVAL_SECTION_IDS`.
- Returns top-K statutory passages above `RAG_MIN_SIMILARITY` threshold.

**Stage 8b — [`ai/gateway.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/gateway.py) — LLM Call:**
- System prompt tells the model: *"A deterministic rules engine already decided the verdict. Explain and cite — do NOT decide compliance."*
- Prompt contains: the rule verdict + evidence, the code snippet, and the retrieved statutory provisions.
- Model returns structured JSON:
  ```json
  {
    "title": "Aadhaar stored without encryption",
    "description": "The POST /register endpoint persists raw Aadhaar...",
    "citation": "DPDP Act 2023, Section 8(5)",
    "citation_text": "the Data Fiduciary shall implement...",
    "cited_section_ids": ["s.8(5)"],
    "suggested_fix": "Apply AES-256 encryption before db.add(user)...",
    "data_flow_summary": "Aadhaar flows from POST /register to users table without encryption",
    "confidence": 0.92
  }
  ```

**Stage 8c — [`ai/guardrail.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/guardrail.py) — Quote Verification:**
- Checks every `citation_text` the model produced.
- Verifies the quote actually exists verbatim (≥85% Levenshtein similarity) in the retrieved corpus chunks.
- If a quote is hallucinated, `guardrail_passed = False` is recorded and the citation is stripped/flagged.

---

### Step 9 — [`pipeline.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/pipeline.py) — Save `Finding` Row

A `Finding` row is committed to PostgreSQL with all fields:
- `rule_id`, `severity` (computed from rule weight and data sensitivity)
- `file_path`, `line_number`, `code_snippet`
- `title`, `description`, `citation`, `citation_text`, `cited_section_ids`
- `suggested_fix`, `data_flow_context`
- `ai_generated`, `ai_confidence`, `guardrail_passed`, `guardrail_notes`

This repeats for every non-compliant verdict.

---

### Step 10 — [`scorecard/scorer.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scorecard/scorer.py) — Calculate Final Grade

`scorer.compute(verdicts)`:

1. **Filters out** `NOT_APPLICABLE` verdicts (excluded from both numerator and denominator — avoids penalizing a code scan for missing web-only evidence).
2. **Weighted average**: Each rule has a configured weight reflecting legal risk:
   - R4 (Consent) = 15%, R6 (Security) = 15%, R3 (Notice) = 12%, R10 (Rights) = 12%, RET = 10%, etc.
3. Weights are **renormalized** to sum to 1.0 after excluding inapplicable rules.
4. **Score → Grade mapping**:
   - ≥90 → **A** (Compliant)
   - ≥75 → **B** (Substantially Compliant)
   - ≥50 → **C** (Partially Compliant)
   - ≥25 → **D** (Significant Gaps)
   - <25 → **F** (Non-Compliant)
5. `scan.overall_score` and `scan.overall_grade` updated.
6. `scan.status = "complete"`, `scan.completed_at = now()` committed.

---

### Step 11 — Frontend Poll Completes

The frontend polling `GET /api/scan/{scan_id}` receives:
```json
{ "status": "complete", "overall_score": 42.5, "overall_grade": "C", "files_scanned": 87 }
```
The UI navigates to the scorecard page.

---

### Step 12 — Frontend Loads Scorecard + Findings

```
GET /api/scorecard/{scan_id}              → overall score, grade, rule breakdown, penalty exposure
GET /api/findings/{scan_id}              → list of findings with severity filter
GET /api/findings/{scan_id}/{finding_id} → full finding detail, code snippet, citations
```

---

### Step 13 — User Downloads PDF Report (Optional)

```
GET /api/scorecard/{scan_id}/pdf
```

[`scorecard/report.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scorecard/report.py):
1. Queries all `Finding` and `RuleResult` rows for the scan.
2. Renders a Jinja2 HTML audit report template.
3. **WeasyPrint** compiles HTML → PDF with full styling.
4. Streamed back as `application/pdf` download.

---

### Full Timeline Summary

```
User action                                 File / Layer
─────────────────────────────────────────────────────────────────────────────
Select ZIP + click Scan    ──────────────▶  Frontend
POST /api/scan/code        ──────────────▶  api/scan.py
  Validate extension                        api/scan.py
  Stream to disk (size-limited)             api/scan.py : _save_upload()
  Check zip-bombs & path traversal          api/scan.py : _safe_extract()
  Create Scan row (PENDING)                 app/models/scan.py → PostgreSQL
  Spawn background asyncio task             api/scan.py
  Return 202 + scan_id                      api/scan.py
─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ background task starts ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
Set status → SCANNING                       pipeline.py
Walk all source files                       scanner/code_scanner.py
  Parse each file with Tree-sitter          code_scanner.py
  Extract routes, functions, models         code_scanner.py
  Classify PII fields                       pii/field_classifier.py
Build call graph (CodeGraph)                context/code_graph.py
Trace PII data flows (ingress → sinks)      context/pii_flow.py
Run 11 compliance rules (no AI)             rules/engine.py + r03..r12
Persist PII fields + data flow edges        pipeline.py : _persist_code_evidence()
Persist RuleResult rows                     pipeline.py : _finish()
Set status → ANALYZING                      pipeline.py : _finish()
For each non-compliant verdict:
  Assemble token-budgeted LLM context       context/assembler.py
  Vector search corpus for legal sections   ai/retrieval.py → pgvector
  Call Gemini/DeepSeek for explanation      ai/gateway.py
  Verify quotes are not hallucinated        ai/guardrail.py
  Save Finding row to PostgreSQL            pipeline.py : _create_finding()
Compute weighted score + letter grade       scorecard/scorer.py
Set status → COMPLETE + grade               pipeline.py : _finish()
─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ frontend poll sees COMPLETE ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
GET /api/scorecard/{id}                     api/scorecard.py
GET /api/findings/{id}                      api/findings.py
GET /api/scorecard/{id}/pdf  (optional)     scorecard/report.py → WeasyPrint
```

---

## 3. Root Backend Files

### [`backend/Dockerfile`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/Dockerfile)
- **What it does**: Defines the containerized environment for running the FastAPI application.
- **How it works**:
  - Uses `python:3.12-slim-bookworm` (Debian 12) to ensure native Playwright dependency compatibility.
  - Installs WeasyPrint system libraries (`libcairo2`, `libpango-1.0-0`, `libgdk-pixbuf-2.0-0`) and Playwright Chromium.
  - Exposes port `8000` and starts Uvicorn binding to `0.0.0.0:8000`.
- **Used for**: Building and launching the backend container via Docker Compose.
- **Where it is used**: Executed by `docker compose up --build`.

### [`backend/requirements.txt`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/requirements.txt)
- **What it does**: Declares all Python packages and versions.
- **Key dependencies**:
  - `fastapi`, `uvicorn`, `pydantic`: Web framework and async runtime.
  - `sqlalchemy`, `asyncpg`, `pgvector`: Async PostgreSQL ORM and vector similarity operations.
  - `google-generativeai`: Gemini models for generation and embeddings.
  - `tree-sitter`, `tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-typescript`, `tree-sitter-java`, `tree-sitter-go`: AST parsers for static code scanning.
  - `playwright`: Dynamic headless browser for web scanning.
  - `weasyprint`, `jinja2`: PDF scorecard generation.
- **Used for**: Installing runtime dependencies inside the container.

### [`backend/pytest.ini`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/pytest.ini)
- **What it does**: Pytest configuration file enabling `asyncio_mode = auto`.
- **Used for**: Running async test suites located in `backend/tests/`.

---

## 4. Core Framework & Orchestration (`backend/app/`)

### [`backend/app/main.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/main.py)
- **What it does**: The FastAPI application entrypoint and startup/shutdown lifecycle manager.
- **How it works**:
  - Runs `lifespan()` context manager on startup:
    1. Initializes database tables and `pgvector` extension via `init_db()`.
    2. Runs `_index_corpus_if_needed()`, checking if the DPDP Act corpus chunks and embeddings are present in PostgreSQL; if not, automatically indexes them.
  - Configures CORS middleware from `settings.cors_origins`.
  - Mounts API routers: `/api/scan`, `/api/findings`, `/api/scorecard`, `/api/health`.
- **Where it is used**: Called directly by Uvicorn (`uvicorn app.main:app`).

### [`backend/app/config.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/config.py)
- **What it does**: Application settings schema and environment variable loader.
- **How it works**: Uses `pydantic-settings` to parse `.env` variables, providing type validation and default values for:
  - Database credentials (`POSTGRES_*`, `DATABASE_URL`).
  - Model settings (`AI_PROVIDER`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_MODEL`, `GEMINI_EMBEDDING_MODEL`).
  - Application networking (`APP_HOST`, `APP_PORT`, `CORS_ORIGINS`).
  - Scanner limits (`MAX_CRAWL_PAGES`, `MAX_FILES_PER_SCAN`, `SCAN_WORKSPACE_DIR`).
  - RAG tuning parameters (`RAG_TOP_K`, `RAG_MIN_SIMILARITY`, `GUARDRAIL_QUOTE_THRESHOLD`).
- **Where it is used**: Imported throughout the backend via `from app.config import settings`.

### [`backend/app/database.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/database.py)
- **What it does**: Async database engine, session factory, and schema initialization.
- **How it works**:
  - Sets up `create_async_engine(settings.database_url)` with pooling.
  - Defines `SessionLocal = async_sessionmaker(engine, expire_on_commit=False)`.
  - Provides `get_db()` dependency generator for FastAPI routes.
  - Runs `init_db()` which executes `CREATE EXTENSION IF NOT EXISTS vector` and `Base.metadata.create_all()`.
- **Where it is used**: In `main.py` (during boot) and injected into FastAPI route handlers.

### [`backend/app/contracts.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/contracts.py)
- **What it does**: Canonical in-memory dataclasses and Pydantic models exchanged between pipeline stages.
- **Key data structures**:
  - `WebScanResult`, `PageEvidence`, `FormInfo`, `CookieInfo`: Captured web elements.
  - `CodeScanResult`, `RouteInfo`, `SymbolInfo`, `ModelInfo`: Extracted AST structures.
  - `PIIFlowPathInfo`: Reconstructed data movement path (route → functions → sink).
  - `RuleVerdict`, `RuleCheck`: Normalized rule evaluation output.
  - `AnalysisContext`: Token-budgeted context prepared for the LLM.
  - `GroundedExplanation`, `RetrievedProvision`: AI output and RAG corpus structures.
- **Where it is used**: Acts as the common vocabulary across `scanner/`, `context/`, `rules/`, `ai/`, and `pipeline.py`.

### [`backend/app/pipeline.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/pipeline.py)
- **What it does**: The central pipeline controller that orchestrates the entire scan workflow.
- **How it works**:
  - `run_web_scan()`: Calls `web_scanner.scan_url()`, feeds evidence into `rules_engine.run_all()`, passes verdicts to `grounded_analysis.py` for AI explanation, computes score via `scorer.py`, and commits models to the database.
  - `run_code_scan()`: Calls `code_scanner.scan_directory()`, builds `CodeGraph`, traces data flows with `pii_flow.py`, executes `rules_engine.run_all()`, runs grounded AI analysis, computes grade, and persists findings.
  - `_finish()`: Persists `RuleResult` rows, triggers `_create_finding()` for each gap/violation, computes final score.
  - `_create_finding()`: Calls assembler → retrieval → gateway → guardrail per verdict.
  - `_retrieval_ids_for()`: Reads `RETRIEVAL_SECTION_IDS` from each checker to pin RAG to the right legal sections.
- **Where it is used**: Enqueued as a background task by `app/api/scan.py`.

---

## 5. API Endpoints (`backend/app/api/`)

### [`backend/app/api/scan.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/api/scan.py)
- **What it does**: Handles scan submissions, archive validation, and status polling.
- **Endpoints**:
  - `POST /api/scan/web`: Accepts `{ "url": "..." }`, runs SSRF guard via `url_guard.py`, creates a `Scan` record, and enqueues `run_web_scan`.
  - `POST /api/scan/code`: Accepts ZIP/tar archive upload, streams to disk (`_save_upload`), validates against zip-bombs and path traversal (`_safe_extract`), creates a `Scan` record, and enqueues `run_code_scan`.
  - `GET /api/scan/{scan_id}`: Returns scan status (`pending`, `scanning`, `analyzing`, `complete`, `failed`), score, grade, and progress counts.
- **Where it is used**: Called by frontend scan forms and polling hooks.

### [`backend/app/api/scorecard.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/api/scorecard.py)
- **What it does**: Delivers aggregated compliance scores, penalty exposure, and downloadable audit reports.
- **Endpoints**:
  - `GET /api/scorecard/{scan_id}`: Returns overall score (0–100), letter grade (A to F), per-rule breakdown, and statutory maximum penalty exposure.
  - `GET /api/scorecard/{scan_id}/pdf`: Compiles findings and scorecards into a formatted PDF using WeasyPrint and streams it as a file download.
- **Where it is used**: Called by frontend scorecard dashboards and export actions.

### [`backend/app/api/findings.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/api/findings.py)
- **What it does**: Queries and filters detailed audit findings.
- **Endpoints**:
  - `GET /api/findings/{scan_id}`: Lists findings with optional severity filter (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - `GET /api/findings/{scan_id}/{finding_id}`: Returns detailed finding data, including verbatim code snippets, AST line numbers, flow paths, statutory citations, and AI-generated fix suggestions.
- **Where it is used**: Called by frontend findings tables and drawer panels.

### [`backend/app/api/health.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/api/health.py)
- **What it does**: Health check probe (`GET /api/health`).
- **How it works**: Pings PostgreSQL and verifies AI provider credentials are configured.
- **Where it is used**: Used by Docker health checks and monitoring probes.

---

## 6. Scanner Engine (`backend/app/scanner/`)

### [`backend/app/scanner/web_scanner.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scanner/web_scanner.py)
- **What it does**: Automated browser crawler for public web applications.
- **How it works**:
  - Uses Playwright headless Chromium to render JavaScript-heavy signup, login, and contact forms.
  - Inspects the DOM for form inputs, labels, and pre-ticked or unticked consent checkboxes.
  - Finds privacy policy, terms of service, and grievance redressal links.
  - Inspects HTTP network response headers for security flags (`HSTS`, `CSP`, `X-Frame-Options`).
  - Collects first-party and third-party tracking cookies.
- **Where it is used**: Called by `pipeline.run_web_scan()`.

### [`backend/app/scanner/url_guard.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scanner/url_guard.py)
- **What it does**: SSRF (Server-Side Request Forgery) prevention guardrail.
- **How it works**: Resolves domain names to IP addresses and rejects:
  - Private RFC 1918 IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Localhost (`127.0.0.1`, `::1`).
  - Link-local / metadata IPs (`169.254.169.254`).
  - Non-HTTP/HTTPS schemes.
- **Where it is used**: Called in `api/scan.py` before creating any web scan record.

### [`backend/app/scanner/code_scanner.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scanner/code_scanner.py)
- **What it does**: Multi-language static code analysis engine powered by Tree-sitter.
- **How it works**:
  - Supports Python, JavaScript, TypeScript, Java, and Go.
  - Builds Concrete Syntax Trees (CST) and executes Tree-sitter S-expression queries to extract:
    1. **HTTP Ingress Endpoints**: FastAPI `@app.post`, Express `router.post`, Spring `@PostMapping`, Gin `r.POST`.
    2. **Functions & Calls**: Caller-callee pairs and parameter passing.
    3. **Database Entities**: SQLAlchemy models, Django models, Prisma schemas, Mongoose schemas.
    4. **PII Fields**: Identifies sensitive personal data in model attributes and request schemas.
    5. **External Sinks**: Unencrypted logging (`print`/`logger`), Sentry, Datadog, third-party analytics calls.
- **Where it is used**: Called by `pipeline.run_code_scan()`.

---

## 7. PII Classification & Indian Statutory Taxonomy (`backend/app/pii/`)

### [`backend/app/pii/taxonomy.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/pii/taxonomy.py)
- **What it does**: Catalog of personal data identifiers categorized under the DPDP Act 2023.
- **How it works**: Defines categories, sensitivity ratings, and matching patterns for:
  - Standard Personal Identifiers (name, email, mobile phone).
  - Indian Government Identifiers (Aadhaar, PAN, Voter ID / EPIC, Passport).
  - Financial Data (bank accounts, UPI IDs, IFSC codes, credit card numbers).
  - Sensitive / Health / Biometric Data.
  - Children's Identifiers (DOB, age, school, guardian information).
- **Where it is used**: Used by `field_classifier.py` and rule evaluators.

### [`backend/app/pii/indian_ids.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/pii/indian_ids.py)
- **What it does**: Exact checksum and format validators for Indian identity documents.
- **How it works**:
  - Implements the **Verhoeff algorithm** for 12-digit Aadhaar validation.
  - Validates 10-digit alphanumeric PAN formats (`[A-Z]{5}[0-9]{4}[A-Z]`).
  - Validates Passport, Driving License, and Voter ID patterns.
- **Where it is used**: In `field_classifier.py` to identify hardcoded mock data, test fixtures, or seed data.

### [`backend/app/pii/field_classifier.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/pii/field_classifier.py)
- **What it does**: High-speed classifier that inspects variable, form, and column names.
- **How it works**: Normalizes casing (`user_aadhaar`, `dobUser`, `guardian-email`) and applies keyword matching and regexes from `taxonomy.py` to classify fields into statutory categories.
- **Where it is used**: Used by `code_scanner.py` and `web_scanner.py`.

---

## 8. Context & Graph Engine (`backend/app/context/`)

### [`backend/app/context/code_graph.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/context/code_graph.py)
- **What it does**: Graph model representing code architecture and call dependencies.
- **How it works**: Connects routes → intermediate controller/service functions → database models/sinks. Provides BFS graph search to find reachability and call chains.
- **Where it is used**: In `pipeline.py` and `pii_flow.py`.

### [`backend/app/context/pii_flow.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/context/pii_flow.py)
- **What it does**: Traces the path of personal data across the software architecture.
- **How it works**:
  - Matches ingress routes collecting PII to downstream database models or external network sinks.
  - Builds complete `PIIFlowPathInfo` chains showing where data enters, transforms, and is stored or transmitted.
  - Flags flows missing consent checks, encryption, retention limits, or crossing third-party boundaries.
- **Where it is used**: Evaluated in rules `r06_security`, `r04_consent`, and `retention`.

### [`backend/app/context/assembler.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/context/assembler.py)
- **What it does**: Assembles a bounded, token-capped context package for the LLM.
- **How it works**: Enforces strict budgets (`MAX_SNIPPET_LINES = 60`, `MAX_FLOWS = 6`, `MAX_CALLERS = 8`) to assemble only relevant code snippets and rule evidence, preventing LLM context overflow and hallucination.
- **Where it is used**: Called in `pipeline.py` before invoking `grounded_analysis.py`.

---

## 9. Deterministic Rules Engine (`backend/app/rules/`)

All rules output deterministic verdicts (`compliant`, `gap`, `violation`, `not_applicable`) based on code or web evidence — **zero AI involvement**:

### [`backend/app/rules/engine.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/engine.py)
- **What it does**: Rule registry and execution coordinator.
- **How it works**: Runs all 11 checkers against `WebScanResult` or `CodeScanResult` + `PIIFlowPaths` and returns a list of `RuleVerdict` objects. Provides `build_verdict()`, `score_from_checks()`, and `status_from_score()` helpers used by every rule module.
- **Where it is used**: Called by `pipeline.py`.

### [`backend/app/rules/evidence.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/evidence.py)
- **What it does**: Helper library to extract clean code snippets, line numbers, and web elements as evidence strings for verdicts.

### Compliance Rules:

| File | DPDP Section | What it checks |
|---|---|---|
| [`r03_notice.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r03_notice.py) | Section 5 | Privacy notice present before data collection; purposes stated; accessible in scheduled Indian languages. |
| [`r04_consent.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r04_consent.py) | Section 6 | Consent free, specific, informed, unconditional. Flags pre-ticked boxes or forced bundling of terms. |
| [`r05_children.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r05_children.py) | Section 9 | Collection of minors' data, behavioral monitoring, or targeted advertising directed at children. |
| [`r06_security.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r06_security.py) | Section 8(5) | HTTPS, HSTS, Secure/HttpOnly cookie attributes; detects hardcoded credentials or cleartext PII logging. |
| [`r07_breach.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r07_breach.py) | Section 8(6) | Incident reporting endpoints and breach notification mechanisms to the DPB and data principals. |
| [`r08_dpia.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r08_dpia.py) | Section 10 | High-risk processing triggers that legally require a Data Protection Impact Assessment. |
| [`r09_sdf.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r09_sdf.py) | Section 10 | Whether processing scale, sensitivity, or risk profile classifies the entity as a Significant Data Fiduciary. |
| [`r10_rights.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r10_rights.py) | Sections 11–14 | Mechanisms supporting Right to Access (s.11), Correction/Erasure (s.12), Grievance Redressal (s.13), Nomination (s.14). |
| [`r11_dpb.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r11_dpb.py) | Section 13 | Clear DPO contact disclosure and grievance escalation paths to the Data Protection Board of India. |
| [`r12_verification.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/r12_verification.py) | Section 9(1) | Verifiable parental consent mechanisms before collecting personal data of children. |
| [`retention.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/rules/retention.py) | Section 8(7) | Storage limitation policies, TTL/expiration fields, and automated deletion logic. |

---

## 10. Statutory Corpus & Vector Database (`backend/app/corpus/`)

### [`backend/app/corpus/dpdp_act.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/corpus/dpdp_act.py)
- **What it does**: Stores the verbatim legal text of the **Digital Personal Data Protection Act, 2023** (Act 22 of 2023).
- **How it works**: Structured into chapters, sections, sub-clauses, and penalty schedule mappings.
- **Where it is used**: Loaded during corpus indexing by `indexer.py`.

### [`backend/app/corpus/dpdp_rules.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/corpus/dpdp_rules.py)
- **What it does**: Stores statutory rules, draft compliance rules, and timeline obligations.
- **Where it is used**: Loaded during corpus indexing by `indexer.py`.

### [`backend/app/corpus/chunker.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/corpus/chunker.py)
- **What it does**: Chunks the legal texts along section and sub-clause boundaries.
- **How it works**: Preserves statutory metadata (Act name, Section number, Title) in every chunk rather than using arbitrary character splits — ensuring citations are always attributable.
- **Where it is used**: In `indexer.py`.

### [`backend/app/corpus/indexer.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/corpus/indexer.py)
- **What it does**: Generates embeddings and writes statutory chunks to PostgreSQL.
- **How it works**:
  - Uses `gemini-embedding-001` (or `text-embedding-004`) to generate 768-dimensional embeddings.
  - Inserts chunks into the `corpus_chunks` table with `pgvector`.
- **Where it is used**: Called at startup in `main.py` if the corpus table is empty.

---

## 11. AI Grounding & Anti-Hallucination Guardrails (`backend/app/ai/`)

### [`backend/app/ai/gateway.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/gateway.py)
- **What it does**: Multi-provider LLM client for Google Gemini and DeepSeek.
- **How it works**:
  - Uses `google.generativeai` when `AI_PROVIDER=gemini`.
  - Uses `httpx` with OpenAI-compatible payload when `AI_PROVIDER=deepseek`.
  - Handles retries, exponential backoff, rate limits, and JSON mode enforcement.
- **Where it is used**: Called by `grounded_analysis.py`.

### [`backend/app/ai/retrieval.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/retrieval.py)
- **What it does**: Semantic search engine querying the statutory corpus.
- **How it works**: Embeds the finding query using Gemini embeddings, performs cosine distance matching (`<=>`) against `corpus_chunks` in PostgreSQL, and filters results by `RAG_MIN_SIMILARITY`.
- **Where it is used**: Called by `grounded_analysis.py`.

### [`backend/app/ai/grounded_analysis.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/grounded_analysis.py)
- **What it does**: Synthesizes the legal explanation for each deterministic finding.
- **How it works**:
  - Sends the rule verdict, code/web evidence, and retrieved statutory sections to the LLM.
  - The system prompt explicitly prevents the LLM from re-deciding compliance — it can only explain and cite.
  - Prompts the LLM to output structured JSON: title, description, citation, exact quote, suggested fix, data flow summary, and confidence.
- **Where it is used**: Called by `pipeline.py` via `_create_finding()`.

### [`backend/app/ai/guardrail.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/ai/guardrail.py)
- **What it does**: Anti-hallucination verification engine.
- **How it works**:
  - Inspects every `citation_text` quote the LLM produced.
  - Verifies that the quoted text actually exists in the statutory corpus using Levenshtein fuzzy string matching.
  - If a quote matches below `GUARDRAIL_QUOTE_THRESHOLD` (85%), it strips or flags the hallucinated citation and sets `guardrail_passed = False` on the finding.
- **Where it is used**: Called in `grounded_analysis.py` immediately after LLM generation.

---

## 12. Scorecard & PDF Generation (`backend/app/scorecard/`)

### [`backend/app/scorecard/scorer.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scorecard/scorer.py)
- **What it does**: Computes compliance scores, letter grades, and statutory penalty exposure.
- **How it works**:
  - Assigns weights to rules based on legal risk (R4 Consent: 15%, R6 Security: 15%, R3 Notice: 12%, R10 Rights: 12%, RET: 10%, etc.).
  - `NOT_APPLICABLE` verdicts are excluded from both numerator and denominator; remaining weights are renormalized so a code-only scan can still achieve A grade.
  - Calculates aggregate score (0–100) and maps to letter grades:
    - **A**: ≥90 (Compliant)
    - **B**: ≥75 (Substantially Compliant)
    - **C**: ≥50 (Partially Compliant)
    - **D**: ≥25 (Significant Gaps)
    - **F**: <25 (Non-Compliant)
  - Maps violations to Schedule penalties under the DPDP Act (up to ₹250 Crores for breach of s.8(5)).
- **Where it is used**: In `pipeline.py` (`_finish()`) and `api/scorecard.py`.

### [`backend/app/scorecard/report.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/scorecard/report.py)
- **What it does**: Generates executive PDF audit reports.
- **How it works**: Renders an audit report HTML template using Jinja2 with scorecards, penalty analyses, findings, and code evidence, then compiles it to PDF using **WeasyPrint**.
- **Where it is used**: Called by `api/scorecard.py` (`GET /api/scorecard/{scan_id}/pdf`).

---

## 13. Database Models (`backend/app/models/`)

All models inherit from SQLAlchemy `DeclarativeBase`:

| Model File | DB Table | Purpose |
|---|---|---|
| [`enums.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/models/enums.py) | — | Defines Python Enums: `ScanType`, `ScanStatus`, `RuleStatus`, `FindingSeverity`. |
| [`scan.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/models/scan.py) | `scans` | Top-level scan record: ID, scan type, target (URL/path), status, score, grade, timestamp. |
| [`rule_result.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/models/rule_result.py) | `rule_results` | Per-rule verdict: `rule_id`, `status`, `score`, `weight`, `evidence`, `checks_passed`, `checks_total`. |
| [`finding.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/models/finding.py) | `findings` | Compliance finding: title, severity, legal explanation, code snippet, citations, suggested fix, guardrail flags. |
| [`pii_field.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/models/pii_field.py) | `pii_fields` | Detected personal data fields: field name, statutory category, sensitivity, source file/URL, line number. |
| [`data_flow.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/models/data_flow.py) | `pii_flow_paths`, `data_flow_edges` | Persisted data movement paths from HTTP ingress to database/external sinks. |
| [`corpus.py`](file:///c:/Users/harin/OneDrive/Desktop/DPDPA-self-compliance-check/backend/app/models/corpus.py) | `corpus_chunks` | Legal text chunks with 768-dim `Vector(768)` embeddings for pgvector RAG queries. |
