# DPDPA Backend — Function-by-Function Technical Deep Dive

> **Audience**: Anyone on the team who needs to understand **exactly what every function does**, **how it works internally**, and **why we chose that approach**. Written in simple but technical language.

---

## Table of Contents

- [Key Concepts (Read This First)](#key-concepts-read-this-first)
- [1. Application Boot — `app/main.py`](#1-application-boot--appmainpy)
- [2. Configuration — `app/config.py`](#2-configuration--appconfigpy)
- [3. Database Setup — `app/database.py`](#3-database-setup--appdatabasepy)
- [4. API Layer — `app/api/scan.py`](#4-api-layer--appapiscanpy)
- [5. Pipeline Orchestrator — `app/pipeline.py`](#5-pipeline-orchestrator--apppipelinepy)
- [6. Code Scanner (Tree-sitter AST) — `app/scanner/code_scanner.py`](#6-code-scanner-tree-sitter-ast--appscannercodecannerpy)
- [7. Web Scanner (Playwright Crawler) — `app/scanner/web_scanner.py`](#7-web-scanner-playwright-crawler--appscannerwebscannerpy)
- [8. SSRF Guard — `app/scanner/url_guard.py`](#8-ssrf-guard--appscannerurlguardpy)
- [9. PII Classifier — `app/pii/field_classifier.py`](#9-pii-classifier--apppiifield_classifierpy)
- [10. PII Taxonomy — `app/pii/taxonomy.py`](#10-pii-taxonomy--apppiitaxonomypy)
- [11. Indian ID Validators — `app/pii/indian_ids.py`](#11-indian-id-validators--apppiiindianidspy)
- [12. Code Graph — `app/context/code_graph.py`](#12-code-graph--appcontextcodegraphpy)
- [13. PII Flow Tracer — `app/context/pii_flow.py`](#13-pii-flow-tracer--appcontextpiiflowpy)
- [14. Context Assembler — `app/context/assembler.py`](#14-context-assembler--appcontextassemblerpy)
- [15. Rules Engine — `app/rules/engine.py`](#15-rules-engine--apprulesenginery)
- [15a. CERT-In Directions Checker — `app/rules/certin.py`](#15a-cert-in-directions-checker--apprulescertinpy)
- [15b. Cross-Border Transfer Checker — `app/rules/cross_border.py`](#15b-cross-border-transfer-checker--apprulescrossborderpy)
- [16. Corpus Chunker — `app/corpus/chunker.py`](#16-corpus-chunker--appcorpuschunkerpy)
- [17. Corpus Indexer (Ingester) — `app/corpus/indexer.py`](#17-corpus-indexer-ingester--appcorpusindexerpy)
- [18. RAG Retrieval — `app/ai/retrieval.py`](#18-rag-retrieval--appairetrie valpy)
- [19. AI Gateway — `app/ai/gateway.py`](#19-ai-gateway--appaigatewaypy)
- [20. Grounded Analysis — `app/ai/grounded_analysis.py`](#20-grounded-analysis--appaigroundedanalysispy)
- [21. Faithfulness Guardrail — `app/ai/guardrail.py`](#21-faithfulness-guardrail--appaiguardrailpy)
- [22. Scorecard Scorer — `app/scorecard/scorer.py`](#22-scorecard-scorer--appscorecardscorepy)
- [23. PDF Report — `app/scorecard/report.py`](#23-pdf-report--appscorecardreportpy)
- [24. Aggregate Scorer — `app/scorecard/aggregate.py`](#24-aggregate-scorer--appscorecardaggregatepy)
- [25. Scorecard API — `app/api/scorecard.py`](#25-scorecard-api--appapiscorecardpy)

---

## Key Concepts (Read This First)

Before diving into functions, here are the core technologies and concepts used in this project, explained simply.

### What is an AST Parser?

**AST = Abstract Syntax Tree**. When you write code like `user.email = request.body.email`, that's just text to a computer. An AST parser reads that text and turns it into a tree structure that understands the **meaning**:

```
Assignment
├── Target: MemberAccess(user, email)
└── Value: MemberAccess(request.body, email)
```

Now the program knows `email` is a **variable being assigned**, not a comment or a string. This is why we can detect PII fields accurately — a regex would match `"email"` everywhere, but an AST knows whether `email` is a database column, a function parameter, or just a word in a comment.

### What is Tree-sitter?

Tree-sitter is the specific AST parser library we use. **Why Tree-sitter instead of Python's built-in `ast` module?**

1. **Multi-language**: Tree-sitter parses Python, JavaScript, TypeScript, Java, and Go with the same API. Python's `ast` only works for Python.
2. **Error-tolerant**: If someone's code has a syntax error, Tree-sitter still parses what it can. Python's `ast` crashes on invalid syntax.
3. **Fast**: Tree-sitter is written in C and compiled into a shared library. It can parse thousands of files in seconds.
4. **S-expression queries**: You can write pattern-matching queries (like SQL for syntax trees) to find specific code structures (routes, models, function calls).

We load one grammar per language:
```python
_GRAMMAR_LOADERS = {
    "python":     ("tree_sitter_python",     "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "java":       ("tree_sitter_java",       "language"),
    "go":         ("tree_sitter_go",         "language"),
}
```

### What is RAG (Retrieval-Augmented Generation)?

RAG is a technique to make AI give **accurate, grounded** answers instead of hallucinating.

**Without RAG**: You ask the AI "what does Section 8(5) say?" and it guesses from its training data. It might invent a quote that sounds right but doesn't exist.

**With RAG**:
1. You store the actual legal text in a database with **vector embeddings** (numbers that represent the meaning of each passage).
2. When you need an answer, you search the database for the most relevant passages using **cosine similarity** (mathematical comparison of meaning-vectors).
3. You give those exact passages to the AI and say: "Only cite from THESE passages."

Our RAG pipeline:
```
Legal text → Chunker (splits by section) → Embedder (Gemini embedding) → pgvector (stores vectors)
                                                                                    ↓
Query → Embed the query → Cosine distance search → Top-K provisions → Send to LLM
```

### What is a Web Crawler?

A web crawler automatically visits web pages and reads their content. We use **Playwright** (not `requests`) because modern websites are built with JavaScript frameworks like React. If you fetch a React page with plain HTTP, you get an empty `<div id="root"></div>` — all the forms, buttons, and consent checkboxes are invisible because they haven't been rendered by JavaScript yet.

Playwright launches a **real Chromium browser** (headless = no visible window) that:
- Loads the page and runs all JavaScript
- Waits for the network to settle (so AJAX calls finish)
- Then reads the fully-rendered DOM

### What is the Context Engine?

The Context Engine is the bridge between raw scan evidence and the AI. Its job: take a 10,000-file repository and distill only the **relevant 60 lines of code** + **6 data flow paths** + **8 related functions** that the AI needs to explain one specific finding. Without this, we'd send the entire codebase to the AI, which would be expensive, slow, and inaccurate.

### What are PII (Personal Identifiable Information) Classifiers?

A PII classifier looks at a field name like `aadhaar_number` or `user_dob` and determines:
- **Category**: "aadhaar" or "date_of_birth"
- **Sensitivity**: "critical" or "medium"

It uses a taxonomy (dictionary of known PII field names) specific to Indian law. It handles camelCase (`userEmail`), snake_case (`user_email`), kebab-case (`user-email`), and PascalCase (`UserEmail`) by normalizing everything first.

### What is the Guardrail?

An AI can hallucinate (make up fake quotes or cite non-existent laws). The guardrail is a **post-processing verification step** that runs **after** the AI generates its response. It checks:

1. **Citation grounding**: Did the AI cite a section it was actually shown?
2. **Quote verification**: Does the quoted text actually appear in the law? (Fuzzy string matching, 85% threshold)
3. **Entailment**: Does the AI's explanation logically follow from the provision it cited?

If any check fails, the finding is **kept but flagged** as unverified.

### What is Request Tracing?

Request tracing means we can follow a single user action (clicking "Scan") through every layer of the backend:

```
User clicks "Scan" → HTTP POST arrives → scan.py validates → pipeline.py orchestrates
  → scanner runs → rules engine evaluates → AI explains → scorer grades → DB saves
  → Frontend polls → Result displayed
```

Every step updates the `scan.status` field in the database (`pending` → `scanning` → `analyzing` → `complete`), so the frontend can show real-time progress.

---

## 1. Application Boot — `app/main.py`

This is where the server starts. Think of it as the "ignition switch."

### `lifespan(app)` — *Server Startup/Shutdown Manager*
**Lines 14–33** · Called automatically when Uvicorn starts the server.

**What it does**: Runs one-time setup tasks before the server accepts any requests.

**How it works, step by step**:
1. Logs the startup with the current environment (`development` / `production`).
2. Calls `init_db()` to create PostgreSQL tables and enable the `pgvector` extension.
3. If `init_db()` fails, it logs the error but **does not crash** — the API will report degraded health instead.
4. Checks if the AI is enabled (both Gemini API key for embeddings and a generation provider key must be set).
5. If AI is enabled, calls `_index_corpus_if_needed()` to embed the legal text into pgvector.
6. The `yield` statement marks where the server is ready. Everything before `yield` runs on startup. Everything after runs on shutdown.

**Why this design**: Using a `lifespan` context manager (instead of `@app.on_event("startup")`) is the modern FastAPI pattern. It ensures cleanup code always runs, even if the server crashes.

### `_index_corpus_if_needed()` — *Legal Text Ingester Check*
**Lines 36–53** · Called during startup if AI is enabled.

**What it does**: Checks if the DPDP Act legal text has already been embedded into PostgreSQL. If not, embeds it.

**How it works**:
1. Opens a fresh database session.
2. Calls `indexer.corpus_is_indexed(session)` — this runs a SQL query checking if any `corpus_chunks` row has an embedding vector.
3. If already indexed → returns immediately (logs "already indexed").
4. If not indexed → calls `indexer.index_corpus(session)` which chunks the law, generates embeddings via Gemini, and inserts everything into the database.
5. If embedding fails (no API key, network error), it logs the error but **does not crash**. Findings will just lack citations.

**Why we tolerate failures**: The scanner and rules engine work without AI. Crashing the whole server because Google's API is temporarily down would lose more than it protects.

### `app = FastAPI(...)` — *App Instance Creation*
**Lines 56–78** · Creates the FastAPI application.

**What it does**: Defines the app with metadata, CORS middleware, and route mounts.

**Key details**:
- CORS is configured from `settings.cors_origin_list` — only the frontend origin is allowed.
- Only `GET` and `POST` HTTP methods are allowed (no PUT, DELETE — the API is scan-and-read, not CRUD).
- Four routers are mounted, each with the `/api` prefix:
  - `/api/health` — health checks
  - `/api/scan` — scan submission and polling
  - `/api/findings` — detailed finding retrieval
  - `/api/scorecard` — grade and PDF report

---

## 2. Configuration — `app/config.py`

### `class Settings` — *All App Configuration in One Place*
**Lines 6–83** · A Pydantic settings class that loads values from environment variables.

**What it does**: Defines every tunable parameter with type validation and defaults.

**Key properties**:

| Property | What it does | Why |
|---|---|---|
| `generation_enabled` | Returns `True` if the configured AI provider has an API key | DeepSeek and Gemini use different keys |
| `embedding_enabled` | Returns `True` if `GEMINI_API_KEY` is set | Embeddings always use Gemini (DeepSeek has no embedding API) |
| `ai_enabled` | Returns `True` if **both** generation and embedding are available | You need both for RAG to work — embeddings without generation can retrieve but not explain, and generation without embeddings can't retrieve relevant legal text |

**Why Pydantic settings**: It validates types automatically. If someone puts `RAG_TOP_K=hello` in the `.env` file, Pydantic will throw a clear error at startup instead of a mysterious `int("hello")` crash deep in the retrieval code.

---

## 3. Database Setup — `app/database.py`

### `class Base` — *SQLAlchemy Declarative Base*
**Line 13** · The parent class all ORM models inherit from.

### `engine` — *Async PostgreSQL Connection Pool*
**Line 17** · Creates the database engine with `pool_pre_ping=True` (tests connections before using them — a dead connection from a database restart won't crash a request).

### `SessionLocal` — *Session Factory*
**Line 19** · Creates database sessions. `expire_on_commit=False` means objects stay usable after a commit — without this, accessing `scan.status` after committing would trigger a lazy load, which fails in async code.

### `get_db()` — *FastAPI Dependency Injection*
**Lines 22–24** · A generator that FastAPI calls to give each request its own database session.

**How it works**: Opens a session at the start of a request, yields it to the route handler, and automatically closes it when the request ends — even if the handler throws an exception.

### `init_db()` — *Schema Creation*
**Lines 27–38** · Called once at startup.

**What it does**:
1. Runs `CREATE EXTENSION IF NOT EXISTS vector` — this enables pgvector (PostgreSQL's vector similarity extension). Without this, the `Vector(768)` column type on the corpus table would fail.
2. Runs `Base.metadata.create_all` — creates all tables defined by our ORM models (scans, findings, pii_fields, etc.) if they don't already exist.

**Why pgvector extension first**: SQLAlchemy tries to validate column types when creating tables. The `corpus_chunks` table has a `Vector(768)` column. If the `vector` extension hasn't been enabled yet, PostgreSQL doesn't know what `vector` is and the table creation fails.

---

## 4. API Layer — `app/api/scan.py`

### `scan_web(payload)` — *POST /api/scan/web*
**Lines 44–65** · Accepts a URL and starts a web scan.

**Step by step**:
1. Calls `validate_scan_url(payload.url)` — the SSRF guard checks that the URL is safe (see Section 8).
2. Creates a `Scan` row in PostgreSQL with `status=PENDING`.
3. Spawns `_run_web_task(scan.id, safe_url)` as an **asyncio background task** — the key pattern here.
4. Returns `HTTP 202 Accepted` with the `scan_id` immediately (doesn't wait for the scan to finish).

**Why background task**: A web scan can take 30+ seconds (loading pages, waiting for JavaScript). If we blocked the HTTP response, the client would see a timeout. Instead, the frontend gets the scan ID instantly and polls `GET /api/scan/{id}` every few seconds to check progress.

### `scan_code(file)` — *POST /api/scan/code*
**Lines 93–136** · Accepts a ZIP/tar archive upload.

**Step by step**:
1. **Extension check** (line 100–104): Only `.zip`, `.gz`, `.tgz`, `.tar` are accepted.
2. **Workspace creation** (line 107–108): Creates `workspace/<scan_id>/` — a dedicated directory for this scan.
3. **`_save_upload()`** (line 112): Streams the file to disk **1 MB at a time** while enforcing the 50 MB size limit. Why streaming? Loading 50 MB into memory all at once would waste RAM.
4. **`_safe_extract()`** (line 115): Validates and extracts the archive (see below).
5. **Cleanup on failure** (lines 116–123): If validation fails, the workspace directory is deleted. The archive file is **always** deleted (line 123), whether or not extraction succeeded.
6. Creates a `Scan` row and spawns the background task.

### `_save_upload(file, destination)` — *Streaming Upload with Size Limit*
**Lines 176–192**

**How it works**:
```python
while chunk := await file.read(1024 * 1024):  # Read 1 MB
    written += len(chunk)
    if written > limit:
        raise HTTPException(413, "Too large")
    out.write(chunk)
```
The walrus operator (`:=`) reads and checks in one step. The file is never fully loaded into memory.

### `_safe_extract(archive, destination)` — *Anti-Zip-Bomb, Anti-Path-Traversal*
**Lines 203–251**

**What it protects against**:

| Attack | How it works | Our defense |
|---|---|---|
| **Zip bomb** | A 1 KB file that expands to 10 GB | Check total uncompressed size against `max_upload_size_mb × 20` |
| **Path traversal** | Archive entry named `../../etc/passwd` | Check `_is_within()` — resolved path must stay under the destination |
| **Absolute paths** | Entry named `/etc/shadow` | Reject any entry where `Path(name).is_absolute()` |
| **Symlinks** | Tar entry that's a symbolic link pointing outside | Reject `member.issym()` and `member.islnk()` |
| **File count bomb** | Archive with 1 million empty files | Reject if `len(members) > max_files_per_scan` |

### `_is_within(base, target)` — *Path Containment Check*
**Lines 195–200**

**How it works**: Resolves both paths to absolute form and checks if `target` is a child of `base`. If `target` is `../../etc/passwd`, resolving it would escape `base`, and `relative_to()` would throw `ValueError`, which we catch and return `False`.

### `get_scan(scan_id)` — *GET /api/scan/{scan_id}*
**Lines 139–156** · The polling endpoint.

The frontend calls this every 2–3 seconds. Returns the current status, score, grade, and progress counts.

---

## 5. Pipeline Orchestrator — `app/pipeline.py`

This is the **central controller** that wires all modules together in the correct order. Think of it as the assembly line.

### `run_code_scan(db, scan_id, root_path)` — *Code Scan Pipeline*
**Lines 149–171**

**Step by step**:
1. Sets `status = SCANNING`.
2. Calls `code_scanner.scan_directory(root_path)` → gets a `CodeScanResult` with all routes, functions, models, PII fields, and call edges.
3. Builds a `CodeGraph(code_result)` — an in-memory directed graph of the code.
4. Calls `pii_flow.trace_flows(code_result, graph)` — traces how PII moves through the code.
5. Calls `rules_engine.run_all(code_result=code_result, flows=flows)` — evaluates all 11 compliance rules deterministically.
6. Calls `_persist_code_evidence()` — saves PII fields and data flow edges to the database.
7. Calls `_finish()` — persists rule results, generates AI explanations, computes the grade.

### `run_web_scan(db, scan_id, url)` — *Web Scan Pipeline*
**Lines 129–146**

Same pattern but simpler (no graph or flow tracing):
1. Sets `status = SCANNING`.
2. Calls `web_scanner.scan_url(url)`.
3. Runs the rules engine.
4. Persists web evidence.
5. Calls `_finish()`.

### `_finish(db, scan, verdicts, ...)` — *Post-Scan Processing*
**Lines 174–223**

**Step by step**:
1. **Persist rule results** (lines 184–200): Saves each `RuleVerdict` as a `RuleResult` row with the rule ID, status, score, weight, and evidence text.
2. **Set status to ANALYZING** (line 202): This is when the AI phase begins.
3. **Generate findings** (lines 204–214): For each non-compliant verdict (not `COMPLIANT` and not `NOT_APPLICABLE`):
   - Assembles a bounded context via `assembler.assemble_for_verdict()`.
   - Calls `_create_finding()` which invokes the full RAG pipeline.
4. **Compute grade** (lines 218–223): Calls `scorer.compute(verdicts)` and saves the score, grade, and `status = COMPLETE`.

### `_create_finding(db, scan, verdict, context)` — *Single Finding Generator*
**Lines 226–257**

**Step by step**:
1. Gets the relevant section IDs from the rule checker via `_retrieval_ids_for()`.
2. Calls `grounded_analysis.explain_verdict()` — this runs the full RAG pipeline (retrieve provisions → call AI → verify quotes).
3. Creates a `Finding` database row with everything: title, description, citation, quote, suggested fix, guardrail status, AI confidence.

### `_retrieval_ids_for(rule_id)` — *Pin RAG to Correct Legal Sections*
**Lines 260–270**

**What it does**: Each rule checker declares which sections of the DPDP Act it's about (e.g., R6 is about Section 8(5)). This function reads that declaration and passes it to the retrieval engine so it only searches those sections.

**Why**: Without this, a Rule 6 (Security) finding might accidentally retrieve and cite Rule 9 (Children) text. Pinning prevents cross-contamination.

### `_persist_code_evidence(db, scan, result, flows)` — *Save Scan Artifacts*
**Lines 298–348**

Saves three types of data to PostgreSQL:
1. **PII fields**: Every personal data field detected (field name, category, sensitivity, file, line).
2. **Data flow edges**: Every caller→callee relationship, with PII categories tagging which edges carry personal data.
3. **PII flow paths**: End-to-end paths showing how PII moves from HTTP ingress to database/external sinks.

### `_set_status(db, scan, status)` and `_fail(db, scan, message)` — *Status Updates*
**Lines 351–360**

Simple helpers. `_fail()` sets `status = FAILED`, records the error message (truncated to 2000 chars), and sets `completed_at`.

---

## 6. Code Scanner (Tree-sitter AST) — `app/scanner/code_scanner.py`

This is the largest file in the project (~2200 lines). It parses source code in 5 languages and extracts everything the rules engine needs.

### `scan_directory(root_path)` — *Entry Point*
**Lines 2199–2206** · The async public API.

**What it does**: Wraps the synchronous `_scan_directory_sync()` in `asyncio.to_thread()`.

**Why `to_thread()`**: Tree-sitter parsing is CPU-bound (lots of computation, no I/O waiting). Running it on the main event loop would block all other requests. `to_thread()` moves it to a worker thread so the API keeps serving.

### `_scan_directory_sync(root_path)` — *File Walker + Parser*
**Lines 2165–2196**

**Step by step**:
1. Creates a `CodeScanResult` and a `_ScanState` (accumulates results across all files).
2. Walks all files under `root_path`, skipping directories like `node_modules`, `.git`, `__pycache__`, `vendor` (defined in `SKIP_DIRECTORIES`).
3. For each file with a supported extension, calls `_scan_file()`.
4. After all files are scanned, runs four post-processing steps:
   - `_resolve_calls()` — matches function calls to their definitions across files.
   - `_resolve_imports()` — maps import statements to the files they import.
   - `_apply_transform_correlation()` — finds assignments like `hashed_email = bcrypt(email)` and marks the corresponding column as hashed.
   - `_dedupe()` — removes duplicate PII fields, edges, and routes.

### `_parser_for(grammar)` — *Grammar Loader (Cached)*
**Lines 333–351**

**What it does**: Loads a Tree-sitter grammar (parser) for a language. Uses `@cache` so each grammar is loaded only once per process.

**How it works**:
1. Looks up the grammar in `_GRAMMAR_LOADERS` (e.g., `"python"` → `("tree_sitter_python", "language")`).
2. Dynamically imports the module (`importlib.import_module`).
3. Creates a `Parser` with the loaded `Language`.

**Why dynamic import**: The grammar modules (`tree_sitter_python`, etc.) are compiled C extensions. Importing them at module level would crash if any single one is missing. Dynamic import means a missing Go grammar only disables Go scanning, not the whole scanner.

### `class _Extractor` — *Base Class for All Language Extractors*
**Lines 614–791**

Every language (Python, JS, TS, Java, Go) has its own extractor class that inherits from `_Extractor`. The base class provides shared functionality.

**Key methods**:

#### `add_symbol(name, kind, node)` — *Register a Symbol*
Records a function, method, or class in the scan result. Captures the source code if the function is short enough (≤150 lines).

#### `add_pii(name, line, location_kind, context)` — *Register a PII Field*
Takes a field name (e.g., `aadhaar`), passes it through `field_classifier.build_field_ref()`, and if it's recognized as PII, adds it to the scan result.

#### `classify_call(receiver, method, args)` — *Determine Call Type*
The most important classification function. Given a function call like `db.add(user)`, it determines what kind of call it is:

| Pattern | Classification | Example |
|---|---|---|
| `logger.info(...)` / `print(...)` | `LOG_OUTPUT` | PII sent to logs = cleartext exposure |
| `requests.post(...)` / `fetch(...)` | `API_SEND` | PII sent to external service |
| `db.add(...)` / `session.save(...)` | `DB_WRITE` | PII written to database |
| `db.query(...)` / `Model.filter(...)` | `DB_READ` | PII read from database |

**How it works**: Normalizes the receiver name (`session` → check if it's in `DB_RECEIVER_NAMES`) and the method name (`add` → check if it's in `DB_WRITE_GENERIC`). Full calls like `print(...)` are checked against `LOG_FULL_CALLS`.

#### `record_call(scope, node, receiver, method, args)` — *Save a Call Edge*
Creates a `_CallSite` with the caller, callee, edge type, and any PII categories found in the arguments.

#### `pii_candidates(node)` — *Find Field-Like Names in an Expression*
Walks all child nodes looking for identifiers and dictionary keys. A bare string literal `"email"` is **not** treated as a field name (it could be a label or a comment). A string is only a field name if the AST says it's a subscript key (`data["email"]`) or an object key (`{ email: value }`).

**Why this distinction matters**: This is the difference between grep and structural analysis. `grep "email"` matches comments and documentation. The AST knows the difference.

### `class _PythonExtractor(_Extractor)` — *Python-Specific Logic*
**Lines 797–1100+**

#### `visit(node, scope, in_class)` — *Recursive Tree Walker*
Walks the tree top-down. For each node, dispatches to the right handler based on node type:
- `decorated_definition` → `visit_decorated()` (handles `@app.route(...)`)
- `function_definition` → `visit_function()`
- `class_definition` → `visit_class()`
- `import_statement` → `visit_import()`
- `assignment` → `visit_assignment()` (detects `__tablename__`, model columns)
- `call` → `visit_call()` (records function calls for the call graph)

#### `extract_model(class_node, class_name, body)` — *ORM Model Detection*
**How it detects SQLAlchemy/Django models**:
1. Looks for `__tablename__ = "users"` assignments → extracts table name.
2. For Django, looks for a nested `class Meta: db_table = "users"`.
3. For each assignment where the right-hand side is a `call`:
   - Checks if the callee is `Column`, `mapped_column`, or ends in `Field` (Django convention).
   - Extracts the column name, type, and checks for encryption/hash/expiry markers.

#### `extract_route(decorator, ...)` — *HTTP Route Detection*
Detects route decorators across frameworks:
- Python: `@app.get("/users")`, `@router.post("/signup")`
- Checks if the decorator name is an HTTP verb (`get`, `post`, `put`, `patch`, `delete`).
- Extracts the path string, HTTP method, and handler function name.
- Also checks for `auth_required` markers to flag whether the route is protected.

### Marker Detection Constants
**Lines 86–213**

The scanner uses keyword-based markers to detect security-relevant patterns:

| Marker Set | Purpose | Examples |
|---|---|---|
| `ENCRYPTION_MARKERS` | Field is encrypted | `encrypt`, `fernet`, `aes`, `kms` |
| `HASH_MARKERS` | Field is hashed | `bcrypt`, `argon2`, `sha256`, `pbkdf2` |
| `EXPIRY_MARKERS` | Field has a TTL/retention policy | `expires`, `ttl`, `retention`, `delete_after` |
| `AUTH_MARKERS` | Route requires authentication | `login_required`, `jwt`, `token_required` |
| `LOG_OBJECT_NAMES` | Object is a logger | `logger`, `console`, `winston`, `slog` |
| `DB_RECEIVER_NAMES` | Object is a database client | `session`, `db`, `cursor`, `prisma`, `knex` |

---

## 7. Web Scanner (Playwright Crawler) — `app/scanner/web_scanner.py`

### Why Playwright (not `requests`)?

A modern React/Next.js page returns this over plain HTTP:
```html
<html><body><div id="root"></div></body></html>
```

All forms, consent checkboxes, and privacy links are rendered by JavaScript **after** the page loads. Playwright runs a real Chromium browser that:
- Executes JavaScript
- Waits for the network to settle
- Then reads the fully rendered DOM

### `scan_url(url)` — *Entry Point*
Launches a headless Chromium browser, navigates to the URL, and collects evidence.

**What it collects**:
- **Forms**: All `<form>` elements, their fields (names, types), and consent checkboxes
- **Consent elements**: Checkboxes near "I agree" / "I consent" text, whether they're pre-checked
- **Privacy notice**: Links containing "privacy" or "data protection" keywords
- **Security headers**: HSTS, CSP, X-Frame-Options, etc. from HTTP response headers
- **Cookies**: All cookies set on page load (name, Secure flag, HttpOnly flag, SameSite)
- **Third-party scripts**: External JavaScript loaded from different domains
- **Grievance links**: Links to DPO contact, complaint forms

### Key Design Decision: Read-Only Cold Load

The scanner **never**:
- Submits a form
- Clicks a button
- Signs in
- Accepts or rejects cookies

Everything is captured on a "cold load" — the state a first-time visitor sees. This is the state the DPDP Act cares about (what happens **before** consent is given).

---

## 8. SSRF Guard — `app/scanner/url_guard.py`

### `validate_scan_url(url)` — *SSRF Prevention*

**What is SSRF?** Server-Side Request Forgery. If someone submits `http://localhost:5432` as a scan URL, the server would scan its own database port. Or `http://169.254.169.254` would access AWS metadata credentials.

**How it works**:
1. Parses the URL and rejects non-HTTP/HTTPS schemes.
2. Resolves the domain name to IP addresses.
3. Rejects:
   - Private IPs: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Localhost: `127.0.0.1`, `::1`
   - Link-local: `169.254.0.0/16` (AWS/GCP metadata endpoint)

**Exception**: `allow_private_scan_targets = True` in config allows scanning localhost — needed when you're self-hosting and scanning your own local app.

---

## 9. PII Classifier — `app/pii/field_classifier.py`

### `normalise(field_name)` — *Name Normalizer*
**Lines 26–35**

Converts any naming convention to lowercase snake_case:
```
userEmail      → user_email
user-email     → user_email
USER_EMAIL     → user_email
user.email     → user_email
```

**How**: Uses regex to detect camelCase boundaries (`(?<=[a-z0-9])(?=[A-Z])`) and insert underscores. Then replaces all non-alphanumeric characters with underscores.

### `classify(field_name, nearby_literal=None)` — *Main Classifier*
**Lines 98–118**

**Step by step**:
1. Normalizes the field name.
2. Checks negative filters — field names like `email_template`, `file_name`, `password_hash_algorithm` that describe PII but don't hold it. Uses multi-token matching so `file_name` is negative but `profile_name` is not.
3. Looks up the name in the alias index (see `_build_alias_index()`).
4. If no exact match, tries all sub-token combinations. For `user_pin_code`, it tries:
   - `user_pin_code` (3 tokens) → no match
   - `user_pin`, `pin_code` (2 tokens) → `pin_code` matches "address"!
   - Longest match wins, so `pin_code` (address) beats `pin` (password).
5. If a `nearby_literal` is provided (a hardcoded value near the field), validates it against Indian ID checksums. A valid Aadhaar number overrides the name-based classification.

### `build_field_ref(field_name, ...)` — *Full PII Reference Builder*
**Lines 121–142**

Calls `classify()` and, if a category is found, looks up the sensitivity level from the taxonomy and packages everything into a `PIIFieldRef` dataclass.

---

## 10. PII Taxonomy — `app/pii/taxonomy.py`

### `PII_TAXONOMY` — *Master Dictionary*

A large dictionary mapping PII categories to their metadata. Example:

```python
"aadhaar": {
    "sensitivity": "critical",
    "sections": ["s.5", "s.6", "s.8(5)", "s.9"],
    "aliases": (
        "aadhaar", "aadhaar_number", "aadhaar_no", "aadhar",
        "uid", "uidai", "aadhaar_id", ...
    ),
}
```

**Categories covered**: name, email, phone, aadhaar, pan, voter_id, passport, driving_license, bank_account, upi_id, ifsc, credit_card, dob, age, gender, address, pin_code, biometric, health, caste, religion, password, ip_address, device_id, location, photo, guardian, school, and more.

Every category has:
- **Sensitivity tier**: `critical`, `high`, `medium`, `low`
- **DPDP Act sections**: Which sections apply to this data type
- **Aliases**: All known field name variations

---

## 11. Indian ID Validators — `app/pii/indian_ids.py`

### `verhoeff_checksum(payload)` — *Aadhaar Checksum*
**Lines 68–82**

Aadhaar uses the **Verhoeff algorithm**, not Luhn. Verhoeff is based on the dihedral group D₅ (a mathematical group of symmetries). It uses three lookup tables:
- `_VERHOEFF_D`: Multiplication table for D₅
- `_VERHOEFF_P`: Permutation table (cycled by digit position)
- `_VERHOEFF_INV`: Inverse table

**Why Verhoeff over Luhn**: Verhoeff catches **all** single-digit errors AND **all** adjacent transposition errors. Luhn cannot catch transpositions (e.g., swapping `23` to `32`). Since Aadhaar numbers are typically hand-typed, transposition is the most common error.

### Other validators:
- **PAN**: Regex `[A-Z]{5}[0-9]{4}[A-Z]` — 10-character alphanumeric
- **Passport**: Regex `[A-Z][0-9]{7}`
- **Voter ID**: Regex `[A-Z]{3}[0-9]{7}`
- **GSTIN**: 15-character with base-36 check digit
- **IFSC**: Regex `[A-Z]{4}0[A-Z0-9]{6}`

---

## 12. Code Graph — `app/context/code_graph.py`

### `class CodeGraph` — *In-Memory Directed Graph*

**What it represents**: A graph where:
- **Nodes** = functions, methods, classes, and external calls (loggers, DB clients, API calls)
- **Edges** = "calls", "imports", "db_write", "db_read", "log_output", "api_send"

**How it's built** (in `__init__`):
1. Indexes all `SymbolInfo` objects by `(file_path, name)` tuples.
2. Builds forward and reverse adjacency lists from all `DataFlowEdgeInfo` edges.

### `outgoing_edges(node)` — *What Does This Function Call?*
Returns all edges leaving a node. The PII flow tracer walks these to trace data movement.

### `callers_of(symbol, hops=2)` — *Who Calls This Function?*
BFS traversal up to `hops` edges upstream. Used by the assembler to show the AI "this function is called by these 8 callers."

### `callees_of(symbol, hops=2)` — *What Does This Function Call?*
BFS traversal downstream. Shows the AI "this function calls these 8 functions."

### `symbol_at(file_path, line_number)` — *What Function Is This Line In?*
Given a file and line number, returns the **innermost** function whose line range contains that line. Used to find the enclosing function for a PII field.

### `resolve(node, line_hint=None)` — *Get Symbol Info for Any Node*
Edges routinely point at things the scanner never indexed (loggers, ORMs, third-party SDKs). Instead of dropping these from context, `resolve()` creates placeholder `SymbolInfo` objects so they still appear in the PII flow trace.

---

## 13. PII Flow Tracer — `app/context/pii_flow.py`

This is the module that answers: **"Where does personal data enter, how does it move, and where does it end up?"**

### `trace_flows(scan_result, graph)` — *Entry Point*
**Lines 124–178**

**Step by step**:
1. For each detected PII field:
   - Find the enclosing symbol (function/class that contains it).
   - Determine the starting nodes in the graph.
   - Walk the graph to find all **terminal sinks** (database writes, log outputs, API sends).
2. For each sink reached, build a `PIIFlowPathInfo` recording the full chain:
   - Source: "email in create_user at routes/auth.py:42"
   - Transforms: "hashed in utils.py:12", "passed to validate_email"
   - Sink: "written to db.add at models/user.py:28"
   - Flags: has_consent_check, has_encryption, has_retention_policy, crosses_third_party

### `_walk_to_sinks(graph, start, pii_field)` — *Depth-First Sink Search*
**Lines 184–218**

**How it works**: DFS traversal from the starting node. At each node:
- Check every outgoing edge.
- If the edge carries the right PII category AND is a terminal type (DB write, API send, log output) → **found a sink**.
- Otherwise, follow the edge to the next node and continue.

**Bounded**: Maximum depth of 8 hops, maximum 6 sinks per field, maximum 500 node expansions per field. Without these limits, recursive code or high-fan-out architectures would explode into thousands of paths.

### `_has_consent_guard(graph, nodes)` — *Consent Check Detection*
**Lines 349–363**

**How it works**: For each node on the data path:
1. Check if the node's own name contains consent markers (`consent`, `opt_in`, `lawful_basis`, etc.).
2. Check the node's outgoing edges — if it calls something named `check_consent()` **before** the data moves forward.

The "before" check matters: a consent function called **after** the data has already been sent to a third party doesn't count as a guard.

### `_leaves_own_host(edge)` — *Third-Party Detection*
**Lines 403–413**

Checks if an API call edge sends data outside the application:
- Extracts URLs from the call target and checks against `INTERNAL_HOST_MARKERS` (localhost, 127.0.0.1, .local, .svc).
- Checks against `THIRD_PARTY_MARKERS` (segment, mixpanel, sentry, stripe, razorpay, etc.).
- The **file path** is NOT checked — a file named `analytics.py` in the user's repo is not a third-party transfer.

---

## 14. Context Assembler — `app/context/assembler.py`

### `assemble_for_verdict(verdict, ...)` — *Build Bounded AI Context*
**Lines 55–89**

**The scaling problem**: A repo could be 10,000 files. We can't send all of it to the AI.

**The solution**: For each finding, assemble only what's relevant:

| Budget | Limit | Why |
|---|---|---|
| Code snippet | 60 lines max | More code = more noise, worse citations |
| Callers | 8 max | Shows where the data enters |
| Callees | 8 max | Shows where the data goes |
| PII flows | 6 max | Shows end-to-end data movement |
| Related models | 4 max | Shows database schema context |
| Related routes | 4 max | Shows HTTP endpoints |

**Step by step**:
1. Find the **focus check** — the first failed check that has a file path.
2. Use the graph to find the symbol at that file + line.
3. Walk 2 hops upstream (`callers_of`) and 2 hops downstream (`callees_of`).
4. Extract the code snippet (the symbol's source, windowed around the focus line).
5. Filter PII flows to only those mentioning the focus file.
6. Filter DB models and routes related to the focus file.

---

## 15. Rules Engine — `app/rules/engine.py`

### Design Principle: **Zero AI, Zero Randomness**

Every rule checker is a pure function: same evidence in → same verdict out. The AI is never consulted for pass/fail decisions. This makes verdicts:
- **Reproducible**: Run twice, get the same result.
- **Auditable**: You can explain exactly why each check passed or failed.
- **Fast**: No API calls needed.

### `run_all(web_result=None, code_result=None, flows=None, certin_evidence=None)` — *Run All 13 Checkers*
**Lines 194–243**

Calls `.check()` on each of the 13 rule checker modules and returns a list of `RuleVerdict` objects.

**Special dispatch for infrastructure rules**: Two checkers (CERT-In and Cross-Border) need `CertInEvidence` — evidence gathered from infrastructure files (Terraform, Docker, CI configs). These receive the extra `certin=certin_evidence` argument while the standard 11 rule checkers receive only `web_result`, `code_result`, and `flows`.

**Key constraint**: A scan is **either** web **or** code, never both. Mixing would produce a misleading grade (a clean repo hiding a non-compliant website). If both are passed, it raises `ValueError`.

### `build_verdict(...)` — *Assemble a Verdict from Checks*
**Lines 93–157**

Takes a list of `RuleCheck` results and produces a `RuleVerdict`.

**Scoring logic**:
- `score = passed / total` (fraction of checks that passed)
- `score = 1.0` → `COMPLIANT`
- `0 < score < 1.0` → `GAP` (partially compliant)
- `score = 0.0` → `VIOLATION`

**Bright-line override**: Some rules have absolute prohibitions. For example, if a website fires tracking scripts before consent, the rule is a `VIOLATION` regardless of how many other checks passed. The score is **capped at 0.5** (not zeroed) — because the checks that did pass still represent real work.

### `not_applicable_verdict(...)` — *Can't Evaluate This Rule*
**Lines 66–90**

A web scan can't check whether a DPIA exists (that's a document, not code/web evidence). Instead of scoring it `0` (unfairly penalizing), the rule returns `NOT_APPLICABLE` with `score = None`. The scorer then **excludes** it from the weighted average entirely.

### The 13 Rule Checkers

Each lives in its own file under `app/rules/`:

| Module | Rule ID | DPDP Section | What It Checks |
|---|---|---|---|
| `r03_notice.py` | R3 | Section 5 | Privacy notice present, purposes stated, language accessibility |
| `r04_consent.py` | R4 | Section 6 | Free, specific, informed consent. No pre-ticked boxes. No forced bundling |
| `r05_children.py` | R5 | Section 9 | Children's data collection, behavioral monitoring, age gates |
| `r06_security.py` | R6 | Section 8(5) | HTTPS, HSTS, secure cookies, no cleartext PII logging, encryption |
| `r07_breach.py` | R7 | Section 8(6) | Breach notification endpoints and mechanisms |
| `r08_dpia.py` | R8 | Section 10 | Data Protection Impact Assessment triggers |
| `r09_sdf.py` | R9 | Section 10 | Significant Data Fiduciary classification triggers |
| `r10_rights.py` | R10 | Sections 11–14 | Right to access, correction, erasure, grievance, nomination |
| `r11_dpb.py` | R11 | Section 13 | DPO contact disclosure and escalation paths |
| `r12_verification.py` | R12 | Section 9(1) | Verifiable parental consent for children |
| `retention.py` | RET | Section 8(7) | TTL/expiry fields, automated deletion logic |
| `certin.py` | CERTIN | Section 8(5); IT Act s.70B(6) | NTP clock sync, 180-day log retention, log sovereignty, hardcoded secrets, transport security |
| `cross_border.py` | XBORDER | Section 16; Rule 15 | Storage regions in infrastructure files — any region outside India is a transfer violation |

---

## 15a. CERT-In Directions Checker — `app/rules/certin.py`

**New in latest pull.** The CERT-In Directions of 28 April 2022 are issued under Section 70B(6) of the IT Act 2000 and are **legally binding on every body corporate in India**, independently of the DPDP Act. They sit alongside DPDP obligations, not instead of them.

**Assessed only from code scans** — a web crawl can't see a Dockerfile or Terraform file.

### `check(web_result, code_result, flows, certin)` — *Entry Point*
**Lines 41–83**

If no code scan or no CERT-In evidence → returns `NOT_APPLICABLE`. Otherwise runs 8 individual checks:

### The 8 CERT-In Checks

| Function | Check Name | What It Verifies |
|---|---|---|
| `_clock_sync()` | `ntp_synchronised_to_nic_or_npl` | NTP time sync configured to NIC (`samay1.nic.in`, `samay2.nic.in`) or NPL (`time.nplindia.org`). Without an approved time source, log timestamps across systems can't be reconciled during breach investigations. |
| `_log_retention()` | `logs_retained_180_days` | Log retention ≥ 180 days (CERT-In minimum). Also warns if < 365 days (DPDP standard for personal-data access logs). |
| `_log_sovereignty()` | `logs_held_in_indian_jurisdiction` | At least one storage region sits inside India. Checks declared regions from Terraform/infra files. |
| `_logging_enabled()` | `logging_enabled` | A logging framework or collector exists in the codebase (e.g., `winston`, `structlog`, `slog`). |
| `_incident_reporting()` | `incident_reaches_a_responder` | An alerting or escalation path exists (PagerDuty, Sentry, alert sinks). Also reports swallowed error paths (`except: pass`) that would silently drop incidents. |
| `_no_hardcoded_secrets()` | `no_hardcoded_secrets` | No credential literals committed to the repository (API keys, passwords in source). |
| `_no_credentials_in_logs()` | `no_credentials_written_to_logs` | No log call carries a credential or government identifier in clear text. Since logs are retained for 180 days, a logged Aadhaar stays exposed for 6 months. |
| `_transport_security()` | `no_deprecated_transport_security` | No deprecated TLS or SSL version configured (SSLv3, TLS 1.0, TLS 1.1). |

**Key constant**: `REPORTING_WINDOW_HOURS = 6` — a reportable incident must reach CERT-In within 6 hours of becoming aware of it.

---

## 15b. Cross-Border Transfer Checker — `app/rules/cross_border.py`

**New in latest pull.** Section 16 of the DPDP Act restricts sending personal data outside India.

### `check(web_result, code_result, flows, certin)` — *Entry Point*
**Lines 34–61**

**Step by step**:
1. If no code scan OR no CERT-In evidence OR no storage regions declared → `NOT_APPLICABLE`. A PaaS deployment with no infrastructure-as-code in its repository is not a violation — it's evidence the scan can't reach.
2. If regions exist → run `_region_check()`.

### `_region_check(certin)` — *Region Validation*
**Lines 64–94**

**How it works**:
1. Calls `certin.foreign_regions()` to get any region outside India.
2. If any foreign region exists → **VIOLATION**. Unlike CERT-In's log-sovereignty check, having an Indian region alongside a foreign one does **not** excuse the foreign one. Section 16 restricts *sending* personal data outside India — a second foreign copy is still a transfer that occurred.
3. If all regions are Indian → **COMPLIANT**.

**Citation pinning**: `RETRIEVAL_SECTION_IDS = ["rule_15"]` — The Act's s.16 is not yet in the statutory corpus (couldn't be sourced from the gazette text), so citations point at Rule 15 of the DPDP Rules, which restates the same restriction.

---

## 16. Corpus Chunker — `app/corpus/chunker.py`

### `build_chunks(max_chars=1200)` — *Split Law into Embeddable Pieces*
**Lines 111–134**

**What it does**: Takes the raw legal text (from `dpdp_act.py` and `dpdp_rules.py`) and splits it into chunks suitable for embedding.

**Why not just split every 1200 characters?**
- A cut in the middle of a sentence creates a chunk that retrieves badly (half a legal provision is useless).
- A cut in the middle of a quote means the guardrail will reject the quote as not matching.

**Splitting policy**: Cut only at sub-clause boundaries:
1. `_cut_points()` finds positions where a new sub-clause demonstrably begins: an enumerator like `(2)` or `(a)` preceded by a sentence-ending character (`.`, `;`, `:`, `—`).
2. `_segments()` splits the text at these cut points.
3. `_pack()` greedily combines segments into chunks up to `max_chars`, never splitting mid-segment.
4. If a single segment exceeds `max_chars`, falls back to sentence boundaries.

**Each chunk carries metadata**:
```python
StatutoryChunk(
    source="dpdp_act",           # Which law
    section_id="s.8(5)",          # Unique ID for retrieval pinning
    section_title="Security...",  # Human-readable title
    citation_label="DPDP Act 2023, Section 8(5)",  # For AI to cite
    chunk_index=0,                # Position within the section
    text="The Data Fiduciary..." # The actual legal text
)
```

---

## 17. Corpus Indexer (Ingester) — `app/corpus/indexer.py`

### `index_corpus(db, force=False)` — *Embed and Store Legal Text*
**Lines 40–104**

**Step by step**:
1. Calls `build_chunks()` to get all statutory chunks.
2. Loads all existing `corpus_chunks` rows from PostgreSQL.
3. **Removes stale rows** — if a chunk no longer exists in the current corpus (e.g., a section was updated), its old embedding is deleted. Keeping stale rows would let the tool cite text that no longer matches what the guardrail verifies against.
4. Identifies chunks that need embedding (new or missing embedding).
5. **Batches embedding calls** — sends 50 texts per API call instead of one by one. A cold boot takes 2–3 API calls instead of 200+.
6. For each chunk, either inserts a new row or updates the existing one.

### `_embedding_input(chunk)` — *What Gets Embedded*
**Lines 29–37**

The embedding input is: `"{citation_label} ({section_title}): {text}"`.

**Why include the citation and title?** So a query like "Section 8(5) security safeguards" matches the embedding of that provision. The `text` alone might not contain "Section 8(5)" in those exact words.

**Why is `chunk_text` different from the embedding input?** Because `chunk_text` is what the guardrail verifies quotes against. Including "DPDP Act 2023, Section 8(5)" in the stored text would make the guardrail accept a "quote" that's actually just the citation label.

### `corpus_is_indexed(db)` — *Quick Check*
**Lines 107–114**

Runs `SELECT id FROM corpus_chunks WHERE embedding IS NOT NULL LIMIT 1`. If any row has an embedding, the corpus is considered indexed.

---

## 18. RAG Retrieval — `app/ai/retrieval.py`

### `retrieve_provisions(db, query_text, ...)` — *Semantic Search*
**Lines 16–65**

**Step by step**:
1. **Embed the query** (line 31): Converts the finding's query text into a 768-dimensional vector using Gemini's embedding model, with `task_type="retrieval_query"`.
2. **Cosine distance search** (lines 39–48): Runs a SQL query against the `corpus_chunks` table:
   ```sql
   SELECT *, embedding <=> query_vector AS distance
   FROM corpus_chunks
   WHERE embedding IS NOT NULL
   ORDER BY distance
   LIMIT 5
   ```
   The `<=>` operator is pgvector's cosine distance operator.
3. **Section pinning** (lines 46–47): If `restrict_section_ids` is provided (e.g., `["s.8(5)"]`), adds a `WHERE section_id IN (...)` clause to prevent cross-topic retrieval.
4. **Similarity filtering** (line 54): Converts distance to similarity (`1.0 - distance`) and drops anything below `RAG_MIN_SIMILARITY` (default 0.35).

**Why cosine distance?** Cosine distance measures the angle between two vectors, ignoring magnitude. Two paragraphs about "data security" will have similar directions in 768-dimensional space, even if one is longer than the other.

### `fetch_by_section_ids(db, section_ids)` — *Exact Lookup*
**Lines 68–85**

No embedding needed — just `SELECT * WHERE section_id IN (...)`. Used as a fallback when AI is unavailable.

---

## 19. AI Gateway — `app/ai/gateway.py`

### Why Two Providers?

| Capability | Provider | Reason |
|---|---|---|
| **Text generation** | DeepSeek OR Gemini (configurable) | Only one place in the codebase needs text generation (explaining verdicts). Making it swappable lets you choose cost vs. quality. |
| **Embeddings** | Gemini ALWAYS | DeepSeek has no embedding API. All vectors must come from one consistent embedding space — mixing would destroy retrieval accuracy. |

### `generate_text(prompt, system_instruction=None)` — *Generate AI Response*
**Lines 114–117**

Routes to `_generate_deepseek()` or `_generate_gemini()` based on `settings.ai_provider`.

### `_generate_deepseek(prompt, system_instruction)` — *DeepSeek Call*
**Lines 120–182**

Uses `httpx.AsyncClient` to call DeepSeek's OpenAI-compatible REST API. Enforces `response_format: json_object` to get structured JSON output.

**Retry logic**: On HTTP 429 (rate limit) or 5xx (server error), retries with exponential backoff (2^attempt seconds, up to 65 seconds).

**Truncation detection**: If `finish_reason == "length"`, the model hit the output token cap before finishing its JSON. This is raised as `AIResponseTruncatedError` so the caller knows the response is incomplete (not just malformed).

### `_generate_gemini(prompt, system_instruction)` — *Gemini Call*
**Lines 185–225**

Uses the `google-generativeai` SDK. Since the SDK is **synchronous**, the call is wrapped in `_with_retry()` which runs it in `asyncio.to_thread()`.

**Truncation detection**: Gemini 2.5 Flash uses "thinking" tokens that count against `max_output_tokens`. A long prompt can cause the model to exhaust its budget on internal reasoning before emitting any JSON. This is detected via `finish_reason == 2` (MAX_TOKENS) and raised as `AIResponseTruncatedError`.

### `_with_retry(call, what)` — *Retry with Exponential Backoff*
**Lines 77–111**

**Smart retry delay**: Instead of guessing, it reads the `retry_delay.seconds` field from Google's `ResourceExhausted` exception. If Google says "wait 47 seconds", we wait 47 seconds instead of guessing 2^4 = 16.

### `embed(text, task_type)` — *Generate Single Embedding*
**Lines 243–255**

Calls Gemini's embedding model with `output_dimensionality=768`. The native model outputs 3072 dimensions, but we truncate to 768 because:
- Gemini's embedding model uses **Matryoshka representation learning** — the first N dimensions contain the most important information.
- 768 dimensions is 4× smaller, meaning the `corpus_chunks` table is 4× smaller and similarity search is 4× faster.
- After truncation, `_normalise()` scales the vector back to unit length.

### `_normalise(vector)` — *Unit-Length Normalization*
**Lines 228–240**

Divides each component by the vector's magnitude. After Matryoshka truncation, the vector is about 0.58 of unit length. Normalizing keeps similarity scores comparable and enables non-cosine metrics in the future.

### `parse_json_response(raw)` — *Robust JSON Parser*
**Lines 282–315**

AI models sometimes wrap their JSON in markdown code fences (````json ... ````) or add text before/after. This parser handles it:

1. Try parsing as-is.
2. If fails, try removing a wrapping ````json ... ```` fence.
3. If still fails, find the outermost `{...}` or `[...]` and try parsing that.
4. If all attempts fail, return `None`.

**Important**: The fence regex is anchored at the start (`\A`). An unanchored search would match a code fence **inside** a JSON string (e.g., in `suggested_fix`), which would corrupt a valid response.

---

## 20. Grounded Analysis — `app/ai/grounded_analysis.py`

### `explain_verdict(db, verdict, context, restrict_section_ids)` — *Full RAG Pipeline*
**Lines 145–208**

This is the master function that ties retrieval, generation, and verification together.

**Step by step**:
1. Build a retrieval query from the verdict and context.
2. Call `retrieval.retrieve_provisions()` — semantic search for relevant legal text.
3. If no provisions found → return a fallback (deterministic-only explanation, no AI).
4. Call `gateway.generate_text()` with the assembled prompt.
5. Handle errors gracefully:
   - `AIUnavailableError` → fallback
   - `AIResponseTruncatedError` → fallback with explanation
   - Any other error → fallback (a failed AI call must **never** fail the scan)
6. Parse the JSON response.
7. If parsing fails → fallback with the raw response snippet for debugging.
8. Build a `GroundedExplanation` from the parsed JSON.
9. Run `guardrail.apply()` — verify citations and quotes.
10. Return the (possibly flagged) explanation.

### `SYSTEM_INSTRUCTION` — *What We Tell the AI*
**Lines 23–53**

The system prompt has strict rules:
- "You do not decide compliance" — the verdict is already decided.
- "Cite ONLY provisions in the PROVISIONS block" — can't make up sections.
- "citation_text must be a SINGLE CONTIGUOUS SPAN copied character for character" — can't stitch together fragments.
- "An automated check compares your quote" — tells the model about the guardrail so it tries harder.
- "Write for a developer who has to fix the code, not for a lawyer."

### `_build_prompt(verdict, context, provisions)` — *Prompt Construction*
**Lines 70–111**

Assembles four blocks:
1. **VERDICT**: The rule ID, status, and evidence (truncated to 1200 chars).
2. **FAILED CHECKS**: Each failing check with file path and line number (truncated to 600 chars each).
3. **CONTEXT**: The assembled code snippet, callers, callees, PII flows (from the assembler).
4. **PROVISIONS**: The retrieved statutory text with section IDs, citation labels, and titles.

### `_fallback(verdict, reason)` — *When AI Is Unavailable*
**Lines 125–142**

Returns a `GroundedExplanation` with:
- Title and description from the deterministic verdict.
- Empty citation (no AI = no quote to give).
- Confidence = 0.0.
- `guardrail_passed = False` with the reason.

---

## 21. Faithfulness Guardrail — `app/ai/guardrail.py`

### Three Verification Checks

The guardrail runs three independent checks on every AI-generated explanation:

### Check 1: `citation_grounded` — *Did the AI cite what it was shown?*
**Lines 172–189**

**How it works**:
1. Parses section IDs from the AI's citation text (e.g., "Section 8(5)" → `s.8(5)`).
2. Collects the section IDs of provisions that were actually retrieved.
3. For each cited ID, checks if it's in the allowed set.

**Sub-section tolerance**: If the AI was shown `s.12` but cited `s.12(1)`, that's OK (narrowing is fine). But if shown `s.8(5)` and citing `s.8`, that's NOT OK (widening to a section with 11 sub-sections, most of which weren't shown).

### Check 2: `quote_verified` — *Does the quote actually exist?*
**Lines 191–202**

### `_best_quote_ratio(quote, provisions)` — *Fuzzy String Matching*
**Lines 137–163**

**How it works**:
1. Normalizes both the quote and the provision text (lowercase, collapse whitespace).
2. First check: is the quote a substring of the provision? If yes, similarity = 1.0.
3. If not a substring, uses `SequenceMatcher` (Levenshtein-like) to compute similarity.
4. **Sliding window**: A short quote from a long section would score badly against the whole section. So it also slides a window (the size of the quote) across the provision text and checks similarity at each position.
5. Returns the best ratio found.

If the best ratio is below `GUARDRAIL_QUOTE_THRESHOLD` (0.85), the quote is deemed hallucinated.

### Check 3: `entailment_ok` — *Does the explanation follow from the provision?*
**Lines 204–239**

**How it works**:
1. Extracts "content tokens" from both the AI's description and the cited provision (words ≥ 4 chars, excluding stopwords like "the", "and", "shall").
2. Computes vocabulary overlap: `|intersection| / |claim_tokens|`.
3. If overlap < 12%, the claim likely has nothing to do with the provision.
4. **Obligation denial check**: If the AI says "the law does not require encryption", that contradicts the provision which does require it. Detected via regex patterns like "does not require", "no legal obligation", "exempt from".

### `apply(explanation, provisions)` — *Stamp Results*
**Lines 249–265**

**What happens on failure**:
- Failed quote → `citation_text` is cleared (empty string).
- Failed grounding → `citation` is replaced with "Requires manual verification".
- Any failure → `confidence` is capped at 0.4.
- The finding is **kept** but flagged. Hiding it would be worse — the user wouldn't know the tool was uncertain.

---

## 22. Scorecard Scorer — `app/scorecard/scorer.py`

### `compute(verdicts)` — *Calculate Final Grade*
**Lines 68–118**

**Step by step**:
1. **Filter out inapplicable rules**: Verdicts with `NOT_APPLICABLE` status are excluded from both numerator and denominator.
2. **Handle empty results**: If no rules could be assessed (e.g., a bot wall blocked the crawl), return `grade = None` instead of `F`. Saying "Non-Compliant" about a site nobody inspected would be a false statement.
3. **Weighted average**: Each rule has a weight reflecting legal risk (updated with CERT-In and Cross-Border rules):
   - R4 (Consent) = 14%, R6 (Security) = 14%
   - R3 (Notice) = 11%, R10 (Rights) = 11%
   - CERTIN (CERT-In Directions) = 9%
   - RET (Retention) = 8%
   - R5 (Children) = 7%, R7 (Breach) = 7%
   - XBORDER (Cross-Border) = 5%, R8 (DPIA) = 5%
   - R9, R11, R12 = 3% each
4. **Renormalization**: After removing inapplicable rules, the remaining weights are renormalized to sum to 100%. Without this, a code-only scan would cap around 80% even if every applicable rule passed.
5. **Grade mapping**:
   - ≥90 → **A** (Compliant)
   - ≥75 → **B** (Substantially Compliant)
   - ≥50 → **C** (Partially Compliant)
   - ≥25 → **D** (Significant Gaps)
   - <25 → **F** (Non-Compliant)

### `severity_for(verdict, sensitivity)` — *Finding Severity*
**Lines 121–134**

Combines the rule's legal weight with the data's sensitivity to determine finding severity:
- Critical data (Aadhaar, biometric) → always `CRITICAL`.
- Violation on a high-weight rule (Consent, Security) → `CRITICAL`.
- Violation on a low-weight rule → `HIGH`.
- Gap on a high-weight rule → `HIGH`.
- Gap on a low-weight rule → `MEDIUM`.
- Everything else → `LOW`.

---

## 23. PDF Report — `app/scorecard/report.py`

### `render_pdf(db, scan_id)` — *Generate PDF Report*

**Step by step**:
1. Queries all `RuleResult`, `Finding`, and `PIIFlowPath` rows for the scan.
2. Renders an HTML template using **Jinja2** with:
   - The grade (color-coded: green for A/B, amber for C, red for D/F).
   - A rule breakdown table (rule ID, status, checks passed, provision, evidence).
   - All findings, each with severity-colored left border.
   - For each finding: title, description, file location, code snippet, citation, suggested fix.
   - **Unverified findings** get an amber warning box: "This explanation did not pass the faithfulness check and requires manual review."
3. Converts HTML to PDF using **WeasyPrint** — a Python library that renders HTML/CSS to PDF.

**Why WeasyPrint (not wkhtmltopdf or Chrome headless)?**
- Pure Python — no need for a headless browser or external binary.
- Supports `@page` CSS rules for proper A4 pagination.
- Runs inside Docker without X11/display dependencies.
- Handles `page-break-inside: avoid` to keep findings from splitting across pages.

---

## 24. Aggregate Scorer — `app/scorecard/aggregate.py`

**New in latest pull.** Combines results from multiple scan stages (policy + web + code) into a single unified report.

### `build_aggregate(web_rules=None, code_rules=None)` — *Merge Two Scorecards*
**Lines 80–160**

**The problem**: A web scan and a code scan produce separate scorecards. The user wants one unified view.

**The merge strategy**: When a rule was assessed by both stages, take the **lower** of the two scores:
- A rule is only as compliant as its weakest observed evidence.
- Averaging would let a strong code score paper over a page that tracks before consent.
- When only one stage could reach a rule, that stage's score stands unchanged.
- When neither could reach a rule, it's excluded (same as a single scan).

**Step by step**:
1. Index web rules and code rules by `rule_id`.
2. For each rule ID:
   - If both stages have a score → pick the **minimum** (worst case).
   - If only one stage has a score → use that score.
   - If neither stage could assess it → add to `not_assessed` list.
3. Compute weighted average and grade from the merged rule set using the same `RULE_WEIGHTS` and `GRADE_BANDS` as the single-scan scorer.

### `class AggregateRule` — *One Merged Rule*
```python
@dataclass
class AggregateRule:
    rule_id: str           # "R6"
    rule_name: str         # "Security Safeguards"
    score: float           # The lower of web_score and code_score
    status: str            # From the worst-scoring side
    web_score: float | None   # Score from web scan (None if not assessed)
    code_score: float | None  # Score from code scan (None if not assessed)
    sources: list[str]     # ["web", "code"] or ["code"] etc.
    evidence: str | None   # From the worst-scoring side
```

---

## 25. Scorecard API — `app/api/scorecard.py`

### `get_scorecard(scan_id)` — *GET /api/scans/{scan_id}/scorecard*
**Lines 63–177**

**What it does**: Returns the full scorecard for a single scan.

**Key design**: Splits rules into two lists:
- `rules` — rules that were actually assessed (with status, score, weight, evidence)
- `not_assessed` — rules the scan couldn't reach (with the reason)

**Why two lists?** Showing unevaluable rules alongside graded ones invites them to be read as failures. A web crawl can't see a breach register, and an axis pinned at zero for that reason looks identical to one pinned at zero for non-compliance. The frontend renders these separately.

**Summary stats**: The endpoint also returns counts of findings by severity, PII field count, flow path count, and unverified citation count — all via SQL `GROUP BY` aggregate queries.

### `get_aggregate_report(...)` — *GET /api/scans/aggregate*
**Lines 180–321**

**What it does**: Stage 4 — combines results from whichever of stages 1–3 (policy, web, code) already ran into one unified report.

**Parameters**: `policy_scan_id`, `web_scan_id`, `code_scan_id` — all optional, at least one required.

**Step by step**:
1. Validate scan IDs and load scans from the database.
2. If web and/or code scan IDs given → load their `RuleResult` rows.
3. Call `aggregate.build_aggregate()` to merge rule results.
4. If a policy scan is included → load `PolicyCheck` and `PolicyClaimRecord` rows:
   - Count satisfied, failed, and unassessed checks.
   - Build `gap_findings` list with severity, DPDP section, evidence, and quotes.
   - Count contradicted claims (claims the scan disproved).
5. Return the combined result.

**Policy gap severity**: Certain requirements are rated `high` instead of the default `medium`:
- `notice.children` — children's data is high-sensitivity
- `notice.breach_intimation` — breach notification is a bright-line obligation
- `notice.security_measures` — security safeguards are high-weight
- `notice.cross_border` — cross-border transfer is a restriction
- `notice.withdraw_consent` — consent withdrawal is a fundamental right

### `get_pdf_report(scan_id)` — *GET /api/scans/{scan_id}/report/pdf*
**Lines 324–342**

Calls `report.render_pdf()` and returns the PDF as a downloadable `application/pdf` response with filename `dpdp-compliance-{scan_id}.pdf`.

---

## Architecture Summary — One Request, Complete Trace

```
┌─ FRONTEND ─────────────────────────────────┐
│  User clicks "Upload ZIP + Scan"           │
│  POST /api/scan/code (multipart form)      │
└──────────────────┬─────────────────────────┘
                   │
┌─ scan.py ────────▼─────────────────────────┐
│  1. Validate file extension (.zip/.tar)    │
│  2. Stream to disk (1 MB chunks, 50 MB max)│
│  3. _safe_extract() — anti-zipbomb/path    │
│  4. Create Scan row (status=PENDING)       │
│  5. Return HTTP 202 + scan_id              │
│  6. Spawn background task ──────────────── │──▶ asyncio.create_task()
└────────────────────────────────────────────┘
                                              │
┌─ pipeline.py ──────────────────────────────▼┐
│  status → SCANNING                          │
│                                             │
│  ┌─ code_scanner.py ──────────────────────┐ │
│  │ Tree-sitter AST for each .py/.js/.ts   │ │
│  │ Extract: routes, functions, models,    │ │
│  │          PII fields, call edges,       │ │
│  │          CERT-In infra evidence        │ │
│  └────────────────────────────────────────┘ │
│                                             │
│  ┌─ code_graph.py ────────────────────────┐ │
│  │ Build directed call graph (BFS/DFS)    │ │
│  └────────────────────────────────────────┘ │
│                                             │
│  ┌─ pii_flow.py ─────────────────────────┐  │
│  │ Trace PII from HTTP ingress → sinks   │  │
│  │ Check: consent? encryption? retention?│  │
│  └────────────────────────────────────────┘  │
│                                             │
│  ┌─ rules/engine.py ─────────────────────┐  │
│  │ 13 rules, pure functions, no AI       │  │
│  │ Includes CERT-In + Cross-Border       │  │
│  │ Returns: COMPLIANT / GAP / VIOLATION  │  │
│  └────────────────────────────────────────┘  │
│                                             │
│  Save rule results to DB                    │
│  status → ANALYZING                         │
│                                             │
│  For each non-compliant verdict:            │
│  ┌─ assembler.py ────────────────────────┐  │
│  │ Pack bounded context (60 lines max)   │  │
│  └───────────────┬───────────────────────┘  │
│                  │                          │
│  ┌─ retrieval.py ▼───────────────────────┐  │
│  │ Embed query → pgvector cosine search  │  │
│  │ Return top-5 statutory provisions     │  │
│  └───────────────┬───────────────────────┘  │
│                  │                          │
│  ┌─ gateway.py ──▼───────────────────────┐  │
│  │ Send to Gemini/DeepSeek               │  │
│  │ Get structured JSON explanation       │  │
│  └───────────────┬───────────────────────┘  │
│                  │                          │
│  ┌─ guardrail.py ▼──────────────────────┐   │
│  │ Verify: citation grounded?           │   │
│  │         quote exists in law?         │   │
│  │         explanation entailed?        │   │
│  │ Flag unverified findings             │   │
│  └───────────────────────────────────────┘   │
│                                             │
│  Save Finding rows to DB                    │
│                                             │
│  ┌─ scorer.py ───────────────────────────┐  │
│  │ Weighted average → letter grade (A-F) │  │
│  └───────────────────────────────────────┘  │
│                                             │
│  status → COMPLETE, grade = "C"             │
└─────────────────────────────────────────────┘
                   │
┌─ FRONTEND ───────▼─────────────────────────┐
│  Poll sees status=COMPLETE                 │
│  GET /api/scorecard/{id} → grade breakdown │
│  GET /api/findings/{id} → detailed list    │
│  GET /api/scorecard/{id}/pdf → WeasyPrint  │
└────────────────────────────────────────────┘
```
