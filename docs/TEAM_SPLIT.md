# Team Work Division — Cyber Kavach 2026

4 members, 4 modules. Each person owns their slice end-to-end and can explain every line in it to the jury.

---

## HARIN — Core Engine (Scanner + Context + PII)

**Owns:** `backend/app/scanner/`, `backend/app/context/`, `backend/app/pii/`

This is the hardest technical layer. Everything downstream depends on Harin's output.

### Files
```
backend/app/scanner/
  web_scanner.py         Playwright crawl, form extraction, consent detection, headers
  code_scanner.py        tree-sitter AST parsing, symbol extraction, route/model detection

backend/app/context/
  code_graph.py          Build call graph + dependency edges from AST
  pii_flow.py            Trace each PII field: source → transform → sink
  assembler.py           Pack relevant context for AI prompts

backend/app/pii/
  taxonomy.py            PII categories, sensitivity tiers
  indian_ids.py          Aadhaar Verhoeff, PAN format, GSTIN, Luhn card validation
  field_classifier.py    Field name → PII category classifier
```

### What Harin delivers
- `WebScanResult` — forms, consent elements, privacy notice, security headers, cookies
- `CodeScanResult` — files, symbols, db_models, routes, pii_fields, data_flow_edges
- `PIIFlowPath` — end-to-end trace of each PII field through the codebase
- Context assembler that packs code graph + PII flows into a structured object

### Jury questions Harin answers
- "How does your scanner detect PII across different languages?"
- "Explain the data flow tracing — how do you track an Aadhaar number from input to storage?"
- "What is tree-sitter and why did you choose AST parsing over regex?"
- "How does Verhoeff checksum validation work for Aadhaar?"

### Build order
1. tree-sitter parser setup (Python + JS) — Hour 1-2
2. PII taxonomy + Indian ID validators — Hour 2
3. Code scanner: AST walk, symbol/route/model extraction — Hour 3
4. Data flow edge builder + PII flow tracer — Hour 4
5. Web scanner: Playwright crawl + form/consent/header checks — Hour 5
6. Context assembler — Hour 6

### Interface contract (what Harin gives to others)
```python
@dataclass
class WebScanResult:
    url: str
    forms: list[FormInfo]
    consent_elements: list[ConsentInfo]
    privacy_notice: Optional[NoticeInfo]
    security_headers: dict[str, str]
    third_party_scripts: list[ScriptInfo]
    cookies: list[CookieInfo]

@dataclass
class CodeScanResult:
    files: list[FileInfo]
    symbols: list[SymbolInfo]
    db_models: list[ModelInfo]
    routes: list[RouteInfo]
    pii_fields: list[PIIField]
    data_flow_edges: list[DataFlowEdge]

@dataclass
class PIIFlowPath:
    pii_category: str
    source: str
    transforms: list[str]
    sink: str
    has_consent_check: bool
    has_encryption: bool
    has_retention_policy: bool

@dataclass
class AnalysisContext:
    code_snippet: str
    callers: list[SymbolInfo]
    callees: list[SymbolInfo]
    pii_flows: list[PIIFlowPath]
    related_models: list[ModelInfo]
```

---

## PRERANA — Rules Engine (11 compliance dimensions)

**Owns:** `backend/app/rules/`, `backend/app/corpus/`

Prerana's DPDP knowledge drives this layer. Each rule checker is a pure function that takes scan results and returns a verdict with evidence.

### Files
```
backend/app/rules/
  engine.py              Orchestrator — runs all checkers, aggregates results
  r03_notice.py          Rule 3: Notice before collection
  r04_consent.py         Rule 4: Free, specific, informed consent
  r05_children.py        Rule 5: Children's data protection
  r06_security.py        Rule 6: Security safeguards
  r07_breach.py          Rule 7: Breach notification (72hr)
  r08_dpia.py            Rule 8: Data Protection Impact Assessment
  r09_sdf.py             Rule 9: Significant Data Fiduciary obligations
  r10_rights.py          Rule 10: Data Principal rights (access/correct/erase/nominate)
  r11_dpb.py             Rule 11: Data Protection Board readiness
  r12_verification.py    Rule 12: Compliance verification/audit
  retention.py           s.8(7): Retention and erasure

backend/app/corpus/
  dpdp_act.py            All 44 sections as structured Python data
  dpdp_rules.py          All 23 notified rules as structured Python data
  chunker.py             Section → citation-bearing chunks for RAG
  indexer.py             Embed chunks + store in pgvector
```

### What Prerana delivers
- `RuleResult` for each of the 11 dimensions (status + score + evidence + section citation)
- Statutory corpus ready for embedding (chunked, with citation labels)
- The mapping between what the scanner finds and what the law requires

### Every rule checker follows this pattern
```python
def check(scan_result, context) -> RuleResult:
    # Look at scan_result for evidence
    # Return deterministic verdict
    return RuleResult(
        rule_id="R4",
        rule_name="Consent",
        status="gap",           # compliant | gap | violation | not_applicable
        score=0.5,
        evidence="Consent checkbox found but pre-checked",
        dpdp_section="s.6(1)",
        dpdp_rule="Rule 4"
    )
```

### Jury questions Prerana answers
- "Walk us through how Rule 4 consent checking works"
- "How do you map a code-level finding to a specific DPDP section?"
- "What is the difference between a gap and a violation in your scoring?"
- "How did you handle Rule 9 SDF — how do you determine if someone is an SDF?"
- "Explain how the corpus is structured for RAG retrieval"

### Build order
1. Corpus: type out DPDP Act key sections + all 23 notified Rules as structured data — Hour 1-2
2. Chunker + indexer (prepare for pgvector embedding) — Hour 2
3. engine.py orchestrator + RuleResult dataclass — Hour 3
4. Priority rules: R3, R4, R6, R10, retention (most demo-visible) — Hour 3-5
5. Remaining rules: R5, R7, R8, R9, R11, R12 — Hour 6-7

### Interface contract
```python
@dataclass
class RuleResult:
    rule_id: str            # "R3", "R4", ..., "RET"
    rule_name: str          # "Notice", "Consent", ...
    status: str             # compliant | gap | violation | not_applicable
    score: float            # 0.0 to 1.0
    evidence: str           # what was found or missing
    dpdp_section: str       # "s.5", "s.6(1)", ...
    dpdp_rule: str          # "Rule 3", "Rule 4", ...

@dataclass
class StatutoryChunk:
    source: str             # "act" or "rules"
    section_id: str         # "s.6(1)" or "rule_4"
    section_title: str
    text: str
    citation_label: str     # "DPDP Act 2023, Section 6(1)"
```

---

## MANAN — Frontend + Scorecard + Demo App

**Owns:** `frontend/`, `backend/app/scorecard/`, `backend/app/api/`, sample vulnerable app

Manan builds everything the jury sees: the dashboard, the scorecard logic, the API endpoints that wire backend to frontend, and the demo app that we scan live.

### Files
```
frontend/src/
  App.jsx                 Router setup
  main.jsx                Entry point
  pages/
    Home.jsx              Landing page + scan input
    ScanResults.jsx       Scorecard + findings display
    DataFlow.jsx          PII flow visualization
  components/
    ScanForm.jsx          URL input + code upload dropzone
    ScoreCard.jsx         Radar chart (Recharts) + overall grade badge
    RuleStatus.jsx        Per-rule compliance cards with status badges
    FindingsList.jsx      Sortable table of findings with citations
    CodeViewer.jsx        Syntax-highlighted code with flagged lines
    DataFlowGraph.jsx     Visual PII flow: source → transform → sink
  api/
    client.js             Axios instance + API calls

backend/app/scorecard/
  scorer.py               Weighted scoring: per-rule scores → overall grade
  report.py               PDF generation (Jinja2 + WeasyPrint)

backend/app/api/
  scan.py                 POST /scan/web, POST /scan/code
  findings.py             GET /scans/{id}/findings
  scorecard.py            GET /scans/{id}/scorecard
  health.py               GET /health

sample-app/               Intentionally vulnerable Flask app for demo
```

### What Manan delivers
- Working React dashboard with scan input, radar chart scorecard, findings list, code viewer
- Scoring algorithm (weighted average across 11 rules → A/B/C/D/F grade)
- API routes that connect frontend to scanner/rules/AI layers
- PDF report export
- Sample vulnerable app with violations across all 11 dimensions

### Jury questions Manan answers
- "Walk us through the UI — how does a user interact with this?"
- "How is the overall grade calculated? What are the weights?"
- "How does the radar chart map to the dimensions?"
- "Show us the PDF report"
- "Tell us about the sample app — what violations did you plant?"

### Scoring weights Manan implements
```
R04 Consent:    15%
R06 Security:   15%
R03 Notice:     12%
R10 Rights:     12%
Retention:      10%
R05 Children:   8%
R07 Breach:     8%
R08 DPIA:       5%
R09 SDF:        5%
R11 DPB:        5%
R12 Verify:     5%

Grade: A (90+), B (75-89), C (50-74), D (25-49), F (0-24)
```

### Build order
1. React scaffold + Tailwind + routing — Hour 1
2. ScanForm component (URL input + file upload) — Hour 2
3. API routes (scan.py, findings.py, scorecard.py) — Hour 3-4
4. Scorer + grade calculation — Hour 4
5. ScoreCard radar chart + RuleStatus cards — Hour 5-6
6. FindingsList + CodeViewer — Hour 6-7
7. Sample vulnerable Flask app — Hour 7
8. PDF report — Hour 8
9. Polish: loading states, error handling, responsive — Hour 9

---

## ARYAN — AI Layer + Integration + Product (Team Lead)

**Owns:** `backend/app/ai/`, `backend/app/models/`, `backend/app/database.py`, `backend/app/config.py`, `backend/app/main.py`, `docker-compose.yml`, infrastructure, README, presentation

Aryan is the architect. He sets up the project skeleton everyone works in, builds the AI layer (Gemini RAG + guardrail), wires all modules together, and owns the product narrative.

### Files
```
backend/app/
  main.py                FastAPI app, CORS, lifespan events
  config.py              Pydantic settings from env vars
  database.py            SQLAlchemy async engine + session factory

backend/app/models/
  scan.py                Scan model
  finding.py             Finding model
  rule_result.py         RuleResult model
  pii_field.py           PIIField model
  data_flow.py           DataFlowEdge + FlowPath models

backend/app/ai/
  gateway.py             Gemini client (embedding + generation)
  embeddings.py          text-embedding-004 wrapper
  grounded_analysis.py   RAG pipeline: retrieve provisions → generate explanation
  guardrail.py           Citation exists? Quote matches? Entailment holds?

docker-compose.yml       Postgres + backend + frontend
.env.example
.gitignore
alembic.ini + migrations
README.md
```

### What Aryan delivers
- Project skeleton that everyone clones and works in
- Database models + migrations
- Gemini RAG pipeline: embed corpus → retrieve top-k → generate grounded explanation
- Faithfulness guardrail (3 checks: citation exists, quote matches, entailment)
- Integration: wire scanner → context → rules → AI → scorecard → API
- README and presentation narrative

### Jury questions Aryan answers
- "What is your architecture and why did you design it this way?"
- "Explain the deterministic verdict principle — why doesn't AI decide compliance?"
- "How does your grounded RAG work? How do you prevent hallucinated citations?"
- "What is the faithfulness guardrail? Walk us through the 3 checks"
- "What is the product vision? How would this be used in practice?"
- "Why these tech choices — FastAPI, pgvector, Gemini, tree-sitter?"

### Build order
1. Project scaffold: git init, docker-compose, FastAPI skeleton, DB setup — Hour 0 (before everyone starts)
2. SQLAlchemy models + Alembic migration — Hour 1
3. Gemini gateway + embeddings wrapper — Hour 3-4
4. Grounded analysis: RAG retrieve + generate — Hour 5-6
5. Guardrail: citation + quote + entailment checks — Hour 6
6. Integration: wire all 4 modules together end-to-end — Hour 7-8
7. Testing full pipeline: upload code → scan → rules → AI → scorecard — Hour 8-9
8. README + presentation prep — Hour 9-10

---

## Dependency Flow

```
ARYAN (skeleton + DB models)
  │
  ├──→ HARIN (scanner + context + PII)
  │       │
  │       └──→ uses Aryan's DB models to store results
  │
  ├──→ PRERANA (rules + corpus)
  │       │
  │       ├──→ consumes Harin's ScanResult + Context
  │       └──→ corpus used by Aryan's RAG layer
  │
  ├──→ MANAN (frontend + API + scorecard)
  │       │
  │       ├──→ API calls Harin's scanners
  │       ├──→ API calls Prerana's rules engine
  │       └──→ API calls Aryan's AI layer
  │
  └──→ ARYAN (AI layer)
          │
          ├──→ consumes Prerana's corpus (for RAG retrieval)
          ├──→ consumes Harin's context (for grounded prompts)
          └──→ integration: wires everything together
```

### Parallel work windows

**Hours 1-2:** Aryan sets up skeleton + DB. Others read architecture doc, set up local env.

**Hours 2-6:** All 4 work in parallel on their own modules. No blocking.
- Harin: scanners + PII + context
- Prerana: rules + corpus
- Manan: frontend + API stubs (mock data until real scanners ready)
- Aryan: AI layer + models

**Hours 7-8:** Integration. Aryan wires modules together. Manan switches from mocks to real API.

**Hours 9-10:** End-to-end testing. Demo prep. README.

---

## Git Workflow

Each person works on their own directory. Minimal merge conflicts.

```
main
  └── everyone pushes to main directly (hackathon, not production)
      commit format: "[module] what changed"
      examples:
        [scanner] add tree-sitter Python parser + PII field detection
        [rules] implement R3 notice + R4 consent checkers
        [frontend] add scorecard radar chart component
        [ai] add Gemini RAG pipeline + citation guardrail
        [infra] add docker-compose + DB migrations
```

No branches. Direct to main. Commit early, commit often. The jury reads commit history.

---

## What each person presents (5 min each in 20-min slot)

1. **Aryan (3 min):** Product pitch + architecture overview + AI/guardrail demo
2. **Harin (5 min):** Live code scan demo + data flow trace walkthrough
3. **Prerana (5 min):** Rule-by-rule walkthrough + statutory mapping + how verdict works
4. **Manan (5 min):** UI walkthrough + scorecard explanation + PDF report + sample app
5. **Q&A (remaining):** Each person answers questions about their module

---

## Tech Choice Justifications

Every choice must be explainable. Below is every technology, why we picked it, who explains it, and what the alternative was.

### ARYAN explains (architecture + AI decisions)

| Choice | Why | What we considered instead |
|---|---|---|
| **FastAPI** over Flask/Django | Async by default so scanner and AI calls don't block each other. Auto-generates OpenAPI docs, which helped us wire frontend fast. Type hints with Pydantic give us runtime validation for free. | Flask has no native async. Django is too heavy for a 10-hour build. |
| **PostgreSQL + pgvector** over Pinecone/Chroma | Single database for both application data and vector search. No external API dependency, no rate limits, no billing surprises during demo. pgvector runs as a Postgres extension so we get SQL joins between findings and embeddings in one query. | Pinecone adds network latency and a separate auth flow. Chroma is in-memory and doesn't persist across restarts. |
| **Gemini 2.5 Flash** | Fastest inference for our use case. We need low latency because we run AI on every finding. Flash is cheap enough to call repeatedly without burning through API credits during a live demo. Large context window means we can pack substantial code context. | Other frontier models are slower and more expensive per call, and would mean a second provider for embeddings. Gemini's text-embedding-004 gives us one provider for both embedding and generation. |
| **text-embedding-004** (768 dim) over OpenAI ada | Same provider as our generation model, so one API key, one SDK, one billing. 768 dimensions is a good balance between quality and storage. Google's embedding model benchmarks well on legal/technical text. | OpenAI ada-002 would mean managing two API keys and two SDKs for no real benefit. |
| **Deterministic verdict + AI explains** over letting AI decide compliance | The jury's biggest concern will be trust. If AI decides "compliant" or "violation", how do you audit that? Our rules engine produces the verdict using concrete checks (checkbox found? encryption present?). AI only generates the explanation and citation. You can verify the verdict without AI. | Fully AI-driven analysis would be faster to build but impossible to trust or audit. |
| **Grounded RAG** over fine-tuning or prompt-only | We have a fixed, small corpus (DPDP Act + Rules, roughly 50 pages). RAG retrieves the exact provision before generation, so every citation is traceable. Fine-tuning would bake legal text into weights where you can't verify it. Prompt-only would hit context limits and hallucinate citations. | Fine-tuning takes hours and you can't point to where a citation came from. Stuffing the entire Act into every prompt wastes tokens and context. |
| **Faithfulness guardrail (3 checks)** | CERT-In jury will test if citations are real. Our guardrail checks: (1) does the cited section exist in our corpus, (2) does the quoted text actually appear in that section (fuzzy match > 0.85), (3) does the claim follow from the provision. Findings that fail are flagged, not hidden. | Without this, one hallucinated citation during the demo would destroy credibility. |
| **Docker Compose** over bare metal | One command to start everything: Postgres + pgvector + backend + frontend. Any team member can run the full stack locally. No "works on my machine" during demo. | Installing Postgres + pgvector natively on each laptop would waste an hour of hackathon time. |

### HARIN explains (scanner + engine decisions)

| Choice | Why | What we considered instead |
|---|---|---|
| **tree-sitter** over regex/semgrep | tree-sitter gives us a real AST, not pattern matching on text. We can walk the syntax tree to find function definitions, class hierarchies, DB model columns, and route decorators structurally. A regex can't tell if "email" is a variable name, a string literal, or a comment. tree-sitter can. | Regex breaks on multiline code, nested structures, and string literals. Semgrep is powerful but its rule language has a learning curve and it's designed for security rules, not data flow analysis. |
| **Multi-language support** (Python, JS, TS, Java, Go) | Indian apps are built in all of these. A compliance tool that only handles Python misses most real-world codebases. tree-sitter has grammar packages for each language, so adding a language is just importing another grammar. | Supporting only Python would be simpler but would fail the "scalability" judging criterion (10% of score). |
| **Playwright** over requests/BeautifulSoup for web scanning | Modern web forms are JavaScript-rendered. A simple HTTP request gets the server HTML, which might be an empty div with a React mount point. Playwright runs a real browser, executes JavaScript, and gives us the actual rendered DOM with all form fields, checkboxes, and consent elements. | requests + BeautifulSoup would miss any SPA or dynamically rendered form, which is most modern Indian web apps. |
| **Code graph (directed graph in Postgres)** over in-memory | The graph persists across analysis steps. Rules engine, AI layer, and scorecard can all query the same graph independently. Storing in Postgres means we can join edges with PII fields to answer "which functions touch this Aadhaar field?" in SQL. | NetworkX in-memory graph would be faster for small codebases but disappears on restart and can't be queried by other modules. |
| **PII flow tracing (source → transform → sink)** | The jury cares about data flow, not just field detection. Finding "email" in a column definition is easy. Showing that the email enters at a registration form, passes through a logging function that prints it in plaintext, and then gets sent to a third-party analytics API without consent — that is what the context engine does. It traces the full lifecycle. | Just listing PII fields without flow context would be a detection tool, not a compliance tool. The DPDP Act cares about how data is processed, not just that it exists. |
| **Verhoeff checksum for Aadhaar** | Aadhaar uses Verhoeff, not Luhn. If we used Luhn, we would get false positives and false negatives on Aadhaar numbers. Getting this right shows the jury we understand Indian identity infrastructure. | Most tools use regex-only (12 digits starting with 2-9). That catches phone numbers and random 12-digit strings as Aadhaar. |

### PRERANA explains (rules + legal mapping decisions)

| Choice | Why | What we considered instead |
|---|---|---|
| **11 dimensions covering the full obligation set** | Most compliance tools check three or four things. We score 11 dimensions because that is the set a Data Fiduciary can actually be assessed on from a site or a codebase. Note the notified Rules 2025 contain 23 rules, not the 12 of the January draft, and the numbering moved: SDF duties went from draft 11 to notified 13, rights from draft 12 to notified 14. A Data Fiduciary cannot be compliant on consent but ignore breach notification. The scorecard must reflect the full picture. | Covering only three would be faster to build but would fail the "regulatory alignment" criterion (10%) and the jury would immediately ask "what about breach notification? what about children's data?" |
| **Deterministic rule checkers (pure functions)** | Each rule checker takes scan results in and returns a verdict out. No side effects, no AI calls, no randomness. If you run the same scan twice, you get the same verdict. This is auditable. The jury can read the function and verify the logic. | Making AI decide compliance would be black-box. An auditor needs to see exactly why a verdict was reached. |
| **Three-tier status: compliant / gap / violation** | Real compliance is not binary. A site might have a consent checkbox but it is pre-checked — that is a gap, not a full violation and not compliant either. Three tiers give useful information: violation means "you are breaking the law", gap means "you are trying but falling short", compliant means "this requirement is satisfied". | Binary pass/fail loses nuance. The jury will test edge cases — a gap finding shows we thought about partial compliance. |
| **Statutory corpus as structured Python data** | Typing out the Act sections and Rules as Python dataclasses means every chunk has a machine-readable section_id, title, and citation_label. No PDF parsing, no OCR errors, no stale cached HTML. The source of truth is in our code and we can verify every character. | Scraping from a government website would introduce parsing errors and would fail if the site is down during the demo. PDF extraction of legal text is messy (columns, footnotes, headers mid-sentence). |
| **Citation-bearing chunks** for RAG | Each chunk carries its own citation label ("DPDP Act 2023, Section 6(1)"). When the AI retrieves a chunk, the citation comes with it — the model does not need to guess which section it is reading. This is why our citations are accurate. | Chunking by token count without citation metadata means the model has to figure out which section a chunk belongs to, which is where hallucinated citations come from. |

### MANAN explains (frontend + scoring + demo decisions)

| Choice | Why | What we considered instead |
|---|---|---|
| **React 19 + Vite** over Next.js/Angular | We need a fast SPA, not SSR. Vite gives sub-second hot reload during development. React is the most widely understood frontend framework, so any team member can jump in if needed. No server-side complexity. | Next.js adds SSR/routing complexity we don't need. Angular has a steeper learning curve and slower dev server. |
| **Recharts** for radar chart | Recharts is built for React, uses SVG (crisp at any zoom), and has a RadarChart component out of the box. We need exactly one chart type — a radar showing every scored dimension — and Recharts does it with minimal code. | D3 is powerful but requires writing SVG by hand. Chart.js uses canvas (blurry on zoom) and has a less React-native API. |
| **Tailwind CSS 4** over Bootstrap/Material | Utility classes keep styling in the component, no separate CSS files to manage. Tailwind 4 has a Vite plugin so setup is one line. Dark mode for free. Looks professional without a design system. | Bootstrap looks generic. Material UI adds 200KB of components we won't use. |
| **Weighted scoring with rule priorities** | Consent and security carry 15% each because they are the core obligations with the highest penalty exposure. Children's data carries 8% because it applies only when processing minors' data. The weights reflect legal risk, not equal distribution. The jury will ask why consent matters more than DPIA — because Section 6 is a prerequisite for all lawful processing. | Equal weights (9% each) would be simpler but legally wrong. A site that nails consent but has no breach notification is in a very different compliance position than vice versa. |
| **Sample vulnerable Flask app** for demo | We need a live target to scan that fails across every scored dimension. Building our own means we know exactly what violations exist and can narrate the demo around them. The app is intentionally bad: plaintext Aadhaar, pre-checked consent, no age gate, PII in logs. | Using a real website risks legal issues and unpredictable results. Using mock data means the jury doesn't see a real scan. |
| **PDF report (Jinja2 + WeasyPrint)** | Compliance officers want a downloadable report, not just a web dashboard. WeasyPrint renders HTML templates to PDF, so we reuse the same data. Jinja2 templates mean the report layout is customizable. | ReportLab is lower-level and requires manual coordinate placement. wkhtmltopdf needs a separate binary install. |
| **Axios** over fetch | Interceptors for error handling, request/response transforms, and base URL config in one place. Three lines to set up, consistent across all API calls. | Native fetch works but needs manual error handling, no interceptors, and more boilerplate per call. |

---

## Common Questions the Whole Team Should Be Ready For

**"Why not use an existing compliance tool?"**
Existing tools are checkbox audits or manual questionnaires. None of them read your actual code, trace data flows, or cite specific DPDP provisions. We built a tool that looks at what the code actually does, not what a developer claims it does.

**"How do you handle false positives?"**
Three layers: (1) PII field classifier has a negative filter that rejects UI/config fields like "email_template" or "phone_format", (2) Indian ID validators use actual checksums not just regex, (3) findings that fail the AI guardrail are flagged as unverified rather than dropped. We prefer transparency over silence.

**"Can this scale to large codebases?"**
The context assembler does not send the entire codebase to AI. It builds a code graph, identifies relevant nodes (2 hops upstream and downstream from each PII field), and packs only that context. A 10,000-file repo gets analyzed the same way as a 10-file repo — only the relevant code reaches the AI.

**"What happens when the DPDP Act gets amended?"**
The statutory corpus is structured Python data, not a scraped PDF. Updating a section means changing one string in dpdp_act.py and re-running the indexer. The rule checkers reference section IDs, so new provisions can be added without touching existing rules.

**"Is this only for Indian law?"**
The architecture is law-agnostic. The scanner, context engine, and AI layer work on any codebase. The rules engine and corpus are DPDP-specific, but swapping in GDPR provisions and GDPR rule checkers would produce a GDPR compliance tool. We scoped to DPDP because that is the problem statement.

**"Did you use AI to write this code?"**
We used AI coding assistance during the build, as permitted by the hackathon rules. Every team member understands and can explain their module because we designed the architecture first and implemented against fixed interface contracts. The design decisions are ours.
