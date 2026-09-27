# DPDPA Compliance Self-Check

Scans a web form or a codebase and produces a compliance scorecard against the
Digital Personal Data Protection Act 2023 and the DPDP Rules 2025.

Built for the Cyber Kavach Challenge 2026, problem statement S3.

## The design decision that matters

**The verdict is deterministic. AI only explains it.**

A rules engine decides whether each requirement is met, using concrete checks:
is the consent checkbox pre-checked, is the Aadhaar column encrypted, does an
erasure endpoint exist. Those checks are pure functions. Run the same scan twice
and you get the same verdict.

Gemini is then handed the verdict that was already decided, along with the
statutory provisions retrieved for it, and asked to explain and cite. It is
never asked whether something is compliant.

This means you can audit any finding without trusting the model, and a wrong
model output degrades the explanation rather than the verdict.

## Faithfulness guardrail

Every AI explanation passes three checks before it is stored:

1. **Citation grounding** — the cited section must exist among the provisions
   actually retrieved for this finding. The model cannot cite what it was not shown.
2. **Quote verification** — the quoted statutory text must really appear in the
   cited provision.
3. **Entailment** — the claim must follow from the provision, and must not
   invert its obligation.

A finding that fails is kept and flagged, never silently dropped.

## Coverage, stated precisely

The Digital Personal Data Protection Rules, 2025 were notified by G.S.R. 846(E)
on 13 November 2025 and contain **23 rules**, not the 12 of the January 2025
draft. Numbering moved between the two: additional obligations of a Significant
Data Fiduciary went from draft rule 11 to notified rule 13, and rights of Data
Principals from draft 12 to notified 14.

This tool evaluates **11 compliance dimensions** covering the operative
obligations a Data Fiduciary can be assessed against from a website or a
codebase. Each dimension cites specific provisions of the Act and of the
notified Rules:

| Dimension | Act | Rules 2025 |
|---|---|---|
| Notice | s.5 | rule 3, rule 9 |
| Consent | s.6, s.7 | rule 3, rule 4 |
| Children's data | s.9 | rule 10, rule 12 |
| Security safeguards | s.8(4), s.8(5) | rule 6 |
| Breach notification | s.8(6) | rule 7 |
| Impact assessment | s.10(2) | rule 13 |
| Significant Data Fiduciary | s.10(1), s.10(2) | rule 13 |
| Data Principal rights | s.11 to s.14 | rule 14 |
| Board readiness | s.13, s.27 | rule 9, rule 14 |
| Compliance verification | s.8(1), s.8(2) | rule 6 |
| Retention and erasure | s.8(7) | rule 8 |

Rules 15 to 23 govern cross-border transfer, research exemptions and the
constitution and procedure of the Board itself. They are carried in the corpus
so they can be cited, but they are not scored: a scanner cannot determine from
source code whether the Board has been properly constituted.

## Architecture

```
Web scanner (Playwright)  ─┐
                           ├─→ Context engine ─→ Rules engine ─→ Grounded RAG ─→ Scorecard
Code scanner (tree-sitter)─┘    code graph      11 dimensions      + guardrail      A-F grade
                                PII flow map     deterministic       Gemini
```

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Module ownership and tech justifications in [docs/TEAM_SPLIT.md](docs/TEAM_SPLIT.md).

## Stack

| Layer | Choice | Why |
|---|---|---|
| API | FastAPI | Async, so scanning and AI calls do not block each other |
| Database | PostgreSQL + pgvector | One store for app data and vector search, no external vector service |
| Code parsing | tree-sitter | Real AST across five languages, not regex over text |
| Web scanning | Playwright | Modern forms are JS-rendered; an HTTP fetch sees an empty div |
| AI | Gemini 2.5 Flash + text-embedding-004 | One provider for generation and embedding, fast enough to call per finding |
| Frontend | React 19 + Vite + Recharts | Fast dev loop, SVG radar chart for the scorecard |

## Running it

```bash
cp .env.example .env
# set POSTGRES_PASSWORD and GEMINI_API_KEY in .env
docker compose up --build
```

Backend on http://localhost:8000, interactive API docs at `/docs`.

Frontend separately:

```bash
cd frontend && npm install && npm run dev
```

Without `GEMINI_API_KEY` the scan still runs and still produces a scorecard.
Findings just carry no grounded explanation or citation.

## Models

Generation and embedding are split by capability, not preference.

| Job | Provider | Why |
|---|---|---|
| Explanation and citation | DeepSeek V4.1-Flash, or Gemini via `AI_PROVIDER` | The only step that writes prose, so the only one worth making swappable. DeepSeek reached over its OpenAI-compatible API. |
| Corpus and query embeddings | Gemini `gemini-embedding-001` | DeepSeek publishes no embedding endpoint. Corpus and query vectors must share one space or retrieval degrades silently. |

`gemini-embedding-001` emits 3072 dimensions and is truncated to 768 to match
the corpus column, then re-normalised: truncating a Matryoshka embedding leaves
it well short of unit length.

## Status

All modules implemented. **480 tests pass.**

Verified end to end against `sample-app/`, the deliberately non-compliant demo
target: upload, scan, 11 verdicts, grounded explanations, scorecard, dashboard.
It grades **F at 9.2/100** with 10 findings, 47 personal data fields and 82 data
flow paths traced.

With DeepSeek generation and Gemini embeddings live, **all 10 findings pass the
faithfulness guardrail** with citations grounded in the notified gazette text.
The guardrail still rejects a fabricated section number and an invented quote
when those are injected deliberately, so the pass rate reflects good output
rather than a disabled check.

Not exercised:

- **PDF export on Windows.** WeasyPrint needs cairo and pango, which ship in
  the backend container but not on a bare Windows host. The endpoint returns
  503 with an explanation rather than failing opaquely. Run under Docker.

Known rough edge: a single logical database write can produce more than one
traced flow, because an ORM `add` and the following `commit` are both sinks.
This inflates the flow count without changing any verdict.

Running against a rate-limited key is slow but correct: the gateway honours the
`retry_delay` a 429 carries rather than dropping the finding. On Gemini's free
tier, whose quota is 20 generations per minute, a full scan spends most of its
time waiting. DeepSeek does not have that constraint.
