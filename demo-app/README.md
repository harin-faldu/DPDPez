# Bharat Bazaar, demonstration fixture

**This is a demo fixture, not a product.** It is a small Flask application built to be
scanned by the DPDP Act 2023 compliance reviewer in this repository. It exists to show
what the scanner does with an application that is mostly compliant and has a few real
gaps left in it, which is what almost every live application looks like.

It is the counterpart to `sample-app/`, which is deliberately non-compliant and grades F.
Do not treat either of them as a reference implementation of the Act.

Every name, address, email, identifier and document number in this fixture is invented.
Email domains end in `.invalid` or `example.invalid`, which can never resolve. No real
Aadhaar number, PAN, card number or person appears anywhere. Do not type a real
identifier into it.

## Measured grades

Two scans, two independent scorecards. Evidence is never shared between them.

| Scan | Grade | Score | Applicable rules | Checks passed |
|------|-------|-------|------------------|---------------|
| Code scan, `demo-app/` | B, Substantially Compliant | 81.1 | 10 (R3 excluded) | 29 of 36 |
| Web scan, `http://127.0.0.1:5001/` | B, Substantially Compliant | 82.9 | 7 (R7, R8, R12, RET excluded) | 24 of 27 |

The deliberate gaps behind those numbers are in `KNOWN_GAPS.md`.

## Running it

```
cd demo-app
.venv/Scripts/python.exe app.py
```

The first run creates `.venv` dependencies from `requirements.txt` if you are setting it
up fresh:

```
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
```

It binds to `127.0.0.1:5001` only, runs with the debugger off and the reloader off, and
keeps its data in a local SQLite file. Two files are created on first start and are
already in `.gitignore`:

* `bharat_bazaar.sqlite3`, the database
* `local_keys.txt`, the encryption key and the lookup key

Templates are cached because the debugger is off, so restart the process after editing
one.

### Fixture accounts

Both are invented. Passphrases are shown on the sign in page as well.

| Login | Passphrase | Role |
|-------|-----------|------|
| `buyer.one@example.invalid` | `FixturePass!2026` | account holder |
| `privacy.ops@bharatbazaar.invalid` | `FixtureOps!2026` | privacy ops, can open the internal reports |

## Scanning it

### Code scan

```
cd backend
.venv/Scripts/python.exe -c "import asyncio,sys; sys.path.insert(0,'.'); \
from app.scanner import code_scanner; from app.context.code_graph import CodeGraph; \
from app.context import pii_flow; from app.rules import engine; from app.scorecard import scorer; \
r=asyncio.run(code_scanner.scan_directory('../demo-app')); g=CodeGraph(r); \
f=pii_flow.trace_flows(r,g); v=engine.run_all(code_result=r,flows=f); c=scorer.compute(v); \
print(c.overall_grade, c.overall_score); \
[print(x.rule_id, x.status, x.score, x.checks_passed, len(x.checks)) for x in v]"
```

### Web scan

Start the fixture first, then scan it. The SSRF guard blocks loopback targets unless
private targets are allowed, so set that for the scan process:

```
cd backend
ALLOW_PRIVATE_SCAN_TARGETS=true .venv/Scripts/python.exe -c "import asyncio,sys; \
sys.path.insert(0,'.'); from app.scanner import web_scanner; from app.rules import engine; \
from app.scorecard import scorer; \
r=asyncio.run(web_scanner.scan_url('http://127.0.0.1:5001/')); \
v=engine.run_all(web_result=r); c=scorer.compute(v); print(c.overall_grade, c.overall_score)"
```

## What the fixture does

An Indian retail site with a seller verification flow, which is why it holds both
ordinary contact data and identity documents.

| Area | Routes |
|------|--------|
| Public | `/`, `/products`, `/signup`, `/login`, `/logout`, `/consent/banner`, `/livez` |
| Notices | `/privacy`, `/privacy-policy`, `/cookies`, `/cookie-policy`, `/terms`, `/children`, `/security`, `/refund`, `/grievance`, `/grievance-redressal` |
| Rights, authenticated | `/account`, `/account/data`, `/account/my-data`, `/account/correct`, `/account/correction`, `/account/delete`, `/account/delete-my-data`, `/account/nominee`, `/account/audit-trail` |
| Other authenticated | `/kyc`, `/consent/preferences`, `/consent/withdraw`, `/grievance` (POST) |
| Internal, staff guard | `/internal/v1/customer-export`, `/internal/v1/compliance-report` |

### Controls that are genuinely implemented

* **Notice, section 5.** `/privacy` is linked from the header of every page, not only the
  footer, so it precedes collection. It itemises every purpose with its lawful basis and
  its retention period, names the Data Protection Officer and the Grievance Officer with
  contact addresses, and explains how to take a complaint to the Data Protection Board.
  The table is generated from `purposes.py`, the same register the product reads, so the
  notice cannot drift from the code.
* **Consent, sections 6 and 7.** A banner with Accept and Reject as the same size, weight
  and colour, plus per purpose checkboxes that start unchecked. `ConsentRecord` stores
  who, when, which purpose and which version of the notice. `/consent/withdraw` is a one
  click withdrawal and `/consent/preferences` treats an unticked box as a withdrawal.
  `consent_service.has_consent` is read server side before any analytics or marketing
  processing runs.
* **No pre-consent tracking.** No third party script, pixel, tag manager, beacon or
  webfont exists anywhere in the application. The analytics stub at
  `static/analytics-stub.js` is served from this origin and is referenced by a page only
  after analytics consent has been recorded. A cold load sets no cookie at all.
* **Cookies.** Two cookies can exist and both are strictly necessary: `bb_session` after
  sign in and `bb_consent_choice` after a choice. Both carry Secure, HttpOnly and
  SameSite.
* **Rights, sections 11 to 14.** Access, correction, erasure, nomination and grievance
  redressal are implemented as working authenticated routes in `account_routes.py` and
  `rights_service.py`, with the access export available as HTML and as JSON.
* **Security, section 8(5).** Personal data columns use a Fernet backed
  `EncryptedString` type, so plaintext never reaches the database file. Credentials go
  through PBKDF2-HMAC-SHA256 at 240,000 rounds. A keyed HMAC digest is stored beside the
  encrypted address so sign in can find a row without decrypting the table. Every route
  that can reach personal data is behind `login_required`, the internal reports have a
  second staff guard, nothing personal is written to the log, and every response carries
  a content security policy, HSTS, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` and `Permissions-Policy`.
* **Retention, section 8(7).** Every operational table carries `retain_until`, written
  from the purpose register at insert time, and `purge_expired_records` sweeps hourly.
* **Breach, section 8(6).** `BreachIncident` records detection time and a 72 hour
  deadline, with separate `notify_board` and `notify_affected_principals` paths.
* **Audit and record of processing, section 8(1).** `AuditLogEntry` records reads as well
  as writes with the purpose of each access, `processing_register.py` holds the record of
  processing activities, and `generate_compliance_report` produces the evidence pack.
* **Children, section 9.** Date of birth is collected and evaluated, not just stored.
  `calculate_age` feeds `is_minor`, which feeds the guardian consent challenge and
  `tracking_allowed_for`, which refuses analytics for a minor whatever the consent record
  says.

### Gaps left in on purpose

See `KNOWN_GAPS.md`. They are the point of the fixture: a scanner that fails everything
is not useful, and neither is one that passes everything.

## Safety notes

* Loopback only, debugger off, reloader off.
* No outbound network call at runtime. Mail is written to a `mail_outbox` table and left
  there.
* Synthetic data only.
* Not hardened, not rate limited, no CSRF tokens. Do not expose it to a network.
