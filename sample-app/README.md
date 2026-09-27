# Sample Vulnerable App

> ## WARNING: INTENTIONALLY VULNERABLE DEMO FIXTURE. DO NOT DEPLOY.
>
> This Flask app exists only as the scan target for the DPDP compliance
> reviewer. Every privacy failure in it was planted on purpose. It must never
> be deployed, exposed through a tunnel, or run on a machine that holds real
> data. It binds to `127.0.0.1` only, the debugger is off, and every value it
> stores is a synthetic placeholder. Never type a real Aadhaar, PAN, card
> number or personal detail into any form in this app.

**OWNER: Manan**

A deliberately non-compliant Flask app used as the live scan target during the
demo. Building our own target means we know exactly which violations exist and
can narrate the demo around them, instead of scanning a real site and hoping.

Do not fix anything in here. The violations are the point.

## Planned violations, one per rule

| Rule | Violation to plant |
|---|---|
| R3 Notice | No privacy notice page anywhere |
| R4 Consent | Single consent checkbox, pre-checked with `checked` |
| R5 Children | Date-of-birth collected but never evaluated |
| R6 Security | Aadhaar stored as plaintext `String`, password stored with `md5`, Aadhaar written to `logging.info` |
| R7 Breach | No incident model, no notification path |
| R8 DPIA | No assessment document |
| R9 SDF | No DPO, no audit log |
| R10 Rights | No access, correction, erasure or nomination endpoint |
| R11 DPB | No grievance intake |
| R12 Verify | No audit trail of data access |
| Retention | No expiry on any column, no cleanup job |

Also plant one cross-file data flow worth showing on the graph: Aadhaar arrives
at `POST /kyc`, gets written to the users table, is read back by a reporting
function, and is sent to an external analytics URL with no consent check. That
single path lights up R4, R6 and Retention at once and is the clearest thing to
show the jury.

Use synthetic values only. No real Aadhaar, PAN or card numbers, including in
fixtures and seed data.

## Where each violation lives

| Rule | Planted at |
|---|---|
| R3 Notice | `templates/base.html` footer, `templates/index.html`, `templates/signup.html`: no notice page exists and nothing links to one |
| R4 Consent | `templates/signup.html` single `checked` checkbox; `routes/signup.py` reads `consent_all` and never branches on it; `reporting.py` sends without a consent lookup; no withdrawal route |
| R5 Children | `templates/signup.html` collects `date_of_birth`, `models.py` stores it, nothing computes an age or asks for parental consent |
| R6 Security | `models.py` plaintext `aadhaar_number`; `crypto_utils.legacy_password_digest` uses `hashlib.md5`; `routes/kyc.py` writes Aadhaar to `logging.info`; `routes/account.py` `GET /api/customer/<id>` returns PII unauthenticated |
| R7 Breach | absent by design: no incident model, no notification path |
| R8 DPIA | absent by design: no assessment document in the tree |
| R9 SDF | absent by design: no DPO named anywhere, no audit log model |
| R10 Rights | absent by design: no access, correction, erasure or nomination route |
| R11 DPB | absent by design: no grievance intake or escalation path |
| R12 Verify | `models.load_user_record` and `routes/account.py` read PII with no audit trail |
| Retention | `models.User` has no expiry column, `app.py` registers no cleanup job |

### Negative controls

Two things in here are correct on purpose, so the scanner can be shown
separating a real finding from a clean one rather than flagging everything:

- `User.pan_number_encrypted` is written through `crypto_utils.encrypt_value`
  (Fernet) in the same request that writes Aadhaar in the clear.
- `User.support_pin_pbkdf2` is a salted PBKDF2-HMAC-SHA256 digest, next to the
  md5 password column.
- `routes/account.py` `GET /dashboard/<id>` carries a session guard, next to
  the unauthenticated JSON endpoint.

### The cross-file Aadhaar flow

```
POST /kyc            routes/kyc.py        submit_kyc()
  -> logging.info    routes/kyc.py        plaintext identifier in the log
  -> db write        models.py            store_kyc_record()
  -> push            reporting.py         push_kyc_to_analytics()
  -> db read         models.py            load_user_record()
  -> third party     reporting.py         requests.post(ANALYTICS_ENDPOINT)
```

`ANALYTICS_ENDPOINT` points at a reserved `.invalid` hostname, so nothing can
actually leave the machine. The send is wrapped in a try/except so a live demo
does not break when DNS fails.

## Layout

```
sample-app/
  app.py             factory, config, synthetic seed data
  models.py          SQLAlchemy models plus the read and write helpers
  crypto_utils.py    two bad hashers and two good ones
  reporting.py       partner export, far end of the Aadhaar flow
  routes/
    __init__.py      shared session guard
    signup.py        GET and POST /signup
    kyc.py           GET and POST /kyc
    account.py       /, /dashboard/<id>, /api/customer/<id>
  templates/
    base.html  index.html  signup.html  kyc.html  dashboard.html
  requirements.txt
```

## Running it locally

Only on a workstation, never anywhere reachable.

```bash
cd sample-app
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS or Linux
pip install -r requirements.txt
python app.py
```

It listens on `http://127.0.0.1:5000` and creates `demo_storefront.db` in the
working directory with two placeholder customers. Delete that file to reset.

Point the web scanner at `http://127.0.0.1:5000` and the code scanner at the
`sample-app/` directory.
