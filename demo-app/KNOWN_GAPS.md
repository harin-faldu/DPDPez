# Known gaps

These are left in deliberately. Each one is the kind of gap a competent team genuinely
misses: a control that exists but does not reach far enough, or a document nobody has
written yet. None of them is an obvious omission, and none is a keyword trick.

Every gap below was confirmed by running the scanner, and the check name it trips is
named so a reviewer can go and look.

## Code scan gaps

### 1. No impact assessment, despite large scale identity processing

* **Rule:** R8, section 10(2), 1 of 3 checks passed
* **Checks failed:** `dpia_document_exists`, `assessment_covers_found_pii`
* **Where:** nothing in the repository

The platform knows which of its activities are high risk and says so:
`processing_register.high_risk_processing_activities` names seller verification, which
holds a permanent account number and part of an Aadhaar number for every verified seller,
and account creation, which holds a date of birth for every account. That is the
identification step. The assessment itself was never written, so the scanner finds eight
personal data categories in use with no assessment covering any of them.

This is the most common real shape of this gap. Teams identify the risk in a register and
then never produce the document.

### 2. A Data Protection Officer, but no independent Data Auditor

* **Rule:** R9, section 10(2)(b), 2 of 3 checks passed
* **Check failed:** `independent_audit_mechanism`
* **Where:** `contacts.py` has the officer, nothing has the auditor

`contacts.data_protection_officer` names an appointed officer and the contact is published
in the footer of every page and in the notice, so `dpo_identified` passes. Section 10(2)(b)
separately requires a Significant Data Fiduciary to have a Data Auditor carry out periodic
audits, and there is no audit engagement, no audit artefact and no audit handler anywhere.

Internal audit logging is not the same control. `AuditLogEntry` records who read what, and
it passes R12, but an internal log is evidence for an auditor rather than a substitute for
one.

### 3. No path for responding to a direction of the Board

* **Rule:** R11, section 27, 2 of 3 checks passed
* **Check failed:** `board_direction_response_path`
* **Where:** `models.py`, `rights_service.py`

Grievance intake works, tickets carry a state and a thirty day response deadline, and the
escalation route to the Board is written into the notice. What does not exist is anything
on the inbound side: no table, endpoint or handler for a direction the Board issues under
section 27 telling the fiduciary to take remedial measures. The team built the path a
Data Principal walks and not the path the regulator walks.

### 4. The retention sweep does not cover two tables

* **Rule:** RET, section 8(7)
* **Check failed:** `pii_storage_has_expiry`
* **Where:** `models.ExportedReport`, `models.AuditLogEntry`, `retention_policy.COVERED_TABLES`

`retention_policy.COVERED_TABLES` lists seven tables, each with the purpose its rows are
held under, and `purge_expired_records` deletes rows past `retain_until` hourly. Two
stores are outside it:

* `exported_reports` keeps `requested_by_email` for every generated extract, encrypted,
  with no `retain_until` column at all. It is the table the scanner names.
* `audit_log` has no retention clock either. It holds no personal data column, so it does
  not trip the check, but it grows without bound and outlives the purpose periods of the
  rows it describes.

`processing_register.register_coverage_gaps` reports both rather than hiding them, which
is the honest half of the gap: the team knows, and has not fixed it.

### 5. Erasure does not reach the derived analytics table

* **Rule:** RET, section 8(7)
* **Check failed:** `erasure_propagates_to_copies`
* **Where:** `rights_service.erase_account`, `models.AnalyticsRollup`

`erase_account` walks `LINKED_STORES` and removes the verification records, orders,
tickets, guardian confirmations, nominees and consent history that carry the account id,
then deletes the account row and any unsent mail. It does not touch `analytics_rollup`.

Those rows are keyed by `principal_ref`, an HMAC of the account id, so they are not
obviously personal and nobody thought about them. They are still derived from the erased
account and still single out a person, and there is no anonymisation, redaction or
cascade step anywhere in the codebase to deal with them. The erasure page says so to the
account holder rather than claiming a clean deletion.

### 6. Two paths reach personal data with no consent or basis check

* **Rule:** R4, section 6, 2 of 3 checks passed
* **Check failed:** `consent_enforced_server_side`, 6 of 95 traced flows
* **Where:** `marketing.queue_promotional_email`, `legacy_api.legacy_customer_export`

**The marketing send step does not re-read the consent record.**
`marketing.build_campaign_audience` filters on `has_consent` when the audience is built,
and `queue_promotional_email` then trusts that list. A withdrawal that lands between the
build and the send is not honoured for the batch already in flight. Withdrawal is supposed
to take effect at once under section 6(4), and for a queued campaign it does not.

**The legacy extract reads four personal fields with no basis assertion.** Every other
function that touches personal data calls `assert_lawful_basis` or `require_consent`
first. `legacy_customer_export` calls neither, which is what puts its four fields into the
unguarded flow list.

### 7. The legacy extract returns far more than it needs

* **Rule:** no check fails on this one, it is a purpose limitation and minimisation
  finding a reviewer has to make
* **Where:** `legacy_api.legacy_customer_export`

The endpoint is authenticated and behind a second staff guard, so it does not trip
`pii_endpoints_authenticated`. The dashboard that consumes it renders a display label and
an order count. The payload carries the contact address, the name, the telephone number,
the date of birth, the minor flag and both timestamps for every account, and it writes no
audit trail entry when it does so.

This is the gap a scanner cannot decide on its own and a human can. It is left in because
the demo should have at least one finding that needs a person.

## Web scan gaps

### 8. Served over plain HTTP

* **Rule:** R6, section 8(5)
* **Check failed:** `https_enforced`

The fixture binds to `127.0.0.1:5001` over HTTP so that it can be scanned locally without
a certificate. A deployment terminates TLS in front of the application, which is why the
strict transport security header is still sent. A scan should report this, and it does.

### 9. Correction and nomination are not discoverable before sign in

* **Rule:** R10, sections 12 and 14, 3 of 5 checks passed on the web scan
* **Checks failed:** `correction_path_exists`, `nomination_path_exists`
* **Where:** `templates/base.html` footer

Both rights are fully implemented and the code scan gives them credit: R10 passes 5 of 5
against the repository. On the rendered site they are reachable only from inside the
account area and from the body of the privacy notice, not from the public footer, so an
anonymous crawl cannot find them.

This is the clearest illustration of why the two scans are kept apart. The right exists,
works and is authenticated, and a person who has not signed in still cannot find it.
Discoverability is part of the obligation, and only the web scan can see that it is
missing.
