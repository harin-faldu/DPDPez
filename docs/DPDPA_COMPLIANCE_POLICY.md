# DPDPA Self-Compliance Check — Privacy & Data Processing Policy

**Product**: DPDPA Self-Compliance Check Platform
**Effective Date**: __________________, 2026
**Version**: 1.0
**Document Classification**: Confidential — Client-Facing

---

> This document constitutes the Privacy Policy, Data Processing Agreement (DPA), and Service-Level Terms between the **Service Provider** (operator of the DPDPA Self-Compliance Check Platform, hereinafter "we", "us", "the Platform") and the **Client** (the entity or individual using the Platform to assess DPDP Act compliance, hereinafter "you", "Data Fiduciary", "the Client").
>
> This policy is drafted in compliance with the **Digital Personal Data Protection Act, 2023** (Act 22 of 2023), the **DPDP Rules, 2025**, and applicable jurisprudence of the Data Protection Board of India.

---

## Table of Contents

1. [Definitions](#1-definitions)
2. [Scope & Applicability](#2-scope--applicability)
3. [Roles Under the DPDP Act](#3-roles-under-the-dpdp-act)
4. [Lawful Basis for Processing](#4-lawful-basis-for-processing)
5. [Categories of Data Processed](#5-categories-of-data-processed)
6. [Purpose Limitation](#6-purpose-limitation)
7. [Data Collection & Notice (Section 5)](#7-data-collection--notice-section-5)
8. [Consent Mechanism (Section 6)](#8-consent-mechanism-section-6)
9. [Data Flow Within the Platform](#9-data-flow-within-the-platform)
10. [Third-Party Data Sharing & Sub-Processors](#10-third-party-data-sharing--sub-processors)
11. [Security Safeguards (Section 8(5))](#11-security-safeguards-section-85)
12. [Data Retention & Erasure (Section 8(7))](#12-data-retention--erasure-section-87)
13. [Breach Notification (Section 8(6))](#13-breach-notification-section-86)
14. [Children's Data (Section 9)](#14-childrens-data-section-9)
15. [Data Principal Rights (Sections 11–14)](#15-data-principal-rights-sections-11-14)
16. [Cross-Border Data Transfer (Section 16)](#16-cross-border-data-transfer-section-16)
17. [Grievance Redressal (Section 13)](#17-grievance-redressal-section-13)
18. [Significant Data Fiduciary Obligations (Section 10)](#18-significant-data-fiduciary-obligations-section-10)
19. [Client Obligations](#19-client-obligations)
20. [Limitation of Liability & Disclaimer](#20-limitation-of-liability--disclaimer)
21. [Governing Law & Dispute Resolution](#21-governing-law--dispute-resolution)
22. [Amendments & Version History](#22-amendments--version-history)
23. [Annexure A — Data Processing Inventory](#annexure-a--data-processing-inventory)
24. [Annexure B — Sub-Processor List](#annexure-b--sub-processor-list)
25. [Annexure C — Technical Security Measures](#annexure-c--technical-security-measures)
26. [Signature Block](#signature-block)

---

## 1. Definitions

| Term | Definition |
|---|---|
| **Platform** | The DPDPA Self-Compliance Check application, including its backend (FastAPI + PostgreSQL), frontend (React), AI analysis pipeline, and PDF report generator. |
| **Code Scan** | The process of analysing uploaded source code archives (.zip/.tar.gz) using Tree-sitter Abstract Syntax Tree (AST) parsing to identify personal data handling patterns. |
| **Web Scan** | The process of crawling a Client-provided URL using a headless Chromium browser to inspect forms, consent mechanisms, security headers, and cookies. |
| **Scan Data** | All data ingested, generated, or derived during a Code Scan or Web Scan, including uploaded source code, crawled web content, detected PII field names, data flow graphs, rule verdicts, AI-generated findings, and PDF reports. |
| **Personal Data** | As defined in Section 2(t) of the DPDP Act, 2023 — any data about an individual who is identifiable by or in relation to such data. |
| **Data Principal** | The individual to whom personal data relates (Section 2(j)). |
| **Data Fiduciary** | Any person who alone or in conjunction with other persons determines the purpose and means of processing (Section 2(i)). |
| **Data Processor** | Any person who processes personal data on behalf of a Data Fiduciary (Section 2(k)). |
| **Incidental Personal Data** | Personal data that may be present within uploaded source code (e.g., hardcoded test data, seed files, configuration fixtures) or crawled web pages — data the Platform encounters incidentally while performing compliance analysis but does not intentionally collect. |
| **Compliance Report** | The generated PDF document containing the compliance scorecard, rule-by-rule verdicts, statutory citations, and remediation guidance. |
| **AI Provider** | Third-party generative AI services (Google Gemini, DeepSeek) used to generate statutory explanations of deterministic compliance findings. |

---

## 2. Scope & Applicability

### 2.1 What This Policy Covers

This policy applies to **all processing activities** performed by the Platform, including:

- (a) Receiving and temporarily storing uploaded source code archives.
- (b) Crawling Client-specified public URLs using a headless browser.
- (c) Static analysis of source code to detect personal data fields, data flow paths, and compliance patterns.
- (d) Deterministic rule evaluation against 11 DPDP Act compliance dimensions.
- (e) Sending rule verdicts and code evidence to third-party AI providers for statutory explanation generation.
- (f) Storing scan results, findings, and scorecard data in PostgreSQL.
- (g) Generating and delivering PDF compliance reports.

### 2.2 What This Policy Does Not Cover

- The Client's own data processing activities (which are the subject of the compliance assessment).
- Data processed exclusively on the Client's local machine if the Platform is self-hosted without any external network calls.
- The internal policies of third-party AI providers (governed separately under Annexure B).

### 2.3 Territorial Application

This policy applies when the Platform processes personal data of Data Principals within the territory of India, consistent with Section 3 of the DPDP Act, 2023.

---

## 3. Roles Under the DPDP Act

### 3.1 For Scan Data Containing Incidental Personal Data

| Entity | DPDP Act Role | Rationale |
|---|---|---|
| **The Client** | **Data Fiduciary** | The Client determines that their source code / website should be scanned, and provides the data to the Platform. |
| **The Platform (We)** | **Data Processor** | We process the Client's data solely on their instructions and for the purpose of generating the compliance assessment. We do not determine the purpose of the underlying data processing. |

### 3.2 For Platform Operational Data

| Entity | DPDP Act Role | Rationale |
|---|---|---|
| **The Platform (We)** | **Data Fiduciary** | For server logs, IP addresses, and any operational telemetry, we determine the purpose and means of processing. |

### 3.3 Acknowledgement

The Client acknowledges that:
- The Platform is an **automated compliance assessment tool**, not a legal advisor.
- The Platform's output does not constitute legal advice, legal certification, or a guarantee of DPDP Act compliance.
- The Client remains the Data Fiduciary for all personal data within their own systems and bears ultimate responsibility for compliance.

---

## 4. Lawful Basis for Processing

| Processing Activity | Lawful Basis | DPDP Act Reference |
|---|---|---|
| Receiving uploaded source code | **Consent** — Client actively uploads | Section 6 |
| Crawling Client-specified URL | **Consent** — Client explicitly provides the URL and initiates the scan | Section 6 |
| Static code analysis (AST parsing, PII field detection) | **Legitimate use** — necessary for the performance of the contracted service | Section 7(b) |
| Sending evidence to AI providers for explanation | **Consent** — Client is informed of AI involvement and proceeds | Section 6 |
| Storing scan results in PostgreSQL | **Legitimate use** — necessary to deliver the service result | Section 7(b) |
| Server access logs | **Legitimate use** — necessary for system security and incident response | Section 7(f) |

---

## 5. Categories of Data Processed

### 5.1 Data We Intentionally Collect

| Category | Examples | Sensitivity | Retention |
|---|---|---|---|
| Scan Target Metadata | Filename of uploaded archive; URL submitted for web scan | Low | Duration of scan + retention period |
| Scan Configuration | Scan type (code/web), timestamp, scan ID (UUID) | Low | Duration of scan + retention period |
| Compliance Results | Rule verdicts, scores, grades, finding titles, code snippets (relative paths only), statutory citations, suggested fixes | Low | Retention period |
| Server Logs | IP addresses, User-Agent strings, HTTP method/path, response codes | Medium (contains IP) | 90 days |

### 5.2 Data We May Incidentally Encounter

| Category | How It Enters | Examples | Sensitivity |
|---|---|---|---|
| **Hardcoded Test/Seed Data** | Embedded in uploaded source code | Test Aadhaar numbers, mock PAN values, sample email addresses in seed files or unit tests | Medium to Critical |
| **Configuration Secrets** | Embedded in uploaded source code | API keys, database credentials, JWT secrets in `.env` files or config files | Critical |
| **Form Field Content** | Crawled from Client's live website | Pre-filled form values, placeholder text in input fields | Low to Medium |
| **Cookie Values** | Captured during web scan | Session tokens, tracking identifiers, consent preferences | Medium |

### 5.3 Data We Never Collect

- (a) User account credentials — the Platform has **no user authentication system**.
- (b) Payment or financial information.
- (c) Biometric data.
- (d) Health records.
- (e) Data from any source other than what the Client directly provides.

---

## 6. Purpose Limitation

All data processed by the Platform is used **exclusively** for:

1. **Compliance Assessment**: Detecting personal data handling patterns, evaluating against DPDP Act rules, and generating compliance verdicts.
2. **Statutory Explanation**: Sending rule verdicts and bounded code evidence to AI providers to generate grounded legal explanations with citations.
3. **Report Generation**: Compiling findings into a structured PDF audit report.
4. **Service Improvement**: Aggregate, anonymised statistics on common compliance gaps (no individual scan data is used for training AI models).

We **do not**:
- Use Client source code or scan results for any purpose other than delivering the compliance assessment.
- Share, sell, license, or otherwise transfer Client data to any third party other than the AI sub-processors listed in Annexure B.
- Use Client data to train, fine-tune, or improve any machine learning model.
- Profile individual Data Principals whose data may be incidentally present in uploaded code.

---

## 7. Data Collection & Notice (Section 5)

### 7.1 Notice Before Collection

Before any data is processed, the Platform presents a clear notice informing the Client:

- (a) **What data will be processed**: source code files or web page content.
- (b) **Why**: to generate a DPDP Act compliance assessment.
- (c) **Who processes it**: the Platform and its AI sub-processors (listed in Annexure B).
- (d) **How long**: for the retention period specified in Section 12.
- (e) **Rights**: the Client's right to request deletion at any time.

### 7.2 Format & Language

The notice is provided:
- In **clear, plain English** on the scan submission page.
- In **Hindi** (हिन्दी) as an alternative language option.
- Before the Client clicks the "Scan" / "Upload" button — not buried in a terms page accessible only via a footer link.

### 7.3 Itemised Description of Personal Data (Rule 3(2))

Consistent with DPDP Rules 2025, Rule 3(2), the notice itemises:
- Each category of personal data likely to be processed (source code content, URL content, derived metadata).
- The purpose for each category.
- The identity and contact of the Data Protection Officer.

---

## 8. Consent Mechanism (Section 6)

### 8.1 Freely Given, Specific, Informed Consent

Consent is obtained through an **explicit, affirmative action**:
- The Client must **actively click** "Start Scan" or "Upload and Analyse" — there is no pre-ticked checkbox.
- The consent request is specific to the compliance scan; it is not bundled with unrelated terms.
- The Client may withdraw consent at any time by requesting deletion of their scan data (see Section 15).

### 8.2 Granular Consent for AI Processing

A separate, clearly labelled consent toggle is provided for:
- **AI-powered explanation**: "I consent to my scan evidence being sent to [AI Provider] for statutory analysis."
- If the Client declines AI processing, the Platform delivers deterministic-only results (rule verdicts and evidence without AI-generated explanations).

### 8.3 No Consent Bundling

Consent for the compliance scan is not conditional on:
- Accepting marketing communications.
- Sharing data with partners.
- Agreeing to any other unrelated processing.

### 8.4 Consent Withdrawal (Section 6(4))

The Client may withdraw consent at any time by:
- Requesting scan data deletion via the Grievance Redressal mechanism (Section 17).
- Using the Platform's data deletion API endpoint (if available).

Upon withdrawal, we will erase all scan data associated with the Client within **72 hours**, except where retention is required by law.

---

## 9. Data Flow Within the Platform

The following diagram traces exactly how data moves through the system:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                            CLIENT SIDE                                      │
│                                                                             │
│  ZIP Archive ─── or ─── URL    (Client uploads / provides target)           │
└─────────────┬──────────────┬────────────────────────────────────────────────┘
              │              │
              ▼              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PLATFORM BACKEND (India)                              │
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐                                       │
│  │ Code Scanner  │     │ Web Scanner   │   ← Runs within Docker container     │
│  │ (Tree-sitter) │     │ (Playwright)  │   ← No data leaves this boundary     │
│  └──────┬───────┘     └──────┬────────┘     during scanning                  │
│         │                    │                                                │
│         ▼                    ▼                                                │
│  ┌─────────────────────────────────┐                                         │
│  │     Rules Engine (Deterministic) │  ← Zero data shared externally          │
│  │     11 DPDP Act rules evaluated  │                                        │
│  └──────────────┬──────────────────┘                                         │
│                 │                                                             │
│                 ▼                                                             │
│  ┌─────────────────────────────────┐      ┌─────────────────────────────┐    │
│  │      Context Assembler           │─────▶│  AI Provider API             │    │
│  │  (Token-budgeted, truncated,     │      │  (Google Gemini / DeepSeek)  │    │
│  │   no raw PII sent — only rule    │      │  ← Receives ONLY:            │    │
│  │   verdicts + bounded snippets)   │      │    • Rule verdict             │    │
│  └──────────────────────────────────┘      │    • Bounded code snippet     │    │
│                                            │    • Statutory provisions      │    │
│                 ▼                           └──────────────┬──────────────┘    │
│  ┌──────────────────────────────┐                         │                   │
│  │  PostgreSQL (pgvector)        │◀───────────────────────┘                   │
│  │  • Scan metadata              │   AI response (JSON) stored                │
│  │  • Rule verdicts              │                                            │
│  │  • Findings + citations       │                                            │
│  │  • PII field names (not values)│                                           │
│  │  • Data flow edges            │                                            │
│  └──────────────┬───────────────┘                                            │
│                 │                                                             │
│                 ▼                                                             │
│  ┌──────────────────────────────┐                                            │
│  │   PDF Report (WeasyPrint)     │                                            │
│  │   Streamed to Client          │                                            │
│  └──────────────────────────────┘                                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 9.1 Data Minimisation Safeguards

| Safeguard | Implementation |
|---|---|
| **Code snippets are bounded** | The Context Assembler caps code sent to AI at 60 lines maximum, selecting only the failing check's immediate vicinity. |
| **PII field names, not values** | The scanner extracts field/column **names** (e.g., `aadhaar_number`, `pan_card`) — not the actual personal data values stored in those fields. |
| **Evidence truncation** | Evidence strings are capped at 1200 characters; failed check details at 600 characters. |
| **Uploaded archives deleted after extraction** | The raw `.zip`/`.tar.gz` file is deleted from disk immediately after safe extraction. |
| **Source code deleted after scan** | The extracted `workspace/<scan_id>/src/` directory is deleted upon scan completion. |

---

## 10. Third-Party Data Sharing & Sub-Processors

### 10.1 Sub-Processors

We engage the following sub-processors, and no others:

| Sub-Processor | Purpose | Data Shared | Legal Basis |
|---|---|---|---|
| **Google (Gemini API)** | Generating statutory explanation text and embedding vectors for RAG retrieval | Rule verdicts, bounded code snippets (max 60 lines), statutory provision text | Client consent (Section 6); contractual necessity |
| **DeepSeek** (alternative) | Generating statutory explanation text when configured as the AI provider | Same as above | Client consent (Section 6); contractual necessity |
| **Cloud Infrastructure Provider** | Hosting PostgreSQL, Docker containers, and the application runtime | All Platform data resides on hosted infrastructure | Contractual necessity; security measures per Section 11 |

### 10.2 Sub-Processor Obligations

Each sub-processor is contractually bound to:
- Process data only for the specific purpose described above.
- Not retain, train on, or use data beyond what is necessary to deliver the API response.
- Implement security measures at least equivalent to those described in Section 11.
- Notify us of any data breach within 48 hours.

### 10.3 No Other Sharing

We do not share Client data with:
- Advertisers, analytics providers, or data brokers.
- Government authorities, except when compelled by a valid legal order under applicable Indian law.
- Any affiliate, partner, or other entity for marketing, profiling, or secondary purposes.

---

## 11. Security Safeguards (Section 8(5))

We implement reasonable security safeguards to protect personal data from unauthorised access, disclosure, alteration, and destruction:

### 11.1 Infrastructure Security

| Measure | Implementation |
|---|---|
| **Encryption in Transit** | All client-facing endpoints served over HTTPS/TLS 1.2+. Backend-to-database connections encrypted via SSL. |
| **Encryption at Rest** | PostgreSQL data volumes use AES-256 disk encryption. |
| **Network Isolation** | Backend, database, and frontend run in isolated Docker containers. The database is not exposed to the public internet (accessible only via Docker internal network). |
| **SSRF Prevention** | The URL Guard (`url_guard.py`) blocks scans targeting private/internal IP ranges, localhost, link-local, and metadata endpoints (169.254.169.254) — prevents the Platform from being used as an SSRF vector. |
| **Secrets Management** | API keys and database credentials loaded from environment variables (`.env`), never hardcoded in source or committed to version control. |

### 11.2 Application Security

| Measure | Implementation |
|---|---|
| **Archive Validation** | Zip-bomb protection (20× decompression ratio limit), path-traversal prevention, symlink rejection, and file count limits (max 5,000 files). |
| **Upload Size Limits** | Maximum 50 MB per archive, enforced during streaming (not after full upload). |
| **CORS Policy** | Restricted to configured allowed origins only. |
| **Input Validation** | Pydantic schema validation on all API inputs. |
| **No Authentication State** | The Platform stores no passwords, session tokens, or user accounts — reducing the attack surface for credential theft. |

### 11.3 AI Guardrails

| Measure | Implementation |
|---|---|
| **Anti-Hallucination Guardrail** | Every statutory quote produced by the AI is verified against the actual corpus using Levenshtein similarity matching (≥85% threshold). Hallucinated citations are flagged or stripped. |
| **Deterministic Verdicts** | The AI never decides compliance status. All pass/fail/gap verdicts are computed deterministically by the Rules Engine. The AI only explains and cites. |
| **Token Budget Enforcement** | Data sent to AI providers is strictly bounded (60 lines code, 6 flow paths, 8 callers) — preventing accidental leakage of large code sections. |

### 11.4 Operational Security

- Regular dependency updates and vulnerability scanning.
- Principle of least privilege for database access.
- Logging of all scan operations (without logging personal data values).
- Incident response procedures documented and tested (see Section 13).

---

## 12. Data Retention & Erasure (Section 8(7))

### 12.1 Retention Schedule

| Data Category | Retention Period | Justification |
|---|---|---|
| **Uploaded source code archive** (.zip/.tar.gz) | **Deleted immediately** after extraction | No longer needed once files are parsed |
| **Extracted source files** (workspace/src/) | **Deleted immediately** upon scan completion (or failure) | Needed only during AST parsing |
| **Scan results** (verdicts, findings, scores) | **[90 / 180 / 365] days** after scan completion | Client needs time to review, remediate, and re-scan |
| **PII field metadata** (field names, categories, locations) | Same as scan results | Part of the compliance assessment |
| **Data flow edges and PII flow paths** | Same as scan results | Part of the compliance assessment |
| **Generated PDF reports** | Generated on-demand, not persistently stored; the Client downloads immediately | Regenerated from DB if needed |
| **Server access logs** | **90 days** | Security monitoring and incident investigation |
| **AI provider API logs** | Subject to AI provider's own retention policy (see Annexure B) | Outside our direct control |

### 12.2 Automated Deletion

- A scheduled background job purges all scan data older than the configured retention period.
- PostgreSQL `CASCADE DELETE` ensures that deleting a `Scan` record automatically removes all associated `RuleResult`, `Finding`, `PIIField`, `DataFlowEdge`, and `PIIFlowPath` records.

### 12.3 Client-Initiated Deletion

The Client may request immediate deletion of any specific scan or all their scan data via the Grievance Redressal mechanism. We will action such requests within **72 hours**.

---

## 13. Breach Notification (Section 8(6))

### 13.1 Notification to the Data Protection Board

In the event of a personal data breach, we will:

1. **Notify the Data Protection Board of India** in the form and manner prescribed under Rule 7 of the DPDP Rules, 2025 — **without unreasonable delay** and in any case within **72 hours** of becoming aware of the breach.
2. The notification will include:
   - Nature of the breach and categories of data affected.
   - Approximate number of Data Principals affected.
   - Likely consequences of the breach.
   - Measures taken or proposed to mitigate the breach.

### 13.2 Notification to Affected Clients

We will notify the affected Client:

1. **Without unreasonable delay** and in any case within **72 hours** of becoming aware.
2. Via the contact details provided at the time of service engagement.
3. With clear, plain-language description of:
   - What happened.
   - What data was affected.
   - What the Client should do.
   - Our remediation steps.

### 13.3 Notification to Data Principals

Where the breach involves personal data of identifiable Data Principals (e.g., personal data incidentally present in uploaded source code), we will:

1. Notify each affected Data Principal in the manner prescribed by the Board.
2. Coordinate with the Client (as the Data Fiduciary for that personal data) on joint notification obligations.

### 13.4 Breach Register

We maintain a confidential breach register recording all incidents, their classification, response actions, and notifications issued.

---

## 14. Children's Data (Section 9)

### 14.1 Platform Usage

The Platform is **not intended for use by persons under 18 years of age**. We do not knowingly collect personal data from children.

### 14.2 Children's Data in Scanned Code

The Platform's compliance rules actively check for children's data handling patterns in Client source code (Rule R05, Rule R12). However:
- The Platform detects **field names** (e.g., `child_dob`, `guardian_consent`, `minor_flag`) — not actual children's personal data.
- If the Platform incidentally encounters actual personal data of children in uploaded source code, it is handled under the same retention and deletion policies as all Incidental Personal Data.

### 14.3 No Behavioural Monitoring or Tracking

The Platform does not engage in:
- Behavioural monitoring of any user, adult or child.
- Targeted advertising.
- Tracking or profiling of any kind.

---

## 15. Data Principal Rights (Sections 11–14)

Where the Platform acts as a Data Processor handling personal data on behalf of the Client (Data Fiduciary), Data Principal rights requests will be managed as follows:

### 15.1 Right to Access (Section 11)

| Who Exercises | How |
|---|---|
| **Client** (for their scan data) | The Client can access all scan results, findings, and reports via the Platform's API (`GET /api/scan/{id}`, `GET /api/findings/{id}`, `GET /api/scorecard/{id}`). |
| **Data Principal** (whose data appears in scanned code) | The Data Principal should contact the Client (Data Fiduciary). We will assist the Client in responding upon written request. |

### 15.2 Right to Correction and Erasure (Section 12)

| Who Exercises | How |
|---|---|
| **Client** | Request erasure via the Grievance Redressal mechanism. We erase within 72 hours. |
| **Data Principal** | Contact the Client (Data Fiduciary), who may instruct us to erase. |

### 15.3 Right to Grievance Redressal (Section 13)

See Section 17 of this policy.

### 15.4 Right of Nomination (Section 14)

We will honour any valid nomination received from a Data Principal through the Client (Data Fiduciary), enabling a nominee to exercise the rights of the Data Principal in case of death or incapacity.

---

## 16. Cross-Border Data Transfer (Section 16)

### 16.1 Current Transfer Arrangements

| Destination | Data Transferred | Legal Mechanism |
|---|---|---|
| **Google (Gemini API)** | Bounded code snippets + rule verdicts for AI explanation | Processed through Google's Gemini API (subject to Google's data processing terms); transferred only when the Client consents to AI-powered analysis |
| **DeepSeek** (if configured) | Same as above | Processed through DeepSeek's API infrastructure |

### 16.2 Government Notification

We do not transfer personal data to any country that has been restricted by the Central Government under Section 16(1) of the DPDP Act, 2023.

### 16.3 Client's Right to Restrict

The Client may decline AI processing entirely (see Section 8.2), in which case **no data leaves Indian infrastructure** and only deterministic compliance results are delivered.

---

## 17. Grievance Redressal (Section 13)

### 17.1 Data Protection Officer

| Detail | Information |
|---|---|
| **Name** | [_________________________] |
| **Designation** | Data Protection Officer |
| **Email** | [dpo@__________________.com] |
| **Phone** | [+91-__________] |
| **Postal Address** | [_________________________] |

### 17.2 Grievance Process

1. **Submit**: Email the DPO with your scan ID(s) and the nature of your request.
2. **Acknowledge**: We will acknowledge receipt within **48 hours**.
3. **Resolve**: We will resolve the grievance within **[7 / 15 / 30] calendar days**, depending on complexity.
4. **Escalation**: If unsatisfied, the Data Principal or Client may file a complaint with the **Data Protection Board of India** under Section 27 of the DPDP Act.

### 17.3 Response Timelines

| Request Type | Response Time |
|---|---|
| Data Access Request | 7 calendar days |
| Data Deletion Request | 72 hours |
| Data Correction Request | 7 calendar days |
| General Grievance | 15 calendar days |
| Complex Investigation | 30 calendar days (with interim update at 15 days) |

---

## 18. Significant Data Fiduciary Obligations (Section 10)

### 18.1 Self-Assessment

The Platform currently processes:
- **No personal data at scale** — it processes only what the Client uploads, and only for the duration of the scan.
- **No profiling, tracking, or automated decision-making** that affects Data Principals.

Based on this assessment, we do **not** currently qualify as a Significant Data Fiduciary under Section 10. We will re-assess this classification:
- Annually.
- Upon any notification from the Central Government.
- Upon material changes to processing volume or nature.

### 18.2 If Designated as SDF

Should we be designated as a Significant Data Fiduciary, we will:
- Appoint a **Data Protection Officer** based in India (Section 10(2)(a)).
- Appoint an **independent Data Auditor** (Section 10(2)(b)).
- Conduct periodic **Data Protection Impact Assessments** (Section 10(2)(c)).
- Publish the DPIA summary and audit findings as required by the Rules.

---

## 19. Client Obligations

The Client represents and warrants that:

1. **Authority**: They have the legal authority to upload the source code or provide the URL for scanning.
2. **No Prohibited Data**: They will not knowingly upload source code or provide URLs that contain:
   - Actual personal data of real individuals (as opposed to synthetic test data) unless necessary for the compliance assessment and covered by appropriate legal basis.
   - Data belonging to children (under 18) unless they have obtained verifiable parental consent.
3. **Data Fiduciary Responsibility**: The Client remains the Data Fiduciary for all personal data within their systems. The Platform's compliance assessment does not relieve the Client of any obligation under the DPDP Act.
4. **No Misuse**: The Client will not use the Platform to:
   - Scan third-party systems without authorisation.
   - Extract personal data from scanned code for purposes unrelated to compliance.
   - Circumvent security controls or engage in any illegal activity.
5. **Accuracy of Information**: The Client is responsible for the accuracy and completeness of the source code or URLs provided for assessment.

---

## 20. Limitation of Liability & Disclaimer

### 20.1 No Legal Advice

The Platform is a **technical compliance assessment tool**. Its output:
- Does not constitute legal advice, legal opinion, or a compliance certification.
- Should be reviewed by a qualified legal professional before reliance.
- May contain AI-generated content that, despite guardrails, could include inaccuracies.

### 20.2 Best-Effort Accuracy

- Deterministic rule verdicts are computed from code/web evidence using published, auditable logic. They are reproducible.
- AI-generated explanations are verified against the statutory corpus by the Guardrail system. Findings that fail quote verification are flagged with `guardrail_passed = false`.
- The Platform cannot detect all compliance issues — particularly those requiring human judgment, legal interpretation, or access to organisational policies not reflected in code.

### 20.3 Limitation

To the maximum extent permitted by law, our total liability for any claim arising from the use of the Platform shall not exceed the fees paid by the Client for the specific scan giving rise to the claim.

---

## 21. Governing Law & Dispute Resolution

- **Governing Law**: This policy is governed by the laws of India, including the Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025.
- **Jurisdiction**: The courts of [__________], India shall have exclusive jurisdiction.
- **Dispute Resolution**: The parties will first attempt to resolve disputes through good-faith negotiation. If unresolved within 30 days, disputes shall be referred to arbitration under the Arbitration and Conciliation Act, 1996, with the seat of arbitration in [__________], India.

---

## 22. Amendments & Version History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | __________ | __________ | Initial release |

We may update this policy from time to time. Material changes will be communicated to Clients via email or a prominent notice on the Platform at least **30 days** before taking effect.

---

## Annexure A — Data Processing Inventory

| # | Processing Activity | Personal Data Category | Data Principals Affected | Legal Basis | Retention | Sub-Processors |
|---|---|---|---|---|---|---|
| 1 | Code Scan — Upload & Extract | Incidental PD in source code (test data, seed values) | Individuals whose data appears in test fixtures | Client consent (S.6) | Deleted on scan completion | None (processed locally) |
| 2 | Code Scan — AST Analysis | PII field names, data flow edges | Indirect — field names reference PD categories | Legitimate use (S.7) | Retention period | None (processed locally) |
| 3 | Web Scan — Browser Crawl | Form field labels, cookie names/values, page content | Individuals whose data appears on crawled pages | Client consent (S.6) | Deleted on scan completion | None (processed locally) |
| 4 | AI Explanation | Rule verdicts + bounded code snippets | Indirect — snippets may reference PD field names | Client consent (S.6) with granular AI toggle | API call duration only (not retained by us beyond AI response) | Google Gemini / DeepSeek |
| 5 | Scan Result Storage | Findings, scores, citations, field names | Indirect | Legitimate use (S.7) | Configured retention period | Cloud infra provider |
| 6 | PDF Report Generation | Compilation of #5 | Indirect | Legitimate use (S.7) | Generated on-demand, not stored | None |
| 7 | Server Access Logs | IP addresses, User-Agent | Platform users (Clients) | Legitimate use (S.7) | 90 days | Cloud infra provider |

---

## Annexure B — Sub-Processor List

| Sub-Processor | Registered Address | Processing Activity | Data Location | DPA in Place | Last Reviewed |
|---|---|---|---|---|---|
| **Google LLC** (Gemini API) | 1600 Amphitheatre Parkway, Mountain View, CA, USA | AI text generation, embedding generation | Google Cloud (region per Google's policy) | ☐ Yes / ☐ Pending | __________ |
| **DeepSeek** (if configured) | [Address] | AI text generation | [Data centre location] | ☐ Yes / ☐ Pending | __________ |
| **[Cloud Provider]** | [Address] | Infrastructure hosting (compute, database, networking) | [Region — preferably India] | ☐ Yes / ☐ Pending | __________ |

---

## Annexure C — Technical Security Measures

| Control Domain | Measure | Status |
|---|---|---|
| **Encryption — Transit** | TLS 1.2+ on all HTTP endpoints; SSL for database connections | ☑ Implemented |
| **Encryption — Rest** | AES-256 disk encryption on PostgreSQL volumes | ☐ To implement |
| **Network Segmentation** | Docker container isolation; database not publicly exposed | ☑ Implemented |
| **SSRF Protection** | URL Guard blocks private IPs, localhost, link-local, metadata endpoints | ☑ Implemented |
| **Archive Security** | Zip-bomb protection, path-traversal rejection, symlink blocking, size limits | ☑ Implemented |
| **Input Validation** | Pydantic schema validation on all API inputs | ☑ Implemented |
| **CORS** | Restricted to configured allowed origins | ☑ Implemented |
| **AI Guardrail** | Levenshtein quote verification (≥85% threshold) on all AI-generated citations | ☑ Implemented |
| **AI Data Minimisation** | Token-budgeted context (60 lines, 6 flows, 8 callers) | ☑ Implemented |
| **Temporary File Cleanup** | Archives deleted post-extraction; workspace deleted post-scan | ☑ Implemented |
| **Secrets Management** | Credentials via environment variables; not in source code | ☑ Implemented |
| **Dependency Management** | requirements.txt with pinned versions; periodic vulnerability scanning | ☐ To implement |
| **Logging Hygiene** | Operational logs do not contain personal data values | ☑ Implemented |
| **Access Control** | No user authentication (reduced attack surface); future: role-based access | ☐ Planned |
| **Penetration Testing** | External security assessment | ☐ To schedule |

---

## Signature Block

This document has been reviewed and approved by the authorised representatives of both parties:

**Service Provider:**

| Field | Value |
|---|---|
| Organisation Name | _________________________________ |
| Authorised Signatory | _________________________________ |
| Designation | _________________________________ |
| Date | _________________________________ |
| Signature | _________________________________ |

**Client:**

| Field | Value |
|---|---|
| Organisation Name | _________________________________ |
| Authorised Signatory | _________________________________ |
| Designation | _________________________________ |
| Date | _________________________________ |
| Signature | _________________________________ |

---

*This policy was prepared based on the Digital Personal Data Protection Act, 2023 (Act 22 of 2023) and the Digital Personal Data Protection Rules, 2025, as published in the Gazette of India. It should be reviewed by a qualified legal professional before formal adoption.*
