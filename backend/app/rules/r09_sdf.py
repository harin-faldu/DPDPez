"""R9 Significant Data Fiduciary Obligations, DPDP Act s.10; Rule 9.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R9"
RULE_NAME = "Significant Data Fiduciary Obligations"
DPDP_SECTION = "s.10"
DPDP_RULE = "Rule 9"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# Additional SDF obligations are Rules 2025 rule_11, not rule_9, which covers
# publication of contact information.
# SDF additional obligations are rule_13 in the notified Rules, not rule_11,
# which is disability consent.
RETRIEVAL_SECTION_IDS: list[str] = ["s.10(1)", "s.10(2)", "rule_13"]

_DPO_KEYWORDS: tuple[str, ...] = (
    "data_protection_officer",
    "dpo",
    "dpo_contact",
    "dpo_email",
    "privacy_officer",
)

_DPO_TEXT_MARKERS: tuple[str, ...] = ("data protection officer", "dpo@", "privacy officer")

_AUDIT_KEYWORDS: tuple[str, ...] = (
    "independent_audit",
    "compliance_audit",
    "data_audit",
    "dpdp_audit",
    "audit_report",
    "annual_audit",
    "external_audit",
    "data_auditor",
)

_DECISION_KEYWORDS: tuple[str, ...] = (
    "credit_score",
    "risk_model",
    "ml_model",
    "classifier",
    "recommendation_engine",
    "automated_decision",
    "scoring_model",
    "predict_",
)

# Sending data to this many separate hosts is a volume-of-processing signal in
# its own right, which is one of the factors s.10(1) lists.
_HOST_SCALE_THRESHOLD = 5

_FAIRNESS_KEYWORDS: tuple[str, ...] = (
    "fairness",
    "bias_audit",
    "bias_check",
    "model_card",
    "algorithmic_audit",
    "disparate_impact",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R9 and return a deterministic verdict.

    Checks:
      - a Data Protection Officer is identified
      - an independent audit mechanism exists
      - algorithmic fairness is addressed where automated decisions use PII

    Note: SDF status is designated by the Central Government, so the tool
    cannot determine it from code. Treat SDF obligations as advisory
    unless the repo shows scale indicators, and be explicit in the
    evidence string that status was inferred rather than established.
    The jury will ask how you decided this.
    """
    flows = flows or []

    if web_result is None and code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason="No web or code evidence was supplied.",
        )

    indicators = _scale_indicators(web_result, code_result, flows)
    if not indicators:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "Significant Data Fiduciary status is notified by the Central Government under "
                "s.10(1) and cannot be read off a codebase. No scale indicator was found in this "
                "scan, so the additional s.10(2) obligations are reported as not applicable "
                "rather than failed."
            ),
        )

    # Everything below is conditional on an inference, so the evidence string
    # has to say so. The tool is flagging obligations that would apply if the
    # fiduciary were notified, not asserting that it has been.
    inference_note = (
        "SDF status was inferred, not established: s.10(1) reserves the designation to the "
        f"Central Government. Scale indicators observed: {ev.join_names(indicators, limit=5)}."
    )

    checks: list[RuleCheck] = [_dpo_check(web_result, code_result)]
    notes: list[str] = [inference_note]

    if code_result is not None:
        checks.append(_audit_check(code_result))
        checks.append(_fairness_check(code_result))
    else:
        # A Data Auditor's report and a bias assessment are internal artefacts.
        # A crawl cannot see either, and scoring their absence off a web scan
        # would report a failure the evidence does not support.
        notes.append(
            "No code scan was supplied, so the s.10(2)(b) audit mechanism and the s.10(2)(c) "
            "verification of algorithmic software were not assessed and are excluded from this "
            "score rather than failed."
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
    )


def _scale_indicators(web_result, code_result, flows) -> list[str]:
    indicators: list[str] = []
    categories = ev.pii_categories_found(code_result)
    critical = [category for category in categories if ev.is_critical_category(category)]
    if critical:
        indicators.append(
            f"critical tier personal data processed ({ev.join_names(critical, limit=3)})"
        )
    if len(categories) >= 5:
        indicators.append(f"{len(categories)} distinct personal data categories processed")
    third_party = ev.third_party_flows(flows)
    if third_party:
        indicators.append(
            f"{len(third_party)} personal data flow(s) cross to a third party"
        )
    # Recipients only. Counting every third-party host let a jsdelivr bundle, a
    # Google Font and a CDN image push a small site over the volume threshold,
    # which would read as evidence of the scale that triggers s.10 designation.
    # Fetching a stylesheet from a CDN is not sending personal data to anyone.
    hosts = ev.data_recipient_hosts(web_result)
    if len(hosts) >= _HOST_SCALE_THRESHOLD:
        indicators.append(
            f"the page sends data to {len(hosts)} distinct third party recipient(s) "
            f"({ev.join_names(hosts, limit=3)})"
        )
    if ev.web_observable(web_result) and web_result.age_gate_fields:
        indicators.append("age or date of birth collected, so children may be users")
    if ev.sensitive_fields(web_result):
        indicators.append(
            f"{len(ev.sensitive_fields(web_result))} sensitive category field(s) collected from "
            "the public site"
        )
    return indicators


def _dpo_check(web_result, code_result) -> RuleCheck:
    # Rules 2025 rule 9 requires the contact of the person who can answer a
    # question about processing to be published, so a published contact is the
    # primary evidence and the code is only a fallback.
    published = ev.dpo_contact(web_result)
    if published:
        return RuleCheck(
            name="dpo_identified",
            passed=True,
            detail=(
                f"the contact for questions about processing is published as {published} on "
                f"{web_result.entry_url}, as Rule 9 requires"
            ),
        )
    contact = ev.grievance_contact(web_result)
    if contact:
        return RuleCheck(
            name="dpo_identified",
            passed=True,
            detail=(
                f"a named contact for data protection questions is published as "
                f"{contact} on {web_result.entry_url}"
            ),
        )
    symbols = ev.find_symbols(code_result, _DPO_KEYWORDS)
    if not symbols:
        symbols = ev.find_symbols_by_source(code_result, _DPO_TEXT_MARKERS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="dpo_identified",
            passed=True,
            detail=(
                f"Data Protection Officer identified by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    searched = (
        "in the published site or in code"
        if ev.web_observable(web_result) or web_result is None
        else "in code; the crawl was blocked, so the published site could not be read"
    )
    return RuleCheck(
        name="dpo_identified",
        passed=False,
        detail=(
            f"no Data Protection Officer contact found {searched}; "
            "s.10(2)(a) requires an SDF to appoint one based in India, and Rule 9 requires the "
            "contact to be published"
        ),
    )


def _audit_check(code_result) -> RuleCheck:
    files = ev.find_files(code_result, _AUDIT_KEYWORDS)
    if files:
        return RuleCheck(
            name="independent_audit_mechanism",
            passed=True,
            detail=f"audit artefact found at {ev.join_names([f.path for f in files])}",
            file_path=files[0].path,
        )
    symbols = ev.find_symbols(code_result, _AUDIT_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="independent_audit_mechanism",
            passed=True,
            detail=(
                f"audit mechanism implemented by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    return RuleCheck(
        name="independent_audit_mechanism",
        passed=False,
        detail=(
            "no data audit artefact or handler found; s.10(2)(b) requires an SDF to have a Data "
            "Auditor carry out periodic audits"
        ),
    )


def _fairness_check(code_result) -> RuleCheck:
    decision_edges = [
        edge
        for edge in (code_result.data_flow_edges if code_result is not None else [])
        if edge.pii_categories and ev.matches(edge.sink_symbol, _DECISION_KEYWORDS)
    ]
    decision_symbols = ev.find_symbols(code_result, _DECISION_KEYWORDS)

    if not decision_edges and not decision_symbols:
        return RuleCheck(
            name="algorithmic_fairness_addressed",
            passed=True,
            detail=(
                "no automated decision making on personal data was found, so the s.10(2)(c) duty "
                "to verify algorithmic software is not triggered"
            ),
        )

    fairness_files = ev.find_files(code_result, _FAIRNESS_KEYWORDS)
    fairness_symbols = ev.find_symbols(code_result, _FAIRNESS_KEYWORDS)
    if fairness_files or fairness_symbols:
        where = (
            fairness_files[0].path
            if fairness_files
            else ev.loc(fairness_symbols[0].file_path, fairness_symbols[0].line_number)
        )
        return RuleCheck(
            name="algorithmic_fairness_addressed",
            passed=True,
            detail=f"algorithmic fairness assessed at {where}",
        )

    if decision_edges:
        edge = decision_edges[0]
        where = ev.loc(edge.sink_file, edge.sink_line)
        subject = (
            f"{edge.sink_symbol} at {where} consumes "
            f"{ev.join_names(edge.pii_categories)} personal data"
        )
    else:
        symbol = decision_symbols[0]
        where = ev.loc(symbol.file_path, symbol.line_number)
        subject = f"{symbol.name} at {where} performs automated decision making"
    return RuleCheck(
        name="algorithmic_fairness_addressed",
        passed=False,
        detail=(
            f"{subject}, and no fairness or bias assessment artefact was found; s.10(2)(c) "
            "requires algorithmic software to be verified for risks to Data Principal rights"
        ),
    )
