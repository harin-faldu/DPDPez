"""R12 Compliance Verification, DPDP Act s.8(1); Rule 12.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R12"
RULE_NAME = "Compliance Verification"
DPDP_SECTION = "s.8(1)"
DPDP_RULE = "Rule 12"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# The log retention and monitoring duty this rule leans on sits in Rules 2025
# rule_6, not rule_12, which covers the procedure for exercising rights.
# s.8(1) puts the burden of demonstrating compliance on the Fiduciary; rule_6
# requires retained logs.
RETRIEVAL_SECTION_IDS: list[str] = ["s.8(1)", "s.8(2)", "rule_6"]

_AUDIT_MODEL_KEYWORDS: tuple[str, ...] = (
    "audit_log",
    "audit_trail",
    "access_log",
    "activity_log",
    "event_log",
    "audit_event",
    "data_access_log",
)

_AUDIT_SYMBOL_KEYWORDS: tuple[str, ...] = (
    "log_access",
    "record_access",
    "audit_event",
    "write_audit",
    "emit_audit",
    "audit_log",
    "track_access",
)

_ROPA_FILE_KEYWORDS: tuple[str, ...] = (
    "ropa",
    "records_of_processing",
    "processing_register",
    "data_inventory",
    "data_map",
    "data_catalog",
    "data_catalogue",
    "processing_activities",
)

_ROPA_TEXT_MARKERS: tuple[str, ...] = (
    "record of processing",
    "records of processing",
    "processing activities",
    "data inventory",
)

_EXPORT_KEYWORDS: tuple[str, ...] = (
    "export_audit",
    "audit_report",
    "compliance_report",
    "generate_report",
    "export_log",
    "export_audit_log",
    "compliance_export",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R12 and return a deterministic verdict.

    Checks:
      - an audit trail records access to personal data
      - processing activities are documented, a RoPA equivalent
      - evidence of compliance is retrievable, not just asserted

    Note: s.8(1) puts the burden of demonstrating compliance on the Data
    Fiduciary. This rule checks whether the system could produce that
    evidence at all, which is why an audit log is the central check.
    """
    if code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "No code scan was run. An audit trail and a record of processing activities are "
                "internal artefacts, so a crawl of the public site cannot establish whether the "
                "fiduciary could demonstrate compliance."
            ),
        )

    checks: list[RuleCheck] = [
        _audit_trail_check(code_result),
        _ropa_check(code_result),
        _retrievability_check(code_result),
    ]

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
    )


def _audit_trail_check(code_result) -> RuleCheck:
    models = ev.find_models(code_result, _AUDIT_MODEL_KEYWORDS)
    if models:
        model = models[0]
        return RuleCheck(
            name="audit_trail_records_pii_access",
            passed=True,
            detail=(
                f"audit trail {model.class_name} at "
                f"{ev.loc(model.file_path, model.line_number)} with columns "
                f"{ev.join_names([column.name for column in model.columns], limit=6)}"
            ),
            file_path=model.file_path,
            line_number=model.line_number,
        )
    symbols = ev.find_symbols(code_result, _AUDIT_SYMBOL_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="audit_trail_records_pii_access",
            passed=True,
            detail=(
                f"access to personal data is recorded by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    return RuleCheck(
        name="audit_trail_records_pii_access",
        passed=False,
        detail=(
            f"no audit trail table or audit writer found across {len(code_result.db_models)} "
            f"model(s) and {len(code_result.symbols)} symbol(s), so who read personal data and "
            "when cannot be reconstructed"
        ),
    )


def _ropa_check(code_result) -> RuleCheck:
    files = ev.find_files(code_result, _ROPA_FILE_KEYWORDS)
    if files:
        return RuleCheck(
            name="processing_activities_documented",
            passed=True,
            detail=(
                f"record of processing activities found at "
                f"{ev.join_names([f.path for f in files])}"
            ),
            file_path=files[0].path,
        )
    symbols = ev.find_symbols_by_source(code_result, _ROPA_TEXT_MARKERS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="processing_activities_documented",
            passed=True,
            detail=(
                f"processing activities documented in code at "
                f"{ev.loc(symbol.file_path, symbol.line_number)} inside {symbol.name}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    categories = ev.pii_categories_found(code_result)
    scope = (
        f" covering the {len(categories)} category(ies) actually processed "
        f"({ev.join_names(categories, limit=5)})"
        if categories
        else ""
    )
    return RuleCheck(
        name="processing_activities_documented",
        passed=False,
        detail=(
            f"no record of processing activities or data inventory found in the "
            f"scanned source{scope}"
        ),
    )


def _retrievability_check(code_result) -> RuleCheck:
    symbols = ev.find_symbols(code_result, _EXPORT_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="compliance_evidence_retrievable",
            passed=True,
            detail=(
                f"compliance evidence can be produced by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    routes = ev.find_routes(code_result, _EXPORT_KEYWORDS)
    if routes:
        route = routes[0]
        return RuleCheck(
            name="compliance_evidence_retrievable",
            passed=True,
            detail=(
                f"compliance evidence can be produced by {route.http_method} {route.path} at "
                f"{ev.loc(route.file_path, route.line_number)}"
            ),
            file_path=route.file_path,
            line_number=route.line_number,
        )
    return RuleCheck(
        name="compliance_evidence_retrievable",
        passed=False,
        detail=(
            "no export or reporting path over the audit trail was found, so compliance under "
            "s.8(1) could only be asserted rather than demonstrated on request"
        ),
    )
