"""R8 Data Protection Impact Assessment, DPDP Act s.10(2); Rule 8.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R8"
RULE_NAME = "Data Protection Impact Assessment"
DPDP_SECTION = "s.10(2)"
DPDP_RULE = "Rule 8"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# The DPIA duty sits in s.10(2)(a) and in the Significant Data Fiduciary
# obligations of Rules 2025 rule_11, not in rule_8, which covers erasure.
# The assessment is an SDF obligation under s.10(2), carried into rule_13. It
# is not a standalone numbered rule.
RETRIEVAL_SECTION_IDS: list[str] = ["s.10(2)", "rule_13"]

_DPIA_FILE_KEYWORDS: tuple[str, ...] = (
    "dpia",
    "impact_assessment",
    "data_protection_impact",
    "privacy_impact",
    "pia_report",
)

_DPIA_TEXT_MARKERS: tuple[str, ...] = (
    "data protection impact assessment",
    "privacy impact assessment",
    "dpia",
)

_RISK_FILE_KEYWORDS: tuple[str, ...] = (
    "risk_register",
    "risk_assessment",
    "threat_model",
    "privacy_risk",
    "risk_review",
)

_RISK_SYMBOL_KEYWORDS: tuple[str, ...] = (
    "high_risk",
    "risk_assessment",
    "risk_score",
    "risk_register",
    "threat_model",
)

_RISK_TEXT_MARKERS: tuple[str, ...] = ("high risk", "high-risk", "risk assessment")


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R8 and return a deterministic verdict.

    Checks:
      - a DPIA document or assessment record exists
      - high-risk processing is identified somewhere in the repo
      - the assessment covers the PII categories the scanner actually found

    Note: A DPIA is a document obligation, so this checker reads files and
    docstrings rather than the AST. Return not_applicable for a web-only
    scan: a crawl cannot see whether a DPIA exists, and scoring it zero
    would understate the grade for a reason that is not the site's fault.
    """
    if code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "No code or repository scan was run. A DPIA is an internal document, so a web "
                "crawl cannot establish whether one exists and this rule is excluded from the "
                "weighted score rather than failed."
            ),
        )

    dpia_files = ev.find_files(code_result, _DPIA_FILE_KEYWORDS)
    dpia_symbols = ev.find_symbols_by_source(code_result, _DPIA_TEXT_MARKERS)
    categories = ev.pii_categories_found(code_result)

    checks: list[RuleCheck] = [
        _document_check(code_result, dpia_files, dpia_symbols),
        _risk_check(code_result),
        _coverage_check(dpia_files, dpia_symbols, categories),
    ]

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
    )


def _document_check(code_result, dpia_files, dpia_symbols) -> RuleCheck:
    if dpia_files:
        return RuleCheck(
            name="dpia_document_exists",
            passed=True,
            detail=(
                f"assessment document found at {ev.join_names([f.path for f in dpia_files])}"
            ),
            file_path=dpia_files[0].path,
        )
    if dpia_symbols:
        symbol = dpia_symbols[0]
        return RuleCheck(
            name="dpia_document_exists",
            passed=True,
            detail=(
                f"assessment recorded in code at {ev.loc(symbol.file_path, symbol.line_number)} "
                f"inside {symbol.name}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    return RuleCheck(
        name="dpia_document_exists",
        passed=False,
        detail=(
            f"no impact assessment document or record found across "
            f"{len(code_result.files)} scanned file(s)"
        ),
    )


def _risk_check(code_result) -> RuleCheck:
    files = ev.find_files(code_result, _RISK_FILE_KEYWORDS)
    if files:
        return RuleCheck(
            name="high_risk_processing_identified",
            passed=True,
            detail=f"risk documentation found at {ev.join_names([f.path for f in files])}",
            file_path=files[0].path,
        )
    symbols = ev.find_symbols(code_result, _RISK_SYMBOL_KEYWORDS)
    if not symbols:
        symbols = ev.find_symbols_by_source(code_result, _RISK_TEXT_MARKERS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="high_risk_processing_identified",
            passed=True,
            detail=(
                f"high risk processing identified by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    return RuleCheck(
        name="high_risk_processing_identified",
        passed=False,
        detail=(
            "nothing in the repository identifies which processing is high risk, so there is no "
            "record of what an assessment would have to cover"
        ),
    )


def _coverage_check(dpia_files, dpia_symbols, categories) -> RuleCheck:
    if not categories:
        return RuleCheck(
            name="assessment_covers_found_pii",
            passed=True,
            detail=(
                "the scanner found no personal data categories in this repository, so there is "
                "no processing for an assessment to cover"
            ),
        )
    rendered = ev.join_names(categories, limit=6)
    if dpia_files or dpia_symbols:
        where = dpia_files[0].path if dpia_files else ev.loc(
            dpia_symbols[0].file_path, dpia_symbols[0].line_number
        )
        return RuleCheck(
            name="assessment_covers_found_pii",
            passed=True,
            detail=(
                f"assessment at {where} is present for the {len(categories)} personal data "
                f"category(ies) the scanner found ({rendered}); the scanner verifies that the "
                "assessment exists, a reviewer still has to confirm it addresses each category"
            ),
        )
    return RuleCheck(
        name="assessment_covers_found_pii",
        passed=False,
        detail=(
            f"{len(categories)} personal data category(ies) are processed ({rendered}) with no "
            "assessment document in the repository covering any of them"
        ),
    )
