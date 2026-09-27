"""R7 Breach Notification, DPDP Act s.8(6); Rule 7.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R7"
RULE_NAME = "Breach Notification"
DPDP_SECTION = "s.8(6)"
DPDP_RULE = "Rule 7"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# rule_7 sets the intimation content and timeline.
RETRIEVAL_SECTION_IDS: list[str] = ["s.8(6)", "rule_7"]

_BREACH_KEYWORDS: tuple[str, ...] = (
    "breach",
    "incident",
    "security_event",
    "data_leak",
    "exposure_event",
)

_BOARD_KEYWORDS: tuple[str, ...] = (
    "notify_board",
    "board_notification",
    "notify_dpb",
    "dpb_notify",
    "report_to_board",
    "intimate_board",
    "data_protection_board",
    "cert_in",
)

_PRINCIPAL_KEYWORDS: tuple[str, ...] = (
    "notify_affected",
    "notify_users",
    "notify_principal",
    "notify_data_principal",
    "breach_email",
    "breach_notice",
    "send_breach",
    "alert_users",
)

_TIMELINE_COLUMNS: tuple[str, ...] = (
    "notified_at",
    "reported_at",
    "intimated_at",
    "detected_at",
    "discovered_at",
    "deadline",
    "due_at",
    "notify_by",
)

_TIMELINE_SYMBOLS: tuple[str, ...] = (
    "breach_notification_window",
    "breach_deadline",
    "notification_window",
    "notification_deadline",
    "breach_sla",
    "intimation_window",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R7 and return a deterministic verdict.

    Checks:
      - a breach or incident record exists in the data model
      - a notification path to the Data Protection Board exists
      - a notification path to affected Data Principals exists
      - the timeline obligation is represented in code or configuration

    Note: Rules 2025 sets the intimation obligation to the Board without undue
    delay and in any case within the prescribed window. Look for the
    mechanism, not a perfect implementation: a breach table with a
    notified_at column and a sender function is enough to pass, while
    nothing at all is a violation.
    """
    if code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "No code scan was run. Breach intimation is an internal response capability, "
                "so a crawl of the public site cannot see whether the mechanism exists."
            ),
        )

    breach_models = ev.find_models(code_result, _BREACH_KEYWORDS)
    checks: list[RuleCheck] = [
        _record_check(code_result, breach_models),
        _path_check(
            code_result,
            name="board_notification_path",
            keywords=_BOARD_KEYWORDS,
            missing_detail=(
                "no function, endpoint or file that intimates the Data Protection Board was "
                "found; s.8(6) requires intimation to the Board in the event of a breach"
            ),
            found_prefix="Board intimation handled by",
        ),
        _path_check(
            code_result,
            name="principal_notification_path",
            keywords=_PRINCIPAL_KEYWORDS,
            missing_detail=(
                "no function or endpoint that notifies affected Data Principals was found; "
                "s.8(6) requires intimation to each affected Data Principal as well as the Board"
            ),
            found_prefix="Data Principal intimation handled by",
        ),
        _timeline_check(code_result, breach_models),
    ]

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
    )


def _record_check(code_result, breach_models) -> RuleCheck:
    if breach_models:
        model = breach_models[0]
        columns = ev.join_names([column.name for column in model.columns], limit=6)
        return RuleCheck(
            name="breach_record_exists",
            passed=True,
            detail=(
                f"breach record {model.class_name} at "
                f"{ev.loc(model.file_path, model.line_number)} with columns {columns}"
            ),
            file_path=model.file_path,
            line_number=model.line_number,
        )
    return RuleCheck(
        name="breach_record_exists",
        passed=False,
        detail=(
            f"no breach or incident table found across {len(code_result.db_models)} database "
            "model(s), so a breach could not be recorded let alone intimated"
        ),
    )


def _path_check(code_result, *, name, keywords, missing_detail, found_prefix) -> RuleCheck:
    symbols = ev.find_symbols(code_result, keywords)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name=name,
            passed=True,
            detail=(
                f"{found_prefix} {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    routes = ev.find_routes(code_result, keywords)
    if routes:
        route = routes[0]
        return RuleCheck(
            name=name,
            passed=True,
            detail=(
                f"{found_prefix} {route.http_method} {route.path} at "
                f"{ev.loc(route.file_path, route.line_number)}"
            ),
            file_path=route.file_path,
            line_number=route.line_number,
        )
    return RuleCheck(name=name, passed=False, detail=missing_detail)


def _timeline_check(code_result, breach_models) -> RuleCheck:
    for model in breach_models:
        for column in model.columns:
            if ev.matches(column.name, _TIMELINE_COLUMNS):
                return RuleCheck(
                    name="notification_timeline_represented",
                    passed=True,
                    detail=(
                        f"{model.class_name}.{column.name} at "
                        f"{ev.loc(model.file_path, column.line_number)} records when intimation "
                        "was due or sent, so the timeline obligation is tracked"
                    ),
                    file_path=model.file_path,
                    line_number=column.line_number,
                )
    symbols = ev.find_symbols(code_result, _TIMELINE_SYMBOLS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="notification_timeline_represented",
            passed=True,
            detail=(
                f"notification window configured as {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    return RuleCheck(
        name="notification_timeline_represented",
        passed=False,
        detail=(
            "no notified_at style column and no configured notification window found, so nothing "
            "in the system tracks whether intimation happened within the prescribed period"
        ),
    )
