"""R11 Data Protection Board Readiness, DPDP Act s.13, s.27; Rule 11.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R11"
RULE_NAME = "Data Protection Board Readiness"
DPDP_SECTION = "s.13, s.27"
DPDP_RULE = "Rule 11"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# rule_9 is the publication of contact information a Data Principal uses to raise
# a grievance before approaching the Board.
# s.13 is grievance redressal before the Board; rule_9 is the published
# contact point; rule_14 the exercise procedure.
RETRIEVAL_SECTION_IDS: list[str] = ["s.13", "s.27", "rule_9", "rule_14"]

_COMPLAINT_KEYWORDS: tuple[str, ...] = (
    "grievance",
    "complaint",
    "redressal",
    "dispute",
    "ticket",
    "support_request",
)

_STATE_COLUMNS: tuple[str, ...] = (
    "status",
    "state",
    "stage",
    "resolution",
    "resolved",
    "is_resolved",
    "closed",
)

_DEADLINE_COLUMNS: tuple[str, ...] = (
    "due_at",
    "due_date",
    "deadline",
    "respond_by",
    "resolve_by",
    "sla_at",
    "sla_due",
    "escalate_at",
    "responded_at",
    "resolved_at",
)

_BOARD_KEYWORDS: tuple[str, ...] = (
    "board_direction",
    "board_order",
    "board_request",
    "data_protection_board",
    "dpb_request",
    "dpb_response",
    "regulator_request",
    "regulatory_request",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R11 and return a deterministic verdict.

    Checks:
      - a complaint or grievance intake mechanism exists
      - complaints are tracked with a state and a response deadline
      - a path exists to respond to a Board direction

    Note: s.13 gives the Data Principal a right to grievance redressal before
    approaching the Board, so an intake that records nothing and has no
    deadline is a gap even when the form exists.
    """
    if web_result is None and code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason="No web or code evidence was supplied.",
        )

    if web_result is not None and not ev.web_observable(web_result) and code_result is None:
        # A grievance page the crawler was turned away from is not a missing one.
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=ev.crawl_blocked_reason(web_result),
        )

    checks: list[RuleCheck] = [_intake_check(web_result, code_result)]
    notes: list[str] = []
    if web_result is not None and not ev.web_observable(web_result):
        notes.append(ev.crawl_blocked_reason(web_result))

    if code_result is not None:
        checks.append(_tracking_check(code_result))
        checks.append(_board_direction_check(code_result))
    else:
        notes.append(
            "No code scan was supplied, so complaint state tracking and the response path to a "
            "Board direction were not assessed."
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
    )


def _intake_check(web_result, code_result) -> RuleCheck:
    contact = ev.grievance_contact(web_result) or ev.dpo_contact(web_result)
    if contact:
        return RuleCheck(
            name="complaint_intake_exists",
            passed=True,
            detail=(
                f"grievance intake published as {contact} on "
                f"{web_result.entry_url}"
            ),
        )
    policy = ev.policy_document(web_result, "grievance")
    if policy is not None:
        return RuleCheck(
            name="complaint_intake_exists",
            passed=True,
            detail=(
                f"grievance procedure published at {policy.url}, discovered by "
                f"{policy.discovered_via.replace('_', ' ')}"
            ),
        )
    links = ev.find_links(web_result, _COMPLAINT_KEYWORDS)
    if links:
        return RuleCheck(
            name="complaint_intake_exists",
            passed=True,
            detail=f"grievance intake reachable at {ev.join_names(links)}",
        )
    routes = ev.find_routes(code_result, _COMPLAINT_KEYWORDS)
    if routes:
        route = routes[0]
        return RuleCheck(
            name="complaint_intake_exists",
            passed=True,
            detail=(
                f"grievance intake endpoint {route.http_method} {route.path} at "
                f"{ev.loc(route.file_path, route.line_number)}"
            ),
            file_path=route.file_path,
            line_number=route.line_number,
        )
    models = ev.find_models(code_result, _COMPLAINT_KEYWORDS)
    if models:
        model = models[0]
        return RuleCheck(
            name="complaint_intake_exists",
            passed=True,
            detail=(
                f"grievances recorded in {model.class_name} at "
                f"{ev.loc(model.file_path, model.line_number)}"
            ),
            file_path=model.file_path,
            line_number=model.line_number,
        )
    return RuleCheck(
        name="complaint_intake_exists",
        passed=False,
        detail=(
            "no grievance contact, intake endpoint or complaint table found; s.13(1) requires a "
            "readily available means of registering a grievance"
        ),
    )


def _tracking_check(code_result) -> RuleCheck:
    models = ev.find_models(code_result, _COMPLAINT_KEYWORDS)
    if not models:
        return RuleCheck(
            name="complaints_tracked_with_deadline",
            passed=False,
            detail=(
                f"no complaint table found across {len(code_result.db_models)} database model(s), "
                "so a grievance cannot be tracked to a resolution or a response deadline"
            ),
        )
    model = models[0]
    column_names = [column.name for column in model.columns]
    has_state = any(ev.matches(name, _STATE_COLUMNS) for name in column_names)
    has_deadline = any(ev.matches(name, _DEADLINE_COLUMNS) for name in column_names)
    location = ev.loc(model.file_path, model.line_number)

    if has_state and has_deadline:
        return RuleCheck(
            name="complaints_tracked_with_deadline",
            passed=True,
            detail=(
                f"{model.class_name} at {location} tracks each grievance with a state and a "
                f"response deadline (columns {ev.join_names(column_names, limit=6)})"
            ),
            file_path=model.file_path,
            line_number=model.line_number,
        )
    missing = []
    if not has_state:
        missing.append("a resolution state")
    if not has_deadline:
        missing.append("a response deadline")
    return RuleCheck(
        name="complaints_tracked_with_deadline",
        passed=False,
        detail=(
            f"{model.class_name} at {location} accepts grievances but has no "
            f"{ev.join_names(missing)}; columns present are "
            f"{ev.join_names(column_names, limit=6)}"
        ),
        file_path=model.file_path,
        line_number=model.line_number,
    )


def _board_direction_check(code_result) -> RuleCheck:
    symbols = ev.find_symbols(code_result, _BOARD_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="board_direction_response_path",
            passed=True,
            detail=(
                f"Board directions handled by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    routes = ev.find_routes(code_result, _BOARD_KEYWORDS)
    if routes:
        route = routes[0]
        return RuleCheck(
            name="board_direction_response_path",
            passed=True,
            detail=(
                f"Board directions handled by {route.http_method} {route.path} at "
                f"{ev.loc(route.file_path, route.line_number)}"
            ),
            file_path=route.file_path,
            line_number=route.line_number,
        )
    models = ev.find_models(code_result, _BOARD_KEYWORDS)
    if models:
        model = models[0]
        return RuleCheck(
            name="board_direction_response_path",
            passed=True,
            detail=(
                f"Board directions recorded in {model.class_name} at "
                f"{ev.loc(model.file_path, model.line_number)}"
            ),
            file_path=model.file_path,
            line_number=model.line_number,
        )
    return RuleCheck(
        name="board_direction_response_path",
        passed=False,
        detail=(
            "no handler, endpoint or table for responding to a direction of the Data Protection "
            "Board was found; s.27 lets the Board direct remedial measures the fiduciary has to "
            "act on"
        ),
    )
