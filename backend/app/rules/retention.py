"""RET Retention and Erasure, DPDP Act s.8(7); s.8(7).  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "RET"
RULE_NAME = "Retention and Erasure"
DPDP_SECTION = "s.8(7)"
DPDP_RULE = "s.8(7)"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# Erasure and retention periods are Rules 2025 rule_8.
# rule_8 sets when a specified purpose is deemed no longer served.
RETRIEVAL_SECTION_IDS: list[str] = ["s.8(7)", "rule_8"]

_EXPIRY_COLUMNS: tuple[str, ...] = (
    "expires_at",
    "expiry",
    "expiry_at",
    "expire_at",
    "valid_until",
    "retain_until",
    "retention_until",
    "purge_after",
    "delete_after",
    "deleted_at",
    "ttl",
)

_CLEANUP_KEYWORDS: tuple[str, ...] = (
    "purge",
    "cleanup",
    "clean_up",
    "delete_expired",
    "expire_records",
    "retention_job",
    "retention_sweep",
    "prune",
    "reap_expired",
)

_RETENTION_CONFIG_KEYWORDS: tuple[str, ...] = (
    "retention_days",
    "retention_period",
    "retention_policy",
    "retention_window",
    "data_retention",
    "max_age_days",
    "keep_for_days",
)

_PROPAGATION_KEYWORDS: tuple[str, ...] = (
    "cascade_delete",
    "propagate_delete",
    "purge_related",
    "purge_cache",
    "scrub_logs",
    "anonymise",
    "anonymize",
    "pseudonymise",
    "pseudonymize",
    "redact",
    "purge_backups",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate RET and return a deterministic verdict.

    Checks:
      - PII storage carries an expiry or TTL
      - a scheduled deletion or cleanup job exists
      - a retention period is configured rather than implicit
      - erasure propagates to derived copies, logs, caches, backups

    Note: s.8(7) requires erasure once the purpose is served and retention is
    no longer necessary for a legal purpose. Indefinite storage with no
    expiry anywhere is a violation, not a gap: flows.has_retention_policy
    false across every path is the signal. This is not one of the twelve
    numbered Rules, it is an Act obligation, hence the RET id.
    """
    flows = flows or []

    if code_result is None and not flows:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "No code scan or PII flow paths were supplied. Retention is a property of how "
                "data is stored, which a crawl of the public site cannot observe."
            ),
        )

    checks: list[RuleCheck] = [_expiry_check(code_result, flows)]
    notes: list[str] = []

    if code_result is not None:
        checks.append(_cleanup_check(code_result))
        checks.append(_configured_period_check(code_result))
        checks.append(_propagation_check(code_result, flows))
    else:
        notes.append(
            "No code scan was supplied, so the deletion job, the configured retention period "
            "and erasure propagation were assessed from flow flags only."
        )

    override = None
    if flows and not any(flow.has_retention_policy for flow in flows):
        # s.8(7) makes erasure the default once the purpose is served. If not a
        # single traced path has a retention policy, the data is kept
        # indefinitely by design rather than by oversight, which is the
        # condition the obligation exists to prevent.
        override = (
            f"none of the {len(flows)} traced personal data flows carry a retention policy, so "
            "personal data is held indefinitely with no point at which it is erased."
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
        override_reason=override,
    )


def _expiry_check(code_result, flows) -> RuleCheck:
    columns = ev.pii_columns(code_result)
    if columns:
        models_without_expiry = []
        for model, column, _category in columns:
            has_expiry = column.has_expiry or any(
                ev.matches(other.name, _EXPIRY_COLUMNS) for other in model.columns
            )
            if not has_expiry:
                models_without_expiry.append(model)
        if not models_without_expiry:
            rendered = ev.join_names(
                [f"{model.class_name} at {ev.loc(model.file_path, model.line_number)}"
                 for model, _column, _category in columns]
            )
            return RuleCheck(
                name="pii_storage_has_expiry",
                passed=True,
                detail=f"every table holding personal data carries an expiry: {rendered}",
            )
        first = models_without_expiry[0]
        rendered = ev.join_names(
            [
                f"{model.class_name} at {ev.loc(model.file_path, model.line_number)}"
                for model in models_without_expiry
            ],
            limit=3,
        )
        return RuleCheck(
            name="pii_storage_has_expiry",
            passed=False,
            detail=(
                f"{len(list(dict.fromkeys(m.class_name for m in models_without_expiry)))} table(s) "
                f"store personal data with no expiry, TTL or deletion marker: {rendered}"
            ),
            file_path=first.file_path,
            line_number=first.line_number,
        )

    without_policy = ev.flows_without(flows, "has_retention_policy")
    if flows and not without_policy:
        return RuleCheck(
            name="pii_storage_has_expiry",
            passed=True,
            detail=(
                f"all {len(flows)} traced personal data flow(s) carry a retention policy, "
                f"including {ev.flow_label(flows[0])}"
            ),
        )
    if without_policy:
        return RuleCheck(
            name="pii_storage_has_expiry",
            passed=False,
            detail=(
                f"{len(without_policy)} of {len(flows)} traced personal data flow(s) reach a sink "
                f"with no retention policy: {ev.flow_label(without_policy[0])}"
            ),
        )
    return RuleCheck(
        name="pii_storage_has_expiry",
        passed=True,
        detail="no stored personal data column or flow was found, so nothing is being retained",
    )


def _cleanup_check(code_result) -> RuleCheck:
    symbols = ev.find_symbols(code_result, _CLEANUP_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="scheduled_deletion_job_exists",
            passed=True,
            detail=(
                f"scheduled deletion handled by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    files = ev.find_files(code_result, _CLEANUP_KEYWORDS)
    if files:
        return RuleCheck(
            name="scheduled_deletion_job_exists",
            passed=True,
            detail=f"deletion job defined in {ev.join_names([f.path for f in files])}",
            file_path=files[0].path,
        )
    return RuleCheck(
        name="scheduled_deletion_job_exists",
        passed=False,
        detail=(
            f"no purge, cleanup or expiry job found across {len(code_result.symbols)} symbol(s), "
            "so nothing actually deletes personal data once its purpose is served"
        ),
    )


def _configured_period_check(code_result) -> RuleCheck:
    symbols = ev.find_symbols(code_result, _RETENTION_CONFIG_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="retention_period_configured",
            passed=True,
            detail=(
                f"retention period configured as {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    columns = ev.find_columns(code_result, _RETENTION_CONFIG_KEYWORDS)
    if columns:
        model, column = columns[0]
        return RuleCheck(
            name="retention_period_configured",
            passed=True,
            detail=(
                f"retention period stored as {model.class_name}.{column.name} at "
                f"{ev.loc(model.file_path, column.line_number)}"
            ),
            file_path=model.file_path,
            line_number=column.line_number,
        )
    return RuleCheck(
        name="retention_period_configured",
        passed=False,
        detail=(
            "no named retention period or policy constant found, so how long personal data is "
            "kept is implicit in the code rather than stated and reviewable"
        ),
    )


def _propagation_check(code_result, flows) -> RuleCheck:
    symbols = ev.find_symbols(code_result, _PROPAGATION_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="erasure_propagates_to_copies",
            passed=True,
            detail=(
                f"erasure is propagated to derived copies by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    copies: list[str] = []
    for edge in code_result.data_flow_edges:
        if edge.edge_type in ("log_output", "api_send") and edge.pii_categories:
            copies.append(
                f"{edge.sink_symbol} at {ev.loc(edge.sink_file, edge.sink_line)} "
                f"({edge.edge_type})"
            )
    copies.extend(ev.flow_label(flow) for flow in ev.third_party_flows(flows))
    if copies:
        return RuleCheck(
            name="erasure_propagates_to_copies",
            passed=False,
            detail=(
                f"personal data reaches {len(copies)} derived destination(s) with no cascade, "
                f"redaction or anonymisation step: {ev.join_names(copies, limit=3)}"
            ),
        )
    return RuleCheck(
        name="erasure_propagates_to_copies",
        passed=False,
        detail=(
            "no cascade delete, redaction or anonymisation handler found, so an erasure request "
            "would leave copies in logs, caches and backups behind"
        ),
    )
