"""Rules engine orchestrator.  OWNER: Prerana

Every checker is a pure function: scan evidence in, verdict out. No AI, no
randomness, no side effects. Run the same scan twice and get the same verdict.
That is what makes the output auditable, and it is the whole reason the AI layer
is not allowed to decide status.
"""

from app.contracts import (
    CertInEvidence,
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)

# These mirror RuleStatus in app/models/enums.py and are restated here rather
# than imported, because importing app.models pulls in the ORM and the database
# driver. A checker must not depend on anything that could make a verdict differ
# between one environment and another. test_rules.py asserts the two stay in
# step wherever the ORM dependencies are installed.
STATUS_COMPLIANT = "compliant"
STATUS_GAP = "gap"
STATUS_VIOLATION = "violation"
STATUS_NOT_APPLICABLE = "not_applicable"

# Weights reflect legal risk, not equal distribution. Consent and security carry
# most because they are prerequisites with the highest penalty exposure.
RULE_WEIGHTS: dict[str, float] = {
    "R4": 0.14,
    "R6": 0.14,
    "R3": 0.11,
    "R10": 0.11,
    # The CERT-In Directions are binding under s.70B(6) of the IT Act on every
    # body corporate in India, independently of the DPDP Act, so they carry real
    # weight rather than sitting as an advisory note beside it.
    "CERTIN": 0.09,
    "RET": 0.08,
    "R5": 0.07,
    "R7": 0.07,
    # s.16 restricts sending personal data outside India at all, a bright line
    # rather than a safeguard-around-it duty, so it carries more than a
    # bookkeeping rule despite being assessed from a single infrastructure fact.
    "XBORDER": 0.05,
    "R8": 0.05,
    "R9": 0.03,
    "R11": 0.03,
    "R12": 0.03,
}


# The highest a rule can score once a bright line prohibition is breached. Set
# at the top of the gap band: outright breach cannot read as compliant, but the
# checks that did pass still count toward the grade.
BRIGHT_LINE_SCORE_CEILING = 0.5


def score_from_checks(passed: int, total: int) -> float:
    """Fraction of checks passed, used as the per-rule score."""
    if total <= 0:
        return 0.0
    clamped = min(max(passed, 0), total)
    return clamped / total


def status_from_score(score: float) -> str:
    """Map a score to compliant, gap or violation.

    Real compliance is not binary. A pre-checked consent box is a gap, not a
    clean pass and not a full violation, so the middle tier carries everything
    above zero and below one.
    """
    if score >= 1.0:
        return STATUS_COMPLIANT
    if score > 0.0:
        return STATUS_GAP
    return STATUS_VIOLATION


def not_applicable_verdict(
    *,
    rule_id: str,
    rule_name: str,
    dpdp_section: str,
    dpdp_rule: str,
    reason: str,
) -> RuleVerdict:
    """A rule the available evidence cannot answer either way.

    Score is None rather than 0.0 so the scorecard drops the rule from the
    weighted average instead of counting it as lost marks. A web crawl genuinely
    cannot see whether a DPIA exists, and reporting that as a failure would
    misstate the grade for a reason that is not the site's fault.
    """
    return RuleVerdict(
        rule_id=rule_id,
        rule_name=rule_name,
        status=STATUS_NOT_APPLICABLE,
        score=None,
        evidence=reason,
        dpdp_section=dpdp_section,
        dpdp_rule=dpdp_rule,
        checks=[],
    )


def build_verdict(
    *,
    rule_id: str,
    rule_name: str,
    dpdp_section: str,
    dpdp_rule: str,
    checks: list[RuleCheck],
    notes: list[str] | None = None,
    override_reason: str | None = None,
    not_applicable_reason: str | None = None,
) -> RuleVerdict:
    """Assemble the verdict for one rule from its checks.

    A check is only created when the evidence to decide it exists, so an empty
    check list means the rule was unevaluable and becomes not_applicable rather
    than a zero.

    override_reason marks a bright line prohibition, where the Act bans conduct
    outright instead of requiring safeguards around it. It forces the status to
    violation and caps the score, but does not zero it.

    Zeroing was measured to be wrong. It made a site that passed 8 of 11 consent
    checks score identically to one that passed 1 of 8, because both fired a
    tracker before consent. Across four real sites the rule sat at 0.00 for
    every one of them, so a fifth of the grade stopped discriminating at all and
    everything landed on the same letter. The breach is still a breach, so the
    score cannot reach the compliant band, but the checks that passed are real
    and the grade should show them.

    The cost is that status no longer follows arithmetically from score, so the
    reason is recorded on the verdict rather than left implicit.
    """
    notes = notes or []
    if not checks:
        reason = not_applicable_reason or "No evidence available to evaluate this rule."
        if notes:
            reason = f"{reason} {' '.join(notes)}"
        return not_applicable_verdict(
            rule_id=rule_id,
            rule_name=rule_name,
            dpdp_section=dpdp_section,
            dpdp_rule=dpdp_rule,
            reason=reason,
        )

    passed = sum(1 for check in checks if check.passed)
    total = len(checks)
    score = score_from_checks(passed, total)
    status = status_from_score(score)

    if override_reason:
        score = min(score, BRIGHT_LINE_SCORE_CEILING)
        status = STATUS_VIOLATION

    return RuleVerdict(
        rule_id=rule_id,
        rule_name=rule_name,
        status=status,
        score=score,
        evidence=_evidence_text(passed, total, checks, notes, override_reason),
        dpdp_section=dpdp_section,
        dpdp_rule=dpdp_rule,
        checks=checks,
        bright_line_reason=override_reason,
    )


def _evidence_text(
    passed: int,
    total: int,
    checks: list[RuleCheck],
    notes: list[str],
    override_reason: str | None,
) -> str:
    parts = [f"{passed}/{total} checks passed."]
    if override_reason:
        parts.append(f"Graded as a violation regardless of the other checks: {override_reason}")
    failed = [check for check in checks if not check.passed]
    if failed:
        parts.append("Failed: " + "; ".join(check.detail for check in failed) + ".")
    else:
        parts.append("Evidence: " + "; ".join(check.detail for check in checks) + ".")
    parts.extend(notes)
    return " ".join(parts)


def run_all(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
    certin_evidence: CertInEvidence | None = None,
) -> list[RuleVerdict]:
    """Run every applicable checker and return one verdict per rule.

    A scan is either a web scan or a code scan. Each produces its own scorecard
    and its own grade, and the two are never merged, which is why passing both
    kinds of evidence raises instead of being quietly accepted.

    A checker that cannot be evaluated from the available evidence returns
    status not_applicable with score None, so the scorecard can exclude it from
    the weighted average instead of scoring it zero. A web-only scan genuinely
    cannot assess Rule 8 DPIA, and pretending otherwise would misreport the grade.
    """
    resolved_flows = list(flows) if flows else []
    if web_result is not None and (code_result is not None or resolved_flows):
        # Merging the two would produce a grade that corresponds to no scan
        # anybody ran, and the passes from one side would mask the failures on
        # the other: a clean repository would hide a site that tracks before
        # consent. PII flow paths are derived from the code scan, so they belong
        # to that side of the line too.
        raise ValueError(
            "A scan is either a web scan or a code scan, and the two are scored "
            "separately. run_all was given web evidence together with code evidence; "
            "call it once per scan kind and keep the two scorecards apart."
        )
    verdicts = []
    for checker in RULE_CHECKERS:
        if checker in (certin, cross_border):
            verdicts.append(
                checker.check(
                    web_result=web_result,
                    code_result=code_result,
                    flows=resolved_flows,
                    certin=certin_evidence,
                )
            )
        else:
            verdicts.append(
                checker.check(
                    web_result=web_result,
                    code_result=code_result,
                    flows=resolved_flows,
                )
            )
    return verdicts


# Imported at the bottom on purpose. Each checker imports the scoring helpers
# above from this module, so importing them at the top would form a cycle that
# breaks whenever a checker is imported before the engine.
from app.rules import (  # noqa: E402
    r03_notice,
    r04_consent,
    r05_children,
    r06_security,
    r07_breach,
    r08_dpia,
    r09_sdf,
    r10_rights,
    r11_dpb,
    certin,
    cross_border,
    r12_verification,
    retention,
)

# Ordered for the report, not by weight. Holds modules rather than functions so
# the bottom import stays safe in either import order.
RULE_CHECKERS: list = [
    r03_notice,
    r04_consent,
    r05_children,
    r06_security,
    r07_breach,
    r08_dpia,
    r09_sdf,
    r10_rights,
    r11_dpb,
    r12_verification,
    retention,
    certin,
    cross_border,
]
