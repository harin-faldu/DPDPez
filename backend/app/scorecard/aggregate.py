"""Stage 4: one report built from stages that already ran.

Nothing here is recomputed from merged evidence. The rules engine already
refuses to grade a web scan and a code scan in the same call, because a clean
codebase would hide a site that tracks before consent; that constraint holds
here too; this module combines two already-finished scorecards at the
reporting layer, after each one settled its own verdict from its own evidence.

Where a rule was assessed by both stages, the aggregate takes the lower of the
two scores: a rule is only as compliant as its weakest observed evidence, and
averaging would let a strong code score paper over a page that tracks before
consent. Where only one stage could reach a rule, that stage's score stands
unchanged. Where neither could, the rule is excluded from the weighted average
exactly as a single scan excludes it, so an aggregate missing a stage is not
punished for evidence nobody gathered.

Policy claims are not merged here at all. Stage 2 and stage 3 write to the same
claim rows, in the order they run, so a claim's stored verdict is already
whichever stage last had something to say about it. This module only reads
that state.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.rules.engine import RULE_WEIGHTS
from app.scorecard.scorer import GRADE_BANDS, NOT_ASSESSED_LABEL


class _RuleLike(Protocol):
    rule_id: str
    rule_name: str
    status: str
    score: float | None
    evidence: str | None
    dpdp_section: str | None
    dpdp_rule: str | None


NOT_APPLICABLE = "not_applicable"


@dataclass
class AggregateRule:
    rule_id: str
    rule_name: str
    score: float
    status: str
    dpdp_section: str | None
    dpdp_rule: str | None
    web_score: float | None
    code_score: float | None
    sources: list[str] = field(default_factory=list)
    evidence: str | None = None


@dataclass
class NotAssessedRule:
    rule_id: str
    rule_name: str
    reason: str
    dpdp_section: str | None = None
    dpdp_rule: str | None = None


@dataclass
class AggregateScorecard:
    overall_score: float | None
    overall_grade: str | None
    grade_label: str
    rules: list[AggregateRule] = field(default_factory=list)
    not_assessed: list[NotAssessedRule] = field(default_factory=list)
    stages_included: list[str] = field(default_factory=list)


def _by_rule_id(rules: list[Any] | None) -> dict[str, Any]:
    return {r.rule_id: r for r in (rules or [])}


def build_aggregate(
    *,
    web_rules: list[_RuleLike] | None = None,
    code_rules: list[_RuleLike] | None = None,
) -> AggregateScorecard:
    """Combine two already-graded rule sets into one report.

    web_rules and code_rules are whatever a single scan already produced: a
    list of RuleVerdict or RuleResult rows, not re-run against each other.
    """
    web_by_id = _by_rule_id(web_rules)
    code_by_id = _by_rule_id(code_rules)
    all_rule_ids = sorted(set(web_by_id) | set(code_by_id))

    stages_included = []
    if web_rules is not None:
        stages_included.append("web")
    if code_rules is not None:
        stages_included.append("code")

    rules: list[AggregateRule] = []
    not_assessed: list[NotAssessedRule] = []

    for rule_id in all_rule_ids:
        web = web_by_id.get(rule_id)
        code = code_by_id.get(rule_id)

        web_score = web.score if web is not None and web.status != NOT_APPLICABLE else None
        code_score = code.score if code is not None and code.status != NOT_APPLICABLE else None

        candidates = [
            (source, r, score)
            for source, r, score in (("web", web, web_score), ("code", code, code_score))
            if r is not None and score is not None
        ]
        if not candidates:
            example = web or code
            reason = (
                example.evidence
                if example is not None and example.evidence
                else "Not evaluated by any stage that ran."
            )
            rule_name = example.rule_name if example is not None else rule_id
            dpdp_section = example.dpdp_section if example is not None else None
            dpdp_rule = example.dpdp_rule if example is not None else None
            not_assessed.append(
                NotAssessedRule(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    reason=reason,
                    dpdp_section=dpdp_section,
                    dpdp_rule=dpdp_rule,
                )
            )
            continue

        worst_source, worst, worst_score = min(candidates, key=lambda c: c[2])
        rules.append(
            AggregateRule(
                rule_id=rule_id,
                rule_name=worst.rule_name,
                score=worst_score,
                status=worst.status,
                dpdp_section=worst.dpdp_section,
                dpdp_rule=worst.dpdp_rule,
                web_score=web_score,
                code_score=code_score,
                sources=[source for source, _, _ in candidates],
                evidence=worst.evidence,
            )
        )

    overall_score, overall_grade, grade_label = _score_rules(rules)
    return AggregateScorecard(
        overall_score=overall_score,
        overall_grade=overall_grade,
        grade_label=grade_label,
        rules=rules,
        not_assessed=not_assessed,
        stages_included=stages_included,
    )


def _score_rules(rules: list[AggregateRule]) -> tuple[float | None, str | None, str]:
    if not rules:
        return None, None, NOT_ASSESSED_LABEL

    total_weight = sum(RULE_WEIGHTS.get(r.rule_id, 0.0) for r in rules)
    if total_weight <= 0:
        score = sum(r.score for r in rules) / len(rules) * 100.0
    else:
        weighted = sum(r.score * RULE_WEIGHTS.get(r.rule_id, 0.0) for r in rules)
        score = (weighted / total_weight) * 100.0

    score = round(max(0.0, min(100.0, score)), 1)
    for threshold, letter, label in GRADE_BANDS:
        if score >= threshold:
            return score, letter, label
    return score, "F", "Non-Compliant"
