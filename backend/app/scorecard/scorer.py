"""Scorecard computation."""

from dataclasses import dataclass, field

from app.contracts import RuleVerdict
from app.models.enums import RuleStatus, Severity

# Grade bands. Wide C band on purpose: most real apps land there and the useful
# signal is the per-rule breakdown, not a precise overall number.
GRADE_BANDS = (
    (90.0, "A", "Compliant"),
    (75.0, "B", "Substantially Compliant"),
    (50.0, "C", "Partially Compliant"),
    (25.0, "D", "Significant Gaps"),
    (0.0, "F", "Non-Compliant"),
)

# Weights reflect legal risk, not equal distribution.
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
    "XBORDER": 0.05,
    "R8": 0.05,
    "R9": 0.03,
    "R11": 0.03,
    "R12": 0.03,
}


NOT_ASSESSED_LABEL = "Not Assessed"


@dataclass
class Scorecard:
    """A graded result, or an explicit refusal to grade.

    overall_score and overall_grade are None when nothing could be assessed.
    That is a third state, distinct from a good grade and a bad one, and callers
    have to render it as such.
    """

    overall_score: float | None
    overall_grade: str | None
    grade_label: str
    verdicts: list[RuleVerdict] = field(default_factory=list)
    applicable_rules: int = 0
    excluded_rules: list[str] = field(default_factory=list)

    @property
    def assessed(self) -> bool:
        return self.overall_grade is not None


def grade_for(score: float | None) -> tuple[str | None, str]:
    """Map a score to (letter, label). A missing score is not a failing score."""
    if score is None:
        return None, NOT_ASSESSED_LABEL
    for threshold, letter, label in GRADE_BANDS:
        if score >= threshold:
            return letter, label
    return "F", "Non-Compliant"


def compute(verdicts: list[RuleVerdict]) -> Scorecard:
    """Weighted average of applicable rule scores, mapped to a grade.

    not_applicable verdicts are excluded from both numerator and denominator,
    and the remaining weights are renormalised. Without the renormalisation a
    web-only scan would cap around 80 even with every applicable rule passing,
    because the excluded weight would silently count as lost marks.
    """
    applicable = [
        v
        for v in verdicts
        if v.status != RuleStatus.NOT_APPLICABLE and v.score is not None
    ]
    excluded = [v.rule_id for v in verdicts if v not in applicable]

    if not applicable:
        # Nothing could be assessed, which is not the same as failing. A crawl
        # turned away by a bot wall, or a scan of a target with no evidence to
        # read, would otherwise be published as F Non-Compliant: a verdict about
        # a site nobody actually inspected. The grade is withheld instead.
        return Scorecard(
            overall_score=None,
            overall_grade=None,
            grade_label=NOT_ASSESSED_LABEL,
            verdicts=verdicts,
            applicable_rules=0,
            excluded_rules=excluded,
        )

    total_weight = sum(RULE_WEIGHTS.get(v.rule_id, 0.0) for v in applicable)
    if total_weight <= 0:
        # No configured weights for these rules, fall back to a flat mean so the
        # scorecard still reports something meaningful.
        score = sum(v.score for v in applicable) / len(applicable) * 100.0
    else:
        weighted = sum(
            (v.score or 0.0) * RULE_WEIGHTS.get(v.rule_id, 0.0) for v in applicable
        )
        score = (weighted / total_weight) * 100.0

    score = round(max(0.0, min(100.0, score)), 1)
    letter, label = grade_for(score)

    return Scorecard(
        overall_score=score,
        overall_grade=letter,
        grade_label=label,
        verdicts=verdicts,
        applicable_rules=len(applicable),
        excluded_rules=excluded,
    )


def severity_for(verdict: RuleVerdict, sensitivity: str | None = None) -> str:
    """Severity of a finding raised under a verdict.

    Driven by the rule's weight and the sensitivity of the data involved, so a
    plaintext Aadhaar column outranks a missing referrer-policy header.
    """
    if sensitivity == "critical":
        return Severity.CRITICAL
    weight = RULE_WEIGHTS.get(verdict.rule_id, 0.05)
    if verdict.status == RuleStatus.VIOLATION:
        return Severity.CRITICAL if weight >= 0.12 else Severity.HIGH
    if verdict.status == RuleStatus.GAP:
        return Severity.HIGH if weight >= 0.12 else Severity.MEDIUM
    return Severity.LOW
