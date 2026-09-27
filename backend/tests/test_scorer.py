from app.contracts import RuleVerdict
from app.models.enums import RuleStatus
from app.scorecard import scorer


def verdict(rule_id: str, status: str, score: float | None) -> RuleVerdict:
    return RuleVerdict(
        rule_id=rule_id,
        rule_name=rule_id,
        status=status,
        score=score,
        evidence="",
        dpdp_section="",
        dpdp_rule="",
    )


def test_all_compliant_scores_100():
    verdicts = [verdict(r, RuleStatus.COMPLIANT, 1.0) for r in scorer.RULE_WEIGHTS]
    card = scorer.compute(verdicts)
    assert card.overall_score == 100.0
    assert card.overall_grade == "A"


def test_all_violations_score_zero():
    verdicts = [verdict(r, RuleStatus.VIOLATION, 0.0) for r in scorer.RULE_WEIGHTS]
    card = scorer.compute(verdicts)
    assert card.overall_score == 0.0
    assert card.overall_grade == "F"


def test_not_applicable_rules_are_excluded_and_weights_renormalised():
    """A web-only scan cannot assess DPIA or SDF.

    Without renormalisation those excluded weights would silently count as lost
    marks and cap a perfect web scan below 100.
    """
    verdicts = [
        verdict(r, RuleStatus.COMPLIANT, 1.0)
        for r in ("R3", "R4", "R5", "R6", "R10", "RET")
    ] + [
        verdict(r, RuleStatus.NOT_APPLICABLE, None)
        for r in ("R7", "R8", "R9", "R11", "R12")
    ]
    card = scorer.compute(verdicts)
    assert card.overall_score == 100.0
    assert card.applicable_rules == 6
    assert set(card.excluded_rules) == {"R7", "R8", "R9", "R11", "R12"}


def test_consent_outweighs_a_minor_rule():
    """Weights encode legal risk. Failing consent must cost more than failing DPIA."""
    fail_consent = scorer.compute(
        [verdict("R4", RuleStatus.VIOLATION, 0.0), verdict("R8", RuleStatus.COMPLIANT, 1.0)]
    )
    fail_dpia = scorer.compute(
        [verdict("R4", RuleStatus.COMPLIANT, 1.0), verdict("R8", RuleStatus.VIOLATION, 0.0)]
    )
    assert fail_consent.overall_score < fail_dpia.overall_score


def test_empty_verdicts_withhold_the_grade():
    """No assessable evidence is not a failing grade.

    This previously asserted F. That was wrong: it published "Non-Compliant"
    about a target nobody managed to inspect, which is what a blocked crawl
    produces. See test_not_assessed.py.
    """
    card = scorer.compute([])
    assert card.overall_grade is None
    assert card.overall_score is None
    assert card.grade_label == scorer.NOT_ASSESSED_LABEL
    assert card.applicable_rules == 0


def test_grade_bands():
    assert scorer.grade_for(95.0)[0] == "A"
    assert scorer.grade_for(80.0)[0] == "B"
    assert scorer.grade_for(60.0)[0] == "C"
    assert scorer.grade_for(30.0)[0] == "D"
    assert scorer.grade_for(10.0)[0] == "F"


def test_severity_scales_with_rule_weight_and_sensitivity():
    heavy = verdict("R6", RuleStatus.VIOLATION, 0.0)
    light = verdict("R12", RuleStatus.VIOLATION, 0.0)
    assert scorer.severity_for(heavy) == "critical"
    assert scorer.severity_for(light) == "high"
    assert scorer.severity_for(light, sensitivity="critical") == "critical"


def test_gap_is_less_severe_than_violation_on_the_same_rule():
    gap = scorer.severity_for(verdict("R4", RuleStatus.GAP, 0.5))
    violation = scorer.severity_for(verdict("R4", RuleStatus.VIOLATION, 0.0))
    order = ["critical", "high", "medium", "low", "info"]
    assert order.index(gap) > order.index(violation)
