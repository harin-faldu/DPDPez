"""Nothing assessable is not the same as failing.

A crawl turned away by a bot wall produced applicable_rules=0, which the scorer
graded 0.0 / F / Non-Compliant. That publishes a damning verdict about a site
nobody was able to inspect, and it is the mirror image of the bug where a
blocked crawl reports "no trackers found". Both directions are unacceptable:
the tool must say it could not look.
"""

from app.contracts import RuleVerdict
from app.models.enums import RuleStatus
from app.scorecard import scorer


def _na(rule_id: str) -> RuleVerdict:
    return RuleVerdict(
        rule_id=rule_id,
        rule_name=rule_id,
        status=RuleStatus.NOT_APPLICABLE,
        score=None,
        evidence="crawl was blocked",
        dpdp_section="",
        dpdp_rule="",
    )


def _scored(rule_id: str, score: float) -> RuleVerdict:
    return RuleVerdict(
        rule_id=rule_id,
        rule_name=rule_id,
        status=scorer.RuleStatus.COMPLIANT if score >= 1.0 else RuleStatus.GAP,
        score=score,
        evidence="",
        dpdp_section="",
        dpdp_rule="",
    )


class TestWithheldGrade:
    def test_all_not_applicable_withholds_the_grade(self):
        card = scorer.compute([_na(r) for r in ("R3", "R4", "R6", "R10")])
        assert card.overall_grade is None
        assert card.overall_score is None
        assert card.grade_label == scorer.NOT_ASSESSED_LABEL
        assert not card.assessed

    def test_no_verdicts_at_all_withholds_the_grade(self):
        card = scorer.compute([])
        assert card.overall_grade is None
        assert not card.assessed

    def test_a_withheld_grade_is_not_an_f(self):
        card = scorer.compute([_na("R4")])
        assert card.overall_grade != "F"
        assert "non-compliant" not in card.grade_label.lower()

    def test_one_assessable_rule_still_produces_a_grade(self):
        # Partial evidence is still evidence. Only a total absence withholds.
        card = scorer.compute([_na("R3"), _scored("R4", 1.0)])
        assert card.assessed
        assert card.overall_grade == "A"
        assert card.applicable_rules == 1


class TestGradeFor:
    def test_none_score_maps_to_not_assessed(self):
        letter, label = scorer.grade_for(None)
        assert letter is None
        assert label == scorer.NOT_ASSESSED_LABEL

    def test_zero_is_still_a_real_failing_grade(self):
        # A genuine zero must keep failing. Withholding applies to absent
        # evidence, never to evidence that was read and came back bad.
        letter, label = scorer.grade_for(0.0)
        assert letter == "F"
        assert label == "Non-Compliant"
