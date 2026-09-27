"""A bright line breach caps a rule's score; it does not erase the rule.

Zeroing was measured to be wrong. Across four real sites, R4 sat at exactly 0.00
for every one of them, because every commercial site fires a tag manager before
consent. Together with a second bug that did the same to R5, about a third of
every web grade was lost identically by every target, so four very different
sites all landed on the same letter and the grade stopped discriminating.

The breach is still a breach: status stays violation and the score cannot reach
the compliant band. But a site that passed 8 of 11 consent checks must not score
the same as one that passed 1 of 8.
"""

import pytest

from app.contracts import RuleCheck
from app.rules import engine

VIOLATION = "violation"
COMPLIANT = "compliant"


def _checks(passed: int, total: int) -> list[RuleCheck]:
    return [
        RuleCheck(name=f"check_{i}", passed=i < passed, detail=f"detail {i}")
        for i in range(total)
    ]


def _verdict(passed: int, total: int, *, breach: str | None = None):
    return engine.build_verdict(
        rule_id="R4",
        rule_name="Consent",
        dpdp_section="s.6",
        dpdp_rule="Rule 4",
        checks=_checks(passed, total),
        override_reason=breach,
    )


class TestPartialCreditSurvivesABreach:
    def test_a_breach_still_reads_as_a_violation(self):
        v = _verdict(8, 11, breach="tracker fired before consent")
        assert v.status == VIOLATION
        assert v.bright_line_reason

    def test_a_breach_cannot_reach_the_compliant_band(self):
        v = _verdict(10, 11, breach="tracker fired before consent")
        assert v.score <= engine.BRIGHT_LINE_SCORE_CEILING

    def test_doing_more_right_scores_better_even_in_breach(self):
        """The whole point. These two used to be indistinguishable at 0.00."""
        better = _verdict(8, 11, breach="tracker fired before consent")
        worse = _verdict(1, 8, breach="tracker fired before consent")
        assert better.score > worse.score
        assert better.status == worse.status == VIOLATION

    def test_a_breach_with_nothing_else_passing_still_scores_zero(self):
        v = _verdict(0, 8, breach="tracker fired before consent")
        assert v.score == 0.0

    def test_no_breach_leaves_the_score_untouched(self):
        # Guards the near miss found while modelling this: capping
        # unconditionally dropped a fully compliant fixture from B to C.
        v = _verdict(10, 10)
        assert v.score == pytest.approx(1.0)
        assert v.status == COMPLIANT
        assert v.bright_line_reason is None

    def test_a_clean_rule_outscores_a_breached_one_that_passed_more_checks(self):
        clean = _verdict(6, 10)
        breached = _verdict(9, 10, breach="tracker fired before consent")
        assert clean.score > breached.score


class TestAuditability:
    def test_the_reason_is_recorded_not_implied(self):
        """With the cap, status no longer follows from the score arithmetically,
        so the reason has to be on the verdict for a reviewer to recompute it."""
        v = _verdict(8, 11, breach="tracker fired before consent")
        assert v.bright_line_reason == "tracker fired before consent"
        assert v.status != engine.status_from_score(v.score)

    def test_the_breach_is_named_in_the_evidence(self):
        v = _verdict(8, 11, breach="tracker fired before consent")
        assert "tracker fired before consent" in v.evidence

    def test_an_unbreached_verdict_still_derives_status_from_score(self):
        for passed, total in ((0, 4), (2, 4), (4, 4)):
            v = _verdict(passed, total)
            assert v.status == engine.status_from_score(v.score)
