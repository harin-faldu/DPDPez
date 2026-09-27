"""Stage 4: combining two already-graded scorecards into one report.

Nothing here re-runs a checker. A web verdict and a code verdict for the same
rule are both already finished scores; the point of this module is only how
they are combined for the report, never how they were reached.
"""

from app.contracts import RuleVerdict
from app.scorecard import aggregate as agg


def verdict(rule_id: str, status: str, score: float | None, **kw) -> RuleVerdict:
    return RuleVerdict(
        rule_id=rule_id,
        rule_name=kw.get("rule_name", rule_id),
        status=status,
        score=score,
        evidence=kw.get("evidence", "evidence text"),
        dpdp_section=kw.get("dpdp_section", "s.1"),
        dpdp_rule=kw.get("dpdp_rule", "Rule 1"),
    )


class TestOnlyOneStageRan:
    def test_web_only_uses_the_web_score(self):
        result = agg.build_aggregate(web_rules=[verdict("R4", "gap", 0.5)])
        rule = result.rules[0]
        assert rule.score == 0.5
        assert rule.web_score == 0.5
        assert rule.code_score is None
        assert rule.sources == ["web"]
        assert result.stages_included == ["web"]

    def test_code_only_uses_the_code_score(self):
        result = agg.build_aggregate(code_rules=[verdict("R6", "compliant", 1.0)])
        rule = result.rules[0]
        assert rule.score == 1.0
        assert rule.sources == ["code"]
        assert result.stages_included == ["code"]

    def test_neither_stage_ran_gives_no_score(self):
        result = agg.build_aggregate()
        assert result.overall_score is None
        assert result.overall_grade is None
        assert result.rules == []


class TestBothStagesAssessedTheSameRule:
    def test_the_lower_of_the_two_scores_wins(self):
        result = agg.build_aggregate(
            web_rules=[verdict("R4", "gap", 0.8)],
            code_rules=[verdict("R4", "gap", 0.3)],
        )
        rule = result.rules[0]
        assert rule.score == 0.3
        assert rule.web_score == 0.8
        assert rule.code_score == 0.3
        assert sorted(rule.sources) == ["code", "web"]

    def test_a_tie_keeps_that_score(self):
        result = agg.build_aggregate(
            web_rules=[verdict("R10", "compliant", 1.0)],
            code_rules=[verdict("R10", "compliant", 1.0)],
        )
        assert result.rules[0].score == 1.0


class TestNotApplicableIsExcludedNotZeroed:
    def test_a_not_applicable_web_verdict_falls_back_to_the_code_score(self):
        result = agg.build_aggregate(
            web_rules=[verdict("R8", "not_applicable", None)],
            code_rules=[verdict("R8", "gap", 0.6)],
        )
        rule = result.rules[0]
        assert rule.score == 0.6
        assert rule.sources == ["code"]

    def test_not_applicable_on_both_sides_is_excluded_entirely(self):
        result = agg.build_aggregate(
            web_rules=[verdict("R8", "not_applicable", None, evidence="no DPIA evidence from a crawl")],
        )
        assert result.rules == []
        assert len(result.not_assessed) == 1
        assert result.not_assessed[0].rule_id == "R8"
        assert "DPIA" in result.not_assessed[0].reason

    def test_a_rule_no_stage_mentions_at_all_does_not_appear(self):
        result = agg.build_aggregate(web_rules=[verdict("R4", "gap", 0.5)])
        assert all(r.rule_id != "R8" for r in result.rules)
        assert all(r.rule_id != "R8" for r in result.not_assessed)


class TestOverallScoring:
    def test_a_fully_compliant_aggregate_scores_100(self):
        result = agg.build_aggregate(
            web_rules=[verdict(rid, "compliant", 1.0) for rid in agg.RULE_WEIGHTS],
        )
        assert result.overall_score == 100.0
        assert result.overall_grade == "A"

    def test_unassessed_rules_are_renormalised_away_not_penalised(self):
        full = agg.build_aggregate(
            web_rules=[verdict(rid, "compliant", 1.0) for rid in agg.RULE_WEIGHTS],
        )
        partial = agg.build_aggregate(
            web_rules=[
                verdict(rid, "compliant", 1.0)
                for rid in agg.RULE_WEIGHTS
                if rid != "R8"
            ]
            + [verdict("R8", "not_applicable", None)],
        )
        assert full.overall_score == partial.overall_score == 100.0

    def test_no_assessable_rules_withholds_the_grade(self):
        result = agg.build_aggregate(web_rules=[verdict("R8", "not_applicable", None)])
        assert result.overall_score is None
        assert result.overall_grade is None
        assert result.grade_label == "Not Assessed"
