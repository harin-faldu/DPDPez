"""Severity for a policy gap finding.

A failed PolicyCheck carries no rule weight to derive a severity from the way a
RuleVerdict does, so this is a small, separate heuristic: gaps close to a
bright-line prohibition or a principal's ability to act on a right at all are
rated high, everything else medium.
"""

from app.api.scorecard import _policy_gap_severity


def test_children_gap_is_high():
    assert _policy_gap_severity("notice.children") == "high"


def test_breach_intimation_gap_is_high():
    assert _policy_gap_severity("notice.breach_intimation") == "high"


def test_an_ordinary_notice_gap_is_medium():
    assert _policy_gap_severity("notice.itemised_data") == "medium"


def test_an_unknown_requirement_defaults_to_medium():
    assert _policy_gap_severity("notice.something_new") == "medium"
