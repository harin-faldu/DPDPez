"""Unassessed is a third state, not a shade of failure.

Found by scanning four real sites. One was behind a bot wall and one renders its
notice client side, so nothing could be read from either. Both reported fifteen
failed requirements against notices nobody had managed to open.

The analyser had it right: every check was marked unassessed. The contract did
not. `failed_checks` returned everything where `satisfied` was False, which
folds "the notice does not say this" together with "we could not read the
notice". Any consumer of that property, the aggregation stage and the dashboard
included, would publish failures the site never earned.
"""

from app.contracts import PolicyRequirementCheck, PolicyScanResult
from app.policy import analyzer


def check(requirement_id: str, *, satisfied: bool, unassessed: bool = False):
    return PolicyRequirementCheck(
        requirement_id=requirement_id,
        title=requirement_id,
        dpdp_section="s.5",
        dpdp_rule="Rule 3",
        satisfied=satisfied,
        unassessed=unassessed,
        evidence=(analyzer.UNASSESSED_PREFIX if unassessed else "") + "detail",
    )


def result(*checks) -> PolicyScanResult:
    return PolicyScanResult(entry_url="https://example.test", checks=list(checks))


class TestThreeStates:
    def test_an_unassessed_check_is_not_a_failure(self):
        r = result(check("a", satisfied=False, unassessed=True))
        assert r.failed_checks == []
        assert len(r.unassessed_checks) == 1

    def test_an_unassessed_check_is_not_a_pass_either(self):
        r = result(check("a", satisfied=False, unassessed=True))
        assert r.satisfied_checks == []

    def test_a_real_gap_still_reports_as_failed(self):
        r = result(check("a", satisfied=False))
        assert [c.requirement_id for c in r.failed_checks] == ["a"]
        assert r.unassessed_checks == []

    def test_a_satisfied_check_reports_as_satisfied(self):
        r = result(check("a", satisfied=True))
        assert [c.requirement_id for c in r.satisfied_checks] == ["a"]

    def test_the_three_states_partition_the_checks(self):
        r = result(
            check("pass", satisfied=True),
            check("gap", satisfied=False),
            check("unknown", satisfied=False, unassessed=True),
        )
        total = len(r.satisfied_checks) + len(r.failed_checks) + len(r.unassessed_checks)
        assert total == len(r.checks) == 3


class TestBlockedScanEarnsNoFailures:
    def test_a_scan_that_read_nothing_reports_no_failures(self):
        """The whole point. A bot wall is not a compliance finding."""
        r = PolicyScanResult(
            entry_url="https://example.test",
            crawl_blocked=True,
            crawl_note="the site answered HTTP 403",
            checks=[
                check(f"r{i}", satisfied=False, unassessed=True) for i in range(15)
            ],
        )
        assert r.failed_checks == []
        assert len(r.unassessed_checks) == 15
        assert r.crawl_note


class TestIsUnassessed:
    def test_reads_the_flag(self):
        assert analyzer.is_unassessed(check("a", satisfied=False, unassessed=True))

    def test_a_genuine_gap_is_not_unassessed(self):
        assert not analyzer.is_unassessed(check("a", satisfied=False))

    def test_falls_back_to_the_evidence_prefix(self):
        # A check built before the flag existed must still report correctly.
        legacy = PolicyRequirementCheck(
            requirement_id="a",
            title="a",
            dpdp_section="s.5",
            dpdp_rule="Rule 3",
            satisfied=False,
            evidence=analyzer.UNASSESSED_PREFIX + "could not be fetched",
        )
        assert analyzer.is_unassessed(legacy)
