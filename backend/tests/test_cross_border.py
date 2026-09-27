"""XBORDER: s.16 cross-border transfer, read from the same infra evidence
CERT-In's log-sovereignty check already gathers, for a different obligation.
"""

from app.contracts import CertInEvidence, CertInHit
from app.rules import cross_border


def hit(value: str) -> CertInHit:
    return CertInHit(file_path="infra.tf", line_number=3, detail=value, value=value)


class TestNotApplicable:
    def test_no_code_result_is_not_applicable(self):
        verdict = cross_border.check(certin=CertInEvidence(storage_regions=[hit("ap-south-1")], has_indian_region=True, files_examined=1))
        assert verdict.status == "not_applicable"

    def test_no_certin_evidence_is_not_applicable(self):
        verdict = cross_border.check(code_result=object())
        assert verdict.status == "not_applicable"

    def test_unexamined_evidence_is_not_applicable(self):
        verdict = cross_border.check(code_result=object(), certin=CertInEvidence())
        assert verdict.status == "not_applicable"

    def test_no_declared_region_at_all_is_not_applicable(self):
        """A PaaS deployment with no infrastructure-as-code proves nothing either way."""
        verdict = cross_border.check(code_result=object(), certin=CertInEvidence(files_examined=3))
        assert verdict.status == "not_applicable"


class TestRegionCheck:
    def test_every_region_inside_india_passes(self):
        evidence = CertInEvidence(
            storage_regions=[hit("ap-south-1")], has_indian_region=True, files_examined=1
        )
        verdict = cross_border.check(code_result=object(), certin=evidence)
        assert verdict.status == "compliant"
        assert verdict.score == 1.0
        assert verdict.checks[0].passed is True

    def test_a_foreign_region_fails(self):
        evidence = CertInEvidence(
            storage_regions=[hit("us-east-1")], has_indian_region=False, files_examined=1
        )
        verdict = cross_border.check(code_result=object(), certin=evidence)
        assert verdict.status == "violation"
        assert verdict.score == 0.0
        assert "us-east-1" in verdict.checks[0].detail
        assert "s.16" in verdict.checks[0].detail

    def test_a_mix_of_indian_and_foreign_regions_still_fails(self):
        """An Indian region alongside a foreign one does not excuse the foreign one."""
        evidence = CertInEvidence(
            storage_regions=[hit("ap-south-1"), hit("eu-west-1")],
            has_indian_region=True,
            files_examined=1,
        )
        verdict = cross_border.check(code_result=object(), certin=evidence)
        assert verdict.status == "violation"
        assert "eu-west-1" in verdict.checks[0].detail

    def test_the_citation_points_at_rule_15_not_an_unsourced_act_section(self):
        assert cross_border.RETRIEVAL_SECTION_IDS == ["rule_15"]
