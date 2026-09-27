"""The guardrail is the reason a citation from this tool can be trusted.

These tests are deliberately adversarial: each one simulates a specific way a
language model fabricates legal authority.
"""

from app.ai import guardrail
from app.contracts import GroundedExplanation, RetrievedProvision

SECTION_8_5 = RetrievedProvision(
    section_id="s.8(5)",
    citation_label="DPDP Act 2023, Section 8(5)",
    section_title="Obligations of Data Fiduciary",
    text=(
        "A Data Fiduciary shall protect personal data in its possession or under "
        "its control, including in respect of any processing undertaken by it or "
        "on its behalf by a Data Processor, by taking reasonable security "
        "safeguards to prevent personal data breach."
    ),
    similarity=0.9,
)

SECTION_6_1 = RetrievedProvision(
    section_id="s.6(1)",
    citation_label="DPDP Act 2023, Section 6(1)",
    section_title="Consent",
    text=(
        "The consent given by the Data Principal shall be free, specific, "
        "informed, unconditional and unambiguous with a clear affirmative action."
    ),
    similarity=0.88,
)


def _explanation(**overrides) -> GroundedExplanation:
    base = {
        "title": "Aadhaar stored without encryption",
        "description": (
            "The Aadhaar column stores personal data without reasonable security "
            "safeguards, so the Data Fiduciary does not protect personal data in "
            "its control against a personal data breach."
        ),
        "citation": "DPDP Act 2023, Section 8(5)",
        "citation_text": (
            "by taking reasonable security safeguards to prevent personal data breach"
        ),
        "cited_section_ids": ["s.8(5)"],
        "suggested_fix": "Wrap the column in an encrypted type.",
        "data_flow_summary": "Aadhaar enters at /kyc and is stored in plaintext.",
        "confidence": 0.9,
    }
    base.update(overrides)
    return GroundedExplanation(**base)


class TestSectionIdNormalisation:
    def test_parses_the_spellings_a_model_actually_emits(self):
        found = guardrail.normalise_section_ids(
            "See Section 8(5), s.6(1), sec 9 and Rule 6 of the 2025 Rules."
        )
        assert {"s.8(5)", "s.6(1)", "s.9", "rule_6"} <= found

    def test_returns_empty_for_prose_with_no_citation(self):
        assert guardrail.normalise_section_ids("This looks bad generally.") == set()


class TestCitationGrounding:
    def test_accepts_a_citation_that_was_retrieved(self):
        report = guardrail.check(_explanation(), [SECTION_8_5])
        assert report.citation_grounded

    def test_rejects_a_section_that_was_never_shown_to_the_model(self):
        # The classic hallucination: a real-sounding section the retrieval step
        # never returned.
        explanation = _explanation(
            citation="DPDP Act 2023, Section 42(3)", cited_section_ids=["s.42(3)"]
        )
        report = guardrail.check(explanation, [SECTION_8_5])
        assert not report.citation_grounded
        assert not report.passed

    def test_rejects_when_nothing_was_retrieved(self):
        report = guardrail.check(_explanation(), [])
        assert not report.citation_grounded

    def test_rejects_an_explanation_with_no_citation_at_all(self):
        explanation = _explanation(citation="", cited_section_ids=[])
        report = guardrail.check(explanation, [SECTION_8_5])
        assert not report.citation_grounded


class TestQuoteVerification:
    def test_accepts_a_verbatim_quote(self):
        report = guardrail.check(_explanation(), [SECTION_8_5])
        assert report.quote_verified

    def test_accepts_a_quote_with_only_whitespace_differences(self):
        explanation = _explanation(
            citation_text=(
                "by taking   reasonable security safeguards\nto prevent personal "
                "data breach"
            )
        )
        report = guardrail.check(explanation, [SECTION_8_5])
        assert report.quote_verified

    def test_rejects_an_invented_quote(self):
        explanation = _explanation(
            citation_text=(
                "Every Data Fiduciary must encrypt all data using AES-256 at rest."
            )
        )
        report = guardrail.check(explanation, [SECTION_8_5])
        assert not report.quote_verified
        assert not report.passed

    def test_rejects_a_missing_quote(self):
        report = guardrail.check(_explanation(citation_text=""), [SECTION_8_5])
        assert not report.quote_verified


class TestEntailment:
    def test_accepts_a_claim_drawn_from_the_provision(self):
        report = guardrail.check(_explanation(), [SECTION_8_5])
        assert report.entailment_ok

    def test_rejects_a_claim_unrelated_to_the_cited_provision(self):
        explanation = _explanation(
            description=(
                "The button colour fails the recommended contrast ratio for "
                "readability on mobile displays."
            )
        )
        report = guardrail.check(explanation, [SECTION_8_5])
        assert not report.entailment_ok


class TestApply:
    def test_a_clean_explanation_survives_untouched(self):
        explanation = guardrail.apply(_explanation(), [SECTION_8_5])
        assert explanation.guardrail_passed
        assert explanation.citation_text
        assert explanation.confidence == 0.9

    def test_a_failed_explanation_is_flagged_not_deleted(self):
        # Dropping the finding would hide a real compliance problem just because
        # the prose about it could not be verified.
        explanation = guardrail.apply(
            _explanation(citation="Section 42(3)", cited_section_ids=["s.42(3)"]),
            [SECTION_8_5],
        )
        assert not explanation.guardrail_passed
        assert explanation.guardrail_notes
        assert explanation.title
        assert explanation.confidence <= 0.4

    def test_an_unverified_quote_is_stripped(self):
        explanation = guardrail.apply(
            _explanation(citation_text="Data must be encrypted with AES-256."),
            [SECTION_8_5],
        )
        assert explanation.citation_text == ""

    def test_multiple_retrieved_provisions_do_not_confuse_grounding(self):
        explanation = guardrail.apply(_explanation(), [SECTION_6_1, SECTION_8_5])
        assert explanation.guardrail_passed


class TestSubsectionGrounding:
    """A narrower reference to a provision the model was shown is not invented law.

    Found live: shown s.12 and s.13, the model cited s.12(1) and s.13(1). Exact
    matching rejected both as ungrounded, which would have trained the prompt
    toward vaguer citations rather than better ones.
    """

    SECTION_12 = RetrievedProvision(
        section_id="s.12",
        citation_label="DPDP Act 2023, Section 12",
        section_title="Right to correction and erasure of personal data",
        text=(
            "A Data Principal shall have the right to correction, completion, "
            "updating and erasure of her personal data for the processing of "
            "which she has previously given consent."
        ),
        similarity=0.8,
    )

    def test_parent_section_id(self):
        assert guardrail.parent_section_id("s.12(1)") == "s.12"
        assert guardrail.parent_section_id("s.8(5)") == "s.8"
        assert guardrail.parent_section_id("s.12") is None
        assert guardrail.parent_section_id("rule_14") is None

    def test_subsection_of_a_retrieved_section_is_grounded(self):
        explanation = _explanation(
            description=(
                "The application provides no path for a Data Principal to obtain "
                "correction or erasure of her personal data."
            ),
            citation="DPDP Act 2023, Section 12(1)",
            citation_text="the right to correction, completion, updating and erasure",
            cited_section_ids=["s.12(1)"],
        )
        report = guardrail.check(explanation, [self.SECTION_12])
        assert report.citation_grounded
        assert report.passed

    def test_widening_to_the_parent_is_still_rejected(self):
        # Shown only s.8(5), a citation of bare s.8 covers eleven sub-sections
        # the model never saw, so the obligation it names cannot be checked.
        explanation = _explanation(
            citation="DPDP Act 2023, Section 8", cited_section_ids=["s.8"]
        )
        report = guardrail.check(explanation, [SECTION_8_5])
        assert not report.citation_grounded

    def test_an_unrelated_section_is_still_rejected(self):
        explanation = _explanation(
            citation="DPDP Act 2023, Section 40(2)", cited_section_ids=["s.40(2)"]
        )
        report = guardrail.check(explanation, [self.SECTION_12])
        assert not report.citation_grounded


class TestObligationDenial:
    """Absence findings are the tool's normal output and must not be rejected.

    Found on the first live web scan: counting negation words flagged two
    accurate findings, "the notice names no way to complain" and "CSP and
    X-Content-Type-Options are missing", against provisions they cited
    correctly. Almost every compliance finding says something is missing, so
    the signal has to be whether the negation attaches to the duty itself.
    """

    ORDINARY_ABSENCE = [
        "The privacy notice sits in the footer only and names no way to complain.",
        "CSP and X-Content-Type-Options headers are missing from every response.",
        "No consent mechanism was found on the ten forms that collect personal data.",
        "The application does not encrypt the Aadhaar column and never has.",
        "There is no grievance intake endpoint anywhere in the codebase.",
    ]

    DENIES_THE_DUTY = [
        "The Act does not require encryption of stored personal data.",
        "There is no statutory obligation to provide a grievance mechanism.",
        "A Data Fiduciary is not required to intimate the Board of a breach.",
        "This provision does not apply to personal data collected online.",
        "The Data Fiduciary is exempt from this obligation.",
    ]

    def test_ordinary_absence_findings_are_not_treated_as_denial(self):
        for text in self.ORDINARY_ABSENCE:
            assert not guardrail._denies_the_obligation(text), text

    def test_denying_the_duty_is_caught(self):
        for text in self.DENIES_THE_DUTY:
            assert guardrail._denies_the_obligation(text), text

    def test_a_real_absence_finding_passes_the_full_check(self):
        explanation = _explanation(
            description=(
                "The application stores personal data without reasonable security "
                "safeguards and does not protect it against personal data breach."
            )
        )
        assert guardrail.check(explanation, [SECTION_8_5]).entailment_ok

    def test_a_finding_that_denies_the_duty_is_blocked(self):
        explanation = _explanation(
            description=(
                "A Data Fiduciary is not required to take reasonable security "
                "safeguards to prevent a personal data breach of personal data."
            )
        )
        report = guardrail.check(explanation, [SECTION_8_5])
        assert not report.entailment_ok
        assert not report.passed
