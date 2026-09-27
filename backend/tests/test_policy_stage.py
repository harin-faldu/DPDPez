"""Stage 1 tests: reading what an organisation publishes about itself.

Fully offline. Every document here is fixture prose written for the case it
proves, and the one test that exercises the fetch path drives a mock transport,
because a test that needs a live site tells you about the site rather than about
the code.

The cases that matter most are the ones where a naive implementation is wrong:
a negative sentence that still discloses, a negative sentence that is only a
disclaimer, and a notice nobody could open being reported as a notice that says
nothing.
"""

import ast
from pathlib import Path

import httpx
import pytest

from app.contracts import PolicyDocument, PolicyScanResult
from app.corpus.dpdp_act import ACT_SECTIONS
from app.corpus.dpdp_rules import RULES
from app.policy import analyzer, discovery
from app.policy import scanner as policy_scanner
from app.policy.requirements import EXPECTED_POLICY_KINDS, REQUIREMENTS, requirements_for
from app.scanner import trackers, web_scanner

# --------------------------------------------------------------------- fixtures

WELL_DRAFTED = """
Privacy Notice
Last updated 1 April 2026.

Personal data we collect:
We collect your name, email address, mobile number and billing address when you
create an account, and your delivery address when you place an order.

Purpose of processing:
We use your personal data to fulfil your orders, to provide customer support and
to send you updates about an order you have placed.

How long we keep your data:
We retain your account data for 90 days after you close your account. We retain
transaction records for seven years to meet our obligations under tax law.

Who we share your data with:
We share your personal data with Razorpay for payment processing, with Google
Analytics for usage measurement, and with Bluedart Express Ltd for delivery.

Transfers outside India:
Some of your personal data is stored on servers located in Singapore and in the
United States.

Your rights:
You have the right to access your personal data, the right to correction, the
right to erasure and the right to nominate another individual. We will respond
to any request within 30 days.

How to withdraw consent:
You may withdraw your consent at any time from the privacy settings in your
account, and withdrawal is as easy as giving consent was.

Security measures:
Personal data is encrypted at rest using AES-256 and in transit using TLS 1.3,
and access is governed by role-based access control.

Data breach:
If a personal data breach occurs we will notify you and notify the Data
Protection Board within 72 hours.

Children:
We require verifiable parental consent before processing the personal data of a
child under the age of 18.

Grievance redressal:
Our Grievance Officer will acknowledge your complaint within 7 days. You may
write to the Grievance Officer at grievance@shophub.example.

Complaints to the Board:
If you are not satisfied with our response you may complain to the Data
Protection Board of India.

Consent management:
Consent may also be given through a registered Consent Manager.
"""

THIN = """
Privacy Policy
Your privacy matters to us. We are committed to protecting it.
We may use the information you give us to improve the website.
By using this website you agree to this policy.
Terms | Privacy | Cookies | Refunds | About
"""

NEGATION = """
Privacy Policy

We collect your name and email address when you place an order.

We do not share your personal data with third parties.

We do not transfer your personal data outside India. All of our servers are
located in Mumbai.

We do not knowingly collect personal data from children under the age of 18.

We do not retain your personal data for longer than 90 days after your order is
complete.

Personal data is encrypted in transit using TLS.

You may withdraw your consent at any time by writing to our Grievance Officer.

If you are not satisfied with our response you may complain to the Data
Protection Board.

We will notify you of any personal data breach without undue delay.

You have the right to access and the right to erasure of your personal data.
"""

LEGALESE = """
Privacy Policy

Notwithstanding anything contained hereinabove, the Company shall, pursuant to
the provisions of applicable law and without prejudice to any of its other
rights hereunder, be entitled to process, store, transfer and otherwise deal
with such personal data as may be furnished by the User from time to time,
whether directly or indirectly, in connection with the Services, and the User
hereby irrevocably consents thereto, it being clarified for the avoidance of
doubt that the foregoing shall survive termination hereof.

The aforesaid processing shall, inter alia, include such purposes as the Company
may in its sole and absolute discretion deem fit, and the User acknowledges that
the consequences thereof have been explained to it mutatis mutandis, whereupon
the User shall be deemed to have waived any objection whatsoever in respect
thereof, howsoever arising, and the same shall be binding in perpetuity.

The personal data we collect and the purpose for which we use it are as set out
hereinabove, and the User's rights in respect thereof shall be exercisable only
in accordance with the terms hereof.
"""


def document(
    text: str | None,
    kind: str = "privacy",
    *,
    reachable: bool = True,
    url: str | None = None,
    via: str = "link",
) -> PolicyDocument:
    words = len((text or "").split())
    return PolicyDocument(
        url=url or f"https://shophub.example/{kind}",
        kind=kind,
        reachable=reachable,
        discovered_via=via,
        body_text=text,
        word_count=words,
    )


def check_by(checks, requirement_id):
    return next(c for c in checks if c.requirement_id == requirement_id)


def _imported_modules(path: str) -> set[str]:
    """Every module a file imports, read from its syntax rather than its prose.

    Matching on substrings caught the word "random" inside a docstring, which is
    the sort of test that fails on a comment and passes on a bug.
    """
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".")[0])
    return names


# ------------------------------------------------------------- legal grounding


class TestEveryCitationResolves:
    """A citation to a provision the corpus does not hold is a citation nobody
    can check, which is worse than no citation at all."""

    def test_every_retrieval_section_id_is_in_the_corpus(self):
        available = {s.section_id for s in ACT_SECTIONS} | {r.section_id for r in RULES}
        dangling = {
            requirement.requirement_id: [
                sid for sid in requirement.retrieval_section_ids if sid not in available
            ]
            for requirement in REQUIREMENTS
        }
        dangling = {k: v for k, v in dangling.items() if v}
        assert not dangling, f"requirements cite provisions the corpus lacks: {dangling}"

    def test_every_requirement_cites_at_least_one_provision(self):
        for requirement in REQUIREMENTS:
            assert requirement.retrieval_section_ids, requirement.requirement_id

    def test_every_expected_policy_kind_has_requirements(self):
        for kind in EXPECTED_POLICY_KINDS:
            assert requirements_for(kind), kind


# ------------------------------------------------------------- shared discovery


class TestDiscoveryIsTheSingleSourceOfTruth:
    """Two stages find policies. One implementation finds them, or the two
    stages disagree about what the site publishes and every cross-stage finding
    built on that disagreement is worthless."""

    def test_the_web_scanner_uses_the_shared_helpers(self):
        assert web_scanner._html_to_text is discovery.html_to_text
        assert web_scanner._normalise_url is discovery.normalise_url
        assert web_scanner._fingerprint is discovery.fingerprint
        assert web_scanner._origin is discovery.origin
        assert web_scanner.MIN_POLICY_WORDS == discovery.MIN_POLICY_WORDS

    def test_markup_is_reduced_to_readable_prose(self):
        html = (
            "<html><head><style>b{color:red}</style><script>var x=1</script></head>"
            "<body><h1>Privacy</h1><p>We collect your name &amp; email.</p></body></html>"
        )
        text = discovery.html_to_text(html)
        assert "We collect your name & email." in text
        assert "var x" not in text and "color:red" not in text

    def test_conventional_paths_are_probed_against_the_origin(self):
        probes = discovery.probe_candidates("https://shophub.example/some/deep/page?x=1")
        urls = {p["url"] for p in probes}
        assert "https://shophub.example/privacy-policy" in urls
        assert all(p["via"] == "well_known_path" for p in probes)
        assert any(p["gated"] for p in probes), "contact probes must stay gated"

    def test_a_soft_404_that_echoes_the_homepage_is_not_a_policy(self):
        homepage = discovery.fingerprint("Welcome to ShopHub. Shop the latest range.")
        assert discovery.echoes_homepage("Welcome to ShopHub. Shop the latest range.", homepage)
        assert not discovery.echoes_homepage("Privacy Policy. We collect your name.", homepage)
        assert not discovery.judge_reachable(
            status=200, content_type="text/html", words=900, homepage_echo=True
        )

    def test_a_short_shell_is_not_a_readable_document(self):
        assert not discovery.judge_reachable(
            status=200, content_type="text/html", words=12, homepage_echo=False
        )
        assert discovery.judge_reachable(
            status=200, content_type="text/html", words=900, homepage_echo=False
        )

    def test_a_pdf_notice_counts_even_though_its_words_cannot_be_read(self):
        assert discovery.judge_reachable(
            status=200, content_type="application/pdf", words=0, homepage_echo=False
        )

    def test_a_link_only_reachable_after_a_404_is_not_reachable(self):
        assert not discovery.judge_reachable(
            status=404, content_type="text/html", words=900, homepage_echo=False
        )

    def test_links_are_preferred_over_probes_without_dropping_them(self):
        anchors = [
            {"href": f"https://shophub.example/legal/doc{i}", "text": "Terms of use",
             "aria_label": "", "title": "", "in_footer": True}
            for i in range(30)
        ]
        anchors.append(
            {"href": "https://shophub.example/data-protection", "text": "Privacy notice",
             "aria_label": "", "title": "", "in_footer": True}
        )
        ordered = discovery.order_candidates(
            discovery.build_candidates("https://shophub.example/", anchors)
        )
        assert len(ordered) <= discovery.MAX_POLICY_FETCHES
        assert ordered[0]["kind"] == trackers.KIND_PRIVACY
        assert any(o["via"] == "well_known_path" for o in ordered)

    def test_anchors_come_out_of_plain_markup(self):
        html = (
            '<footer><a href="/privacy-policy" title="Our notice">Privacy</a>'
            '<a href="#top">Top</a><a href="mailto:a@b.example">Mail</a>'
            '<a href="/grievance-redressal">Grievance Redressal</a></footer>'
        )
        anchors = discovery.extract_anchors(html, "https://shophub.example/")
        hrefs = {a["href"] for a in anchors}
        assert "https://shophub.example/privacy-policy" in hrefs
        assert "https://shophub.example/grievance-redressal" in hrefs
        assert not any("mailto" in h or "#top" in h for h in hrefs)

    def test_a_bot_wall_is_named_rather_than_read_as_an_empty_site(self):
        assert discovery.blocking_reasons(403, "Access denied")
        assert discovery.blocking_reasons(200, "Just a moment...")
        assert discovery.blocking_reasons(200, "")
        assert not discovery.blocking_reasons(200, "Privacy Policy. " + "x " * 400)


# ------------------------------------------------------------------- the reader


class TestAWellDraftedNotice:
    def test_most_requirements_are_satisfied(self):
        checks, _ = analyzer.analyse([document(WELL_DRAFTED)])
        satisfied = {c.requirement_id for c in checks if c.satisfied}
        assert len(checks) == len(REQUIREMENTS)
        assert len(satisfied) >= len(REQUIREMENTS) - 1, sorted(
            c.requirement_id for c in checks if not c.satisfied
        )

    def test_satisfied_checks_are_recorded_not_only_failures(self):
        """A requirement the notice does meet is evidence the aggregate should
        credit, and evidence a later stage may contradict."""
        checks, _ = analyzer.analyse([document(WELL_DRAFTED)])
        result = PolicyScanResult(entry_url="https://shophub.example/", checks=checks)
        assert result.satisfied_checks
        assert len(result.satisfied_checks) + len(result.failed_checks) == len(checks)

    def test_a_satisfied_check_carries_its_own_quote_from_the_document(self):
        checks, _ = analyzer.analyse([document(WELL_DRAFTED)])
        retention = check_by(checks, "notice.retention_period")
        assert retention.satisfied
        assert retention.quote and retention.quote in WELL_DRAFTED
        assert retention.source_url == "https://shophub.example/privacy"

    def test_structural_evidence_outranks_prose(self):
        checks, _ = analyzer.analyse([document(WELL_DRAFTED)])
        heading = check_by(checks, "notice.itemised_data")
        assert heading.satisfied
        assert heading.confidence >= 0.85
        assert not heading.requires_human_validation

    def test_requirements_flagged_for_human_check_stay_flagged_when_met(self):
        checks, _ = analyzer.analyse([document(WELL_DRAFTED)])
        for requirement_id in ("notice.cross_border", "notice.children", "notice.consent_manager"):
            check = check_by(checks, requirement_id)
            assert check.requires_human_validation, requirement_id
            assert check.confidence <= 0.7, requirement_id

    def test_plain_language_is_always_a_human_judgement(self):
        checks, _ = analyzer.analyse([document(WELL_DRAFTED)])
        plain = check_by(checks, "notice.plain_language")
        assert plain.satisfied
        assert plain.requires_human_validation
        assert plain.confidence < 0.7


class TestAThinNotice:
    def test_most_requirements_fail(self):
        checks, _ = analyzer.analyse([document(THIN)])
        gaps = analyzer.gap_checks(checks)
        assert len(gaps) >= len(REQUIREMENTS) - 2, sorted(
            c.requirement_id for c in checks if c.satisfied
        )

    def test_a_gap_is_not_an_unassessed_requirement(self):
        checks, _ = analyzer.analyse([document(THIN)])
        assert not analyzer.unassessed_checks(checks)
        assert all("not assessed" not in c.evidence for c in checks)

    def test_absence_in_a_stub_is_reported_less_confidently_than_in_a_long_notice(self):
        thin_checks, _ = analyzer.analyse([document(THIN)])
        long_text = THIN + "\nWe like privacy very much indeed. " * 200
        long_checks, _ = analyzer.analyse([document(long_text)])
        thin_gap = check_by(thin_checks, "notice.breach_intimation")
        long_gap = check_by(long_checks, "notice.breach_intimation")
        assert not thin_gap.satisfied and not long_gap.satisfied
        assert thin_gap.confidence < long_gap.confidence
        assert thin_gap.requires_human_validation

    def test_a_footer_link_row_is_not_read_as_a_statement(self):
        """Terms | Privacy | Cookies holds the word privacy and asserts nothing."""
        sentences = analyzer.sentences_of(document(THIN))
        nav = [s for s in sentences if "Refunds" in s.text]
        assert nav and all(s.shape == analyzer.SHAPE_NAV for s in nav)

    def test_the_absence_detail_from_the_requirement_is_what_the_reader_sees(self):
        checks, _ = analyzer.analyse([document(THIN)])
        gap = check_by(checks, "notice.retention_period")
        assert "s.8(7)" in gap.evidence or "erasure once" in gap.evidence


class TestNegationIsRead:
    """Marker presence alone must never decide a check. Whether the sentence
    asserts or denies changes the answer, and for some requirements a denial is
    itself the disclosure the Act asks for."""

    @pytest.mark.parametrize(
        "sentence,marker,denial",
        [
            ("we do not share your personal data with third parties.", "share your", True),
            ("we do not knowingly collect personal data from children.", "children", True),
            ("we do not retain personal data for longer than 90 days.", "retain", False),
            ("if you are not satisfied you may complain to the data protection board.",
             "data protection board", False),
            ("personal data is never transferred outside india.", "outside india", True),
            ("we share data with processors; we do not sell it.", "share", False),
            ("you cannot withdraw consent once given.", "withdraw consent", True),
            ("you may withdraw your consent at any time.", "withdraw your consent", False),
            ("if you do not want us to share your data, write to us.", "share your", False),
            ("we do not transfer data outside india without your explicit consent.",
             "outside india", False),
        ],
    )
    def test_negation_scope(self, sentence, marker, denial):
        assert analyzer.is_denial(sentence, sentence.index(marker)) is denial

    def test_a_refusal_to_share_satisfies_the_sharing_disclosure(self):
        checks, _ = analyzer.analyse([document(NEGATION)])
        sharing = check_by(checks, "notice.third_party_sharing")
        assert sharing.satisfied
        assert "negative" in sharing.evidence
        assert sharing.requires_human_validation, "a negative disclosure is exactly what a later stage should test"
        assert sharing.quote and sharing.quote in NEGATION

    def test_a_refusal_to_transfer_satisfies_the_cross_border_disclosure(self):
        checks, _ = analyzer.analyse([document(NEGATION)])
        assert check_by(checks, "notice.cross_border").satisfied

    def test_a_childrens_disclaimer_is_not_a_childrens_procedure(self):
        """"We do not knowingly collect from children" tells a Data Principal
        nothing about the verifiable parental consent section 9 requires."""
        checks, _ = analyzer.analyse([document(NEGATION)])
        children = check_by(checks, "notice.children")
        assert not children.satisfied
        assert "disclaimer" in children.evidence
        assert children.quote and children.quote in NEGATION
        assert children.requires_human_validation

    def test_a_limited_negation_is_still_a_retention_period(self):
        checks, claims = analyzer.analyse([document(NEGATION)])
        assert check_by(checks, "notice.retention_period").satisfied
        assert any(c.value == "90 days" for c in claims if c.claim_type == "retention")

    def test_a_route_inside_a_conditional_is_not_a_refusal_to_offer_one(self):
        checks, _ = analyzer.analyse([document(NEGATION)])
        assert check_by(checks, "notice.complain_to_board").satisfied

    def test_a_flat_refusal_to_share_becomes_a_testable_claim(self):
        _, claims = analyzer.analyse([document(NEGATION)])
        refusals = [c for c in claims if c.subject == "no onward sharing"]
        assert refusals and refusals[0].value == "none"
        assert refusals[0].quote in NEGATION


class TestFalsePositiveDiscipline:
    """Every case here is a marker that matched something which was never a
    statement about personal data."""

    def test_a_board_of_directors_is_not_the_data_protection_board(self):
        text = (
            "Corporate Governance\n"
            "Our board of directors reviews company strategy every quarter. "
            "The board of directors met in March and approved the annual accounts. "
            "We collect your name and email address to operate your account here."
        )
        checks, _ = analyzer.analyse([document(text)])
        assert not check_by(checks, "notice.complain_to_board").satisfied

    def test_a_minor_amendment_is_not_a_child(self):
        text = (
            "We may make minor changes to this policy from time to time. "
            "A minor amendment will not be announced separately. "
            "We collect your name and email address in order to operate the service."
        )
        checks, _ = analyzer.analyse([document(text)])
        assert not check_by(checks, "notice.children").satisfied

    def test_a_share_this_article_button_is_not_a_data_disclosure(self):
        text = (
            "Share this article with your friends using the share button below. "
            "Social sharing is available on every page of this website today. "
            "We collect your name and email address in order to operate the service."
        )
        checks, _ = analyzer.analyse([document(text)])
        assert not check_by(checks, "notice.third_party_sharing").satisfied

    def test_all_rights_reserved_is_not_a_data_principal_right(self):
        text = (
            "Copyright 2026 ShopHub. All rights reserved. "
            "We reserve the right to change these terms at any time we choose. "
            "We collect your name and email address in order to operate the service."
        )
        checks, _ = analyzer.analyse([document(text)])
        assert not check_by(checks, "notice.exercise_rights").satisfied

    def test_usage_measurement_is_not_a_transfer_to_the_united_states(self):
        """Found by reading output: a substring match put "usa" inside "usage"
        and a sentence about analytics became a cross-border transfer claim."""
        text = (
            "We process your personal data for usage measurement and usage analytics. "
            "All processing takes place on servers located in Mumbai, India."
        )
        _, claims = analyzer.analyse([document(text)])
        assert not [c for c in claims if c.value == "United States"]

    def test_a_purpose_is_not_a_contact_point(self):
        text = (
            "We use your personal data to provide customer support and to keep our "
            "support team informed about your order status at all times."
        )
        checks, claims = analyzer.analyse([document(text)])
        assert not check_by(checks, "notice.contact_point").satisfied
        assert not [c for c in claims if c.claim_type == "contact"]


class TestAnUnreadableNoticeIsNotASilentOne:
    """A policy that could not be read is not a policy that says nothing, and
    the two must not collapse into the same finding."""

    def test_an_unreachable_notice_leaves_its_requirements_unassessed(self):
        docs = [document(None, reachable=False)]
        checks, _ = analyzer.analyse(docs)
        assert len(analyzer.unassessed_checks(checks)) == len(REQUIREMENTS)
        assert not analyzer.gap_checks(checks)
        assert all(analyzer.is_unassessed(c) for c in checks)

    def test_an_unassessed_check_says_why_and_carries_no_confidence(self):
        checks, _ = analyzer.analyse([document(None, reachable=False)])
        check = check_by(checks, "notice.retention_period")
        assert check.evidence.startswith(analyzer.UNASSESSED_PREFIX)
        assert "could not be fetched" in check.evidence
        assert check.confidence == 0.0
        assert check.requires_human_validation

    def test_an_empty_body_is_unassessed_rather_than_a_failure(self):
        checks, _ = analyzer.analyse([document("", reachable=True)])
        assert len(analyzer.unassessed_checks(checks)) == len(REQUIREMENTS)

    def test_a_notice_too_thin_to_be_a_document_is_distinguished_from_a_missing_one(self):
        stub = document("Privacy Policy. Coming soon.", reachable=False)
        checks, _ = analyzer.analyse([stub])
        assert "could not be fetched" in check_by(checks, "notice.itemised_data").evidence

        checks, _ = analyzer.analyse([])
        assert "no privacy document was found" in check_by(checks, "notice.itemised_data").evidence

    def test_no_documents_at_all_still_produces_every_check(self):
        checks, claims = analyzer.analyse([])
        assert len(checks) == len(REQUIREMENTS)
        assert not claims

    def test_a_readable_notice_is_assessed_even_when_the_cookie_notice_is_not(self):
        docs = [document(WELL_DRAFTED), document(None, kind="cookie", reachable=False)]
        checks, _ = analyzer.analyse(docs)
        assert check_by(checks, "notice.itemised_data").satisfied
        # withdraw_consent applies to both kinds and the notice covers it, so it
        # is assessed rather than held back by the unreadable cookie page.
        assert check_by(checks, "notice.withdraw_consent").satisfied

    def test_missing_kinds_counts_unreadable_as_missing_text(self):
        docs = [document(WELL_DRAFTED), document(None, kind="cookie", reachable=False)]
        assert analyzer.missing_kinds(docs) == ["cookie", "grievance"]


# -------------------------------------------------------------------- the claims


class TestRetentionClaims:
    def test_a_numeric_period_is_normalised_and_quoted_verbatim(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        retention = [c for c in claims if c.claim_type == "retention"]
        values = {c.value for c in retention}
        assert "90 days" in values
        assert "7 years" in values, "a period written in words must normalise too"
        for claim in retention:
            assert claim.quote in WELL_DRAFTED, claim.quote

    def test_the_category_comes_from_beside_the_period_not_the_sentence(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        by_value = {c.value: c.subject for c in claims if c.claim_type == "retention"}
        assert by_value["90 days"] == "account data"
        assert by_value["7 years"] == "transaction records"

    def test_an_unquantified_promise_is_still_recorded_with_no_value(self):
        text = (
            "We retain your personal data for as long as is necessary to provide the "
            "service to you and for no other purpose whatsoever."
        )
        _, claims = analyzer.analyse([document(text)])
        retention = [c for c in claims if c.claim_type == "retention"]
        assert retention and retention[0].value is None
        assert retention[0].confidence < 0.8

    def test_a_response_deadline_is_not_a_retention_period(self):
        text = (
            "We will respond to your access request within 30 days of receiving it, "
            "and we will keep you informed while we do so."
        )
        _, claims = analyzer.analyse([document(text)])
        assert not [c for c in claims if c.claim_type == "retention"]
        assert [c for c in claims if c.subject == "response timeline"]

    def test_a_breach_deadline_is_not_a_retention_period(self):
        text = (
            "In the event of a personal data breach we will store the incident record "
            "and notify the Data Protection Board within 72 hours of becoming aware."
        )
        _, claims = analyzer.analyse([document(text)])
        assert not [c for c in claims if c.claim_type == "retention"]
        timelines = [c for c in claims if c.subject == "notification timeline"]
        assert timelines and timelines[0].value == "72 hours"


class TestThirdPartyClaims:
    def test_known_processors_are_named_with_a_verbatim_quote(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        named = {c.value for c in claims if c.subject == "named recipient"}
        assert "Razorpay" in named
        assert "Google Analytics" in named
        for claim in claims:
            assert claim.quote in WELL_DRAFTED

    def test_a_company_with_a_corporate_suffix_is_recognised(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        named = {c.value for c in claims if c.subject == "named recipient"}
        assert any("Bluedart" in n for n in named), named

    def test_an_ordinary_capitalised_word_is_not_a_recipient(self):
        text = (
            "We share your personal data with our processors. The Data Protection "
            "Board of India may also require disclosure under Section 36 of the Act."
        )
        _, claims = analyzer.analyse([document(text)])
        named = {c.value for c in claims if c.subject == "named recipient"}
        assert not named, named

    def test_a_right_is_not_an_organisation(self):
        """Found on a live notice: "the right to Object" ends in "to", so the
        introducer test alone recorded Object as a company."""
        text = (
            "Right to Withdraw Consent: If we rely on your consent to process "
            "personal data, you have the right to withdraw that consent. "
            "Right to Object to or Restrict Processing: you may object to it."
        )
        _, claims = analyzer.analyse([document(text)])
        named = {c.value for c in claims if c.subject == "named recipient"}
        assert not named, named

    def test_a_footer_that_lost_its_separators_is_not_a_list_of_recipients(self):
        text = (
            "Home Our Story Our Products Our Solutions Blogs Legal Glossary "
            "Contact Us Terms and Conditions Privacy Policy Manage Consent"
        )
        _, claims = analyzer.analyse([document(text)])
        assert not [c for c in claims if c.subject == "named recipient"]

    def test_the_site_is_not_a_recipient_of_its_own_data(self):
        text = (
            "In cases where you engage with Redacto through a partner, we share "
            "your personal data with Redacto.io for account provisioning."
        )
        _, claims = analyzer.analyse(
            [document(text, url="https://www.redacto.ai/en-in/privacy-policy")]
        )
        named = {c.value for c in claims if c.subject == "named recipient"}
        assert not any("Redacto" in n for n in named), named

    def test_named_recipients_are_capped_per_document(self):
        vendors = " ".join(
            f"We share your personal data with Vendor{i} Technologies Ltd for hosting."
            for i in range(120)
        )
        _, claims = analyzer.analyse([document(vendors)])
        named = [c for c in claims if c.subject == "named recipient"]
        assert len(named) <= analyzer._MAX_NAMED_PARTIES


class TestOtherClaimTypes:
    def test_rights_offered_are_extracted_by_name(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        rights = {c.value for c in claims if c.claim_type == "rights"}
        assert {"access", "correction", "erasure", "nomination"} <= rights

    def test_cross_border_destinations_are_named(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        destinations = {c.value for c in claims if c.subject == "destination"}
        assert {"Singapore", "United States"} <= destinations

    def test_a_jurisdiction_is_not_a_transfer_destination(self):
        """Found on a live notice: naming the law that applies to a reader in the
        European Union became a claim that data is transferred there."""
        text = (
            "Depending on your jurisdiction, including under the General Data "
            "Protection Regulation in the European Union and the Digital Personal "
            "Data Protection Act in India, you have the rights set out below."
        )
        _, claims = analyzer.analyse([document(text)])
        assert not [c for c in claims if c.claim_type == "cross_border"]

    def test_a_real_transfer_is_still_read(self):
        text = (
            "Your personal data is transferred to and stored on servers located in "
            "the European Union and in Singapore for redundancy."
        )
        _, claims = analyzer.analyse([document(text)])
        destinations = {c.value for c in claims if c.subject == "destination"}
        assert {"European Union", "Singapore"} <= destinations

    def test_a_contact_point_is_recorded_as_a_channel_never_as_an_address(self):
        """Rule 9 asks for a published contact, not for this tool to keep a copy
        of it. The channel is the testable part; the address is not ours."""
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        contacts = [c for c in claims if c.claim_type == "contact"]
        assert contacts
        assert any(c.value and "email" in c.value for c in contacts)
        for claim in claims:
            assert "@" not in claim.quote, claim.quote
            assert "grievance@shophub.example" not in str(claim.value)

    def test_a_childrens_age_threshold_is_normalised(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        ages = {c.value for c in claims if c.subject == "age threshold"}
        assert "under 18" in ages

    def test_security_controls_are_named(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        controls = {c.value for c in claims if c.claim_type == "security"}
        assert "AES-256" in controls
        assert "encryption at rest" in controls

    def test_every_claim_type_the_stage_promises_is_reachable(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        kinds = {c.claim_type for c in claims}
        assert {
            "retention", "third_party", "rights", "cross_border", "contact", "children"
        } <= kinds


class TestClaimHygiene:
    def test_no_claim_is_left_looking_verified(self):
        """None means nobody has looked, which is not the same as looked and
        found nothing. Collapsing the two turns an unrun check into a pass."""
        _, claims = analyzer.analyse([document(WELL_DRAFTED)])
        assert claims
        for claim in claims:
            assert claim.verified_by is None
            assert claim.verification is None
            assert claim.verification_detail is None

    def test_every_quote_is_a_contiguous_substring_of_its_source(self):
        for text in (WELL_DRAFTED, NEGATION, THIN, LEGALESE):
            checks, claims = analyzer.analyse([document(text)])
            for claim in claims:
                assert claim.quote in text, claim.quote
            for check in checks:
                if check.quote:
                    assert check.quote in text, check.quote

    def test_no_quote_carries_a_contact_value(self):
        text = (
            "Write to our Data Protection Officer at dpo@shophub.example or call us "
            "on +91 98200 11223 to exercise your right to erasure of personal data."
        )
        checks, claims = analyzer.analyse([document(text)])
        for quote in [c.quote for c in claims] + [c.quote for c in checks if c.quote]:
            assert "@" not in quote, quote
            assert "98200" not in quote, quote

    def test_claims_are_only_read_from_documents_that_could_be_read(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED, reachable=False)])
        assert not claims

    def test_claims_are_not_read_from_a_terms_of_service(self):
        _, claims = analyzer.analyse([document(WELL_DRAFTED, kind="terms")])
        assert not claims

    def test_duplicate_claims_collapse(self):
        repeated = (WELL_DRAFTED + "\n") * 3
        _, once = analyzer.analyse([document(WELL_DRAFTED)])
        _, thrice = analyzer.analyse([document(repeated)])
        assert len(thrice) == len(once)


class TestReadability:
    def test_legalese_is_read_as_not_plain_language(self):
        checks, _ = analyzer.analyse([document(LEGALESE)])
        plain = check_by(checks, "notice.plain_language")
        assert not plain.satisfied
        assert "legalese" in plain.evidence or "average" in plain.evidence
        assert plain.requires_human_validation

    def test_the_three_measures_are_reported(self):
        stats = analyzer.readability(analyzer.sentences_of(document(LEGALESE)))
        assert stats["avg_words"] > analyzer._MAX_AVG_SENTENCE_WORDS
        assert stats["legalese"] > analyzer._MAX_LEGALESE_PER_1000
        assert stats["clauses"] > 0

    def test_plain_prose_passes(self):
        checks, _ = analyzer.analyse([document(WELL_DRAFTED)])
        assert check_by(checks, "notice.plain_language").satisfied

    def test_a_notice_with_no_prose_to_judge_is_unassessed_not_failed(self):
        checks, _ = analyzer.analyse([document("Privacy | Terms | Cookies | Refunds " * 20)])
        plain = check_by(checks, "notice.plain_language")
        assert analyzer.is_unassessed(plain)


class TestTheAnalyserIsPure:
    def test_the_same_documents_give_the_same_answer(self):
        docs = [document(WELL_DRAFTED), document(NEGATION, kind="cookie")]
        first = analyzer.analyse(docs)
        second = analyzer.analyse(docs)
        assert [(c.requirement_id, c.satisfied, c.confidence) for c in first[0]] == [
            (c.requirement_id, c.satisfied, c.confidence) for c in second[0]
        ]
        assert [(c.claim_type, c.subject, c.value) for c in first[1]] == [
            (c.claim_type, c.subject, c.value) for c in second[1]
        ]

    def test_the_analyser_module_reaches_no_network_and_no_clock(self):
        """Purity is what lets a stored document be re-analysed later and give
        the same answer, so it is asserted rather than assumed."""
        imported = _imported_modules(analyzer.__file__)
        # urllib.parse is string work and is allowed. urllib.request is not.
        for forbidden in (
            "httpx", "requests", "socket", "urllib.request", "asyncio",
            "datetime", "time", "random", "secrets", "subprocess",
        ):
            assert forbidden not in imported, f"{forbidden} reached {imported}"

    def test_analysing_does_not_mutate_the_documents(self):
        doc = document(WELL_DRAFTED)
        before = (doc.body_text, doc.word_count, doc.reachable)
        analyzer.analyse([doc])
        assert (doc.body_text, doc.word_count, doc.reachable) == before


# ------------------------------------------------------------------ the fetching


def _transport(routes: dict[str, tuple[int, str]], *, default=(404, "")) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        status, body = routes.get(request.url.path, default)
        return httpx.Response(status, text=body, headers={"content-type": "text/html"})

    return httpx.MockTransport(handler)


@pytest.fixture
def offline(monkeypatch):
    """No DNS, no sockets. The guard is exercised in its own tests."""
    monkeypatch.setattr(policy_scanner, "validate_scan_url", lambda url: url)


class TestScanPolicies:
    async def test_a_linked_notice_is_found_fetched_and_read(self, offline):
        home = '<html><body><footer><a href="/privacy-policy">Privacy</a></footer></body></html>'
        transport = _transport(
            {
                "/": (200, home + "<p>" + "Welcome to ShopHub. " * 60 + "</p>"),
                "/privacy-policy": (200, f"<html><body>{WELL_DRAFTED}</body></html>"),
            }
        )
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        notice = next(d for d in result.documents if d.kind == "privacy" and d.reachable)
        assert notice.word_count > discovery.MIN_POLICY_WORDS
        assert notice.linked_from_homepage
        assert result.satisfied_checks
        assert result.claims_of("retention")
        assert not result.crawl_blocked

    async def test_an_unlinked_notice_is_still_found_by_probing(self, offline):
        transport = _transport(
            {
                "/": (200, "<html><body>" + "Welcome to ShopHub. " * 60 + "</body></html>"),
                "/privacy": (200, f"<html><body>{WELL_DRAFTED}</body></html>"),
            }
        )
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        notice = next(d for d in result.documents if d.kind == "privacy" and d.reachable)
        assert notice.discovered_via == "well_known_path"
        assert "privacy" not in result.missing_policies

    async def test_a_bot_wall_never_reads_as_a_site_that_publishes_nothing(self, offline):
        transport = _transport({}, default=(403, "Access denied. Cloudflare Ray ID: abc"))
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        assert result.crawl_blocked
        assert "not evidence that the site publishes none" in result.crawl_note
        assert not result.readable_documents
        assert len(analyzer.unassessed_checks(result.checks)) == len(REQUIREMENTS)
        assert not analyzer.gap_checks(result.checks)

    async def test_a_blocked_homepage_does_not_stop_the_probes(self, offline):
        """The homepage being walled says nothing about /privacy, and treating it
        as fatal would report a published notice as absent."""
        transport = _transport(
            {"/privacy": (200, f"<html><body>{WELL_DRAFTED}</body></html>")},
            default=(403, "Access denied"),
        )
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        assert result.crawl_blocked
        assert result.readable_documents
        assert result.satisfied_checks

    async def test_a_soft_404_serving_the_homepage_is_not_a_policy(self, offline):
        homepage = "<html><body>" + "Welcome to ShopHub, the best shop. " * 40 + "</body></html>"
        transport = _transport({}, default=(200, homepage))
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        assert not result.readable_documents
        assert result.missing_policies == list(EXPECTED_POLICY_KINDS)

    async def test_a_contact_page_only_counts_when_it_names_a_grievance_route(self, offline):
        sales = "<html><body>" + "Call our showroom between 10am and 7pm daily. " * 20 + "</body></html>"
        transport = _transport({"/contact": (200, sales)})
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        assert not [d for d in result.documents if d.url.endswith("/contact")]

    async def test_the_note_is_honest_when_nothing_could_be_read(self, offline):
        transport = _transport({"/": (200, "<html><body>" + "Shop now. " * 60 + "</body></html>")})
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        assert not result.crawl_blocked
        assert "rendered entirely in the browser" in result.crawl_note

    async def test_a_redirect_is_followed_and_revalidated(self, offline):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/privacy":
                return httpx.Response(301, headers={"location": "/legal/privacy"})
            if request.url.path == "/legal/privacy":
                return httpx.Response(
                    200, text=WELL_DRAFTED, headers={"content-type": "text/html"}
                )
            return httpx.Response(404, text="")

        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=httpx.MockTransport(handler)
        )
        assert [d for d in result.documents if d.reachable and d.kind == "privacy"]

    async def test_the_stage_stays_a_light_fetch(self):
        """Trackers, cookies and consent banners are stage 2's job. A light
        fetch that guessed at them would guess worse than a browser."""
        imported = _imported_modules(policy_scanner.__file__)
        assert "playwright" not in imported, imported
        assert "playwright.async_api" not in imported

    async def test_the_result_carries_no_stage_two_evidence(self, offline):
        transport = _transport(
            {"/privacy": (200, f"<html><body>{WELL_DRAFTED}</body></html>")}
        )
        result = await policy_scanner.scan_policies(
            "https://shophub.example/", transport=transport
        )
        assert not hasattr(result, "cookies")
        assert not hasattr(result, "network_requests")
        assert not hasattr(result, "consent_banner")
