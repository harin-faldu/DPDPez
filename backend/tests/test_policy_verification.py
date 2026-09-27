"""Stage 2 testing stage 1's claims.

The payoff of running the stages in order. A notice promising no third party
sharing, on a page that loaded trackers before anyone consented, is a finding
neither stage produces alone.

The rule that matters most here is what counts as a contradiction. Not seeing
something is not evidence it is absent: a processor reached from the server
never touches the page, and a rights path behind a sign in is invisible to a
crawl. Those are not_observable, and the code stage answers them. Calling them
contradictions would manufacture findings out of the scanner's own blind spots.
"""

from app.contracts import (
    FormField,
    NetworkRequest,
    PolicyClaim,
    WebScanResult,
)
from app.policy import verification as v


def claim(claim_type: str, subject: str, value: str | None = None) -> PolicyClaim:
    return PolicyClaim(
        claim_type=claim_type,
        subject=subject,
        value=value,
        quote="a verbatim sentence from the notice",
        source_url="https://example.test/privacy",
    )


def tracker(host: str) -> NetworkRequest:
    return NetworkRequest(
        url=f"https://{host}/collect",
        host=host,
        resource_type="beacon",
        is_third_party=True,
        before_consent=True,
        tracker_category="analytics",
    )


def web(**kw) -> WebScanResult:
    kw.setdefault("entry_url", "https://example.test")
    kw.setdefault("served_over_https", True)
    return WebScanResult(**kw)


class TestNoSharingClaim:
    def test_a_tracker_before_consent_contradicts_a_no_sharing_promise(self):
        result = v.verify_against_web(
            [claim("third_party", "no onward sharing", "none")],
            web(network_requests=[tracker("www.google-analytics.com")]),
        )[0]
        assert result.verification == v.CONTRADICTED
        assert "google-analytics" in result.verification_detail

    def test_a_clean_page_supports_a_no_sharing_promise(self):
        result = v.verify_against_web(
            [claim("third_party", "no onward sharing", "none")], web()
        )[0]
        assert result.verification == v.SUPPORTED

    def test_the_verdict_is_attributed_to_this_stage(self):
        result = v.verify_against_web(
            [claim("third_party", "no onward sharing", "none")], web()
        )[0]
        assert result.verified_by == v.WEB


class TestNamedRecipient:
    def test_a_disclosed_recipient_seen_on_the_page_is_supported(self):
        result = v.verify_against_web(
            [claim("third_party", "named recipient", "LinkedIn")],
            web(network_requests=[tracker("snap.licdn.com")]),
        )[0]
        assert result.verification == v.SUPPORTED

    def test_a_recipient_not_seen_is_unobservable_rather_than_contradicted(self):
        """A processor reached from the server never touches the page.

        Reporting silence as a contradiction would invent a finding out of this
        scanner's own blind spot.
        """
        result = v.verify_against_web(
            [claim("third_party", "named recipient", "Some Payment Processor")], web()
        )[0]
        assert result.verification == v.NOT_OBSERVABLE

    def test_corporate_furniture_does_not_match_every_host(self):
        # "Private Limited" identifies nobody; matching on it would tie any
        # Indian company to any host on the page.
        assert v._hosts_matching("VertexTech Labs Private Limited", ["snap.licdn.com"]) == []

    def test_a_brand_matches_the_domain_it_actually_serves_from(self):
        assert v._hosts_matching("LinkedIn", ["snap.licdn.com"]) == ["snap.licdn.com"]
        assert v._hosts_matching("HubSpot", ["js-na2.hs-scripts.com"])


class TestThingsThisStageCannotSee:
    def test_retention_is_never_judged_from_a_page_load(self):
        result = v.verify_against_web([claim("retention", "account data", "90 days")], web())[0]
        assert result.verification == v.NOT_OBSERVABLE
        assert "code scan" in result.verification_detail

    def test_breach_and_cross_border_are_left_to_a_later_stage(self):
        results = v.verify_against_web(
            [claim("breach", "intimation"), claim("cross_border", "transfer", "Ireland")],
            web(),
        )
        assert {r.verification for r in results} == {v.NOT_OBSERVABLE}

    def test_a_rights_path_behind_a_sign_in_is_not_a_broken_promise(self):
        result = v.verify_against_web([claim("rights", "right to erasure", "erasure")], web())[0]
        assert result.verification == v.NOT_OBSERVABLE

    def test_a_linked_rights_path_supports_the_promise(self):
        result = v.verify_against_web(
            [claim("rights", "right to erasure", "erasure")],
            web(rights_links=["https://example.test/delete-account"]),
        )[0]
        assert result.verification == v.SUPPORTED


class TestAgeCondition:
    def test_an_age_condition_with_no_age_field_is_contradicted(self):
        result = v.verify_against_web([claim("children", "age condition", "18")], web())[0]
        assert result.verification == v.CONTRADICTED

    def test_an_age_field_supports_the_condition(self):
        result = v.verify_against_web(
            [claim("children", "age condition", "18")],
            web(age_gate_fields=[FormField(name="date_of_birth", input_type="date")]),
        )[0]
        assert result.verification == v.SUPPORTED


class TestEncryptionClaim:
    def test_plain_http_contradicts_an_encryption_claim(self):
        result = v.verify_against_web(
            [claim("security", "encryption in transit", "encrypted")],
            web(served_over_https=False),
        )[0]
        assert result.verification == v.CONTRADICTED

    def test_https_does_not_prove_a_claim_about_stored_data(self):
        result = v.verify_against_web(
            [claim("security", "encryption at rest", "encrypted")], web()
        )[0]
        assert result.verification == v.NOT_OBSERVABLE


class TestBlockedCrawlProducesNoFindings:
    def test_a_blocked_crawl_contradicts_nothing(self):
        """Someone else's bot wall is not a finding against the site."""
        claims = [
            claim("third_party", "no onward sharing", "none"),
            claim("children", "age condition", "18"),
            claim("contact", "grievance channel"),
        ]
        results = v.verify_against_web(
            claims, web(crawl_blocked=True, crawl_note="answered HTTP 403")
        )
        assert v.contradictions(results) == []
        assert {r.verification for r in results} == {v.NOT_OBSERVABLE}


class TestUntestedStaysUntested:
    def test_no_web_evidence_leaves_the_verdict_unset(self):
        """None means nobody looked, which is not the same as found nothing."""
        results = v.verify_against_web([claim("third_party", "no onward sharing", "none")], None)
        assert results[0].verification is None
        assert results[0].verified_by is None

    def test_the_original_claim_is_not_mutated(self):
        original = claim("third_party", "no onward sharing", "none")
        v.verify_against_web([original], web(network_requests=[tracker("x.test")]))
        assert original.verification is None


class TestAgeClaimShapes:
    """An active condition and a passive disclaimer fail for different reasons.

    A real notice carried all three of "must be 18", "do not knowingly collect
    from under 16" and "do not knowingly collect from under 13", on a site with
    no age field anywhere.
    """

    def test_a_passive_disclaimer_is_answered_on_its_own_terms(self):
        passive = PolicyClaim(
            claim_type="children",
            subject="age condition",
            value="under 13",
            quote="We do not knowingly collect personal information from individuals under 13.",
            source_url="https://example.test/privacy",
        )
        result = v.verify_against_web([passive], web())[0]
        assert result.verification == v.CONTRADICTED
        assert "knowingly" in result.verification_detail
        assert "s.9" in result.verification_detail

    def test_an_active_condition_is_answered_as_unenforced(self):
        active = PolicyClaim(
            claim_type="children",
            subject="age condition",
            value="18",
            quote="The Services are intended for individuals who are 18 years of age or older.",
            source_url="https://example.test/privacy",
        )
        result = v.verify_against_web([active], web())[0]
        assert result.verification == v.CONTRADICTED
        assert "knowingly" not in result.verification_detail

    def test_an_age_field_supports_either_shape(self):
        for quote in (
            "We do not knowingly collect from under 13.",
            "You must be 18 to use the Services.",
        ):
            claim_ = PolicyClaim(
                claim_type="children", subject="age condition", value="x",
                quote=quote, source_url="u",
            )
            result = v.verify_against_web(
                [claim_], web(age_gate_fields=[FormField(name="dob", input_type="date")])
            )[0]
            assert result.verification == v.SUPPORTED
