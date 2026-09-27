"""The three things the URL and host evidence on its own cannot see.

1. CNAME cloaking. A tracker served from the site's own subdomain, whose DNS
   chain ends at a third party. The registrable domain says first party, so
   without the chain the request leaves the third party and pre-consent
   evidence altogether.
2. Server-side tagging. A first party endpoint that receives measurement
   traffic and forwards it onward from the server, where no browser can follow.
   It cannot be fixed, so it has to be disclosed.
3. Request payloads. A beacon carrying an email address reads as "a beacon was
   sent" until the body is inspected.

No test here touches DNS or the network. The resolver is injected and stubbed,
and the one browser test runs against a local file with every http and https
request aborted at the route layer.
"""

import asyncio
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

from app.contracts import NetworkRequest, PageInfo, WebScanResult
from app.rules import evidence as ev
from app.rules import r04_consent
from app.scanner import cname, payload_pii, trackers, url_guard, web_scanner
from app.scanner.url_guard import same_site

ENTRY = "https://shophub.example/"

# A distinctive value used to prove it is never stored. It is fabricated for
# this suite and belongs to nobody.
SAMPLE_EMAIL = "rupa.desai@shoppers.example"
SAMPLE_MOBILE = "+919812345678"


def _request(
    url: str,
    *,
    resource_type: str = "beacon",
    method: str = "POST",
    before_consent: bool = True,
    **overrides,
) -> NetworkRequest:
    host = trackers.normalise_host(urlparse(url).hostname)
    return NetworkRequest(
        url=url,
        host=host,
        resource_type=resource_type,
        method=method,
        is_third_party=bool(host) and not same_site(url, ENTRY),
        before_consent=before_consent,
        tracker_category=trackers.classify_tracker(host),
        **overrides,
    )


def _result(requests: list[NetworkRequest], **overrides) -> WebScanResult:
    result = WebScanResult(
        entry_url=ENTRY,
        pages=[
            PageInfo(
                url=ENTRY,
                title="Shophub",
                status_code=200,
                text_content=(
                    "Shophub India sells household goods across nineteen thousand pin codes. "
                    "Browse the catalogue, add to your cart and pay on delivery or by UPI. "
                ) * 3,
            )
        ],
        network_requests=requests,
        **overrides,
    )
    result.server_side_tag_endpoints = web_scanner.detect_server_side_tagging(requests)
    return result


def _stub_resolver(chains: dict[str, list[str]], calls: list[str] | None = None):
    def resolve(host: str) -> list[str]:
        if calls is not None:
            calls.append(host)
        return list(chains.get(host, []))

    return resolve


# ------------------------------------------------------------- CNAME cloaking


class TestCNAMECloaking:
    def test_a_cloaked_subdomain_becomes_third_party_with_its_category(self):
        requests = [_request("https://metrics.shophub.example/collect?id=1")]
        assert requests[0].is_third_party is False

        cloaked = asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver(
                    {"metrics.shophub.example": ["c.eu.analytics.hotjar.com"]}
                ),
            )
        )

        assert cloaked == ["metrics.shophub.example"]
        assert requests[0].is_third_party is True
        assert requests[0].cname_cloaked is True
        assert requests[0].cname_target == "c.eu.analytics.hotjar.com"
        assert requests[0].tracker_category == "replay"
        assert requests[0].cname_chain == ["c.eu.analytics.hotjar.com"]

    def test_an_ordinary_subdomain_stays_first_party(self):
        requests = [_request("https://cdn.shophub.example/app.js", resource_type="script")]
        cloaked = asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver(
                    {"cdn.shophub.example": ["shophub-example.cdn-provider.example"]}
                ),
            )
        )
        assert cloaked == []
        assert requests[0].is_third_party is False
        assert requests[0].cname_cloaked is False
        assert requests[0].tracker_category is None
        # The chain is still recorded, so a reviewer sees what was checked
        # rather than only what was found.
        assert requests[0].cname_chain == ["shophub-example.cdn-provider.example"]

    def test_a_chain_that_stays_inside_the_organisation_is_not_cloaking(self):
        requests = [_request("https://metrics.shophub.example/collect")]
        asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver(
                    {"metrics.shophub.example": ["origin.shophub.example"]}
                ),
            )
        )
        assert requests[0].cname_cloaked is False
        assert requests[0].is_third_party is False

    def test_a_chain_ending_at_a_consent_platform_is_not_cloaking(self):
        """The script that draws the banner has to load before any choice
        exists, so a consent platform is never counted as a tracker."""
        requests = [_request("https://privacy.shophub.example/otSDKStub.js",
                             resource_type="script")]
        asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver({"privacy.shophub.example": ["cdn.cookielaw.org"]}),
            )
        )
        assert requests[0].cname_cloaked is False
        assert requests[0].is_third_party is False


class TestCNAMEFailureIsSilent:
    def test_a_resolver_that_raises_leaves_the_request_first_party(self):
        def explode(host: str) -> list[str]:
            raise OSError("no such host")

        requests = [_request("https://metrics.shophub.example/collect")]
        assert asyncio.run(cname.resolve_and_mark(requests, resolver=explode)) == []
        assert requests[0].cname_cloaked is False
        assert requests[0].is_third_party is False
        assert requests[0].cname_chain == []

    def test_a_resolver_that_never_answers_is_abandoned_not_waited_on(self):
        async def hang(host: str) -> list[str]:
            await asyncio.sleep(30)
            return ["c.eu.analytics.hotjar.com"]

        requests = [_request("https://metrics.shophub.example/collect")]
        loop = asyncio.new_event_loop()
        try:
            started = loop.time()
            cloaked = loop.run_until_complete(
                cname.resolve_and_mark(requests, resolver=hang, timeout=0.05)
            )
            elapsed = loop.time() - started
        finally:
            loop.close()
        assert cloaked == []
        assert requests[0].cname_cloaked is False
        assert elapsed < 5

    def test_an_empty_chain_is_not_a_finding(self):
        requests = [_request("https://metrics.shophub.example/collect")]
        asyncio.run(cname.resolve_and_mark(requests, resolver=_stub_resolver({})))
        assert requests[0].cname_cloaked is False
        assert requests[0].cname_chain == []

    def test_the_system_resolver_reconstructs_a_chain_without_touching_dns(self, monkeypatch):
        monkeypatch.setattr(
            cname.socket,
            "gethostbyname_ex",
            lambda host: (
                "c.eu.analytics.hotjar.com",
                ["metrics.shophub.example"],
                ["203.0.113.5"],
            ),
        )
        assert cname.system_resolver("metrics.shophub.example") == [
            "c.eu.analytics.hotjar.com"
        ]

    def test_a_lookup_error_from_the_system_resolver_is_an_empty_chain(self, monkeypatch):
        def boom(host: str):
            raise OSError("temporary failure in name resolution")

        monkeypatch.setattr(cname.socket, "gethostbyname_ex", boom)
        assert cname.system_resolver("metrics.shophub.example") == []


class TestCNAMECostControl:
    def test_only_measurement_shaped_resources_are_resolved(self):
        requests = [
            _request("https://img.shophub.example/logo.png", resource_type="image"),
            _request("https://fonts.shophub.example/a.woff2", resource_type="font"),
            _request("https://css.shophub.example/a.css", resource_type="stylesheet"),
            _request("https://metrics.shophub.example/collect", resource_type="beacon"),
            _request("https://api.shophub.example/v1/cart", resource_type="xhr"),
        ]
        assert cname.candidate_hosts(requests) == [
            "metrics.shophub.example",
            "api.shophub.example",
        ]

    def test_the_apex_is_never_resolved(self):
        """DNS cannot carry a CNAME at a zone apex, so resolving the one host
        every page contacts would spend the budget and learn nothing."""
        requests = [_request("https://shophub.example/collect", resource_type="xhr")]
        assert cname.candidate_hosts(requests) == []

    def test_third_party_hosts_are_not_resolved(self):
        requests = [_request("https://www.google-analytics.com/g/collect")]
        assert cname.candidate_hosts(requests) == []

    def test_the_number_of_lookups_is_capped(self):
        requests = [
            _request(f"https://n{i}.shophub.example/collect") for i in range(40)
        ]
        assert len(cname.candidate_hosts(requests)) == cname.MAX_CNAME_LOOKUPS
        assert cname.MAX_CNAME_LOOKUPS <= 20

    def test_each_host_is_resolved_once_per_scan(self):
        calls: list[str] = []
        requests = [
            _request("https://metrics.shophub.example/collect?n=1"),
            _request("https://metrics.shophub.example/collect?n=2"),
            _request("https://metrics.shophub.example/collect?n=3"),
        ]
        asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver(
                    {"metrics.shophub.example": ["c.eu.analytics.hotjar.com"]}, calls
                ),
            )
        )
        assert calls == ["metrics.shophub.example"]
        # One lookup, but every request on that host carries the result.
        assert all(r.cname_cloaked for r in requests)

    def test_the_lookup_budget_is_bounded_in_time_and_concurrency(self):
        assert 0 < cname.CNAME_TIMEOUT_SECONDS <= 5
        assert 1 < cname.CNAME_LOOKUP_CONCURRENCY <= 10

    def test_the_scan_entry_point_accepts_an_injected_resolver(self):
        import inspect

        assert "dns_resolver" in inspect.signature(web_scanner.scan_url).parameters


class TestCloakingReachesTheEvidence:
    def _cloaked_result(self) -> WebScanResult:
        requests = [_request("https://metrics.shophub.example/collect")]
        asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver(
                    {"metrics.shophub.example": ["c.eu.analytics.hotjar.com"]}
                ),
            )
        )
        return _result(requests)

    def test_the_result_exposes_the_cloaked_hosts(self):
        assert self._cloaked_result().cloaked_hosts == ["metrics.shophub.example"]

    def test_the_request_reaches_the_pre_consent_signal(self):
        result = self._cloaked_result()
        assert [r.host for r in result.trackers_before_consent] == [
            "metrics.shophub.example"
        ]
        assert result.third_party_hosts == ["metrics.shophub.example"]

    def test_the_finding_says_first_party_in_name_and_names_the_target(self):
        verdict = r04_consent.check(web_result=self._cloaked_result())
        assert "first party in name" in verdict.evidence
        assert "c.eu.analytics.hotjar.com" in verdict.evidence
        assert "metrics.shophub.example" in verdict.evidence

    def test_a_cloaked_tracker_before_consent_is_still_graded_as_one(self):
        verdict = r04_consent.check(web_result=self._cloaked_result())
        assert verdict.bright_line_reason
        assert "resolving to c.eu.analytics.hotjar.com" in verdict.bright_line_reason

    def test_the_note_explains_why_a_first_party_url_was_counted(self):
        note = ev.cname_cloaking_note(self._cloaked_result())
        assert "resolve by CNAME to a third party tracker" in note
        assert "metrics.shophub.example resolves to c.eu.analytics.hotjar.com" in note

    def test_nothing_is_claimed_when_no_host_is_cloaked(self):
        result = _result([_request("https://cdn.shophub.example/app.js",
                                   resource_type="script")])
        assert result.cloaked_hosts == []
        assert ev.cname_cloaking_note(result) is None


# -------------------------------------------------------- server-side tagging


class TestServerSideTagDetection:
    @pytest.mark.parametrize(
        "path",
        ["/g/collect", "/gtm", "/sgtm/collect", "/tr", "/events", "/collect", "/metrics"],
    )
    def test_a_measurement_shaped_first_party_path_is_recorded(self, path):
        endpoints = web_scanner.detect_server_side_tagging(
            [_request(f"https://shophub.example{path}", resource_type="xhr")]
        )
        assert len(endpoints) == 1
        assert endpoints[0].host == "shophub.example"
        assert endpoints[0].path == path
        assert endpoints[0].matched_on == "path"

    def test_a_measurement_shaped_payload_is_enough_on_its_own(self):
        request = _request("https://shophub.example/api/v3/ingest", resource_type="fetch")
        request.payload_captured = True
        request.payload_shape = "cid, tid"
        endpoints = web_scanner.detect_server_side_tagging([request])
        assert len(endpoints) == 1
        assert endpoints[0].matched_on == "payload"
        assert endpoints[0].marker == "cid, tid"

    def test_path_and_payload_together_are_reported_as_both(self):
        request = _request("https://shophub.example/g/collect", resource_type="fetch")
        request.payload_captured = True
        request.payload_shape = "cid, tid"
        endpoints = web_scanner.detect_server_side_tagging([request])
        assert endpoints[0].matched_on == "path and payload"
        assert "/g/collect carrying cid, tid" == endpoints[0].marker

    def test_repeat_requests_collapse_onto_one_endpoint(self):
        requests = [
            _request("https://shophub.example/g/collect?n=1", resource_type="fetch"),
            _request("https://shophub.example/g/collect?n=2", resource_type="fetch"),
            _request("https://shophub.example/g/collect?n=3", resource_type="fetch"),
        ]
        endpoints = web_scanner.detect_server_side_tagging(requests)
        assert len(endpoints) == 1
        assert endpoints[0].request_count == 3

    def test_a_third_party_endpoint_is_not_server_side_tagging(self):
        """The onward hop is visible there, so it is an ordinary third party
        finding rather than something this scan cannot follow."""
        assert web_scanner.detect_server_side_tagging(
            [_request("https://www.google-analytics.com/g/collect")]
        ) == []

    def test_a_cloaked_host_is_not_counted_twice(self):
        requests = [_request("https://metrics.shophub.example/collect")]
        asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver(
                    {"metrics.shophub.example": ["c.eu.analytics.hotjar.com"]}
                ),
            )
        )
        assert web_scanner.detect_server_side_tagging(requests) == []

    def test_an_ordinary_form_post_is_not_measurement_traffic(self):
        assert web_scanner.detect_server_side_tagging(
            [_request("https://shophub.example/signup", resource_type="xhr")]
        ) == []

    def test_a_path_that_merely_contains_the_word_is_not_a_match(self):
        assert trackers.server_side_tag_marker("/past-events/2025") is None
        assert trackers.server_side_tag_marker("/collectibles") is None
        assert trackers.server_side_tag_marker("/g/collect") == "/g/collect"
        assert trackers.server_side_tag_marker("/api/metrics") == "/metrics"

    def test_a_plain_get_that_is_not_a_beacon_is_not_counted(self):
        assert web_scanner.detect_server_side_tagging(
            [_request("https://shophub.example/events", method="GET", resource_type="document")]
        ) == []

    def test_one_stray_measurement_parameter_is_not_a_beacon_payload(self):
        assert trackers.beacon_payload_marker(["tid"]) is None
        assert trackers.beacon_payload_marker(["email", "password"]) is None
        assert trackers.beacon_payload_marker(["tid", "cid", "en"]) == "cid, en, tid"


class TestServerSideTaggingIsDisclosed:
    def _tagged_result(self) -> WebScanResult:
        request = _request("https://shophub.example/g/collect", resource_type="fetch")
        request.payload_captured = True
        request.payload_shape = "cid, tid"
        return _result([request])

    def test_the_endpoint_is_recorded_on_the_result(self):
        result = self._tagged_result()
        assert len(result.server_side_tag_endpoints) == 1
        assert result.server_side_tag_endpoints[0].before_consent is True

    def test_the_wording_says_the_scan_cannot_follow_the_onward_hop(self):
        note = ev.server_side_tagging_note(self._tagged_result())
        assert "server-side path that this scan cannot follow" in note
        assert "out of reach of any browser based scanner" in note

    def test_the_wording_forbids_reading_silence_as_a_clean_result(self):
        note = ev.server_side_tagging_note(self._tagged_result())
        assert (
            "absence of a third party request for these events is therefore not evidence "
            "that no third party received them" in note
        )

    def test_no_destination_is_invented(self):
        """The onward hop is not observable, so nothing may name a recipient."""
        note = ev.server_side_tagging_note(self._tagged_result())
        for invented in ("google", "meta", "facebook", "forwarded to "):
            assert invented not in note.lower()

    def test_the_disclosure_reaches_the_consent_verdict(self):
        verdict = r04_consent.check(web_result=self._tagged_result())
        assert "this scan cannot follow" in verdict.evidence

    def test_a_site_with_no_such_endpoint_says_nothing(self):
        result = _result([_request("https://shophub.example/signup", resource_type="xhr")])
        assert result.server_side_tag_endpoints == []
        assert ev.server_side_tagging_note(result) is None


# ------------------------------------------------------------ payload capture


class TestPayloadClassification:
    def test_an_email_in_a_form_encoded_beacon_is_found(self):
        findings = payload_pii.scan_payload(
            f"v=2&tid=G-TEST&cid=1.2&en=purchase&em={SAMPLE_EMAIL.replace('@', '%40')}"
        )
        assert "email" in [f.pii_category for f in findings]

    def test_a_nested_json_payload_is_taken_apart(self):
        findings = payload_pii.scan_payload(
            '{"pixel_id":"1","event_name":"Purchase","event_time":1730000000,'
            f'"user_data":{{"email_address":"{SAMPLE_EMAIL}","ct":"Ahmedabad"}}}}'
        )
        categories = [f.pii_category for f in findings]
        assert "email" in categories
        assert "address" in categories

    def test_a_field_name_and_a_value_are_told_apart(self):
        findings = payload_pii.scan_payload(f"tid=G-1&cid=2&full_name=Rupa&em={SAMPLE_EMAIL}")
        by_category = {f.pii_category: f for f in findings}
        assert by_category["name"].detected_via == "field_name"
        assert by_category["email"].detected_via in ("field_name", "value")

    def test_an_indian_mobile_is_found_by_its_value(self):
        findings = payload_pii.scan_payload(f"contact={SAMPLE_MOBILE}&tid=G-1&cid=2")
        assert "phone" in [f.pii_category for f in findings]

    def test_a_pan_is_found_by_its_format(self):
        findings = payload_pii.scan_payload("ref=ABCDE1234F&tid=G-1&cid=2")
        assert "pan" in [f.pii_category for f in findings]

    def test_an_ordinary_form_post_is_classified_from_its_names(self):
        findings = payload_pii.scan_payload("full_name=Rupa+Desai&mobile=9812345678")
        categories = {f.pii_category for f in findings}
        assert categories == {"name", "phone"}

    def test_the_occurrence_count_is_kept(self):
        findings = payload_pii.scan_payload(
            '{"a":{"email":"one@example.test"},"b":{"email":"two@example.test"}}'
        )
        email = next(f for f in findings if f.pii_category == "email")
        assert email.occurrences == 2

    def test_the_parameter_name_is_kept_as_the_hint(self):
        findings = payload_pii.scan_payload(f"user_data.em={SAMPLE_EMAIL}&tid=G-1&cid=2")
        email = next(f for f in findings if f.pii_category == "email")
        assert email.field_hint == "user_data.em"


class TestPayloadPrecision:
    def test_a_millisecond_timestamp_is_not_financial_data(self):
        """A thirteen digit epoch passes a Luhn check about one time in ten, so
        a bare run of digits is never treated as proof of anything."""
        for stamp in range(1730000000000, 1730000000040):
            findings = payload_pii.scan_payload(f"ts={stamp}&seq={stamp + 7}")
            assert findings == [], stamp

    def test_a_measurement_event_name_is_not_a_person(self):
        findings = payload_pii.scan_payload(
            '{"tid":"G-1","cid":"2","events":[{"name":"page_view"}]}'
        )
        assert [f.pii_category for f in findings] == []

    def test_a_page_title_in_a_beacon_is_not_a_person(self):
        findings = payload_pii.scan_payload(
            "v=2&tid=G-1&cid=2&dt=Shophub+India&dl=https%3A%2F%2Fa"
        )
        assert findings == []

    def test_a_bare_ten_digit_id_is_not_a_phone_number(self):
        findings = payload_pii.scan_payload("session=9812345678&request=6123456789")
        assert findings == []

    def test_an_empty_body_yields_nothing(self):
        assert payload_pii.scan_payload("") == []
        assert payload_pii.scan_payload(None) == []
        assert payload_pii.scan_payload("   ") == []

    def test_a_malformed_body_does_not_raise(self):
        assert payload_pii.scan_payload("{not json at all") == []
        assert payload_pii.scan_payload("\x00\x01\x02") == []


class TestNoRawValueIsEverStored:
    """The constraint this module exists under. A tool that audits how personal
    data is handled must not become another copy of that data."""

    def test_the_finding_holds_the_category_and_never_the_value(self):
        findings = payload_pii.scan_payload(
            f"em={SAMPLE_EMAIL}&ph={SAMPLE_MOBILE}&tid=G-1&cid=2"
        )
        assert findings
        blob = repr(findings)
        assert SAMPLE_EMAIL not in blob
        assert "rupa" not in blob.lower()
        assert SAMPLE_MOBILE not in blob
        assert "9812345678" not in blob

    def test_the_indicator_says_there_was_a_value_and_how_long_it_was(self):
        findings = payload_pii.scan_payload(f"email={SAMPLE_EMAIL}")
        email = next(f for f in findings if f.pii_category == "email")
        assert email.redacted == f"[redacted email, {len(SAMPLE_EMAIL)} character(s)]"

    def test_the_recorded_request_carries_no_body(self):
        record = _request("https://www.google-analytics.com/g/collect")
        recorder = web_scanner.NetworkRecorder(ENTRY)
        recorder.inspect_payload(
            _FakeRequest(f"em={SAMPLE_EMAIL}&tid=G-1&cid=2"), record
        )
        assert record.payload_captured is True
        assert record.payload_pii
        assert not hasattr(record, "post_data")
        assert SAMPLE_EMAIL not in repr(record)

    def test_the_verdict_text_never_quotes_the_value(self):
        record = _request("https://www.google-analytics.com/g/collect")
        web_scanner.NetworkRecorder(ENTRY).inspect_payload(
            _FakeRequest(f"em={SAMPLE_EMAIL}&ph={SAMPLE_MOBILE}&tid=G-1&cid=2"), record
        )
        verdict = r04_consent.check(web_result=_result([record]))
        assert "email" in verdict.evidence
        assert SAMPLE_EMAIL not in verdict.evidence
        assert "rupa" not in verdict.evidence.lower()
        assert SAMPLE_MOBILE not in verdict.evidence

    def test_no_body_is_written_to_the_log(self, caplog):
        record = _request("https://www.google-analytics.com/g/collect")
        with caplog.at_level(logging.DEBUG):
            web_scanner.NetworkRecorder(ENTRY).inspect_payload(
                _FakeRequest(f"em={SAMPLE_EMAIL}&tid=G-1&cid=2"), record
            )
        assert SAMPLE_EMAIL not in caplog.text

    def test_the_stored_size_is_capped(self):
        assert web_scanner.MAX_PAYLOAD_BYTES <= 16384
        assert web_scanner.MAX_PAYLOADS_INSPECTED <= 250
        assert payload_pii.MAX_PAYLOAD_SCAN_CHARS <= web_scanner.MAX_PAYLOAD_BYTES


class _FakeRequest:
    """Stands in for a Playwright request, which is never constructed here."""

    def __init__(self, post_data: str | None) -> None:
        self.post_data = post_data


class TestPayloadCaptureRules:
    def test_a_get_with_no_body_is_skipped(self):
        record = _request("https://www.google-analytics.com/collect", method="GET",
                          resource_type="image")
        web_scanner.NetworkRecorder(ENTRY).inspect_payload(_FakeRequest(None), record)
        assert record.payload_captured is False

    def test_a_first_party_post_is_inspected_too(self):
        """A cloaked host is not known to be third party until after the crawl,
        and a server-side tagging endpoint is only recognisable from what it
        receives, so first party bodies cannot be skipped."""
        record = _request("https://shophub.example/g/collect", resource_type="fetch")
        web_scanner.NetworkRecorder(ENTRY).inspect_payload(
            _FakeRequest("v=2&tid=G-1&cid=2&en=page_view"), record
        )
        assert record.payload_captured is True
        assert record.payload_shape

    def test_the_number_of_bodies_read_is_capped(self):
        recorder = web_scanner.NetworkRecorder(ENTRY, payload_limit=2)
        records = [
            _request(f"https://www.google-analytics.com/g/collect?n={i}") for i in range(5)
        ]
        for record in records:
            recorder.inspect_payload(_FakeRequest("tid=G-1&cid=2"), record)
        assert [r.payload_captured for r in records] == [True, True, False, False, False]

    def test_a_request_that_cannot_hand_over_its_body_is_skipped(self):
        class Detached:
            @property
            def post_data(self):
                raise RuntimeError("target closed")

        record = _request("https://www.google-analytics.com/g/collect")
        web_scanner.NetworkRecorder(ENTRY).inspect_payload(Detached(), record)
        assert record.payload_captured is False


class TestPayloadReachesTheEvidence:
    def _result_with_payload(self, body: str) -> WebScanResult:
        record = _request("https://www.google-analytics.com/g/collect")
        web_scanner.NetworkRecorder(ENTRY).inspect_payload(_FakeRequest(body), record)
        return _result([record])

    def test_a_third_party_body_carrying_personal_data_fails_the_check(self):
        verdict = r04_consent.check(
            web_result=self._result_with_payload(f"em={SAMPLE_EMAIL}&tid=G-1&cid=2")
        )
        failed = {c.name for c in verdict.failed_checks}
        assert "no_personal_data_in_third_party_payload" in failed

    def test_a_body_with_nothing_personal_in_it_passes(self):
        verdict = r04_consent.check(
            web_result=self._result_with_payload("v=2&tid=G-1&cid=2&en=heartbeat")
        )
        check = next(
            c for c in verdict.checks if c.name == "no_personal_data_in_third_party_payload"
        )
        assert check.passed is True
        assert "were read" in check.detail

    def test_the_check_is_not_raised_when_no_body_was_read(self):
        result = _result([_request("https://www.google-analytics.com/g/collect?v=2",
                                   method="GET", resource_type="image")])
        verdict = r04_consent.check(web_result=result)
        names = {c.name for c in verdict.checks}
        assert "no_personal_data_in_third_party_payload" not in names

    def test_a_first_party_body_is_not_graded_as_sharing(self):
        record = _request("https://shophub.example/signup", resource_type="xhr")
        web_scanner.NetworkRecorder(ENTRY).inspect_payload(
            _FakeRequest(f"email={SAMPLE_EMAIL}&full_name=Rupa"), record
        )
        verdict = r04_consent.check(web_result=_result([record]))
        names = {c.name for c in verdict.checks}
        assert "no_personal_data_in_third_party_payload" not in names


# ------------------------------------------------------- one offline browser run


async def _capture(path: Path) -> web_scanner.NetworkRecorder:
    """Drive the real recorder over a local file with all traffic aborted."""
    from playwright.async_api import async_playwright

    url = path.as_uri()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--disable-dev-shm-usage"])
        context = await browser.new_context(user_agent=web_scanner.USER_AGENT)
        await context.route(re.compile(r"^https?://"), lambda route: route.abort())
        page = await context.new_page()
        recorder = web_scanner.NetworkRecorder(url)
        recorder.attach(page)
        await web_scanner.goto_and_settle(page, url)
        await browser.close()
    return recorder


@pytest.fixture(scope="module")
def beacon_capture() -> web_scanner.NetworkRecorder:
    fixture = Path(__file__).resolve().parent / "fixtures" / "web" / "beacon_site.html"
    return asyncio.run(_capture(fixture))


class TestPayloadCaptureThroughTheBrowser:
    def test_the_bodies_of_real_beacons_are_read(self, beacon_capture):
        captured = [r for r in beacon_capture.requests if r.payload_captured]
        assert len(captured) >= 2
        assert all(r.payload_bytes > 0 for r in captured)

    def test_the_categories_carried_off_site_are_reported(self, beacon_capture):
        categories = {
            finding.pii_category
            for request in beacon_capture.requests
            for finding in request.payload_pii
        }
        assert {"email", "phone"} <= categories

    def test_the_captured_requests_carry_no_raw_value(self, beacon_capture):
        blob = repr(beacon_capture.requests)
        assert "rupa.desai" not in blob.lower()
        assert "919812345678" not in blob

    def test_a_beacon_with_nothing_personal_in_it_reports_nothing(self, beacon_capture):
        heartbeat = next(
            r for r in beacon_capture.requests if "hotjar" in r.host and r.payload_captured
        )
        assert heartbeat.payload_pii == []
        assert heartbeat.payload_shape


# ------------------------------------------- ground truth from a manual scan

# Taken from a hand verified cold load of an Indian compliance platform's own
# site: 70 requests, 12 hosts, 5 cookies, nothing clicked. The site is on one
# TLD and its backend on another, its assets come from a site builder's CDN,
# and it fires a tag manager before any choice is offered.
LIVE_ENTRY = "https://www.redacto.ai/en-in"
LIVE_ENTRY_HOST = "www.redacto.ai"


def _live_request(url: str, *, resource_type: str = "script", **overrides) -> NetworkRequest:
    host = trackers.normalise_host(urlparse(url).hostname)
    return NetworkRequest(
        url=url,
        host=host,
        resource_type=resource_type,
        method=overrides.pop("method", "GET"),
        is_third_party=bool(host) and not same_site(url, LIVE_ENTRY),
        before_consent=overrides.pop("before_consent", True),
        tracker_category=trackers.classify_tracker(host),
        shares_entry_brand=url_guard.shares_brand_label(host, LIVE_ENTRY_HOST),
        **overrides,
    )


def _live_result(requests: list[NetworkRequest], **overrides) -> WebScanResult:
    return WebScanResult(
        entry_url=LIVE_ENTRY,
        pages=[
            PageInfo(
                url=LIVE_ENTRY,
                title="Redacto",
                status_code=200,
                text_content="Consent management and DPDP compliance for Indian businesses. " * 8,
            )
        ],
        network_requests=requests,
        **overrides,
    )


class TestSiblingBrandDomains:
    def test_the_brand_label_survives_a_change_of_suffix(self):
        assert url_guard.brand_label("api.redacto.io") == "redacto"
        assert url_guard.brand_label("www.redacto.ai") == "redacto"
        assert url_guard.brand_label("shop.co.in") == "shop"

    def test_the_same_brand_under_another_suffix_is_a_probable_same_operator(self):
        assert url_guard.shares_brand_label("api.redacto.io", "www.redacto.ai")
        assert url_guard.shares_brand_label("cdn.redacto.io", "redacto.ai")

    def test_an_unrelated_host_is_not(self):
        assert not url_guard.shares_brand_label("www.google-analytics.com", "www.redacto.ai")
        assert not url_guard.shares_brand_label("redacto-partners.com", "www.redacto.ai")

    def test_the_same_domain_is_left_to_same_site(self):
        assert not url_guard.shares_brand_label("cdn.redacto.ai", "www.redacto.ai")

    def test_a_generic_or_short_label_is_never_treated_as_a_brand(self):
        """Whoever holds cloud.io has nothing to do with whoever holds cloud.ai,
        and a three letter label collides by default rather than by exception."""
        assert not url_guard.shares_brand_label("api.cloud.io", "www.cloud.ai")
        assert not url_guard.shares_brand_label("a.media.io", "b.media.ai")
        assert not url_guard.shares_brand_label("api.abc.io", "www.abc.ai")

    def test_the_sibling_backend_is_not_reported_as_an_external_recipient(self):
        result = _live_result(
            [
                _live_request("https://api.redacto.io/v1/session", resource_type="fetch"),
                _live_request("https://cdn.redacto.io/app.js"),
                _live_request("https://www.googletagmanager.com/gtm.js?id=GTM-1"),
            ]
        )
        assert ev.same_operator_hosts(result) == ["api.redacto.io", "cdn.redacto.io"]
        assert ev.data_recipient_hosts(result) == ["www.googletagmanager.com"]

    def test_the_evidence_says_probable_rather_than_merging_it_away(self):
        result = _live_result(
            [
                _live_request("https://api.redacto.io/v1/session", resource_type="fetch"),
                _live_request("https://www.googletagmanager.com/gtm.js?id=GTM-1"),
            ]
        )
        verdict = r04_consent.check(web_result=result)
        assert "carry the site's own brand under a different domain" in verdict.evidence
        assert "api.redacto.io" in verdict.evidence
        assert "inferred from the name, not established" in verdict.evidence

    def test_a_lookalike_domain_carrying_a_tracker_is_still_a_recipient(self):
        """Otherwise registering a domain with the site's own brand would be a
        way to have a tracker excused from the finding."""
        request = _live_request("https://metrics.redacto.io/collect", resource_type="beacon")
        request.tracker_category = "analytics"
        result = _live_result([request])
        assert ev.same_operator_hosts(result) == []
        assert ev.data_recipient_hosts(result) == ["metrics.redacto.io"]

    def test_a_lookalike_domain_is_resolved_rather_than_taken_on_trust(self):
        """A host the sharing evidence is prepared to excuse is a host worth a
        lookup, or cloaking under a brand matching domain would buy an
        exemption from both checks at once."""
        requests = [_live_request("https://metrics.redacto.io/collect", resource_type="beacon")]
        assert cname.candidate_hosts(requests) == ["metrics.redacto.io"]

    def test_a_cloaked_lookalike_is_still_a_recipient(self):
        requests = [_live_request("https://metrics.redacto.io/collect", resource_type="beacon")]
        asyncio.run(
            cname.resolve_and_mark(
                requests,
                resolver=_stub_resolver(
                    {"metrics.redacto.io": ["c.eu.analytics.hotjar.com"]}
                ),
            )
        )
        result = _live_result(requests)
        assert ev.same_operator_hosts(result) == []
        assert "metrics.redacto.io" in ev.data_recipient_hosts(result)

    def test_the_recorder_sets_the_flag_itself(self):
        recorder = web_scanner.NetworkRecorder(LIVE_ENTRY)
        recorder.record(_FakePlaywrightRequest("https://api.redacto.io/v1/session", "fetch"))
        recorder.record(_FakePlaywrightRequest("https://cdn.jsdelivr.net/npm/a.js", "script"))
        assert [r.shares_entry_brand for r in recorder.requests] == [True, False]


class _FakePlaywrightRequest:
    """Stands in for a Playwright request. No browser is started for this."""

    def __init__(self, url: str, resource_type: str = "script", method: str = "GET") -> None:
        self.url = url
        self.resource_type = resource_type
        self.method = method
        self.post_data = None
        self.frame = None


class TestLiveScanFindingsSurvive:
    def test_the_site_builder_cdn_stays_an_asset_host(self):
        """45 requests, every one a font, image, script or stylesheet. Calling
        that host a recipient of personal data would be the same mistake as
        calling Google Fonts one."""
        requests = [
            _live_request("https://cdn.prod.website-files.com/a/style.css",
                          resource_type="stylesheet"),
            _live_request("https://cdn.prod.website-files.com/a/logo.svg",
                          resource_type="image"),
            _live_request("https://cdn.prod.website-files.com/a/app.js"),
            _live_request("https://d3e54v103j8qbb.cloudfront.net/js/jquery.js"),
        ]
        result = _live_result(requests)
        assert ev.asset_hosts(result) == [
            "cdn.prod.website-files.com",
            "d3e54v103j8qbb.cloudfront.net",
        ]
        assert ev.data_recipient_hosts(result) == []

    def test_an_asset_cdn_that_also_receives_a_beacon_goes_back_to_being_a_recipient(self):
        requests = [
            _live_request("https://cdn.prod.website-files.com/a/app.js"),
            _live_request("https://cdn.prod.website-files.com/track", resource_type="beacon",
                          method="POST"),
        ]
        result = _live_result(requests)
        assert ev.asset_hosts(result) == []
        assert ev.data_recipient_hosts(result) == ["cdn.prod.website-files.com"]

    def test_the_tag_manager_before_consent_is_still_the_headline_finding(self):
        requests = [
            _live_request(f"https://www.googletagmanager.com/gtm.js?id=GTM-{i}")
            for i in range(3)
        ]
        result = _live_result(requests)
        assert len(result.trackers_before_consent) == 3
        verdict = r04_consent.check(web_result=result)
        assert verdict.status == "violation"
        assert "www.googletagmanager.com" in verdict.bright_line_reason

    def test_the_google_ads_cookie_written_before_a_choice_is_still_a_finding(self):
        from app.contracts import CookieInfo

        cookie = CookieInfo(
            name="_gcl_au",
            domain=".redacto.ai",
            secure=False,
            http_only=False,
            set_before_consent=True,
            classification=trackers.classify_cookie("_gcl_au"),
        )
        assert cookie.classification == "advertising"
        result = _live_result([], cookies=[cookie])
        assert [c.name for c in ev.unconsented_cookies(result)] == ["_gcl_au"]

    def test_hubspot_before_consent_now_reaches_the_finding(self):
        """The false negative this ground truth was gathered to catch."""
        requests = [
            _live_request("https://js-na2.hs-scripts.com/12345.js"),
            _live_request("https://js.hs-banner.com/banner.js"),
        ]
        result = _live_result(requests)
        assert [r.host for r in result.trackers_before_consent] == ["js-na2.hs-scripts.com"]
        # The banner script is the one host on the page asking for permission.
        assert "js.hs-banner.com" in result.third_party_hosts


class TestTheseModulesStayOutOfTheVerdictBusiness:
    def test_no_compliance_judgement_leaks_into_the_scanner(self):
        source = "".join(
            Path(module.__file__).read_text(encoding="utf-8")
            for module in (cname, payload_pii)
        ).lower()
        for word in ("violation", "non-compliant", "noncompliant", "penalty", "unlawful"):
            assert word not in source, word
