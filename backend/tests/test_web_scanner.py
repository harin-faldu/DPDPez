"""Web scanner coverage.

Every browser test runs against a local file:// fixture with all http and https
traffic aborted at the route layer, so the suite never touches the network. The
request event still fires for an aborted request, which is exactly the layer the
scanner reads, so blocking the traffic costs the tests nothing.

The fixtures were written from what the benchmark against a real site showed was
missing: tags injected after parsing, pixels that are never script elements, a
banner that offers no way to refuse, and ID and financial fields sitting in a
signup form.
"""

import asyncio
import re
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from app.contracts import CookieInfo, PageInfo, WebScanResult
from app.scanner import trackers, web_scanner


@pytest.fixture(scope="session")
def web_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "web"


async def _abort(route) -> None:
    await route.abort()


async def _collect(path: Path) -> dict:
    """Load one fixture offline and return the evidence as plain data."""
    url = path.as_uri()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--disable-dev-shm-usage"])
        context = await browser.new_context(user_agent=web_scanner.USER_AGENT)
        await context.route(re.compile(r"^https?://"), _abort)
        page = await context.new_page()

        failed: list[str] = []
        page.on("requestfailed", lambda request: failed.append(request.url))

        recorder = web_scanner.NetworkRecorder(url)
        recorder.attach(page)
        outcome = await web_scanner.goto_and_settle(page, url)

        evidence = {
            "url": url,
            "error": outcome.error,
            "failed": failed,
            "requests": list(recorder.requests),
            "banner": await web_scanner._detect_consent_banner(page),
            "forms": await web_scanner._extract_forms(page, url),
            "sensitive": web_scanner._dedupe_fields(
                await web_scanner._extract_sensitive_fields(page)
            ),
            "optins": web_scanner._dedupe_consent_elements(
                await web_scanner._extract_marketing_optins(page)
            ),
            "anchors": await web_scanner._extract_anchors(page, url),
            "text": await web_scanner._inner_text(page),
        }
        await browser.close()
    return evidence


async def _navigate(path: Path) -> web_scanner.LoadOutcome:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--disable-dev-shm-usage"])
        page = await (await browser.new_context()).new_page()
        outcome = await web_scanner.goto_and_settle(page, path.as_uri(), timeout_ms=5000)
        await browser.close()
    return outcome


@pytest.fixture(scope="module")
def tracker_page(web_dir) -> dict:
    return asyncio.run(_collect(web_dir / "tracker_site.html"))


@pytest.fixture(scope="module")
def clean_page(web_dir) -> dict:
    return asyncio.run(_collect(web_dir / "clean_site.html"))


@pytest.fixture(scope="module")
def choice_page(web_dir) -> dict:
    return asyncio.run(_collect(web_dir / "banner_with_choice.html"))


def _result(evidence: dict) -> WebScanResult:
    return WebScanResult(
        entry_url=evidence["url"], network_requests=evidence["requests"]
    )


def _hosts(evidence: dict) -> set[str]:
    return {r.host for r in evidence["requests"]}


# --------------------------------------------------------------- classification


class TestTrackerClassification:
    def test_known_hosts_get_their_category(self):
        assert trackers.classify_tracker("www.googletagmanager.com") == "tag_manager"
        assert trackers.classify_tracker("www.google-analytics.com") == "analytics"
        assert trackers.classify_tracker("securepubads.g.doubleclick.net") == "advertising"
        assert trackers.classify_tracker("connect.facebook.net") == "social"
        assert trackers.classify_tracker("static.hotjar.com") == "replay"

    def test_marketing_automation_and_crm_suites_are_classified(self):
        """Found on a live scan of an Indian compliance vendor's own site:
        HubSpot loaded three hosts before any consent and every one came back
        unclassified, so a suite that identifies a named visitor and writes
        them into a CRM record read as a functional asset. The list was thin on
        marketing platforms as opposed to pure analytics and adtech."""
        assert trackers.classify_tracker("js-na2.hs-scripts.com") == "analytics"
        assert trackers.classify_tracker("js.hs-scripts.com") == "analytics"
        assert trackers.classify_tracker("track.hubspot.com") == "analytics"
        assert trackers.classify_tracker("forms.hsforms.com") == "analytics"
        assert trackers.classify_tracker("js.hsadspixel.net") == "advertising"
        assert trackers.classify_tracker("munchkin.marketo.net") == "analytics"
        assert trackers.classify_tracker("static.klaviyo.com") == "analytics"
        assert trackers.classify_tracker("widgets.leadsquared.com") == "analytics"
        assert trackers.classify_tracker("spl.zeotap.com") == "analytics"

    def test_the_hubspot_banner_script_is_a_consent_platform_not_a_tracker(self):
        """Same exception as every other platform here: the script that draws
        the banner has to load before a choice exists in order to ask for one."""
        assert trackers.is_consent_manager("js.hs-banner.com")
        assert trackers.classify_tracker("js.hs-banner.com") is None

    def test_regional_and_per_customer_subdomains_still_match(self):
        assert trackers.classify_tracker("in.hotjar.com") == "replay"
        assert trackers.classify_tracker("cdn-eu.clarity.ms") == "replay"
        assert trackers.classify_tracker("in1.api.clevertap.com") == "analytics"
        assert trackers.classify_tracker("sdk-01.moengage.com") == "analytics"
        assert trackers.classify_tracker("sk1.wzrk.net") == "analytics"

    def test_matching_is_suffix_based_not_substring(self):
        # media.net is an ad network. socialmedia.network is not.
        assert trackers.classify_tracker("cdn.media.net") == "advertising"
        assert trackers.classify_tracker("socialmedia.network") is None

    def test_error_and_performance_telemetry_is_recognised(self):
        """A crash report carries IP, URL and often a user id, and Sentry's per
        customer ingest hosts have to match on the suffix."""
        assert trackers.classify_tracker("o20004.ingest.us.sentry.io") == "analytics"
        assert trackers.classify_tracker("o12345.ingest.sentry.io") == "analytics"
        assert trackers.classify_tracker("browser-intake-us5.datadoghq.com") == "analytics"
        assert trackers.classify_tracker("api.bugsnag.com") == "analytics"
        assert trackers.classify_tracker("eu.i.posthog.com") == "analytics"

    def test_developer_audience_ad_networks_are_recognised(self):
        """Found on python.org, where nobody expects advertising to be."""
        assert trackers.classify_tracker("media.ethicalads.io") == "advertising"
        assert trackers.classify_tracker("cdn.carbonads.com") == "advertising"
        assert trackers.classify_tracker("srv.buysellads.com") == "advertising"

    def test_a_consent_platform_is_not_a_tracker(self):
        """The script that draws the banner cannot wait for the banner."""
        assert trackers.classify_tracker("cdn.cookielaw.org") is None
        assert trackers.is_consent_manager("cdn.cookielaw.org")

    def test_unknown_and_empty_hosts_are_not_guessed_at(self):
        assert trackers.classify_tracker("cdn.jsdelivr.net") is None
        assert trackers.classify_tracker("shophub.example") is None
        assert trackers.classify_tracker("") is None
        assert trackers.classify_tracker(None) is None


class TestCookieClassification:
    def test_measurement_cookies(self):
        for name in ("_ga", "_ga_TESTID01", "_gid", "_gat_UA-1-1", "_clck", "_hjSessionUser_1"):
            assert trackers.classify_cookie(name) == "analytics", name

    def test_targeting_cookies(self):
        for name in ("_gcl_au", "_fbp", "_fbc", "IDE", "MUID", "_uetvid", "cto_bundle"):
            assert trackers.classify_cookie(name) == "advertising", name

    def test_session_and_security_cookies_are_necessary(self):
        for name in ("sid", "sessionid", "PHPSESSID", "csrftoken", "OptanonConsent"):
            assert trackers.classify_cookie(name) == "necessary", name

    def test_an_unrecognised_cookie_is_unknown_not_necessary(self):
        """The rules engine counts unknown as needing consent. Guessing
        "necessary" here would quietly excuse it."""
        assert trackers.classify_cookie("shophub_ab_bucket") == "unknown"
        assert trackers.classify_cookie("") == "unknown"

    def test_enrichment_fills_the_fields_the_rules_engine_reads(self):
        now = 1_800_000_000.0
        cookie = web_scanner._cookie_info(
            {
                "name": "_ga",
                "domain": ".shophub.example",
                "secure": True,
                "httpOnly": False,
                "sameSite": "Lax",
                "expires": now + 86400 * 400,
            },
            "www.shophub.example",
            before_consent=True,
            now=now,
        )
        assert cookie.classification == "analytics"
        assert cookie.set_before_consent
        assert cookie.is_third_party is False
        assert cookie.expiry_days == 400.0

    def test_a_sibling_subdomain_cookie_is_not_third_party(self):
        """Seen on python.org: a string suffix comparison made
        analytics.python.org a third party recipient of www.python.org's data.
        Third party means another organisation, which url_guard decides."""
        cookie = web_scanner._cookie_info(
            {"name": "sid", "domain": ".analytics.python.org", "expires": -1},
            "www.python.org",
            before_consent=True,
            now=1_800_000_000.0,
        )
        assert cookie.is_third_party is False

    def test_indian_second_level_domains_stay_distinct(self):
        cookie = web_scanner._cookie_info(
            {"name": "sid", "domain": "www.otheruni.ac.in", "expires": -1},
            "portal.myuni.ac.in",
            before_consent=True,
            now=1_800_000_000.0,
        )
        assert cookie.is_third_party is True

    def test_a_cookie_on_another_host_is_third_party(self):
        cookie = web_scanner._cookie_info(
            {"name": "IDE", "domain": ".doubleclick.net", "expires": -1},
            "shophub.example",
            before_consent=True,
            now=1_800_000_000.0,
        )
        assert cookie.is_third_party
        assert cookie.expiry_days is None  # a session cookie has no expiry
        assert cookie.classification == "advertising"


class TestSensitiveFieldPatterns:
    def test_categories_are_recognised_from_names(self):
        assert trackers.sensitive_category("aadhaar_number") == "government_id"
        assert trackers.sensitive_category("aadhaarnumber") == "government_id"
        assert trackers.sensitive_category("bank_account") == "financial"
        assert trackers.sensitive_category("healthStatus") == "health"
        assert trackers.sensitive_category("fingerprint_scan") == "biometric"
        assert trackers.sensitive_category("religion") == "religion"
        assert trackers.sensitive_category("caste_category") == "caste"
        assert trackers.sensitive_category("sexual_orientation") == "sexual_orientation"

    def test_ordinary_fields_are_left_alone(self):
        for name in ("full_name", "email", "mobile", "company", "plan", "healthy_recipes"):
            assert trackers.sensitive_category(name) is None, name

    def test_short_tokens_need_a_word_boundary(self):
        assert trackers.sensitive_category("pan_card") == "government_id"
        assert trackers.sensitive_category("panel_layout") is None


class TestMarketingOptinPatterns:
    def test_a_newsletter_box_is_a_marketing_optin(self):
        assert trackers.is_marketing_optin("promo_optin", "Subscribe to our newsletter")
        assert trackers.is_marketing_optin("", "Yes, send me promotional offers")

    def test_accepting_terms_is_not_a_marketing_optin(self):
        assert not trackers.is_marketing_optin("terms", "I accept the Terms and Conditions")
        assert not trackers.is_marketing_optin("policy", "I have read the Privacy Policy")
        assert trackers.is_terms_acceptance("terms", "I accept the Terms and Conditions")


# ------------------------------------------------------------ network evidence


class TestNetworkCapture:
    def test_no_request_in_this_suite_reached_the_network(self, tracker_page):
        remote = [r.url for r in tracker_page["requests"] if r.url.startswith("http")]
        assert remote, "the fixture is supposed to make remote requests"
        assert set(remote) <= set(tracker_page["failed"])

    def test_tags_injected_after_parsing_are_captured(self, tracker_page):
        """A script element sweep sees none of this, which is why a real site
        came back with zero third party scripts."""
        assert "securepubads.g.doubleclick.net" in _hosts(tracker_page)
        assert "in1.api.clevertap.com" in _hosts(tracker_page)

    def test_pixels_and_beacons_are_captured_with_their_resource_type(self, tracker_page):
        by_host = {r.host: r for r in tracker_page["requests"]}
        assert by_host["www.facebook.com"].resource_type == "image"
        assert by_host["www.google-analytics.com"].resource_type == "image"
        assert by_host["in1.api.clevertap.com"].method == "POST"

    def test_each_captured_host_carries_its_category(self, tracker_page):
        categories = {
            r.host: r.tracker_category for r in tracker_page["requests"] if r.tracker_category
        }
        assert categories["www.googletagmanager.com"] == "tag_manager"
        assert categories["static.hotjar.com"] == "replay"
        assert categories["www.google-analytics.com"] == "analytics"
        assert categories["www.facebook.com"] == "social"
        assert categories["securepubads.g.doubleclick.net"] == "advertising"

    def test_the_consent_platform_host_is_recorded_but_uncategorised(self, tracker_page):
        stub = next(r for r in tracker_page["requests"] if r.host == "cdn.cookielaw.org")
        assert stub.tracker_category is None
        assert stub.is_third_party
        assert "cdn.cookielaw.org" in _result(tracker_page).third_party_hosts


class TestBeforeConsent:
    def test_everything_on_a_cold_load_is_flagged_before_consent(self, tracker_page):
        assert tracker_page["requests"]
        assert all(r.before_consent for r in tracker_page["requests"])

    def test_the_trackers_before_consent_signal_is_populated(self, tracker_page):
        result = _result(tracker_page)
        categories = {r.tracker_category for r in result.trackers_before_consent}
        assert categories == {"tag_manager", "analytics", "advertising", "social", "replay"}
        assert all(r.is_third_party for r in result.trackers_before_consent)

    def test_marking_an_interaction_stops_the_flag(self, tracker_page):
        """Nothing in a default scan calls this, but the flag has to mean
        something for the day something does."""
        recorder = web_scanner.NetworkRecorder("https://shophub.example/")
        recorder.mark_consent_interaction()
        assert recorder.before_consent is False

    def test_a_page_with_no_third_party_requests_reports_none(self, clean_page):
        result = _result(clean_page)
        assert result.trackers_before_consent == []
        assert result.third_party_hosts == []


# ------------------------------------------------------------- consent banners


class TestConsentBannerDetection:
    def test_a_banner_with_no_refusal_is_recorded_as_such(self, tracker_page):
        """Whether refusing is offered at all is the part with legal weight."""
        banner = tracker_page["banner"]
        assert banner.present
        assert banner.has_accept
        assert banner.accept_label == "Accept All Cookies"
        assert banner.has_reject is False
        assert banner.reject_label is None
        assert banner.has_manage_link
        assert banner.has_granular_options is False

    def test_a_banner_offering_both_choices_is_recorded_as_such(self, choice_page):
        banner = choice_page["banner"]
        assert banner.present
        assert banner.has_accept and banner.has_reject
        assert banner.accept_label == "Accept All"
        assert banner.reject_label == "Reject All"
        assert banner.has_manage_link
        assert banner.has_granular_options
        assert banner.selector == "#onetrust-banner-sdk"

    def test_a_modal_banner_over_a_backdrop_is_recorded_as_blocking(self, choice_page):
        assert choice_page["banner"].blocks_page_until_choice

    def test_a_bottom_bar_is_not_recorded_as_blocking(self, tracker_page):
        assert tracker_page["banner"].blocks_page_until_choice is False

    def test_no_banner_means_no_banner(self, clean_page):
        banner = clean_page["banner"]
        assert banner.present is False
        assert banner.has_accept is False
        assert banner.has_reject is False


# ------------------------------------------------------------------ form reads


class TestSensitiveFieldExtraction:
    def test_id_financial_health_biometric_and_caste_fields_are_found(self, tracker_page):
        names = {f.name for f in tracker_page["sensitive"]}
        assert {
            "aadhaar_number",
            "pan_card",
            "bank_account",
            "blood_group",
            "caste_category",
            "fingerprint_scan",
        } <= names

    def test_ordinary_contact_fields_are_not_flagged(self, tracker_page):
        names = {f.name for f in tracker_page["sensitive"]}
        assert not names & {"full_name", "email", "mobile", "terms_accepted"}

    def test_labels_and_requiredness_come_through(self, tracker_page):
        aadhaar = next(f for f in tracker_page["sensitive"] if f.name == "aadhaar_number")
        assert aadhaar.label == "Aadhaar number (for KYC)"
        assert aadhaar.required

    def test_a_plain_contact_form_has_no_sensitive_fields(self, clean_page):
        assert clean_page["sensitive"] == []


class TestMarketingOptinExtraction:
    def test_the_newsletter_box_is_captured_with_its_state(self, tracker_page):
        optins = {e.field_name: e for e in tracker_page["optins"]}
        assert "promo_optin" in optins
        assert optins["promo_optin"].pre_checked
        assert optins["promo_optin"].near_submit

    def test_the_terms_box_is_not_a_marketing_optin(self, tracker_page):
        assert "terms_accepted" not in {e.field_name for e in tracker_page["optins"]}

    def test_consent_elements_still_reach_the_form_contract(self, tracker_page):
        form = tracker_page["forms"][0]
        assert {c.field_name for c in form.consent_elements} == {
            "terms_accepted",
            "promo_optin",
        }
        assert {f.name for f in form.fields} >= {"full_name", "aadhaar_number"}


class TestAnchorReads:
    def test_policy_links_are_found_and_placed(self, tracker_page):
        by_kind = {
            trackers.policy_kind_for_link(a["text"], a["href"]): a
            for a in tracker_page["anchors"]
        }
        assert by_kind["privacy"]["href"].endswith("/privacy-policy")
        assert by_kind["grievance"]["href"].endswith("/grievance-redressal")
        assert by_kind["terms"]["href"].endswith("/terms")

    def test_footer_placement_is_recorded_per_link(self, tracker_page):
        placement = {a["text"]: a["in_footer"] for a in tracker_page["anchors"]}
        assert placement["Privacy Policy"] is True
        assert placement["Grievance Redressal"] is True
        # The link inside the consent banner sits outside the footer.
        assert placement["Cookie Settings"] is False

    def test_the_privacy_notice_is_recorded_as_footer_only(self, tracker_page):
        notice = web_scanner._find_privacy_notice(tracker_page["anchors"])
        assert notice is not None
        assert notice.link_text == "Privacy Policy"
        assert notice.in_footer_only

    def test_the_officer_contact_is_read_out_of_the_page(self, tracker_page):
        contact = web_scanner._extract_dpo_contact([tracker_page["text"]])
        assert contact is not None
        assert "grievance@shophub.example" in contact
        assert "Rahul Verma" in contact


# ----------------------------------------------------------- crawl reliability


def _page(text: str, status: int = 200) -> WebScanResult:
    return WebScanResult(
        entry_url="https://shophub.example/",
        pages=[
            PageInfo(
                url="https://shophub.example/",
                title="Shophub",
                status_code=status,
                text_content=text,
            )
        ],
    )


PROSE = (
    "Shophub India sells household goods across nineteen thousand pin codes. "
    "Browse the catalogue, add to your cart and pay on delivery or by UPI. "
    "Our customer care team answers between nine in the morning and nine at night, "
    "every day of the week, in English, Hindi and Gujarati. "
) * 3


class TestBlockedCrawl:
    def test_a_refusal_status_is_reported_as_blocked(self):
        result = _page(PROSE, status=403)
        web_scanner.assess_crawl_health(result)
        assert result.crawl_blocked
        assert "403" in result.crawl_note

    def test_rate_limiting_is_reported_as_blocked(self):
        result = _page(PROSE, status=429)
        web_scanner.assess_crawl_health(result)
        assert result.crawl_blocked

    def test_a_challenge_page_is_reported_as_blocked(self):
        result = _page("Just a moment...\nChecking your browser before you continue.")
        web_scanner.assess_crawl_health(result)
        assert result.crawl_blocked
        assert "challenge" in result.crawl_note

    def test_an_empty_document_is_reported_as_blocked(self):
        result = _page("   ")
        web_scanner.assess_crawl_health(result)
        assert result.crawl_blocked
        assert "0 characters" in result.crawl_note

    def test_a_failed_entry_load_is_reported_as_blocked(self):
        result = WebScanResult(entry_url="https://shophub.example/")
        web_scanner.assess_crawl_health(result, entry_error="net::ERR_CONNECTION_REFUSED")
        assert result.crawl_blocked
        assert "ERR_CONNECTION_REFUSED" in result.crawl_note

    def test_the_note_never_lets_an_empty_result_read_as_a_clean_site(self):
        result = _page(PROSE, status=403)
        web_scanner.assess_crawl_health(result)
        assert "not evidence that the site has none" in result.crawl_note

    def test_a_served_page_with_nothing_on_it_is_not_called_blocked(self):
        """Finding nothing on a page that was served is a gap in this scanner,
        or a genuinely quiet site. Calling it a bot wall would hide our own bug
        behind an accusation about the site."""
        result = _page(PROSE)
        assert result.forms == []
        assert result.network_requests == []
        web_scanner.assess_crawl_health(result)
        assert result.crawl_blocked is False
        assert result.crawl_note is None

    def test_a_long_page_that_merely_mentions_a_captcha_is_not_blocked(self):
        result = _page(PROSE + " We use reCAPTCHA to protect our signup form. " + PROSE)
        web_scanner.assess_crawl_health(result)
        assert result.crawl_blocked is False

    def test_partial_coverage_is_noted_without_discarding_the_result(self):
        result = _page(PROSE)
        web_scanner.assess_crawl_health(result, failed_pages=3, dropped_requests=12)
        assert result.crawl_blocked is False
        assert "3 page(s)" in result.crawl_note
        assert "12 further network request(s)" in result.crawl_note


class TestLoadStrategy:
    def test_a_page_that_cannot_load_returns_an_error_instead_of_raising(self, web_dir):
        outcome = asyncio.run(_navigate(web_dir / "no_such_fixture.html"))
        assert outcome.response is None
        assert outcome.error and "ERR" in outcome.error
        assert outcome.partial is False

    def test_a_page_that_loads_reports_no_error(self, web_dir):
        outcome = asyncio.run(_navigate(web_dir / "clean_site.html"))
        assert outcome.error is None
        assert outcome.partial is False

    def test_the_settle_wait_is_bounded(self):
        """A page that never goes idle must not hold the crawl open."""
        assert 0 < web_scanner.NETWORK_IDLE_TIMEOUT_MS <= 15000
        assert 0 < web_scanner.SETTLE_DELAY_MS <= 3000

    def test_a_slow_page_is_noted_without_discarding_what_it_yielded(self):
        """Seen on a real ad heavy homepage: the navigation blew its budget
        after the document had rendered. Discarding the page would have thrown
        away 139 captured requests and then called the site unreachable."""
        result = _page(PROSE)
        web_scanner.assess_crawl_health(result, slow_pages=1)
        assert result.crawl_blocked is False
        assert "navigation budget" in result.crawl_note


class TestPolitenessLimits:
    def test_probe_and_capture_caps_are_in_place(self):
        assert len(trackers.POLICY_PROBE_PATHS) + len(trackers.CONTACT_PROBE_PATHS) <= (
            web_scanner.MAX_POLICY_FETCHES
        )
        assert web_scanner.POLICY_FETCH_CONCURRENCY <= 4
        assert web_scanner.MAX_NETWORK_REQUESTS <= 1000
        assert web_scanner.MAX_POLICY_RENDERS <= 3

    def test_probe_paths_cover_the_conventional_locations(self):
        paths = {p for p, _ in trackers.POLICY_PROBE_PATHS}
        assert {
            "/privacy",
            "/privacy-policy",
            "/legal/privacy",
            "/policies/privacy",
            "/cookie-policy",
            "/terms",
            "/grievance",
            "/grievance-redressal",
        } <= paths
        assert "/contact" in trackers.CONTACT_PROBE_PATHS


class TestPolicyTextHandling:
    def test_markup_is_reduced_to_readable_prose(self):
        html = (
            "<html><head><style>b{color:red}</style><script>var x=1</script></head>"
            "<body><h1>Privacy Policy</h1><p>We collect your name &amp; email.</p></body></html>"
        )
        text = web_scanner._html_to_text(html)
        assert "Privacy Policy" in text
        assert "We collect your name & email." in text
        assert "var x" not in text
        assert "color:red" not in text

    def test_urls_dedupe_across_query_and_trailing_slash(self):
        a = web_scanner._normalise_url("https://Shophub.example/privacy/?ref=footer")
        b = web_scanner._normalise_url("https://shophub.example/privacy")
        assert a == b

    def test_a_soft_404_that_echoes_the_homepage_is_recognisable(self):
        homepage = web_scanner._fingerprint(PROSE)
        assert web_scanner._fingerprint(PROSE) == homepage
        assert web_scanner._fingerprint("Privacy Policy. We collect...") != homepage

    def test_real_policy_links_are_classified(self):
        assert (
            trackers.policy_kind_for_link("Privacy policy", "/privacy-policy/cookiepolicy/869.cms")
            == "privacy"
        )
        assert (
            trackers.policy_kind_for_link("Terms of Use and Grievance Redressal Policy", "/terms")
            == "grievance"
        )
        assert trackers.policy_kind_for_link("Children's Privacy", "/kids") == "children"

    def test_an_article_headline_is_not_a_policy_document(self):
        """Found on a live news homepage: a bare "children" or "terms" keyword
        filed six articles as policy documents, and their prose would then have
        been read as the site's privacy notice."""
        headlines = [
            (
                "Mary Kom recalls being suicidal, says she chose to live for her children",
                "/tv/news/hindi/mary-kom-chose-to-live-for-her-children/articleshow/134450703.cms",
            ),
            (
                "Went to sign under bail terms: teacher accused in MDMA case stabbed",
                "/city/kozhikode/went-to-sign-under-bail-terms-teacher/articleshow/134501329.cms",
            ),
            (
                "Should parents teach children how to ask better questions",
                "/life-style/parenting/should-parents-teach-children/articleshow/134499770.cms",
            ),
        ]
        for text, path in headlines:
            assert trackers.policy_kind_for_link(text, path) is None, text

    def test_a_contact_page_only_counts_as_grievance_evidence_when_it_says_so(self):
        assert trackers.mentions_grievance_route(
            "Grievance Officer: write to grievance@shophub.example"
        )
        assert not trackers.mentions_grievance_route(
            "Sales enquiries: call our showroom between 10am and 7pm."
        )


class TestNoCompliancejudgementsLeak:
    def test_the_scanner_module_stays_out_of_the_verdict_business(self):
        source = (
            Path(web_scanner.__file__).read_text(encoding="utf-8")
            + Path(trackers.__file__).read_text(encoding="utf-8")
        ).lower()
        for word in ("violation", "non-compliant", "noncompliant", "penalty", "breach of"):
            assert word not in source, word


class TestCookieContractShape:
    def test_cookies_before_consent_only_returns_flagged_cookies(self):
        result = WebScanResult(
            entry_url="https://shophub.example/",
            cookies=[
                CookieInfo(name="_ga", domain=".shophub.example", secure=True, http_only=False,
                           set_before_consent=True, classification="analytics"),
                CookieInfo(name="sid", domain="shophub.example", secure=True, http_only=True,
                           set_before_consent=False, classification="necessary"),
            ],
        )
        assert [c.name for c in result.cookies_before_consent] == ["_ga"]
