"""Tests for the checks that read the expanded web evidence.

Two failure modes matter more than the rest here, and both are about the tool
lying in the safe-looking direction.

The first is processing that precedes consent. s.6(1) requires consent before
the processing, so a third party tracker that has already fired cannot have been
consented to, and the crawl is the only place that shows up.

The second is a blocked crawl. A bot wall hands back the same empty cookie,
request and form lists as a spotless site, so a checker that grades what it got
reports "no trackers found" on a scan that saw nothing. That is a clean bill of
health nobody earned, which is why every page level check has to disappear from
the score rather than pass.
"""

import pytest

from app.contracts import (
    CodeScanResult,
    ColumnInfo,
    ConsentBanner,
    ConsentElement,
    CookieInfo,
    FormField,
    FormInfo,
    ModelInfo,
    NetworkRequest,
    NoticeInfo,
    PageInfo,
    PolicyDocument,
    SymbolInfo,
    WebScanResult,
)
from app.rules import (
    engine,
    evidence as ev,
    r03_notice,
    r04_consent,
    r05_children,
    r06_security,
    r09_sdf,
    r10_rights,
    r11_dpb,
)

COMPLIANT = "compliant"
GAP = "gap"
VIOLATION = "violation"
NOT_APPLICABLE = "not_applicable"

ENTRY = "https://retail.example.in"

POLICY_BODY = (
    "This policy states the purpose of each kind of processing: account creation, "
    "payment and billing, delivery, and analytics. We share data with our "
    "service providers and other third parties listed below. We retain order "
    "records for 18 months and erase them at the end of that retention period. "
    "You may make a complaint to the Data Protection Board of India."
)


# ------------------------------------------------------------------- fixtures


def banner(**overrides) -> ConsentBanner:
    """A banner where refusing is exactly as easy as accepting."""
    defaults = dict(
        present=True,
        has_accept=True,
        has_reject=True,
        has_granular_options=True,
        has_manage_link=True,
        blocks_page_until_choice=True,
        accept_label="Accept all",
        reject_label="Reject all",
        selector="#cookie-consent",
    )
    defaults.update(overrides)
    return ConsentBanner(**defaults)


def tracker_request(*, before_consent: bool, host: str = "www.google-analytics.com"):
    return NetworkRequest(
        url=f"https://{host}/g/collect?v=2&tid=G-77",
        host=host,
        resource_type="beacon",
        method="POST",
        is_third_party=True,
        before_consent=before_consent,
        tracker_category="analytics",
    )


def signup_form(*, https: bool = True, action: str = "/signup") -> FormInfo:
    return FormInfo(
        action=action,
        method="POST",
        fields=[
            FormField(name="email", input_type="email", label="Email", required=True),
            FormField(name="pan_number", input_type="text", label="PAN", required=True),
        ],
        consent_elements=[
            ConsentElement(
                field_name="consent_account",
                label_text="Create my account and process my order",
                pre_checked=False,
                near_submit=True,
            ),
            ConsentElement(
                field_name="consent_marketing",
                label_text="Send me marketing offers",
                pre_checked=False,
                near_submit=True,
            ),
        ],
        submits_over_https=https,
    )


def asset_request(*, host: str, resource_type: str = "script"):
    """A static asset fetch: third party, but not a recipient of personal data."""
    return NetworkRequest(
        url=f"https://{host}/lib/main.{resource_type}",
        host=host,
        resource_type=resource_type,
        method="GET",
        is_third_party=True,
        before_consent=True,
        tracker_category=None,
    )

def web(
    *,
    requests: list[NetworkRequest] | None = None,
    cookies: list[CookieInfo] | None = None,
    consent_banner: ConsentBanner | None = None,
    policies: list[PolicyDocument] | None = None,
    notice: NoticeInfo | None = None,
    crawl_blocked: bool = False,
    crawl_note: str | None = None,
    marketing_optins: list[ConsentElement] | None = None,
    sensitive: list[FormField] | None = None,
    dpo_contact: str | None = None,
    https: bool = True,
    forms: list[FormInfo] | None = None,
    rights_links: list[str] | None = None,
    age_gate_fields: list[FormField] | None = None,
    title: str = "Retail",
) -> WebScanResult:
    """A crawl carrying only the evidence a given test is about.

    The withdrawal link is present by default because s.6(4) is not what any of
    these tests are about, and a missing one would fail R4 in every case.
    """
    return WebScanResult(
        entry_url=ENTRY,
        pages=[PageInfo(url=ENTRY, title=title, status_code=200, text_content="Shop")],
        forms=forms if forms is not None else [signup_form(https=https)],
        age_gate_fields=age_gate_fields or [],
        privacy_notice=notice,
        security_headers={
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        cookies=cookies or [],
        rights_links=(
            rights_links
            if rights_links is not None
            else [f"{ENTRY}/account/consent-preferences"]
        ),
        served_over_https=https,
        network_requests=requests or [],
        policy_documents=policies or [],
        consent_banner=consent_banner,
        dpo_contact=dpo_contact,
        sensitive_fields=sensitive or [],
        marketing_optins=marketing_optins or [],
        crawl_blocked=crawl_blocked,
        crawl_note=crawl_note,
    )


def blocked_web(**overrides) -> WebScanResult:
    """What a bot wall produces: the flags set, and nothing else observed."""
    defaults = dict(
        crawl_blocked=True,
        crawl_note="403 from the edge on the first request, challenge page returned",
        forms=[],
    )
    defaults.update(overrides)
    return web(**defaults)


def thin_code() -> CodeScanResult:
    """Just enough repository evidence to keep the code side checks alive."""
    return CodeScanResult(
        root_path="/repo",
        db_models=[
            ModelInfo(
                class_name="User",
                table_name="users",
                file_path="app/models/user.py",
                line_number=10,
                columns=[
                    ColumnInfo(
                        name="pan_number", column_type="String", line_number=12, is_encrypted=True
                    )
                ],
            )
        ],
        symbols=[
            SymbolInfo(
                name="withdraw_consent",
                kind="function",
                file_path="app/consent.py",
                line_number=8,
            )
        ],
    )


def check_named(verdict, name):
    return next((c for c in verdict.checks if c.name == name), None)


# --------------------------------------------- consent must precede processing


def test_tracker_firing_before_consent_is_a_violation_on_r4():
    """s.6(1) puts consent before the processing, so this is not a mere gap."""
    verdict = r04_consent.check(
        web_result=web(requests=[tracker_request(before_consent=True)], consent_banner=banner())
    )
    assert verdict.status == VIOLATION
    assert verdict.bright_line_reason
    assert verdict.score <= engine.BRIGHT_LINE_SCORE_CEILING

    failed = check_named(verdict, "no_tracker_before_consent")
    assert failed is not None and not failed.passed
    assert "www.google-analytics.com" in failed.detail
    assert "analytics" in failed.detail
    assert "/g/collect" in failed.detail
    assert "consent" in verdict.evidence.lower()


def test_the_same_tracker_after_consent_does_not_fail_the_check():
    verdict = r04_consent.check(
        web_result=web(requests=[tracker_request(before_consent=False)], consent_banner=banner())
    )
    check = check_named(verdict, "no_tracker_before_consent")
    assert check is not None and check.passed
    assert verdict.status != VIOLATION


def test_a_first_party_request_before_consent_is_not_a_tracker_finding():
    request = NetworkRequest(
        url=f"{ENTRY}/api/cart",
        host="retail.example.in",
        resource_type="xhr",
        before_consent=True,
    )
    check = check_named(
        r04_consent.check(web_result=web(requests=[request], consent_banner=banner())),
        "no_tracker_before_consent",
    )
    assert check is not None and check.passed


def test_non_necessary_cookie_before_consent_fails_but_a_session_cookie_does_not():
    cookies = [
        CookieInfo(
            name="sid",
            domain="retail.example.in",
            secure=True,
            http_only=True,
            same_site="Lax",
            set_before_consent=True,
            classification="necessary",
        ),
        CookieInfo(
            name="_fbp",
            domain=".retail.example.in",
            secure=True,
            http_only=False,
            same_site="Lax",
            set_before_consent=True,
            is_third_party=True,
            classification="advertising",
        ),
    ]
    check = check_named(
        r04_consent.check(web_result=web(cookies=cookies, consent_banner=banner())),
        "no_cookie_before_consent",
    )
    assert check is not None and not check.passed
    assert "_fbp" in check.detail
    assert "sid" not in check.detail

    only_session = check_named(
        r04_consent.check(web_result=web(cookies=cookies[:1], consent_banner=banner())),
        "no_cookie_before_consent",
    )
    assert only_session is not None and only_session.passed
    assert "sid" in only_session.detail


def test_a_cookie_the_scanner_could_not_classify_is_counted_not_excused():
    cookie = CookieInfo(
        name="ajs_anonymous_id",
        domain=".retail.example.in",
        secure=True,
        http_only=False,
        same_site="Lax",
        set_before_consent=True,
    )
    check = check_named(
        r04_consent.check(web_result=web(cookies=[cookie], consent_banner=banner())),
        "no_cookie_before_consent",
    )
    assert check is not None and not check.passed
    assert "classification not reported" in check.detail


# ------------------------------------------------------------ consent banner


def test_a_banner_with_equal_accept_and_reject_passes():
    verdict = r04_consent.check(web_result=web(consent_banner=banner()))
    for name in (
        "consent_banner_present",
        "reject_as_easy_as_accept",
        "banner_offers_per_purpose_choice",
    ):
        check = check_named(verdict, name)
        assert check is not None, name
        assert check.passed, f"{name}: {check.detail}"
    assert not verdict.failed_checks, [c.detail for c in verdict.failed_checks]
    assert verdict.status == COMPLIANT


def test_accept_only_banner_fails_the_parity_check():
    verdict = r04_consent.check(
        web_result=web(
            consent_banner=banner(has_reject=False, reject_label=None, has_manage_link=False)
        )
    )
    check = check_named(verdict, "reject_as_easy_as_accept")
    assert check is not None and not check.passed
    assert "Accept all" in check.detail
    assert "s.6" in check.detail


def test_a_manage_link_is_not_a_refusal():
    """Refusing behind a second screen is not as easy as a one click accept."""
    verdict = r04_consent.check(
        web_result=web(
            consent_banner=banner(
                has_reject=False, reject_label=None, has_granular_options=False
            )
        )
    )
    parity = check_named(verdict, "reject_as_easy_as_accept")
    granular = check_named(verdict, "banner_offers_per_purpose_choice")
    assert parity is not None and not parity.passed
    assert "manage" in parity.detail
    assert granular is not None and not granular.passed


def test_a_second_control_labelled_manage_settings_is_not_counted_as_reject():
    verdict = r04_consent.check(
        web_result=web(consent_banner=banner(reject_label="Manage settings"))
    )
    parity = check_named(verdict, "reject_as_easy_as_accept")
    assert parity is not None and not parity.passed
    assert "Manage settings" in parity.detail


def test_no_banner_at_all_is_a_finding_only_where_something_needs_consent():
    cookie = CookieInfo(
        name="_ga",
        domain=".retail.example.in",
        secure=True,
        http_only=False,
        same_site="Lax",
        classification="analytics",
    )
    with_cookies = check_named(
        r04_consent.check(web_result=web(cookies=[cookie], consent_banner=ConsentBanner())),
        "consent_banner_present",
    )
    assert with_cookies is not None and not with_cookies.passed
    assert ENTRY in with_cookies.detail

    # Nothing observed that would need a banner, so no check is invented.
    assert (
        check_named(
            r04_consent.check(web_result=web(consent_banner=ConsentBanner())),
            "consent_banner_present",
        )
        is None
    )
    assert check_named(r04_consent.check(web_result=web()), "consent_banner_present") is None


# ----------------------------------------------------- opt-ins and purposes


def test_marketing_consent_bundled_into_the_terms_fails():
    optin = ConsentElement(
        field_name="accept_all",
        label_text="I accept the terms and conditions and agree to receive marketing offers",
        pre_checked=False,
        near_submit=True,
    )
    verdict = r04_consent.check(web_result=web(marketing_optins=[optin]))
    check = check_named(verdict, "marketing_consent_separate_from_terms")
    assert check is not None and not check.passed
    assert "accept_all" in check.detail


def test_a_separate_marketing_optin_passes_and_a_pre_checked_one_does_not():
    clean = ConsentElement(
        field_name="newsletter_optin",
        label_text="Send me the newsletter",
        pre_checked=False,
        near_submit=False,
    )
    verdict = r04_consent.check(web_result=web(marketing_optins=[clean]))
    separate = check_named(verdict, "marketing_consent_separate_from_terms")
    assert separate is not None and separate.passed

    pre_checked = ConsentElement(
        field_name="newsletter_optin",
        label_text="Send me the newsletter",
        pre_checked=True,
        near_submit=False,
    )
    verdict = r04_consent.check(
        web_result=web(marketing_optins=[pre_checked], forms=[])
    )
    failed = check_named(verdict, "no_pre_checked_consent")
    assert failed is not None and not failed.passed
    assert "newsletter_optin" in failed.detail
    assert "marketing opt-in block" in failed.detail


def test_a_consent_label_that_names_no_purpose_fails_purpose_limitation():
    form = FormInfo(
        action="/register",
        method="POST",
        fields=[FormField(name="email", input_type="email", required=True)],
        consent_elements=[
            ConsentElement(
                field_name="consent_all",
                label_text="I agree",
                pre_checked=False,
                near_submit=True,
            )
        ],
        submits_over_https=True,
    )
    check = check_named(
        r04_consent.check(web_result=web(forms=[form])),
        "consent_purpose_limitation_stated",
    )
    assert check is not None and not check.passed
    assert '"I agree"' in check.detail
    assert "/register" in check.detail


# ------------------------------------------------------- third party sharing


def test_distinct_third_party_hosts_are_counted_and_checked_against_the_notice():
    requests = [
        tracker_request(before_consent=False, host="www.google-analytics.com"),
        tracker_request(before_consent=False, host="connect.facebook.net"),
        NetworkRequest(
            url="https://cdn.other.example/app.js",
            host="cdn.other.example",
            resource_type="script",
            is_third_party=True,
        ),
        NetworkRequest(
            url=f"{ENTRY}/api/cart", host="retail.example.in", resource_type="xhr"
        ),
    ]
    silent_notice = NoticeInfo(
        url=f"{ENTRY}/privacy",
        link_text="Privacy",
        in_footer_only=False,
        reachable=True,
        body_text="We collect your data for the purpose of providing our service.",
    )
    verdict = r04_consent.check(web_result=web(requests=requests, notice=silent_notice))
    check = check_named(verdict, "third_party_sharing_disclosed")
    assert check is not None and not check.passed
    assert "3 distinct third party host(s)" in check.detail
    assert "connect.facebook.net" in check.detail

    disclosing = NoticeInfo(
        url=f"{ENTRY}/privacy",
        link_text="Privacy",
        in_footer_only=False,
        reachable=True,
        body_text=POLICY_BODY,
    )
    passed = check_named(
        r04_consent.check(web_result=web(requests=requests, notice=disclosing)),
        "third_party_sharing_disclosed",
    )
    assert passed is not None and passed.passed
    assert "3 distinct third party host(s)" in passed.detail


def test_a_cdn_is_not_reported_as_a_recipient_of_personal_data():
    """A jsdelivr bundle is the page arriving, not personal data leaving.

    Counting every third party host the page touched reported Google Fonts and a
    script CDN as undisclosed recipients of personal data under s.5(1), which is
    an assertion the evidence never supported.
    """
    requests = [
        NetworkRequest(
            url="https://cdn.jsdelivr.net/npm/swiper/swiper-bundle.min.js",
            host="cdn.jsdelivr.net",
            resource_type="script",
            is_third_party=True,
        ),
        NetworkRequest(
            url="https://fonts.gstatic.com/s/inter/v13/font.woff2",
            host="fonts.gstatic.com",
            resource_type="font",
            is_third_party=True,
        ),
    ]
    silent_notice = NoticeInfo(
        url=f"{ENTRY}/privacy",
        link_text="Privacy",
        in_footer_only=False,
        reachable=True,
        body_text="We collect your data for the purpose of providing our service.",
    )
    verdict = r04_consent.check(web_result=web(requests=requests, notice=silent_notice))
    assert check_named(verdict, "third_party_sharing_disclosed") is None
    assert "static asset host" in verdict.evidence
    assert "cdn.jsdelivr.net" in verdict.evidence


def test_a_cdn_alongside_a_tracker_is_excluded_from_the_recipient_count():
    """The tracker is still a recipient. The CDN beside it is still not one."""
    requests = [
        tracker_request(before_consent=False, host="www.google-analytics.com"),
        NetworkRequest(
            url="https://cdn.jsdelivr.net/npm/chart.js",
            host="cdn.jsdelivr.net",
            resource_type="script",
            is_third_party=True,
        ),
    ]
    silent_notice = NoticeInfo(
        url=f"{ENTRY}/privacy",
        link_text="Privacy",
        in_footer_only=False,
        reachable=True,
        body_text="We collect your data for the purpose of providing our service.",
    )
    check = check_named(
        r04_consent.check(web_result=web(requests=requests, notice=silent_notice)),
        "third_party_sharing_disclosed",
    )
    assert check is not None and not check.passed
    assert "1 distinct third party host(s)" in check.detail
    assert "www.google-analytics.com" in check.detail
    assert "cdn.jsdelivr.net" in check.detail
    assert "not counted as a recipient" in check.detail


def test_a_cdn_that_also_receives_an_xhr_goes_back_to_being_a_recipient():
    """A CDN domain must not be usable as cover for an endpoint that takes data."""
    requests = [
        NetworkRequest(
            url="https://cdn.jsdelivr.net/collect?uid=abc",
            host="cdn.jsdelivr.net",
            resource_type="xhr",
            method="POST",
            is_third_party=True,
        )
    ]
    assert ev.data_recipient_hosts(web(requests=requests)) == ["cdn.jsdelivr.net"]
    assert ev.asset_hosts(web(requests=requests)) == []


# ------------------------------------------------------- notice discoverability


def well_known_policy(**overrides) -> PolicyDocument:
    defaults = dict(
        url=f"{ENTRY}/privacy-policy",
        kind="privacy",
        reachable=True,
        discovered_via="well_known_path",
        body_text=POLICY_BODY,
        word_count=310,
        linked_from_homepage=False,
        in_footer_only=False,
    )
    defaults.update(overrides)
    return PolicyDocument(**defaults)


def test_a_policy_found_only_by_well_known_path_counts_as_reachable():
    verdict = r03_notice.check(web_result=web(policies=[well_known_policy()]))
    reachable = check_named(verdict, "notice_exists_and_reachable")
    assert reachable is not None and reachable.passed
    assert f"{ENTRY}/privacy-policy" in reachable.detail
    assert "conventional path" in reachable.detail


def test_a_policy_found_only_by_well_known_path_still_fails_before_collection():
    verdict = r03_notice.check(web_result=web(policies=[well_known_policy()]))
    timing = check_named(verdict, "notice_before_collection")
    assert timing is not None and not timing.passed
    assert "probing" in timing.detail
    assert verdict.status == GAP


def test_a_footer_only_policy_link_fails_before_collection_too():
    footer_policy = well_known_policy(
        discovered_via="link", linked_from_homepage=True, in_footer_only=True
    )
    verdict = r03_notice.check(web_result=web(policies=[footer_policy]))
    assert check_named(verdict, "notice_exists_and_reachable").passed
    timing = check_named(verdict, "notice_before_collection")
    assert timing is not None and not timing.passed
    assert "footer" in timing.detail


def test_a_policy_linked_from_the_homepage_outside_the_footer_passes_both():
    linked = well_known_policy(
        discovered_via="link", linked_from_homepage=True, in_footer_only=False
    )
    verdict = r03_notice.check(web_result=web(policies=[linked]))
    assert check_named(verdict, "notice_exists_and_reachable").passed
    assert check_named(verdict, "notice_before_collection").passed


def test_notice_content_checks_read_the_discovered_policy_body():
    verdict = r03_notice.check(web_result=web(policies=[well_known_policy()]))
    for name in (
        "purposes_itemised",
        "retention_stated_in_notice",
        "board_complaint_route_stated",
    ):
        check = check_named(verdict, name)
        assert check is not None, name
        assert check.passed, f"{name}: {check.detail}"


def test_a_notice_silent_on_retention_and_the_board_fails_those_two_checks():
    quiet = well_known_policy(
        body_text=(
            "We process your data for the purpose of account creation and for payment. "
            "Write to our grievance officer with any question."
        )
    )
    verdict = r03_notice.check(web_result=web(policies=[quiet]))
    failed = {c.name for c in verdict.failed_checks}
    assert "retention_stated_in_notice" in failed
    assert "board_complaint_route_stated" in failed
    assert "purposes_itemised" not in failed


def test_a_published_dpo_contact_satisfies_the_notice_contact_check():
    verdict = r03_notice.check(
        web_result=web(policies=[well_known_policy()], dpo_contact="dpo@retail.example.in")
    )
    check = check_named(verdict, "grievance_contact_named")
    assert check is not None and check.passed
    assert "dpo@retail.example.in" in check.detail
    assert "Rule 9" in check.detail


def test_r9_prefers_the_published_dpo_contact_over_the_grievance_inbox():
    result = web(
        sensitive=[FormField(name="pan_number", input_type="text", label="PAN")],
        dpo_contact="dpo@retail.example.in",
    )
    verdict = r09_sdf.check(web_result=result)
    check = check_named(verdict, "dpo_identified")
    assert check is not None and check.passed
    assert "dpo@retail.example.in" in check.detail
    assert "Rule 9" in check.detail


def test_r9_reports_a_missing_published_contact_where_scale_is_indicated():
    result = web(sensitive=[FormField(name="pan_number", input_type="text", label="PAN")])
    verdict = r09_sdf.check(web_result=result)
    check = check_named(verdict, "dpo_identified")
    assert check is not None and not check.passed
    assert "Rule 9" in check.detail


# --------------------------------------------------- security of what is sent


def test_cookies_without_secure_or_samesite_fail_r6():
    cookies = [
        CookieInfo(name="sid", domain="retail.example.in", secure=False, http_only=True),
        CookieInfo(
            name="_ga",
            domain=".retail.example.in",
            secure=True,
            http_only=False,
            same_site="Lax",
        ),
    ]
    verdict = r06_security.check(web_result=web(cookies=cookies))
    check = check_named(verdict, "cookies_carry_secure_flags")
    assert check is not None and not check.passed
    assert '"sid"' in check.detail
    assert "Secure" in check.detail and "SameSite" in check.detail
    assert "HttpOnly" in check.detail  # the analytics cookie is still reported


def test_samesite_none_is_reported_rather_than_counted_as_protection():
    """The browser reports an explicit SameSite=None as the string None."""
    cookie = CookieInfo(
        name="_fbp",
        domain=".retail.example.in",
        secure=True,
        http_only=True,
        same_site="None",
    )
    check = check_named(
        r06_security.check(web_result=web(cookies=[cookie])), "cookies_carry_secure_flags"
    )
    assert check is not None and not check.passed
    assert "SameSite=None" in check.detail
    assert "_fbp" in check.detail


def test_well_flagged_cookies_pass_r6():
    cookies = [
        CookieInfo(
            name="sid",
            domain="retail.example.in",
            secure=True,
            http_only=True,
            same_site="Strict",
        )
    ]
    check = check_named(
        r06_security.check(web_result=web(cookies=cookies)), "cookies_carry_secure_flags"
    )
    assert check is not None and check.passed


def test_sensitive_field_posted_over_plain_http_fails_r6():
    field = FormField(name="pan_number", input_type="text", label="PAN", required=True)
    verdict = r06_security.check(web_result=web(sensitive=[field], https=False))
    check = check_named(verdict, "sensitive_fields_collected_with_care")
    assert check is not None and not check.passed
    assert "pan_number" in check.detail


def test_sensitive_field_posted_off_site_fails_r6():
    field = FormField(name="pan_number", input_type="text", label="PAN", required=True)
    verdict = r06_security.check(
        web_result=web(
            sensitive=[field],
            forms=[signup_form(action="https://forms.thirdparty.example/collect")],
        )
    )
    check = check_named(verdict, "sensitive_fields_collected_with_care")
    assert check is not None and not check.passed
    assert "forms.thirdparty.example" in check.detail
    assert "pan_number" in check.detail


def test_sensitive_field_collected_over_https_on_the_same_host_passes_r6():
    field = FormField(name="pan_number", input_type="text", label="PAN", required=True)
    check = check_named(
        r06_security.check(web_result=web(sensitive=[field])),
        "sensitive_fields_collected_with_care",
    )
    assert check is not None and check.passed


def test_no_sensitive_fields_means_no_check_at_all():
    assert (
        check_named(
            r06_security.check(web_result=web()), "sensitive_fields_collected_with_care"
        )
        is None
    )


# ------------------------------------------------------------- rights on site


def test_a_discovered_grievance_policy_satisfies_the_rights_grievance_check():
    policy = PolicyDocument(
        url=f"{ENTRY}/grievance-redressal",
        kind="grievance",
        reachable=True,
        discovered_via="well_known_path",
        word_count=140,
    )
    check = check_named(
        r10_rights.check(web_result=web(policies=[policy])), "grievance_path_exists"
    )
    assert check is not None and check.passed
    assert "grievance-redressal" in check.detail

    intake = check_named(
        r11_dpb.check(web_result=web(policies=[policy])), "complaint_intake_exists"
    )
    assert intake is not None and intake.passed


# --------------------------------------------- r5 applicability, DPDP Act s.9


def dob_field() -> FormField:
    return FormField(name="date_of_birth", input_type="date", label="Date of birth")


def test_a_general_audience_site_with_trackers_is_not_in_breach_of_s9():
    """The single worst false positive this tool had.

    A bike taxi booking site, a recharge site and a university were all graded
    violation 0/2 on the children's provision for having no age gate and loading
    analytics. s.9(1) bites before processing a child's personal data, so absent
    any child directed signal the obligation is not engaged and there is nothing
    to be in breach of.
    """
    verdict = r05_children.check(
        web_result=web(requests=[tracker_request(before_consent=True)], title="Rapido: Bike Taxi")
    )
    assert verdict.status == NOT_APPLICABLE, verdict.evidence
    assert verdict.score is None
    assert verdict.checks == []


def test_the_not_assessed_verdict_states_its_assumption_rather_than_passing_the_site():
    """not_applicable here is an assumption on the record, never a clean bill."""
    evidence = r05_children.check(
        web_result=web(requests=[tracker_request(before_consent=True)])
    ).evidence
    assert "Not assessed" in evidence
    assert "no child directed signal" in evidence.lower()
    assert "assumption" in evidence
    assert "not a finding of compliance" in evidence
    assert "ought to know" in evidence
    assert "cannot escape them by declining to ask for age" in evidence
    assert "s.9(3)" in evidence


def test_a_university_is_an_adult_service_whatever_its_students_are_called():
    """A student is not a child, and higher education is not a child audience."""
    campus = web(
        requests=[tracker_request(before_consent=True)],
        title="National Forensic Sciences University: Student Admissions",
    )
    assert r05_children.check(web_result=campus).status == NOT_APPLICABLE


def test_a_child_directed_site_with_trackers_is_still_graded():
    """The gate narrows who s.9 reaches. It never softens the finding for them."""
    verdict = r05_children.check(
        web_result=web(
            requests=[tracker_request(before_consent=True)],
            title="Kids Learning Games Online",
        )
    )
    assert verdict.status == VIOLATION, verdict.evidence
    tracking = check_named(verdict, "no_child_tracking")
    assert tracking is not None and not tracking.passed
    assert "www.google-analytics.com" in tracking.detail


def test_a_childrens_privacy_policy_puts_the_rule_back_in_scope():
    policy = PolicyDocument(
        url=f"{ENTRY}/childrens-privacy",
        kind="children",
        reachable=True,
        discovered_via="link",
        body_text="How we handle a child's personal data.",
    )
    verdict = r05_children.check(web_result=web(policies=[policy]))
    assert verdict.status != NOT_APPLICABLE
    assert check_named(verdict, "age_gate_present") is not None


def notice_saying(body: str) -> NoticeInfo:
    return NoticeInfo(
        url=f"{ENTRY}/privacy",
        link_text="Privacy",
        in_footer_only=False,
        reachable=True,
        body_text=body,
    )


def test_a_notice_that_takes_parental_consent_puts_the_rule_back_in_scope():
    """Building a parental consent flow is an admission that children are users."""
    verdict = r05_children.check(
        web_result=web(
            notice=notice_saying(
                "Where an account is opened for a child we obtain the verifiable parental "
                "consent of the parent or lawful guardian before processing."
            )
        )
    )
    assert verdict.status != NOT_APPLICABLE, verdict.evidence
    assert "requires human validation" in verdict.evidence


def test_the_standard_we_do_not_knowingly_collect_disclaimer_is_not_a_child_signal():
    """The boilerplate sentence says children are not users, not that they are.

    It sits in the same paragraph as the words "parental consent" on almost
    every general audience policy in the country, so reading it as a signal
    would put every one of them back in breach of s.9.
    """
    verdict = r05_children.check(
        web_result=web(
            requests=[tracker_request(before_consent=True)],
            notice=notice_saying(
                "Our service is not intended for children. We do not knowingly collect "
                "personal data from a child without verifiable parental consent."
            ),
        )
    )
    assert verdict.status == NOT_APPLICABLE, verdict.evidence


def test_an_age_field_re_engages_the_rule_on_an_otherwise_general_site():
    """Collecting date of birth is data that can reveal the user is a child."""
    verdict = r05_children.check(web_result=web(age_gate_fields=[dob_field()]))
    assert verdict.status != NOT_APPLICABLE, verdict.evidence
    age_gate = check_named(verdict, "age_gate_present")
    assert age_gate is not None and age_gate.passed
    assert "date_of_birth" in age_gate.detail


def test_an_age_field_with_trackers_is_a_s9_3_violation_not_a_free_pass():
    """s.9(3) is an outright prohibition, so the override must survive the gate."""
    verdict = r05_children.check(
        web_result=web(
            requests=[tracker_request(before_consent=True)],
            age_gate_fields=[dob_field()],
        )
    )
    assert verdict.status == VIOLATION
    assert verdict.bright_line_reason
    assert verdict.score <= engine.BRIGHT_LINE_SCORE_CEILING
    assert "s.9(3)" in verdict.evidence


def test_a_max_age_form_field_is_a_cache_directive_and_not_an_age_gate():
    verdict = r05_children.check(
        web_result=web(
            requests=[tracker_request(before_consent=True)],
            age_gate_fields=[FormField(name="max-age", input_type="text", label="Cache")],
        )
    )
    assert verdict.status == NOT_APPLICABLE, verdict.evidence


def test_orm_relationships_and_cache_columns_are_not_childrens_data():
    """parent_id on a comment thread is a foreign key, not a parent's consent."""
    code = CodeScanResult(
        root_path="/repo",
        db_models=[
            ModelInfo(
                class_name="Comment",
                table_name="comments",
                file_path="app/models/comment.py",
                line_number=8,
                columns=[
                    ColumnInfo(name="parent_id", column_type="UUID", line_number=10),
                    ColumnInfo(name="child_node", column_type="UUID", line_number=11),
                    ColumnInfo(name="max_age", column_type="Integer", line_number=12),
                    ColumnInfo(name="age_rating", column_type="String", line_number=13),
                ],
            )
        ],
        symbols=[
            SymbolInfo(
                name="spawn_child_process",
                kind="function",
                file_path="app/worker.py",
                line_number=20,
            )
        ],
    )
    verdict = r05_children.check(code_result=code)
    assert verdict.status == NOT_APPLICABLE, verdict.evidence
    assert verdict.checks == []


def test_a_technical_term_never_counts_as_evidence_of_age_or_a_parent():
    for name in ("max-age", "cache_age", "ttl", "age_rating", "parent_id", "child_node",
                 "child_process", "hasMany", "belongsTo"):
        assert ev.is_technical_term(name), name
    for name in ("date_of_birth", "verify_age", "parental_consent", "guardian_consent"):
        assert not ev.is_technical_term(name), name


# ------------------------------------------------------------- blocked crawls


WEB_RULES = (r03_notice, r04_consent, r05_children, r06_security, r10_rights, r11_dpb)


@pytest.mark.parametrize("checker", WEB_RULES, ids=[m.RULE_ID for m in WEB_RULES])
def test_a_blocked_crawl_is_not_applicable_rather_than_a_verdict(checker):
    """Reporting a clean site off a bot wall is the worst failure this tool has."""
    verdict = checker.check(web_result=blocked_web())
    assert verdict.status == NOT_APPLICABLE, verdict.evidence
    assert verdict.score is None
    assert verdict.checks == []
    assert "blocked" in verdict.evidence
    assert "403 from the edge" in verdict.evidence


def test_a_blocked_crawl_never_reports_a_clean_tracking_result():
    """The same site, blocked, must not pass the checks it would otherwise fail."""
    graded = r04_consent.check(
        web_result=web(requests=[tracker_request(before_consent=True)], consent_banner=banner())
    )
    assert graded.status == VIOLATION

    blocked = r04_consent.check(web_result=blocked_web())
    assert blocked.status == NOT_APPLICABLE
    assert not any(check.passed for check in blocked.checks)


def test_a_blocked_crawl_hides_the_cookies_and_headers_it_did_capture():
    """Whatever answered a blocked request belongs to the bot wall, not the app."""
    cookie = CookieInfo(name="__cf_bm", domain=".retail.example.in", secure=False, http_only=True)
    verdict = r06_security.check(web_result=blocked_web(cookies=[cookie]))
    assert verdict.status == NOT_APPLICABLE
    assert check_named(verdict, "cookies_carry_secure_flags") is None
    assert check_named(verdict, "security_headers_present") is None
    assert check_named(verdict, "https_enforced") is None


def test_a_code_scan_is_unaffected_and_says_what_it_did_not_look_at():
    """The other scan kind is graded separately and stands on its own evidence."""
    verdict = r06_security.check(code_result=thin_code())
    assert verdict.status != NOT_APPLICABLE
    assert verdict.score is not None
    assert check_named(verdict, "pii_encrypted_at_rest") is not None
    assert check_named(verdict, "security_headers_present") is None
    assert check_named(verdict, "cookies_carry_secure_flags") is None
    assert "No web scan was supplied" in verdict.evidence

    consent = r04_consent.check(code_result=thin_code())
    assert consent.status != NOT_APPLICABLE
    withdrawal = check_named(consent, "withdrawal_mechanism_present")
    assert withdrawal is not None and withdrawal.passed
    assert check_named(consent, "consent_mechanism_present") is None
    assert "No web scan was supplied" in consent.evidence


def test_a_code_scan_still_reports_a_missing_age_column():
    """No web scan is not the same as a blocked one: this evidence is real.

    R5 is only assessed where something puts children in scope, so the
    repository here carries a guardian consent handler. That is the fiduciary's
    own admission that it expects children, and against it a missing age column
    is a real finding rather than an artefact of nobody having looked.
    """
    code = thin_code()
    code.symbols.append(
        SymbolInfo(
            name="record_guardian_consent",
            kind="function",
            file_path="app/guardian.py",
            line_number=12,
        )
    )
    verdict = r05_children.check(code_result=code)
    age_gate = check_named(verdict, "age_gate_present")
    assert age_gate is not None and not age_gate.passed
    assert "repository" in age_gate.detail


def test_a_blocked_crawl_leaves_the_code_only_rules_alone():
    verdicts = {v.rule_id: v for v in engine.run_all(web_result=blocked_web())}
    for rule_id in ("R3", "R4", "R5", "R6", "R9", "R10", "R11"):
        assert verdicts[rule_id].status == NOT_APPLICABLE, rule_id
        assert verdicts[rule_id].score is None, rule_id
    for rule_id in ("R7", "R8", "R12", "RET"):
        assert verdicts[rule_id].status == NOT_APPLICABLE, rule_id


def test_no_verdict_from_a_blocked_crawl_carries_a_score():
    for verdict in engine.run_all(web_result=blocked_web()):
        assert verdict.score is None, verdict.rule_id
        assert verdict.status == NOT_APPLICABLE, verdict.rule_id


# ---------------------------------------------------------------- determinism


def rich_web() -> WebScanResult:
    return web(
        requests=[
            tracker_request(before_consent=True),
            tracker_request(before_consent=False, host="connect.facebook.net"),
            NetworkRequest(
                url=f"{ENTRY}/api/cart", host="retail.example.in", resource_type="xhr"
            ),
        ],
        cookies=[
            CookieInfo(
                name="_fbp",
                domain=".retail.example.in",
                secure=False,
                http_only=False,
                set_before_consent=True,
                is_third_party=True,
                classification="advertising",
            )
        ],
        consent_banner=banner(reject_label="Manage settings", has_granular_options=False),
        policies=[well_known_policy()],
        notice=NoticeInfo(
            url=f"{ENTRY}/privacy",
            link_text="Privacy",
            in_footer_only=True,
            reachable=True,
            body_text=POLICY_BODY,
        ),
        marketing_optins=[
            ConsentElement(
                field_name="accept_all",
                label_text="I accept the terms of service and want marketing email",
                pre_checked=True,
                near_submit=True,
            )
        ],
        sensitive=[FormField(name="pan_number", input_type="text", label="PAN")],
        dpo_contact="dpo@retail.example.in",
    )


@pytest.mark.parametrize(
    "checker", engine.RULE_CHECKERS, ids=[m.RULE_ID for m in engine.RULE_CHECKERS]
)
def test_the_web_checks_are_deterministic(checker):
    """Same crawl in, same verdict out, or none of this is auditable."""
    first = checker.check(web_result=rich_web())
    second = checker.check(web_result=rich_web())
    assert first == second
    assert first.evidence == second.evidence
    assert [c.detail for c in first.checks] == [c.detail for c in second.checks]


def test_run_all_over_the_expanded_evidence_is_deterministic():
    assert engine.run_all(web_result=rich_web()) == engine.run_all(web_result=rich_web())
    assert engine.run_all(web_result=blocked_web()) == engine.run_all(web_result=blocked_web())


@pytest.mark.parametrize(
    "checker", engine.RULE_CHECKERS, ids=[m.RULE_ID for m in engine.RULE_CHECKERS]
)
def test_the_web_checks_do_not_mutate_the_scan_result(checker):
    result = rich_web()
    checker.check(web_result=result)
    assert result == rich_web()


# -------------------------------------------------------------- shape of output


def test_no_rule_reports_two_checks_with_the_same_name():
    """A repeated name makes the report ambiguous about which finding failed."""
    inputs = (
        dict(web_result=rich_web()),
        dict(web_result=web(consent_banner=banner(), policies=[well_known_policy()])),
        dict(web_result=blocked_web()),
        dict(code_result=thin_code()),
    )
    for kwargs in inputs:
        for verdict in engine.run_all(**kwargs):
            names = [c.name for c in verdict.checks]
            assert len(names) == len(set(names)), f"{verdict.rule_id} repeats: {names}"


def test_every_web_check_names_the_url_host_cookie_or_field_it_is_about():
    verdicts = engine.run_all(web_result=rich_web())
    for verdict in verdicts:
        for check in verdict.checks:
            assert check.detail.strip(), f"{verdict.rule_id}.{check.name} has no detail"
            assert len(check.detail) > 25, f"{verdict.rule_id}.{check.name} is too vague"
            assert check.name == check.name.lower()


def test_a_bad_site_scores_worse_than_a_good_one_on_every_web_rule():
    good = web(
        consent_banner=banner(),
        policies=[
            well_known_policy(
                discovered_via="link", linked_from_homepage=True, in_footer_only=False
            )
        ],
        dpo_contact="dpo@retail.example.in",
    )
    for checker in (r03_notice, r04_consent):
        clean = checker.check(web_result=good)
        dirty = checker.check(web_result=rich_web())
        assert clean.score is not None and dirty.score is not None
        assert dirty.score < clean.score, checker.RULE_ID


class TestR9ScaleIndicatorCountsRecipientsOnly:
    """SDF designation turns on scale, so what counts as a recipient matters.

    Counting every third-party host let a CDN bundle, a Google Font and a CDN
    image push a small site over the volume threshold. Fetching a stylesheet is
    not sending personal data to anyone, and inflating that count pushes a site
    toward obligations the Act reserves for genuinely large processors.
    """

    @staticmethod
    def _asset_only_site():
        return web(
            requests=[
                asset_request(host="cdn.jsdelivr.net", resource_type="script"),
                asset_request(host="fonts.googleapis.com", resource_type="stylesheet"),
                asset_request(host="fonts.gstatic.com", resource_type="font"),
                asset_request(host="cdnjs.cloudflare.com", resource_type="script"),
                asset_request(host="ajax.googleapis.com", resource_type="script"),
                asset_request(host="images.example-cdn.net", resource_type="image"),
            ]
        )

    def test_asset_hosts_do_not_count_toward_scale(self):
        verdict = r09_sdf.check(web_result=self._asset_only_site())
        assert "distinct third party recipient" not in (verdict.evidence or "")

    def test_real_recipients_still_count(self):
        verdict = r09_sdf.check(
            web_result=web(
                requests=[
                    tracker_request(host="www.google-analytics.com", before_consent=True),
                    tracker_request(host="connect.facebook.net", before_consent=True),
                    tracker_request(host="static.hotjar.com", before_consent=True),
                    tracker_request(host="cdn.mxpnl.com", before_consent=True),
                    tracker_request(host="analytics.tiktok.com", before_consent=True),
                    tracker_request(host="sc-static.net", before_consent=True),
                ]
            )
        )
        assert verdict.status != NOT_APPLICABLE
