"""R4 Consent, DPDP Act s.6, s.7; Rule 4.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    ConsentElement,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R4"
RULE_NAME = "Consent"
DPDP_SECTION = "s.6, s.7"
DPDP_RULE = "Rule 4"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# rule_3(c)(i) carries the withdrawal-ease requirement; rule_4 governs Consent
# Managers.
RETRIEVAL_SECTION_IDS: list[str] = ["s.6", "s.7", "rule_3", "rule_4"]

_WITHDRAWAL_KEYWORDS: tuple[str, ...] = (
    "withdraw",
    "revoke",
    "opt_out",
    "unsubscribe",
    "manage_consent",
    "consent_preferences",
    "privacy_preferences",
    "preference_centre",
    "preference_center",
)

_CONSENT_CODE_KEYWORDS: tuple[str, ...] = (
    "consent",
    "has_consented",
    "check_consent",
    "require_consent",
    "verify_consent",
    "consent_granted",
)

_CONSENT_RECORD_KEYWORDS: tuple[str, ...] = (
    "consent",
    "consent_log",
    "consent_record",
    "consent_receipt",
    "consent_audit",
)

_SUBJECT_COLUMNS: tuple[str, ...] = (
    "user_id",
    "principal_id",
    "subject_id",
    "data_principal_id",
    "account_id",
    "customer_id",
)

_TIMESTAMP_COLUMNS: tuple[str, ...] = (
    "consented_at",
    "granted_at",
    "given_at",
    "recorded_at",
    "created_at",
    "timestamp",
    "occurred_at",
)

_PURPOSE_COLUMNS: tuple[str, ...] = (
    "purpose",
    "purposes",
    "scope",
    "consent_type",
    "processing_purpose",
    "category",
)

# Purposes a consent label can name. s.6(1) requires consent to be specific, so
# a label that names none of these is asking for a blanket permission.
_PURPOSE_LABEL_MARKERS: tuple[str, ...] = (
    "account",
    "registration",
    "register",
    "sign up",
    "login",
    "authenticat",
    "marketing",
    "promotional",
    "offers",
    "newsletter",
    "advertis",
    "analytic",
    "statistic",
    "measurement",
    "personalis",
    "personaliz",
    "recommend",
    "payment",
    "billing",
    "invoice",
    "delivery",
    "shipping",
    "order",
    "support",
    "service",
    "fraud",
    "security",
    "legal",
    "research",
    "survey",
)

# Wording that shows a single control is being used both to accept terms and to
# take marketing consent. Bundling the two means the marketing consent is not
# freely given, because refusing it also refuses the service.
_TERMS_BUNDLE_MARKERS: tuple[str, ...] = (
    "terms and conditions",
    "terms of service",
    "terms of use",
    "the terms",
    "t&c",
    "user agreement",
)

_MARKETING_MARKERS: tuple[str, ...] = (
    "marketing",
    "promotional",
    "newsletter",
    "offers",
    "advertis",
    "deals",
)

# Wording that shows a control refuses rather than defers. "Manage settings" is
# deliberately excluded: it opens a second screen, which is not as easy as the
# single click that accepts.
_REJECT_LABEL_MARKERS: tuple[str, ...] = (
    "reject",
    "decline",
    "deny",
    "refuse",
    "disagree",
    "only necessary",
    "necessary only",
    "essential only",
    "only essential",
    "strictly necessary",
    "continue without",
    "do not accept",
    "opt out",
    "no thanks",
)

# Notice wording that discloses onward sharing to other recipients.
_SHARING_MARKERS: tuple[str, ...] = (
    "third party",
    "third parties",
    "third-party",
    "share your",
    "shared with",
    "sharing your",
    "disclose your",
    "disclosed to",
    "service providers",
    "processors",
    "partners",
    "recipients",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R4 and return a deterministic verdict.

    Checks, each one built only where the evidence to decide it exists:
      - a consent mechanism exists at the point of collection
      - no consent checkbox or opt-in is pre-checked
      - consent is granular, more than one purpose-specific choice
      - every consent request names the purpose it covers
      - a consent banner is shown where cookies or trackers are in play
      - refusing on that banner is as easy as accepting
      - the banner offers a per-purpose choice
      - no third party tracker fires before the visitor chooses
      - no cookie beyond the strictly necessary is set before that choice
      - marketing consent is taken separately from accepting the terms
      - onward sharing to third party hosts is disclosed in the notice
      - a withdrawal mechanism exists
      - consent is checked in code before the data is processed or stored
      - the consent event itself is recorded: who, when, for what

    Note: s.6(1) requires consent to be free, specific, informed and
    unambiguous, and requires it before the processing rather than after.
    A tracker that has already fired cannot have been consented to, which
    makes the pre-consent network evidence the single most load-bearing
    signal a crawl can produce. A pre-checked box fails 'free'. A single
    blanket box fails 'specific'. The server-side check matters just as
    much as any of them: a UI checkbox that no backend code reads is
    decoration, and flows.has_consent_check is where that shows up.
    """
    flows = flows or []
    checks: list[RuleCheck] = []
    notes: list[str] = []

    if web_result is None and code_result is None and not flows:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason="No web, code or data flow evidence was supplied.",
        )

    web_seen = ev.web_observable(web_result)
    if web_result is not None and not web_seen and code_result is None and not flows:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=ev.crawl_blocked_reason(web_result),
        )

    controls = _controls(web_result)
    forms = ev.collecting_forms(web_result)
    banner = ev.consent_banner(web_result)

    if web_seen:
        checks.append(_mechanism_check(controls, forms, banner))
        checks.append(_pre_checked_check(controls))
        checks.append(_granularity_check(controls, banner))
        checks.extend(_purpose_limitation_checks(controls, banner))
        checks.extend(_banner_checks(web_result, banner))
        checks.extend(_pre_consent_checks(web_result))
        checks.extend(_payload_checks(web_result))
        checks.extend(_marketing_checks(web_result))
        checks.extend(_sharing_checks(web_result, notes))
        # Two things the host and URL evidence above cannot say on its own: a
        # first party name that resolves to somebody else's tracker, and a
        # first party endpoint forwarding onward from the server where no
        # browser can follow.
        for disclosure in (
            ev.cname_cloaking_note(web_result),
            ev.server_side_tagging_note(web_result),
        ):
            if disclosure:
                notes.append(disclosure)
    elif web_result is not None:
        notes.append(ev.crawl_blocked_reason(web_result))
    else:
        notes.append(
            "No web scan was supplied, so the collection interface checks for a consent "
            "control, pre-checking, granularity, the banner, pre-consent tracking and onward "
            "sharing were not assessed."
        )

    checks.append(
        _withdrawal_check(web_result, code_result, ev.crawl_was_blocked(web_result))
    )

    if flows or code_result is not None:
        checks.append(_server_side_check(flows, code_result, notes))
    else:
        notes.append(
            "Neither a code scan nor PII flow paths were supplied, so whether consent is "
            "enforced server side was not assessed and is excluded from this score."
        )

    if code_result is not None:
        checks.append(_record_check(code_result))
    else:
        notes.append(
            "No code scan was supplied, so whether the consent event itself is recorded was "
            "not assessed and is excluded from this score."
        )

    override = None
    fired = ev.trackers_before_consent(web_result)
    if fired:
        # s.6(1) requires the consent before the processing, not around it. A
        # third party tracker that has already fired has already processed the
        # visitor's data, so this is a completed breach rather than a defective
        # safeguard, and averaging it against the checks that passed would
        # understate it. Deliberately limited to requests the scanner saw fire
        # before any choice, that went to a third party, and that it could
        # categorise as a tracker: all three, or it is not graded this way.
        first = f"{fired[0].host} ({fired[0].tracker_category})"
        if fired[0].cname_cloaked and fired[0].cname_target:
            # Naming it as an ordinary third party host would lose the point:
            # the host belongs to the site and points somewhere else.
            first = f"{first}, a first party name resolving to {fired[0].cname_target}"
        override = (
            f"{len(fired)} third party tracker request(s) fired before the visitor was given any "
            f"choice, the first to {first}, and s.6(1) "
            "requires consent to precede the processing."
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
        override_reason=override,
    )


def _controls(web_result) -> list[tuple[str, ConsentElement]]:
    """Every consent control found, each labelled with where it sits.

    A consent element inside a form and a standalone marketing opt-in are the
    same kind of control for s.6 purposes, and a pre-ticked box is no more valid
    for sitting outside a form, so both are graded together. Deduplicated on
    field name, because an opt-in that sits inside a scanned form is reported in
    both lists.
    """
    controls: list[tuple[str, ConsentElement]] = []
    seen: set[str] = set()
    for form, element in ev.consent_elements(web_result):
        controls.append((f"the form posting to {form.action}", element))
        seen.add(ev.normalise(element.field_name))
    for element in ev.marketing_optins(web_result):
        key = ev.normalise(element.field_name)
        if key in seen:
            continue
        seen.add(key)
        controls.append(("the marketing opt-in block", element))
    return controls


def _mechanism_check(controls, forms, banner) -> RuleCheck:
    if not controls:
        if banner is not None and banner.present:
            return RuleCheck(
                name="consent_mechanism_present",
                passed=True,
                detail=(
                    "no consent element on any form, but a consent banner is shown at "
                    f"{banner.selector or 'an unnamed selector'} offering "
                    f'"{banner.accept_label or "accept"}"'
                ),
            )
        if forms:
            actions = ev.join_names([form.action for form in forms])
            detail = (
                f"{len(forms)} form(s) collect personal data with no consent element on any "
                f"of them (forms posting to {actions})"
            )
        else:
            detail = "no consent element and no data collecting form found in the crawl"
        return RuleCheck(name="consent_mechanism_present", passed=False, detail=detail)

    where, element = controls[0]
    placement = (
        "beside the submit control" if element.near_submit else "away from the submit control"
    )
    detail = f'consent element "{element.field_name}" present {placement} on {where}'
    return RuleCheck(name="consent_mechanism_present", passed=True, detail=detail)


def _pre_checked_check(controls) -> RuleCheck:
    pre_checked = [(where, element) for where, element in controls if element.pre_checked]
    if pre_checked:
        # s.6(1) requires consent to be free. A box the Data Principal has to
        # untick is an opt out, which is not a free act of giving consent.
        rendered = "; ".join(
            f'consent checkbox "{element.field_name}" pre-checked on {where}'
            for where, element in pre_checked
        )
        return RuleCheck(name="no_pre_checked_consent", passed=False, detail=rendered)
    if not controls:
        return RuleCheck(
            name="no_pre_checked_consent",
            passed=False,
            detail="no consent element exists, so no freely given consent is captured at all",
        )
    names = ev.join_names([element.field_name for _, element in controls])
    return RuleCheck(
        name="no_pre_checked_consent",
        passed=True,
        detail=f"none of the {len(controls)} consent element(s) are pre-checked ({names})",
    )


def _granularity_check(controls, banner) -> RuleCheck:
    names = list(dict.fromkeys(element.field_name for _, element in controls))
    if len(names) >= 2:
        return RuleCheck(
            name="consent_granular",
            passed=True,
            detail=(
                f"{len(names)} purpose specific consent choices offered "
                f"({ev.join_names(names)})"
            ),
        )
    if len(names) == 1:
        where, element = controls[0]
        if banner is not None and banner.present and banner.has_granular_options:
            return RuleCheck(
                name="consent_granular",
                passed=True,
                detail=(
                    f'one consent element "{element.field_name}" on {where}, with per-purpose '
                    "choices also offered on the consent banner"
                ),
            )
        return RuleCheck(
            name="consent_granular",
            passed=False,
            detail=(
                f'single blanket consent element "{element.field_name}" on '
                f'{where} covers every purpose at once; label reads "{element.label_text}"'
            ),
        )
    if banner is not None and banner.present and banner.has_granular_options:
        return RuleCheck(
            name="consent_granular",
            passed=True,
            detail=(
                "no consent element on any form, but the consent banner offers per-purpose "
                f"choices at {banner.selector or 'an unnamed selector'}"
            ),
        )
    return RuleCheck(
        name="consent_granular",
        passed=False,
        detail="no consent choices offered, so consent cannot be specific to a purpose",
    )


def _purpose_limitation_checks(controls, banner) -> list[RuleCheck]:
    """s.6(1) consent covers a stated purpose, so the request has to state one."""
    labelled = [(where, element) for where, element in controls if element.label_text]
    if not labelled:
        return []
    vague = [
        (where, element)
        for where, element in labelled
        if not _names_a_purpose(element.label_text)
    ]
    if not vague:
        named = ev.join_names([element.label_text for _, element in labelled], limit=3)
        return [
            RuleCheck(
                name="consent_purpose_limitation_stated",
                passed=True,
                detail=(
                    f"each of the {len(labelled)} consent request(s) names the purpose it covers "
                    f"({named})"
                ),
            )
        ]
    first_where, first_element = vague[0]
    if banner is not None and banner.present and banner.has_granular_options:
        # Per-purpose banner options do state the purposes, even where a form
        # label is vague, so this is reported without being graded twice.
        return [
            RuleCheck(
                name="consent_purpose_limitation_stated",
                passed=True,
                detail=(
                    f"{len(vague)} consent label(s) name no purpose "
                    f'("{first_element.label_text}" on {first_where}), but the consent banner '
                    "offers per-purpose choices that state them"
                ),
            )
        ]
    rendered = "; ".join(
        f'"{element.label_text}" on {where}' for where, element in vague[:3]
    )
    return [
        RuleCheck(
            name="consent_purpose_limitation_stated",
            passed=False,
            detail=(
                f"{len(vague)} of {len(labelled)} consent request(s) name no purpose, so consent "
                f"is not limited to one: {rendered}"
            ),
        )
    ]


def _names_a_purpose(label: str | None) -> bool:
    lowered = (label or "").lower()
    return any(marker in lowered for marker in _PURPOSE_LABEL_MARKERS)


def _banner_checks(web_result, banner) -> list[RuleCheck]:
    """Banner presence, refusal parity and per-purpose choice, s.6(1) and s.6(4)."""
    cookie_count = len(web_result.cookies)
    request_count = len(web_result.network_requests)
    something_to_consent_to = cookie_count > 0 or request_count > 0

    if banner is None or not banner.present:
        if not something_to_consent_to:
            # Nothing was observed that would need a banner, so a missing banner
            # is not a finding this evidence supports.
            return []
        reported = (
            "the scanner found no consent banner"
            if banner is not None
            else "no consent banner was captured"
        )
        return [
            RuleCheck(
                name="consent_banner_present",
                passed=False,
                detail=(
                    f"{reported} on {web_result.entry_url}, yet the page set {cookie_count} "
                    f"cookie(s) and made {request_count} request(s), so processing starts with no "
                    "choice offered at all"
                ),
            )
        ]

    checks = [
        RuleCheck(
            name="consent_banner_present",
            passed=True,
            detail=(
                f"consent banner shown on {web_result.entry_url} at "
                f"{banner.selector or 'an unnamed selector'}, accept control labelled "
                f'"{banner.accept_label or "not captured"}"'
            ),
        ),
        _reject_parity_check(web_result, banner),
        _banner_granularity_check(web_result, banner),
    ]
    return checks


def _reject_parity_check(web_result, banner) -> RuleCheck:
    accept = banner.accept_label or "accept"
    reject = banner.reject_label or "not captured"
    if banner.has_reject and _is_a_refusal(banner.reject_label):
        return RuleCheck(
            name="reject_as_easy_as_accept",
            passed=True,
            detail=(
                f'consent banner on {web_result.entry_url} offers "{reject}" alongside '
                f'"{accept}", so refusing takes the same one action as accepting'
            ),
        )
    if banner.has_reject:
        return RuleCheck(
            name="reject_as_easy_as_accept",
            passed=False,
            detail=(
                f'the second control on the consent banner is labelled "{reject}" rather than a '
                f'refusal, while "{accept}" accepts everything in one click; s.6(4) requires '
                "refusing to be as easy as giving consent"
            ),
        )
    if banner.has_manage_link:
        return RuleCheck(
            name="reject_as_easy_as_accept",
            passed=False,
            detail=(
                f'the consent banner on {web_result.entry_url} accepts everything with "{accept}" '
                "but offers no refuse control, only a manage link that opens a second screen; "
                "s.6(4) requires refusing to be as easy as giving consent"
            ),
        )
    return RuleCheck(
        name="reject_as_easy_as_accept",
        passed=False,
        detail=(
            f'the consent banner on {web_result.entry_url} offers "{accept}" and no way to '
            "refuse at all, so consent is not free within the meaning of s.6(1)"
        ),
    )


def _is_a_refusal(label: str | None) -> bool:
    """A captured label has to read as a refusal, not as "manage my settings"."""
    if not label:
        # The scanner flagged a refuse control without capturing its text. Take
        # the flag at face value rather than inventing a failure from silence.
        return True
    lowered = label.lower()
    return any(marker in lowered for marker in _REJECT_LABEL_MARKERS)


def _banner_granularity_check(web_result, banner) -> RuleCheck:
    if banner.has_granular_options:
        return RuleCheck(
            name="banner_offers_per_purpose_choice",
            passed=True,
            detail=(
                f"consent banner on {web_result.entry_url} lets the visitor choose per purpose "
                "rather than accepting every category at once"
            ),
        )
    if banner.has_manage_link:
        return RuleCheck(
            name="banner_offers_per_purpose_choice",
            passed=False,
            detail=(
                f"consent banner on {web_result.entry_url} offers only a manage link and no "
                "per-purpose choice on the banner itself, so consent is taken for every purpose "
                "in one act; s.6(1) requires it to be specific"
            ),
        )
    return RuleCheck(
        name="banner_offers_per_purpose_choice",
        passed=False,
        detail=(
            f"consent banner on {web_result.entry_url} takes a single all-or-nothing choice with "
            "no per-purpose option, so consent cannot be specific as s.6(1) requires"
        ),
    )


def _pre_consent_checks(web_result) -> list[RuleCheck]:
    """The highest value web evidence there is: processing that precedes consent."""
    checks: list[RuleCheck] = []

    if web_result.network_requests:
        fired = ev.trackers_before_consent(web_result)
        if fired:
            rendered = ev.join_names(
                [ev.request_label(request) for request in fired],
                limit=4,
            )
            checks.append(
                RuleCheck(
                    name="no_tracker_before_consent",
                    passed=False,
                    detail=(
                        f"{len(fired)} third party tracker request(s) fired on "
                        f"{web_result.entry_url} before the visitor chose anything: {rendered}; "
                        f"first one was {fired[0].method} {fired[0].url}; s.6(1) requires consent "
                        "to precede the processing, so a tracker that has already fired cannot "
                        "have been consented to"
                    ),
                )
            )
        else:
            hosts = ev.third_party_hosts(web_result)
            checks.append(
                RuleCheck(
                    name="no_tracker_before_consent",
                    passed=True,
                    detail=(
                        f"none of the {len(web_result.network_requests)} request(s) observed on "
                        f"{web_result.entry_url} carried a third party tracker before the visitor "
                        f"chose ({len(hosts)} third party host(s) contacted in total)"
                    ),
                )
            )

    if web_result.cookies:
        early = ev.unconsented_cookies(web_result)
        if early:
            rendered = ev.join_names(
                [
                    f'"{cookie.name}" on {cookie.domain} '
                    f"({cookie.classification or 'classification not reported'})"
                    for cookie in early
                ],
                limit=4,
            )
            checks.append(
                RuleCheck(
                    name="no_cookie_before_consent",
                    passed=False,
                    detail=(
                        f"{len(early)} cookie(s) beyond the strictly necessary were written on "
                        f"{web_result.entry_url} before any choice was made: {rendered}"
                    ),
                )
            )
        else:
            necessary = [
                cookie.name
                for cookie in web_result.cookies_before_consent
            ]
            if necessary:
                detail = (
                    f"the only cookie(s) set before a choice was made on {web_result.entry_url} "
                    f"are classified strictly necessary ({ev.join_names(necessary)})"
                )
            else:
                detail = (
                    f"none of the {len(web_result.cookies)} cookie(s) observed on "
                    f"{web_result.entry_url} were written before the visitor made a choice"
                )
            checks.append(
                RuleCheck(name="no_cookie_before_consent", passed=True, detail=detail)
            )

    return checks


def _payload_checks(web_result) -> list[RuleCheck]:
    """What the bodies going to a third party actually carried.

    A URL on its own turns a beacon carrying an email address into "a beacon
    was sent". Only bodies sent to a third party are graded: a body posted to
    the site's own server is the service working, and grading it would turn
    every login form into a finding.

    Both sides of this check are bounded by what was read. It is only raised
    where a third party body was actually inspected, so a pass says the bodies
    that were read carried nothing recognised, not that nothing was ever sent.
    """
    inspected = [
        request
        for request in web_result.network_requests
        if request.payload_captured and request.is_third_party
    ]
    if not inspected:
        return []

    carrying = [request for request in inspected if request.payload_pii]
    if not carrying:
        return [
            RuleCheck(
                name="no_personal_data_in_third_party_payload",
                passed=True,
                detail=(
                    f"{len(inspected)} request body(ies) sent to a third party from "
                    f"{web_result.entry_url} were read, and none carried a category of personal "
                    "data this scanner recognises"
                ),
            )
        ]

    categories = ev.payload_pii_categories(carrying)
    rendered = ev.join_names([ev.payload_pii_label(request) for request in carrying], limit=3)
    early = [request for request in carrying if request.before_consent]
    timing = (
        f"; {len(early)} of them were sent before the visitor chose anything" if early else ""
    )
    return [
        RuleCheck(
            name="no_personal_data_in_third_party_payload",
            passed=False,
            detail=(
                f"{len(carrying)} of {len(inspected)} request body(ies) sent to a third party "
                f"carried personal data ({ev.join_names(categories, limit=6)}): {rendered}"
                f"{timing}; the category and a redacted indicator are recorded, and the values "
                "themselves are not kept by the scanner"
            ),
        )
    ]


def _marketing_checks(web_result) -> list[RuleCheck]:
    """Marketing consent bundled into accepting the terms is not freely given."""
    optins = ev.marketing_optins(web_result)
    if not optins:
        return []
    bundled = [
        element
        for element in optins
        if _bundles_terms(element.label_text)
    ]
    if bundled:
        rendered = "; ".join(
            f'"{element.field_name}" reads "{element.label_text}"' for element in bundled[:3]
        )
        return [
            RuleCheck(
                name="marketing_consent_separate_from_terms",
                passed=False,
                detail=(
                    f"{len(bundled)} of {len(optins)} marketing opt-in(s) take marketing consent "
                    f"in the same control as accepting the terms: {rendered}; refusing marketing "
                    "would mean refusing the service, so that consent is not free under s.6(1)"
                ),
            )
        ]
    return [
        RuleCheck(
            name="marketing_consent_separate_from_terms",
            passed=True,
            detail=(
                f"{len(optins)} marketing opt-in(s) are taken separately from accepting the terms "
                f"({ev.join_names([element.field_name for element in optins])})"
            ),
        )
    ]


def _bundles_terms(label: str | None) -> bool:
    lowered = (label or "").lower()
    if not any(marker in lowered for marker in _TERMS_BUNDLE_MARKERS):
        return False
    return any(marker in lowered for marker in _MARKETING_MARKERS)


def _sharing_checks(web_result, notes) -> list[RuleCheck]:
    """Onward sharing, counting recipients of personal data and nothing else.

    A recipient is a third party the visitor's data actually reached. A script,
    font or stylesheet CDN is not one: it hands the page a file. Counting every
    host the page touched put jsdelivr and Google Fonts in the finding as
    undisclosed recipients of personal data, which is an assertion the evidence
    never supported. The split is stated in the evidence so a reviewer can see
    which host was treated as which, and an unknown host is still a recipient.
    """
    recipients = ev.data_recipient_hosts(web_result)
    assets = ev.asset_hosts(web_result)
    siblings = ev.same_operator_hosts(web_result)
    asset_note = (
        f" A further {len(assets)} third party host(s) were contacted only to fetch static "
        f"assets ({ev.join_names(assets, limit=5)}); a script, font or stylesheet CDN delivers "
        "the page rather than receiving personal data, so it is not counted as a recipient."
        if assets
        else ""
    )
    # Named rather than merged. Ownership is not observable from a page, so the
    # claim stays as weak as the evidence for it and a reviewer can disagree.
    sibling_note = (
        f" {len(siblings)} further host(s) carry the site's own brand under a different domain "
        f"({ev.join_names(siblings, limit=5)}) and none of them was classified as a tracker, so "
        "they read as another domain of the same operator rather than an external recipient; "
        "this is inferred from the name, not established, and a reviewer can confirm it from "
        "the registration."
        if siblings
        else ""
    )

    if not recipients:
        if assets or siblings:
            observed = ev.join_names(assets + siblings, limit=5)
            notes.append(
                f"Every third party host contacted from {web_result.entry_url} was a static "
                f"asset host or a domain carrying the site's own brand ({observed}), so no "
                "disclosure of personal data to a third party recipient was observed and onward "
                f"sharing was not graded.{sibling_note}"
            )
        return []

    rendered = ev.join_names(recipients, limit=5)
    body = ev.notice_text(web_result)
    if not body:
        notes.append(
            f"Personal data reached {len(recipients)} distinct third party host(s) ({rendered}), "
            "but no notice text was captured to check that against, so onward sharing was not "
            f"graded.{asset_note}{sibling_note}"
        )
        return []
    lowered = body.lower()
    if any(marker in lowered for marker in _SHARING_MARKERS):
        return [
            RuleCheck(
                name="third_party_sharing_disclosed",
                passed=True,
                detail=(
                    f"the page sent data to {len(recipients)} distinct third party host(s) "
                    f"acting as recipients of personal data ({rendered}) and the notice "
                    f"discloses sharing with other recipients.{asset_note}{sibling_note}"
                ),
            )
        ]
    return [
        RuleCheck(
            name="third_party_sharing_disclosed",
            passed=False,
            detail=(
                f"the page sent data to {len(recipients)} distinct third party host(s) acting "
                f"as recipients of personal data ({rendered}) while the notice never mentions "
                "sharing, third parties or processors, so the consent obtained cannot have been "
                f"informed under s.6(1).{asset_note}{sibling_note}"
            ),
        )
    ]


def _withdrawal_check(web_result, code_result, crawl_blocked=False) -> RuleCheck:
    links = ev.find_links(web_result, _WITHDRAWAL_KEYWORDS)
    if links:
        return RuleCheck(
            name="withdrawal_mechanism_present",
            passed=True,
            detail=f"consent withdrawal reachable from {ev.join_names(links)}",
        )
    routes = ev.find_routes(code_result, _WITHDRAWAL_KEYWORDS)
    if routes:
        route = routes[0]
        return RuleCheck(
            name="withdrawal_mechanism_present",
            passed=True,
            detail=(
                f"withdrawal endpoint {route.http_method} {route.path} handled by "
                f"{route.handler_name} at {ev.loc(route.file_path, route.line_number)}"
            ),
            file_path=route.file_path,
            line_number=route.line_number,
        )
    symbols = ev.find_symbols(code_result, _WITHDRAWAL_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="withdrawal_mechanism_present",
            passed=True,
            detail=(
                f"withdrawal handled by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    searched = (
        "no withdrawal route or handler found in the code, and the crawl was blocked so the "
        "published site could not be searched for one"
        if crawl_blocked
        else "no withdrawal route, handler or link found"
    )
    return RuleCheck(
        name="withdrawal_mechanism_present",
        passed=False,
        detail=(
            f"{searched}; s.6(4) requires withdrawal to be as easy as giving consent was"
        ),
    )


def _server_side_check(flows, code_result, notes) -> RuleCheck:
    if flows:
        unchecked = ev.flows_without(flows, "has_consent_check")
        if unchecked:
            rendered = "; ".join(ev.flow_label(flow) for flow in unchecked[:3])
            suffix = f" and {len(unchecked) - 3} more" if len(unchecked) > 3 else ""
            return RuleCheck(
                name="consent_enforced_server_side",
                passed=False,
                detail=(
                    f"{len(unchecked)} of {len(flows)} personal data flows reach a sink with no "
                    f"consent check on the path: {rendered}{suffix}"
                ),
            )
        return RuleCheck(
            name="consent_enforced_server_side",
            passed=True,
            detail=(
                f"all {len(flows)} personal data flow(s) pass a consent check before the sink, "
                f"including {ev.flow_label(flows[0])}"
            ),
        )

    notes.append("No PII flow paths were supplied, so the server side check fell back to symbol names.")
    symbols = ev.find_symbols(code_result, _CONSENT_CODE_KEYWORDS)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name="consent_enforced_server_side",
            passed=True,
            detail=(
                f"consent is read server side by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    return RuleCheck(
        name="consent_enforced_server_side",
        passed=False,
        detail=(
            "no server side consent check found before personal data is processed or stored, so "
            "any consent control in the interface is decoration"
        ),
    )


def _record_check(code_result) -> RuleCheck:
    models = ev.find_models(code_result, _CONSENT_RECORD_KEYWORDS)
    if not models:
        return RuleCheck(
            name="consent_event_recorded",
            passed=False,
            detail=(
                f"no consent record table found across {len(code_result.db_models)} model(s); "
                "who consented, when and for what is not stored"
            ),
        )

    model = models[0]
    column_names = tuple(column.name for column in model.columns)
    missing = []
    if not any(ev.matches(name, _SUBJECT_COLUMNS) for name in column_names):
        missing.append("who consented")
    if not any(ev.matches(name, _TIMESTAMP_COLUMNS) for name in column_names):
        missing.append("when")
    if not any(ev.matches(name, _PURPOSE_COLUMNS) for name in column_names):
        missing.append("for what purpose")

    location = ev.loc(model.file_path, model.line_number)
    if missing:
        return RuleCheck(
            name="consent_event_recorded",
            passed=False,
            detail=(
                f"consent record {model.class_name} at {location} does not capture "
                f"{ev.join_names(missing)}; columns present are {ev.join_names(list(column_names), limit=6)}"
            ),
            file_path=model.file_path,
            line_number=model.line_number,
        )
    return RuleCheck(
        name="consent_event_recorded",
        passed=True,
        detail=(
            f"consent record {model.class_name} at {location} captures the subject, the time "
            "and the purpose of each consent event"
        ),
        file_path=model.file_path,
        line_number=model.line_number,
    )
