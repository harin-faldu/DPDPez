"""R3 Notice, DPDP Act s.5; Rule 3.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R3"
RULE_NAME = "Notice"
DPDP_SECTION = "s.5"
DPDP_RULE = "Rule 3"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# rule_9 is included because the grievance and DPO contact this rule looks for in
# the notice is the same contact Rules 2025 rule_9 requires to be published.
# rule_3 sets notice content; rule_9 requires publishing the contact point a
# notice must name.
RETRIEVAL_SECTION_IDS: list[str] = ["s.5", "rule_3", "rule_9"]

# Distinct processing purposes a notice can name. Itemised means more than one of
# these is present, which is the difference between a real notice and a sentence
# saying data is collected "for business purposes".
_PURPOSE_MARKERS: tuple[str, ...] = (
    "account creation",
    "registration",
    "authentication",
    "marketing",
    "promotional",
    "newsletter",
    "analytics",
    "personalisation",
    "personalization",
    "payment",
    "billing",
    "invoice",
    "delivery",
    "shipping",
    "customer support",
    "customer service",
    "fraud",
    "legal obligation",
    "regulatory",
    "research",
)

_GRIEVANCE_MARKERS: tuple[str, ...] = (
    "grievance officer",
    "grievance redressal",
    "data protection officer",
    "privacy officer",
    "nodal officer",
)

# Phrases that state how long personal data is kept. s.8(7) requires erasure
# once the purpose is served, and a notice that never says for how long leaves
# the Data Principal unable to tell whether that has happened.
_RETENTION_MARKERS: tuple[str, ...] = (
    "retention period",
    "retention periods",
    "retention policy",
    "we retain",
    "we will retain",
    "is retained",
    "are retained",
    "retained for",
    "retained until",
    "how long we keep",
    "how long we store",
    "we keep your",
    "stored for",
    "deleted after",
    "erased after",
    "erase your data",
)

# Rule 3 requires the notice to tell the Data Principal how to complain to the
# Board, which is a different thing from naming an internal grievance officer.
_BOARD_MARKERS: tuple[str, ...] = (
    "data protection board",
    "complaint to the board",
    "complain to the board",
    "the board of india",
    "dpbi",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R3 and return a deterministic verdict.

    Checks:
      - privacy notice exists and is reachable, by link or conventional path
      - notice is available before collection, not only in the footer
      - notice itemises the purposes of processing
      - notice states how long personal data is kept
      - notice tells the Data Principal how to complain to the Board
      - notice names a grievance officer or DPO contact

    Note: Rule 3 is about timing as much as existence. A notice that only
    appears in the footer after a form has been submitted does not meet
    'before collection', and a policy the crawler only found by probing
    /privacy-policy is reachable without being presented, so existence and
    timing stay two separate checks.
    """
    if web_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "No web scan was run, and a published notice under s.5 is served to the "
                "Data Principal rather than stored in the repository, so a code only scan "
                "cannot confirm or deny it."
            ),
        )

    if not ev.web_observable(web_result):
        # Every check in this rule reads the published site. Grading a blocked
        # crawl would report a site with no notice at all, which is a finding the
        # evidence does not support.
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=ev.crawl_blocked_reason(web_result),
        )

    checks: list[RuleCheck] = []
    notes: list[str] = []
    notice = web_result.privacy_notice
    policy = ev.policy_document(web_result, "privacy")

    checks.append(_reachable_check(web_result, notice, policy))
    checks.append(_timing_check(web_result, notice, policy))

    body = ev.notice_text(web_result)
    where = ev.notice_url(web_result) or web_result.entry_url
    if body:
        checks.append(_purpose_check(body, where))
        checks.append(_retention_check(body, where))
        checks.append(_board_complaint_check(body, where))
    else:
        notes.append(
            "Notice body text was not captured by the crawl, so itemisation of purposes, the "
            "retention period and the route to the Board were not assessed and are excluded "
            "from this score rather than failed."
        )

    checks.append(_contact_check(web_result, body, where))

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
    )


def _reachable_check(web_result, notice, policy) -> RuleCheck:
    """Reachable by a link or by a conventional path both count as published."""
    if notice is not None and notice.reachable:
        return RuleCheck(
            name="notice_exists_and_reachable",
            passed=True,
            detail=f'privacy notice reachable at {notice.url} (link text "{notice.link_text}")',
        )
    if policy is not None:
        via = (
            "found by probing a conventional path rather than from any link on the site"
            if policy.discovered_via != "link"
            else "found from a link on the site"
        )
        return RuleCheck(
            name="notice_exists_and_reachable",
            passed=True,
            detail=(
                f"privacy policy reachable at {policy.url}, {via}, "
                f"{policy.word_count} word(s) long"
            ),
        )
    if notice is not None and not notice.reachable:
        return RuleCheck(
            name="notice_exists_and_reachable",
            passed=False,
            detail=(
                f'privacy notice link "{notice.link_text}" points at {notice.url} '
                "but the page did not load during the crawl"
            ),
        )
    return RuleCheck(
        name="notice_exists_and_reachable",
        passed=False,
        detail=(
            f"no privacy notice link found anywhere on {web_result.entry_url} and no policy at "
            "a conventional path such as /privacy-policy responded"
        ),
    )


def _timing_check(web_result, notice, policy) -> RuleCheck:
    """s.5 requires the notice before collection, not merely somewhere on the site."""
    form_count = len(ev.collecting_forms(web_result))
    if notice is not None and notice.reachable and not notice.in_footer_only:
        return RuleCheck(
            name="notice_before_collection",
            passed=True,
            detail=(
                f"privacy notice at {notice.url} is linked outside the footer and is reachable "
                "before the collection forms are submitted"
            ),
        )
    if (
        policy is not None
        and policy.discovered_via == "link"
        and policy.linked_from_homepage
        and not policy.in_footer_only
    ):
        return RuleCheck(
            name="notice_before_collection",
            passed=True,
            detail=(
                f"privacy policy at {policy.url} is linked from the homepage outside the footer, "
                f"so it is presented before the {form_count} data collecting form(s) found"
            ),
        )
    if notice is not None and notice.in_footer_only:
        return RuleCheck(
            name="notice_before_collection",
            passed=False,
            detail=(
                f"privacy notice at {notice.url} is linked only from the page footer, so it is "
                f"not presented before collection on the {form_count} data collecting form(s) found"
            ),
        )
    if policy is not None:
        reason = (
            "only reachable by probing a conventional path, so nothing on the site presents it"
            if policy.discovered_via != "link"
            else "linked only from the footer, so it comes after collection"
        )
        return RuleCheck(
            name="notice_before_collection",
            passed=False,
            detail=(
                f"privacy policy at {policy.url} is {reason}; the {form_count} data collecting "
                "form(s) found are reached without it"
            ),
        )
    return RuleCheck(
        name="notice_before_collection",
        passed=False,
        detail=(
            f"{form_count} form(s) collect personal data on {web_result.entry_url} with no "
            "notice linked at all, so nothing is presented before collection"
        ),
    )


def _purpose_check(body: str, where: str) -> RuleCheck:
    lowered = body.lower()
    found = [marker for marker in _PURPOSE_MARKERS if marker in lowered]
    mentions_purpose = "purpose" in lowered
    itemised = mentions_purpose and len(found) >= 2
    if itemised:
        detail = (
            f"privacy notice at {where} itemises processing purposes "
            f"(found: {ev.join_names(found)})"
        )
    elif not mentions_purpose:
        detail = (
            f"privacy notice body at {where} never uses the word 'purpose', so the "
            "purposes of processing required by s.5(1)(i) are not stated"
        )
    else:
        named = ev.join_names(found) if found else "none"
        detail = (
            f"privacy notice at {where} mentions purpose but names only "
            f"{len(found)} identifiable processing purpose(s) ({named}); s.5(1)(i) "
            "requires the purposes to be itemised, not stated as a single blanket purpose"
        )
    return RuleCheck(name="purposes_itemised", passed=itemised, detail=detail)


def _retention_check(body: str, where: str) -> RuleCheck:
    lowered = body.lower()
    found = [marker for marker in _RETENTION_MARKERS if marker in lowered]
    if found:
        return RuleCheck(
            name="retention_stated_in_notice",
            passed=True,
            detail=(
                f"privacy notice at {where} states how long personal data is kept "
                f'(wording found: "{found[0]}")'
            ),
        )
    return RuleCheck(
        name="retention_stated_in_notice",
        passed=False,
        detail=(
            f"privacy notice at {where} never states a retention period or when data is erased; "
            "s.8(7) requires erasure once the purpose is served, which the Data Principal cannot "
            "check against a notice that is silent on how long data is kept"
        ),
    )


def _board_complaint_check(body: str, where: str) -> RuleCheck:
    lowered = body.lower()
    found = [marker for marker in _BOARD_MARKERS if marker in lowered]
    if found:
        return RuleCheck(
            name="board_complaint_route_stated",
            passed=True,
            detail=(
                f"privacy notice at {where} tells the Data Principal how to reach the Data "
                f'Protection Board (wording found: "{found[0]}")'
            ),
        )
    return RuleCheck(
        name="board_complaint_route_stated",
        passed=False,
        detail=(
            f"privacy notice at {where} never mentions the Data Protection Board, so it does not "
            "tell the Data Principal how to make a complaint to the Board as Rule 3 requires; "
            "naming an internal grievance officer is not the same thing"
        ),
    )


def _contact_check(web_result, body: str, where: str) -> RuleCheck:
    """Rule 9 requires the contact answering processing questions to be published."""
    dpo = ev.dpo_contact(web_result)
    if dpo:
        return RuleCheck(
            name="grievance_contact_named",
            passed=True,
            detail=(
                f"contact for questions about processing published as {dpo} on "
                f"{web_result.entry_url}, as Rule 9 requires"
            ),
        )
    contact = ev.grievance_contact(web_result)
    if contact:
        return RuleCheck(
            name="grievance_contact_named",
            passed=True,
            detail=f"grievance contact published as {contact} on {web_result.entry_url}",
        )
    body_marker = ev.matches(body, _GRIEVANCE_MARKERS) if body else None
    if body_marker:
        return RuleCheck(
            name="grievance_contact_named",
            passed=True,
            detail=(
                f'privacy notice at {where} names a "{body_marker}" but no contact address '
                "was published in a machine readable place"
            ),
        )
    return RuleCheck(
        name="grievance_contact_named",
        passed=False,
        detail=(
            f"no grievance officer or Data Protection Officer contact found at {where}; "
            "s.5(1)(iii) requires the notice to tell the Data Principal how to complain"
        ),
    )
