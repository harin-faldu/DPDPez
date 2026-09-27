"""R10 Data Principal Rights, DPDP Act s.11-14; Rule 10.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R10"
RULE_NAME = "Data Principal Rights"
DPDP_SECTION = "s.11-14"
DPDP_RULE = "Rule 10"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# The procedure for exercising rights is Rules 2025 rule_12, not rule_10, which
# covers verifiable consent for children.
# Rights of Data Principals is rule_14 in the notified Rules, not rule_12,
# which is child-data exemptions.
RETRIEVAL_SECTION_IDS: list[str] = ["s.11", "s.12", "s.13", "s.14", "rule_14"]

_ACCESS_KEYWORDS: tuple[str, ...] = (
    "download_my_data",
    "download_data",
    "export_data",
    "data_export",
    "my_data",
    "access_request",
    "subject_access",
    "dsar",
)
_ACCESS_FALLBACK: tuple[str, ...] = ("profile", "account", "me")

_CORRECTION_KEYWORDS: tuple[str, ...] = (
    "correction",
    "correct_data",
    "rectify",
    "rectification",
    "update_profile",
    "edit_profile",
    "update_my_data",
)
_CORRECTION_FALLBACK: tuple[str, ...] = ("profile", "account", "user", "users")

_ERASURE_KEYWORDS: tuple[str, ...] = (
    "erase",
    "erasure",
    "delete_account",
    "delete_my_data",
    "forget_me",
    "right_to_be_forgotten",
    "purge_user",
    "remove_my_data",
    "close_account",
)
_ERASURE_FALLBACK: tuple[str, ...] = ("profile", "account", "user", "users", "me")

_NOMINATION_KEYWORDS: tuple[str, ...] = (
    "nominee",
    "nomination",
    "nominate",
    "successor",
    "legal_heir",
)

_GRIEVANCE_KEYWORDS: tuple[str, ...] = (
    "grievance",
    "complaint",
    "redressal",
    "raise_ticket",
    "support_request",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R10 and return a deterministic verdict.

    Checks:
      - an access path exists, s.11
      - a correction path exists, s.12
      - an erasure path exists, s.12(3)
      - a nomination path exists, s.14
      - a grievance redressal path exists, s.13

    Note: Four separate statutory rights, so four separate checks. Partial
    coverage is the common real-world case: most apps have access and
    correction, few have erasure, almost none have nomination. Cite the
    specific section per missing right, not s.11-14 as a block.

    The stub listed erasure against s.13. The Act puts correction and erasure
    together in s.12, with the erasure request in s.12(3), and reserves s.13
    for grievance redressal, so each check cites the section that actually
    grants the right it tests.
    """
    if web_result is None and code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason="No web or code evidence was supplied.",
        )

    crawl_blocked = ev.crawl_was_blocked(web_result)
    if crawl_blocked and code_result is None:
        # A rights link the crawler never reached is not an absent rights link.
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=ev.crawl_blocked_reason(web_result),
        )

    checks: list[RuleCheck] = [
        _right_check(
            web_result,
            code_result,
            name="access_path_exists",
            right="access",
            section="s.11",
            keywords=_ACCESS_KEYWORDS,
            fallback=_ACCESS_FALLBACK,
            fallback_methods=("GET",),
            crawl_blocked=crawl_blocked,
        ),
        _right_check(
            web_result,
            code_result,
            name="correction_path_exists",
            right="correction",
            section="s.12",
            keywords=_CORRECTION_KEYWORDS,
            fallback=_CORRECTION_FALLBACK,
            fallback_methods=("PUT", "PATCH"),
            crawl_blocked=crawl_blocked,
        ),
        _right_check(
            web_result,
            code_result,
            name="erasure_path_exists",
            right="erasure",
            section="s.12(3)",
            keywords=_ERASURE_KEYWORDS,
            fallback=_ERASURE_FALLBACK,
            fallback_methods=("DELETE",),
            crawl_blocked=crawl_blocked,
        ),
        _right_check(
            web_result,
            code_result,
            name="nomination_path_exists",
            right="nomination",
            section="s.14",
            keywords=_NOMINATION_KEYWORDS,
            fallback=(),
            fallback_methods=None,
            crawl_blocked=crawl_blocked,
        ),
        _grievance_check(web_result, code_result, crawl_blocked),
    ]

    notes: list[str] = []
    if crawl_blocked:
        notes.append(ev.crawl_blocked_reason(web_result))
    elif web_result is None:
        notes.append(
            "No web scan was supplied, so each right was looked for in the repository only. A "
            "path offered on the published site would not be visible here."
        )
    elif code_result is None:
        notes.append(
            "No code scan was supplied, so each right was looked for on the published site only. "
            "An endpoint that serves the right without being linked would not be visible here."
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
    )


def _right_check(
    web_result,
    code_result,
    *,
    name,
    right,
    section,
    keywords,
    fallback,
    fallback_methods,
    crawl_blocked=False,
) -> RuleCheck:
    # find_links covers both the links the crawl followed and any policy page it
    # discovered, so a grievance or erasure page found by probing a conventional
    # path counts as a path the Data Principal can reach.
    links = ev.find_links(web_result, keywords)
    if links:
        return RuleCheck(
            name=name,
            passed=True,
            detail=f"{right} right ({section}) offered at {ev.join_names(links)}",
        )

    routes = ev.find_routes(code_result, keywords)
    if routes:
        route = routes[0]
        return RuleCheck(
            name=name,
            passed=True,
            detail=(
                f"{right} right ({section}) served by {route.http_method} {route.path} at "
                f"{ev.loc(route.file_path, route.line_number)}"
            ),
            file_path=route.file_path,
            line_number=route.line_number,
        )

    symbols = ev.find_symbols(code_result, keywords)
    if symbols:
        symbol = symbols[0]
        return RuleCheck(
            name=name,
            passed=True,
            detail=(
                f"{right} right ({section}) implemented by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )

    if fallback and fallback_methods:
        inferred = ev.find_routes(code_result, fallback, methods=fallback_methods)
        if inferred:
            route = inferred[0]
            return RuleCheck(
                name=name,
                passed=True,
                detail=(
                    f"{right} right ({section}) inferred from {route.http_method} {route.path} at "
                    f"{ev.loc(route.file_path, route.line_number)}, which is a generic account "
                    f"endpoint rather than a named {right} request path"
                ),
                file_path=route.file_path,
                line_number=route.line_number,
            )

    searched = (
        "the routes and handlers scanned; the crawl was blocked, so the published site "
        "could not be searched"
        if crawl_blocked
        else "the site links, routes or handlers scanned"
    )
    return RuleCheck(
        name=name,
        passed=False,
        detail=(
            f"no {right} path found in {searched}; {section} "
            f"gives the Data Principal a right to {right} that the system must be able to serve"
        ),
    )


def _grievance_check(web_result, code_result, crawl_blocked=False) -> RuleCheck:
    contact = ev.grievance_contact(web_result) or ev.dpo_contact(web_result)
    if contact:
        return RuleCheck(
            name="grievance_path_exists",
            passed=True,
            detail=(
                f"grievance redressal (s.13) contact published as {contact} "
                f"on {web_result.entry_url}"
            ),
        )
    policy = ev.policy_document(web_result, "grievance")
    if policy is not None:
        return RuleCheck(
            name="grievance_path_exists",
            passed=True,
            detail=(
                f"grievance redressal (s.13) procedure published at {policy.url}, discovered by "
                f"{policy.discovered_via.replace('_', ' ')}"
            ),
        )
    return _right_check(
        web_result,
        code_result,
        name="grievance_path_exists",
        right="grievance redressal",
        section="s.13",
        keywords=_GRIEVANCE_KEYWORDS,
        fallback=(),
        fallback_methods=None,
        crawl_blocked=crawl_blocked,
    )
