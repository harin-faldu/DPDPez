"""Testing what a site says against what it does.

This is why the stages run in order. Stage 1 reads the published notice and
records every assertion as a claim. Stage 2 observes the live site. A claim and
an observation that disagree is a finding neither stage reaches alone: a notice
promising no third party sharing, on a page that loaded eleven trackers before
anyone consented, is not a gap in the notice and not merely a tracker count. It
is a published statement contradicted by the site's own behaviour.

Three outcomes, and the third matters as much as the others:

    supported       the observation bears the claim out
    contradicted    the observation is inconsistent with the claim
    not_observable  this stage cannot see it either way

Silence is not one of them. A claim nobody has tested keeps verification None,
which is how "not looked at yet" stays distinct from "looked and found nothing".
Retention is the clearest case: no crawl can see how long a row survives, so
saying so is the honest answer and the code stage picks it up later.

Pure by construction, so a verdict about a site can be reproduced from stored
evidence without refetching anything.
"""

from app.contracts import PolicyClaim, WebScanResult
from app.scanner.url_guard import registrable_domain

WEB = "web"

SUPPORTED = "supported"
CONTRADICTED = "contradicted"
NOT_OBSERVABLE = "not_observable"

# Claim types a page load can say nothing about. Named rather than left to fall
# through, so the reason is recorded and the code stage knows to pick them up.
_BLIND_TO: dict[str, str] = {
    "retention": (
        "how long a record is kept cannot be seen from a page load; the code "
        "scan reads storage expiry and cleanup jobs"
    ),
    "breach": (
        "breach intimation happens after an incident and leaves no trace on a "
        "page; the code scan reads the notification path"
    ),
    "cross_border": (
        "where data comes to rest is not visible from the browser; a request to "
        "a foreign host shows routing, not storage"
    ),
    "purpose": (
        "whether processing stays within its stated purpose is not observable "
        "from the page"
    ),
}


def verify_against_web(
    claims: list[PolicyClaim], web: WebScanResult | None
) -> list[PolicyClaim]:
    """Return the claims with this stage's verdict recorded on each.

    The claims are copied rather than mutated, so the stage 1 record stays as it
    was read and a disagreement between stages can be shown side by side.
    """
    if web is None:
        return [_copy(c) for c in claims]

    # A blocked crawl observed nothing. Marking claims unsupported on the back
    # of it would turn someone else's bot wall into a finding against the site.
    if web.crawl_blocked:
        return [
            _record(
                c,
                NOT_OBSERVABLE,
                "the crawl was blocked, so nothing on the site was observed",
            )
            for c in claims
        ]

    verified: list[PolicyClaim] = []
    for claim in claims:
        blind = _BLIND_TO.get(claim.claim_type)
        if blind:
            verified.append(_record(claim, NOT_OBSERVABLE, blind))
            continue
        handler = _HANDLERS.get(claim.claim_type)
        verified.append(handler(claim, web) if handler else _copy(claim))
    return verified


def contradictions(claims: list[PolicyClaim]) -> list[PolicyClaim]:
    return [c for c in claims if c.verification == CONTRADICTED]


# ------------------------------------------------------------------ per claim


def _third_party(claim: PolicyClaim, web: WebScanResult) -> PolicyClaim:
    recipients = {registrable_domain(h) for h in web.third_party_hosts}
    trackers = web.trackers_before_consent

    # "We do not share with third parties", tested against what the page did.
    if claim.subject == "no onward sharing" or (claim.value or "").lower() == "none":
        if trackers:
            named = ", ".join(sorted({t.host for t in trackers})[:4])
            return _record(
                claim,
                CONTRADICTED,
                f"the notice states personal data is not shared, yet {len(trackers)} "
                f"third party tracker request(s) fired before any consent was given "
                f"({named})",
            )
        if recipients:
            return _record(
                claim,
                CONTRADICTED,
                "the notice states personal data is not shared, yet the page sent "
                f"requests to {len(recipients)} third party host(s)",
            )
        return _record(
            claim,
            SUPPORTED,
            "no third party request was observed on the scanned pages",
        )

    # A named recipient. Seeing it confirms the disclosure; not seeing it proves
    # nothing, because a processor reached server side never touches the page.
    name = (claim.value or "").strip()
    if not name:
        return _copy(claim)
    match = _hosts_matching(name, web.third_party_hosts)
    if match:
        return _record(
            claim,
            SUPPORTED,
            f"the notice names {name} and the page sent requests to {match[0]}",
        )
    return _record(
        claim,
        NOT_OBSERVABLE,
        f"the notice names {name}, which the page did not contact; a recipient "
        "reached from the server would not appear in a browser scan",
    )


# A brand rarely serves from a host bearing its own name. LinkedIn's pixel is on
# licdn.com, so matching a disclosed recipient by its name token alone reported
# a correctly disclosed processor as never contacted.
_VENDOR_HOSTS: dict[str, tuple[str, ...]] = {
    "linkedin": ("licdn", "linkedin"),
    "google": ("google", "googletagmanager", "doubleclick", "gstatic"),
    "meta": ("facebook", "fbcdn"),
    "facebook": ("facebook", "fbcdn"),
    "microsoft": ("clarity.ms", "bing", "microsoft"),
    "hubspot": ("hs-scripts", "hs-analytics", "hubspot", "hsforms"),
    "adobe": ("omtrdc", "adobedtm", "demdex"),
    "amazon": ("amazon-adsystem", "amazonaws", "media-amazon"),
    "salesforce": ("salesforce", "pardot", "exacttarget"),
    "zendesk": ("zdassets", "zendesk"),
    "intercom": ("intercomcdn", "intercom"),
    "cloudflare": ("cloudflare",),
    "stripe": ("stripe",),
    "razorpay": ("razorpay",),
    "segment": ("segment.io", "segment.com"),
    "mixpanel": ("mxpnl", "mixpanel"),
    "hotjar": ("hotjar",),
    "clevertap": ("clevertap", "wzrk"),
    "moengage": ("moengage",),
    "appsflyer": ("appsflyer",),
    "freshworks": ("freshrelevance", "freshworks", "freshchat"),
}

# Words in a company name that identify nobody.
_NAME_NOISE = frozenset(
    {
        "private", "limited", "ltd", "pvt", "inc", "llc", "llp", "plc", "gmbh",
        "corporation", "corp", "company", "co", "technologies", "technology",
        "solutions", "services", "labs", "systems", "group", "holdings", "the",
        "and", "india", "global", "international", "digital", "software",
    }
)


def _name_tokens(name: str) -> list[str]:
    tokens = [w.strip(".,()").lower() for w in name.split()]
    meaningful = [w for w in tokens if w and w not in _NAME_NOISE and len(w) >= 3]
    return meaningful or [w for w in tokens if w]


def _hosts_matching(name: str, hosts: list[str]) -> list[str]:
    """Hosts that plausibly belong to a named recipient.

    Matches on the brand's known serving domains first, then on any meaningful
    word of the name. Corporate furniture such as "Private Limited" is dropped,
    since matching on it would tie every host to every Indian company.
    """
    needles: set[str] = set()
    for token in _name_tokens(name):
        needles.add(token)
        needles.update(_VENDOR_HOSTS.get(token, ()))
    return [h for h in hosts if any(n in h.lower() for n in needles)]


_RIGHT_WORDS: dict[str, tuple[str, ...]] = {
    "access": ("access", "my data", "download", "copy"),
    "correction": ("correct", "update", "rectif"),
    "erasure": ("delete", "erase", "remove", "close account"),
    "nomination": ("nominee", "nominat"),
    "withdraw_consent": ("withdraw", "preferences", "consent", "opt out", "unsubscribe"),
    "grievance": ("grievance", "complaint", "redress"),
}


def _rights(claim: PolicyClaim, web: WebScanResult) -> PolicyClaim:
    """A right promised in the notice, against a path a visitor could use.

    A right that exists behind a sign in is not visible here, so absence is
    reported as unobservable rather than as a broken promise. The code stage
    answers that one, and calling it a contradiction now would be a guess.
    """
    offered = (claim.value or claim.subject or "").lower()
    links = " ".join(web.rights_links).lower()
    if any(word in links for word in _RIGHT_WORDS.get(offered, (offered,))):
        return _record(
            claim,
            SUPPORTED,
            f"the notice offers {offered} and the site links a path for it",
        )
    if web.rights_links:
        return _record(
            claim,
            NOT_OBSERVABLE,
            f"the notice offers {offered}; the site links rights paths but none "
            "matching it, and a route behind a sign in would not be visible here",
        )
    return _record(
        claim,
        NOT_OBSERVABLE,
        f"the notice offers {offered}; no rights path is linked from the public "
        "pages, though one may exist behind a sign in",
    )


def _contact(claim: PolicyClaim, web: WebScanResult) -> PolicyClaim:
    if web.dpo_contact or web.grievance_contact:
        return _record(
            claim,
            SUPPORTED,
            "the site publishes a contact point for questions about processing",
        )
    return _record(
        claim,
        CONTRADICTED,
        "the notice names a contact channel, but no contact point for processing "
        "questions was found on the scanned pages",
    )


# A notice that only promises not to collect from children "knowingly" is making
# a weaker claim than one setting an age condition, and the two deserve to be
# described differently even though a missing age field undercuts both.
_PASSIVE_AGE_MARKERS = ("knowingly", "unknowingly", "inadvertently", "if we learn", "if we become aware")


def _children(claim: PolicyClaim, web: WebScanResult) -> PolicyClaim:
    """An age claim against whether the site ever asks for an age.

    Two shapes, both undercut by a site that never asks, for different reasons.
    An active condition ("you must be 18") claims an enforcement that is not
    happening. A passive disclaimer ("we do not knowingly collect from under
    13") rests on not knowing, and s.9 conditions the duty on processing a
    child's data rather than on the fiduciary's awareness of it, so declining to
    ask is not a way out.
    """
    if web.age_gate_fields:
        return _record(
            claim,
            SUPPORTED,
            f"the site collects age or date of birth ({web.age_gate_fields[0].name}), "
            "so the stated age condition can be applied at collection",
        )

    passive = any(m in (claim.quote or "").lower() for m in _PASSIVE_AGE_MARKERS)
    if passive:
        return _record(
            claim,
            CONTRADICTED,
            "the notice says it does not knowingly collect from children, but no "
            "age or date of birth field was found, so it never learns a user's "
            "age; s.9 turns on whether a child's data is processed, not on "
            "whether the Data Fiduciary noticed",
        )
    return _record(
        claim,
        CONTRADICTED,
        "the notice states an age condition, but no age or date of birth field "
        "was found on the scanned pages, so nothing checks it at collection",
    )


def _security(claim: PolicyClaim, web: WebScanResult) -> PolicyClaim:
    """Only the transport half is visible. Storage is the code stage's question."""
    haystack = f"{claim.subject or ''} {claim.value or ''}".lower()
    if "encrypt" not in haystack:
        return _record(
            claim,
            NOT_OBSERVABLE,
            "the safeguard described is not observable from a page load; the "
            "code scan reads storage encryption and access control",
        )
    if not web.served_over_https:
        return _record(
            claim,
            CONTRADICTED,
            "the notice claims data is encrypted, yet the site is served over "
            "plain HTTP",
        )
    return _record(
        claim,
        NOT_OBSERVABLE,
        "traffic is encrypted in transit, but the notice's claim is about stored "
        "data, which only the code scan can see",
    )


_HANDLERS = {
    "third_party": _third_party,
    "rights": _rights,
    "contact": _contact,
    "children": _children,
    "security": _security,
}


# ------------------------------------------------------------------- plumbing


def _copy(claim: PolicyClaim) -> PolicyClaim:
    return PolicyClaim(**vars(claim))


def _record(claim: PolicyClaim, verdict: str, detail: str) -> PolicyClaim:
    copied = _copy(claim)
    copied.verified_by = WEB
    copied.verification = verdict
    copied.verification_detail = detail
    return copied
