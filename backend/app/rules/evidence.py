"""Shared evidence lookups for the rule checkers.  OWNER: Prerana

Pure helpers over the scanner contracts. No I/O, no clock, no randomness, and
no mutation of the inputs, so two runs over identical evidence produce
identical verdicts. Every checker builds its detail strings from these so a
finding always carries a file:line or a URL the jury can go and look at.
"""

import re

from app.contracts import (
    CodeScanResult,
    ColumnInfo,
    ConsentBanner,
    ConsentElement,
    CookieInfo,
    DataFlowEdgeInfo,
    FileInfo,
    FormField,
    FormInfo,
    ModelInfo,
    NetworkRequest,
    PIIFlowPathInfo,
    PolicyDocument,
    RouteInfo,
    ScriptInfo,
    SymbolInfo,
    WebScanResult,
)

# Categories the PII taxonomy places in the critical tier. A plaintext column in
# one of these is the difference between a security gap and a bright line breach.
CRITICAL_PII_CATEGORIES: tuple[str, ...] = (
    "aadhaar",
    "pan",
    "passport",
    "financial",
    "biometric",
    "health",
    "password",
)

# Column and field names that imply a critical tier category.
CRITICAL_PII_KEYWORDS: tuple[str, ...] = (
    "aadhaar",
    "aadhar",
    "uidai",
    "pan",
    "pan_number",
    "passport",
    "biometric",
    "fingerprint",
    "face_encoding",
    "iris_scan",
    "bank_account",
    "account_number",
    "card_number",
    "cvv",
    "upi",
    "ifsc",
    "health",
    "medical",
    "diagnosis",
    "password",
    "passwd",
)

PII_COLUMN_KEYWORDS: tuple[str, ...] = CRITICAL_PII_KEYWORDS + (
    "email",
    "phone",
    "mobile",
    "contact_number",
    "address",
    "pincode",
    "postal_code",
    "dob",
    "date_of_birth",
    "birth_date",
    "full_name",
    "first_name",
    "last_name",
    "gender",
    "ip_address",
    "latitude",
    "longitude",
    "gstin",
    "voter_id",
    "salary",
    "income",
)

_KEYWORD_CATEGORY: dict[str, str] = {
    "aadhaar": "aadhaar",
    "aadhar": "aadhaar",
    "uidai": "aadhaar",
    "pan": "pan",
    "pan_number": "pan",
    "passport": "passport",
    "biometric": "biometric",
    "fingerprint": "biometric",
    "face_encoding": "biometric",
    "iris_scan": "biometric",
    "bank_account": "financial",
    "account_number": "financial",
    "card_number": "financial",
    "cvv": "financial",
    "upi": "financial",
    "ifsc": "financial",
    "health": "health",
    "medical": "health",
    "diagnosis": "health",
    "password": "password",
    "passwd": "password",
    "email": "email",
    "phone": "phone",
    "mobile": "phone",
    "contact_number": "phone",
    "address": "address",
    "pincode": "address",
    "postal_code": "address",
    "dob": "dob",
    "date_of_birth": "dob",
    "birth_date": "dob",
    "full_name": "name",
    "first_name": "name",
    "last_name": "name",
    "ip_address": "ip_address",
    "latitude": "location",
    "longitude": "location",
    "gstin": "gstin",
    "voter_id": "voter_id",
    "salary": "financial",
    "income": "financial",
}

# Identifier fragments where "age", "child" or "parent" is a technical term and
# not a fact about a person. An ORM self relationship (parent_id, child_node,
# hasMany), an HTTP cache directive (max-age), a content rating (age_rating) and
# the process API (child_process) all answer a plain keyword search for age or
# children's data, and every one of them is a false positive against s.9.
# Reading a comment thread's parent_id as a parent's consent record, or a cache
# header as a date of birth, is how a service that has nothing to do with
# children ends up graded in breach of the children's provision.
#
# A real children's service that names a column child_id loses a match here.
# That is the safe direction: the applicability gate in R5 has other signals to
# find, and a missed signal produces an assumption a reviewer can overturn,
# while an invented one produces a breach finding nobody can defend.
TECHNICAL_AGE_TERMS: tuple[str, ...] = (
    # HTTP caching, tokens and elapsed time
    "max_age",
    "min_age_seconds",
    "cache_age",
    "cache_control",
    "token_age",
    "session_age",
    "age_seconds",
    "age_ms",
    "ttl",
    # Content ratings describe the material, not the person looking at it.
    "age_rating",
    "content_rating",
    "parental_rating",
    "cert_age",
    # ORM, tree and graph relationships
    "parent_id",
    "parentid",
    "child_id",
    "childid",
    "parent_key",
    "child_key",
    "parent_node",
    "child_node",
    "parent_ref",
    "child_ref",
    "parent_path",
    "tree_node",
    "nested_set",
    "adjacency_list",
    "hasmany",
    "belongsto",
    "hasone",
    "belongstomany",
    # Process and concurrency APIs
    "child_process",
    "childprocess",
    "child_thread",
    "child_span",
)

# Third party hosts that deliver the page's own assets and receive nothing about
# the visitor beyond what serving a file requires: script, font and library
# CDNs. Fetching a stylesheet from one of these is not a disclosure of personal
# data to a recipient, and reporting a jsdelivr bundle or a Google Fonts request
# as onward sharing is a finding no reviewer could defend.
#
# Registrable suffixes, matched suffix wise and never as a substring. Deliberately
# narrow: a host that is not listed stays a recipient, because under-reporting a
# real disclosure is the one direction this tool must not fail in. Payment SDKs,
# bot defence widgets and unknown hosts are therefore all still recipients.
FUNCTIONAL_ASSET_HOST_SUFFIXES: frozenset[str] = frozenset(
    {
        "jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "cdnjs.com",
        "ajax.googleapis.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "gstatic.com",
        "bootstrapcdn.com",
        "jquery.com",
        "fontawesome.com",
        "typekit.net",
        "cloudfront.net",
        "akamaized.net",
        "akamaihd.net",
        "azureedge.net",
        "cdn.shopify.com",
        "shopifycdn.com",
        "jsdelivr.com",
        # Site builder asset CDNs. A live scan turned up 45 requests to
        # Webflow's, every one of them a font, image, script or stylesheet, and
        # calling that host a recipient of personal data would have been the
        # same mistake as calling Google Fonts one.
        "website-files.com",
        "wixstatic.com",
        "parastorage.com",
        "squarespace-cdn.com",
        "imgix.net",
        "cloudinary.com",
        "fastly.net",
        "wp.com",
    }
)

# Resource types that only pull a file down. An xhr, fetch or beacon to the very
# same host is the opposite: it carries data off the page, so it makes that host
# a recipient whatever else it serves.
ASSET_RESOURCE_TYPES: frozenset[str] = frozenset(
    {"script", "stylesheet", "font", "image"}
)

# Script hosts whose presence means behavioural tracking or ad targeting rather
# than site functionality. Used by R5, where tracking of children is prohibited.
TRACKER_DOMAIN_MARKERS: tuple[str, ...] = (
    "google-analytics",
    "googletagmanager",
    "googlesyndication",
    "doubleclick",
    "adservice.google",
    "facebook.net",
    "connect.facebook",
    "fbevents",
    "hotjar",
    "mixpanel",
    "segment.io",
    "segment.com",
    "amplitude",
    "clarity.ms",
    "criteo",
    "taboola",
    "outbrain",
    "adroll",
    "quantserve",
    "scorecardresearch",
    "appsflyer",
    "clevertap",
    "moengage",
    "branch.io",
)

# Tracker categories that mean the visitor is being profiled rather than served.
# A tag manager is listed because its whole job is to load the others.
BEHAVIOURAL_TRACKER_CATEGORIES: tuple[str, ...] = (
    "analytics",
    "advertising",
    "social",
    "replay",
    "tag_manager",
)

# The one cookie classification that may be written before any choice is made.
# Anything else, including a cookie the scanner could not classify, needs
# consent first under s.6(1), so an unclassified cookie is counted rather than
# excused. Missing a real finding is the only direction this tool must not fail
# in.
NECESSARY_COOKIE_CLASS = "necessary"

# Policy kinds whose prose forms part of the notice a Data Principal reads.
_NOTICE_POLICY_KINDS: tuple[str, ...] = ("privacy", "cookie", "grievance", "children")

_SEPARATORS = "-./\\ :"


def normalise(text: str | None) -> str:
    """Lowercase and collapse separators to underscores for stable matching."""
    if not text:
        return ""
    out = text.lower()
    for char in _SEPARATORS:
        out = out.replace(char, "_")
    return out


def matches(text: str | None, keywords: tuple[str, ...]) -> str | None:
    """Return the first keyword that matches text, or None.

    Keywords of four characters or fewer must match a whole token, so "pan"
    fires on "pan_number" but not on "panel" or "company_plan". Longer keywords
    match as substrings.
    """
    haystack = normalise(text)
    if not haystack:
        return None
    parts = [part for part in haystack.split("_") if part]
    for keyword in keywords:
        needle = normalise(keyword)
        if not needle:
            continue
        if "_" not in needle and len(needle) <= 4:
            if needle in parts:
                return keyword
        elif needle in haystack:
            return keyword
    return None


def is_technical_term(name: str | None) -> bool:
    """True when age, child or parent in this identifier is a technical term.

    A checker asks this before treating a name as evidence about a person, so
    that max_age, parent_id, child_node and hasMany stop reading as age or
    children's data. See TECHNICAL_AGE_TERMS for why the exclusions lean towards
    losing a match rather than inventing one.
    """
    return matches(name, TECHNICAL_AGE_TERMS) is not None


def host_suffixes(host: str | None) -> list[str]:
    """['a.b.example.com', 'b.example.com', 'example.com', 'com'].

    Host matching is suffix based, never substring, so cdn.jsdelivr.net resolves
    through jsdelivr.net while notjsdelivr.net.example never does.
    """
    cleaned = (host or "").strip().lower().strip(".")
    parts = [part for part in cleaned.split(".") if part]
    return [".".join(parts[i:]) for i in range(len(parts))]


def is_functional_asset_host(host: str | None) -> bool:
    """True for a script, font or library CDN, which serves the page.

    Says only what the host is. Whether the requests actually made to it were
    asset fetches is a separate question, answered by data_recipient_hosts.
    """
    return any(
        suffix in FUNCTIONAL_ASSET_HOST_SUFFIXES for suffix in host_suffixes(host)
    )


def category_for_keyword(keyword: str) -> str:
    return _KEYWORD_CATEGORY.get(normalise(keyword), keyword)


def is_critical_category(category: str | None) -> bool:
    return matches(category, CRITICAL_PII_CATEGORIES) is not None


def loc(file_path: str | None, line_number: int | None = None) -> str:
    """Render a file:line reference, degrading gracefully when either is absent."""
    if file_path and line_number:
        return f"{file_path}:{line_number}"
    if file_path:
        return file_path
    return "location not reported by scanner"


def join_names(values: list[str], limit: int = 4) -> str:
    """Stable comma list, truncated so an evidence string stays readable."""
    unique = list(dict.fromkeys(values))
    head = unique[:limit]
    rendered = ", ".join(head)
    if len(unique) > limit:
        rendered = f"{rendered} and {len(unique) - limit} more"
    return rendered


# ------------------------------------------------------------------ code scan


def find_symbols(
    code_result: CodeScanResult | None,
    keywords: tuple[str, ...],
    *,
    exclude_technical: bool = False,
) -> list[SymbolInfo]:
    """Symbols whose name matches one of the keywords.

    exclude_technical drops names where the match is an ORM relationship, a
    cache directive or a process API rather than anything about a person. The
    checkers that reason about age or children pass it; the rest do not, because
    there the technical vocabulary never collides with the subject matter.
    """
    if code_result is None:
        return []
    return [
        s
        for s in code_result.symbols
        if matches(s.name, keywords)
        and not (exclude_technical and is_technical_term(s.name))
    ]


_TRIPLE_QUOTED = re.compile(r"(\"\"\"|''')(?:.|\n)*?\1")
_BLOCK_COMMENT = re.compile(r"/\*(?:.|\n)*?\*/")
_LINE_COMMENT = re.compile(r"(?m)(?:#|//).*$")


def strip_commentary(source: str) -> str:
    """Remove docstrings and comments, leaving executable code.

    A comment is not an implementation. Without this, a docstring reading "there
    is no Data Protection Officer named anywhere" matches the needle "data
    protection officer" and the checker reports a DPO exists, which is the exact
    inverse of the truth. Any prose that discusses a control, including one that
    says the control is missing, would otherwise count as the control.

    String literals are deliberately kept, because a real DPO contact or
    retention setting is often a bare literal in config.

    This is a lexical approximation across five languages rather than a parse.
    It can strip a # or // that sits inside a string literal, which costs a
    little recall. Losing a match is the safe direction: a checker that misses
    evidence records a gap the reviewer can overturn, whereas one that invents
    evidence reports compliance nobody has.
    """
    if not source:
        return ""
    cleaned = _TRIPLE_QUOTED.sub(" ", source)
    cleaned = _BLOCK_COMMENT.sub(" ", cleaned)
    return _LINE_COMMENT.sub(" ", cleaned)


def find_symbols_by_source(
    code_result: CodeScanResult | None, needles: tuple[str, ...]
) -> list[SymbolInfo]:
    """Symbols whose executable source contains one of the needles.

    Comments and docstrings are excluded. See strip_commentary.
    """
    if code_result is None:
        return []
    lowered_needles = [n.lower() for n in needles]
    found: list[SymbolInfo] = []
    for symbol in code_result.symbols:
        if not symbol.source:
            continue
        lowered = strip_commentary(symbol.source).lower()
        if any(needle in lowered for needle in lowered_needles):
            found.append(symbol)
    return found


def find_models(
    code_result: CodeScanResult | None,
    keywords: tuple[str, ...],
    *,
    exclude_technical: bool = False,
) -> list[ModelInfo]:
    if code_result is None:
        return []
    return [
        m
        for m in code_result.db_models
        if (matches(m.class_name, keywords) or matches(m.table_name, keywords))
        and not (
            exclude_technical
            and (is_technical_term(m.class_name) or is_technical_term(m.table_name))
        )
    ]


def find_columns(
    code_result: CodeScanResult | None,
    keywords: tuple[str, ...],
    *,
    exclude_technical: bool = False,
) -> list[tuple[ModelInfo, ColumnInfo]]:
    if code_result is None:
        return []
    found: list[tuple[ModelInfo, ColumnInfo]] = []
    for model in code_result.db_models:
        for column in model.columns:
            if not matches(column.name, keywords):
                continue
            if exclude_technical and is_technical_term(column.name):
                continue
            found.append((model, column))
    return found


def find_routes(
    code_result: CodeScanResult | None,
    keywords: tuple[str, ...],
    methods: tuple[str, ...] | None = None,
    *,
    exclude_technical: bool = False,
) -> list[RouteInfo]:
    if code_result is None:
        return []
    found: list[RouteInfo] = []
    for route in code_result.routes:
        if methods and route.http_method.upper() not in methods:
            continue
        if not (matches(route.path, keywords) or matches(route.handler_name, keywords)):
            continue
        if exclude_technical and (
            is_technical_term(route.path) or is_technical_term(route.handler_name)
        ):
            continue
        found.append(route)
    return found


def find_files(
    code_result: CodeScanResult | None, keywords: tuple[str, ...]
) -> list[FileInfo]:
    if code_result is None:
        return []
    return [f for f in code_result.files if matches(f.path, keywords)]


def find_edges(
    code_result: CodeScanResult | None, edge_type: str
) -> list[DataFlowEdgeInfo]:
    if code_result is None:
        return []
    return [e for e in code_result.data_flow_edges if e.edge_type == edge_type]


def pii_columns(
    code_result: CodeScanResult | None,
) -> list[tuple[ModelInfo, ColumnInfo, str]]:
    """Every stored column that holds personal data, with its PII category.

    Prefers the scanner's own classification in pii_fields and falls back to
    column name matching, so the rule still produces evidence when the PII
    module reported nothing for this repository.
    """
    if code_result is None:
        return []
    classified = {
        normalise(ref.field_name): ref
        for ref in code_result.pii_fields
        if ref.field_name
    }
    found: list[tuple[ModelInfo, ColumnInfo, str]] = []
    for model in code_result.db_models:
        for column in model.columns:
            ref = classified.get(normalise(column.name))
            if ref is not None:
                found.append((model, column, ref.pii_category))
                continue
            keyword = matches(column.name, PII_COLUMN_KEYWORDS)
            if keyword:
                found.append((model, column, category_for_keyword(keyword)))
    return found


def pii_categories_found(code_result: CodeScanResult | None) -> list[str]:
    if code_result is None:
        return []
    categories = [ref.pii_category for ref in code_result.pii_fields if ref.pii_category]
    categories.extend(category for _, _, category in pii_columns(code_result))
    return list(dict.fromkeys(categories))


# ------------------------------------------------------------------- web scan


def web_observable(web_result: WebScanResult | None) -> bool:
    """True when what the crawl saw on the page can be relied on.

    A blocked crawl hands back the same empty cookie, request and form lists as
    a spotless site. Reporting "no tracker fired before consent" off a bot wall
    would be a clean bill of health nobody earned, which is the worst way this
    tool can be wrong, so every page level check is skipped instead of passed
    when this is False.
    """
    return web_result is not None and not web_result.crawl_blocked


def crawl_was_blocked(web_result: WebScanResult | None) -> bool:
    """True only where a crawl ran and was turned away.

    Distinct from web_observable, which is also False when no web scan was run
    at all. The difference decides how a checker may word a finding: a code scan
    that finds no date of birth column has real evidence that age is not
    collected, while a blocked crawl has no evidence of anything, and reporting
    the two the same way would put a finding on a site nobody managed to look at.
    """
    return web_result is not None and web_result.crawl_blocked


def crawl_blocked_reason(web_result: WebScanResult | None) -> str:
    """Why the page level checks were skipped, in words a reviewer can act on."""
    if web_result is None:
        return "No web scan was supplied."
    text = (
        f"The crawl of {web_result.entry_url} was blocked, so nothing that happens on the page "
        "was observed. The checks that depend on it are excluded from this score rather than "
        "passed, because an empty result from a blocked crawl is indistinguishable from a clean "
        "site."
    )
    note = (web_result.crawl_note or "").strip()
    return f"{text} Scanner note: {note}" if note else text


def consent_elements(
    web_result: WebScanResult | None,
) -> list[tuple[FormInfo, ConsentElement]]:
    if not web_observable(web_result):
        return []
    return [(form, element) for form in web_result.forms for element in form.consent_elements]


def marketing_optins(web_result: WebScanResult | None) -> list[ConsentElement]:
    """Marketing and newsletter opt-ins, which need consent of their own under s.6."""
    if not web_observable(web_result):
        return []
    return list(web_result.marketing_optins)


def consent_banner(web_result: WebScanResult | None) -> ConsentBanner | None:
    if not web_observable(web_result):
        return None
    return web_result.consent_banner


def collecting_forms(web_result: WebScanResult | None) -> list[FormInfo]:
    """Forms that actually take input, which is where a notice and consent are due."""
    if not web_observable(web_result):
        return []
    return [form for form in web_result.forms if form.fields]


def sensitive_fields(web_result: WebScanResult | None) -> list[FormField]:
    """Form fields collecting a category the Act expects extra care around."""
    if not web_observable(web_result):
        return []
    return list(web_result.sensitive_fields)


def forms_collecting(web_result: WebScanResult | None, field_name: str) -> list[FormInfo]:
    """Forms whose own field list includes the named field."""
    if not web_observable(web_result):
        return []
    target = normalise(field_name)
    return [
        form
        for form in web_result.forms
        if any(normalise(field.name) == target for field in form.fields)
    ]


def find_links(web_result: WebScanResult | None, keywords: tuple[str, ...]) -> list[str]:
    """Rights links and discovered policy URLs matching any of the keywords."""
    if not web_observable(web_result):
        return []
    candidates = list(web_result.rights_links)
    candidates.extend(doc.url for doc in web_result.policy_documents if doc.reachable)
    return [link for link in dict.fromkeys(candidates) if matches(link, keywords)]


def trackers(web_result: WebScanResult | None) -> list[ScriptInfo]:
    if not web_observable(web_result):
        return []
    return [
        script
        for script in web_result.third_party_scripts
        if matches(script.domain, TRACKER_DOMAIN_MARKERS)
        or matches(script.src, TRACKER_DOMAIN_MARKERS)
    ]


def behavioural_requests(web_result: WebScanResult | None) -> list[NetworkRequest]:
    """Third party requests that profile the visitor rather than serve the page.

    Script tags miss most of this. A tag manager loads its payload after the
    HTML is parsed, and beacons, pixels and XHR carry data off-site without ever
    appearing as a script element, so the network layer is the only place the
    full picture exists.
    """
    if not web_observable(web_result):
        return []
    return [
        request
        for request in web_result.network_requests
        if request.is_third_party
        and matches(request.tracker_category, BEHAVIOURAL_TRACKER_CATEGORIES)
    ]


def trackers_before_consent(web_result: WebScanResult | None) -> list[NetworkRequest]:
    """Third party trackers that fired before the visitor chose anything."""
    if not web_observable(web_result):
        return []
    return list(web_result.trackers_before_consent)


def unconsented_cookies(web_result: WebScanResult | None) -> list[CookieInfo]:
    """Cookies written before any choice that are not strictly necessary."""
    if not web_observable(web_result):
        return []
    return [
        cookie
        for cookie in web_result.cookies_before_consent
        if normalise(cookie.classification) != NECESSARY_COOKIE_CLASS
    ]


def third_party_hosts(web_result: WebScanResult | None) -> list[str]:
    """Every distinct third party host the page contacted, of any kind.

    Includes the CDNs. A rule that is counting recipients of personal data wants
    data_recipient_hosts instead, because a font request is not a disclosure.
    """
    if not web_observable(web_result):
        return []
    return list(web_result.third_party_hosts)


def _third_party_requests_by_host(
    web_result: WebScanResult,
) -> dict[str, list[NetworkRequest]]:
    grouped: dict[str, list[NetworkRequest]] = {}
    for request in web_result.network_requests:
        if request.is_third_party:
            grouped.setdefault(request.host, []).append(request)
    return grouped


def _serves_assets_only(host: str, requests: list[NetworkRequest]) -> bool:
    """True when this host only handed the page a file.

    Three conditions, all required. The host is a known asset CDN, none of its
    requests was classified as a tracker, and every request to it was a plain
    asset fetch. A known CDN that also receives an xhr or fires a beacon fails
    the last two and goes back to being a recipient, which is what keeps a CDN
    domain from being usable as cover for a tracking endpoint.
    """
    if not is_functional_asset_host(host):
        return False
    if any(request.tracker_category for request in requests):
        return False
    return all(
        (request.resource_type or "").strip().lower() in ASSET_RESOURCE_TYPES
        for request in requests
    )


def asset_hosts(web_result: WebScanResult | None) -> list[str]:
    """Third party hosts contacted only to fetch the page's own assets.

    These are not recipients of personal data. Naming them separately is what
    lets an evidence string say which third party got what.
    """
    if not web_observable(web_result):
        return []
    grouped = _third_party_requests_by_host(web_result)
    return sorted(
        host for host, requests in grouped.items() if _serves_assets_only(host, requests)
    )


def _probably_same_operator(requests: list[NetworkRequest]) -> bool:
    """True when a host looks like another domain of the site's own operator.

    Two conditions, both required. The scanner recorded that the host carries
    the same brand label as the entry domain under a different public suffix,
    and nothing about the requests to it says tracker. A site on redacto.ai
    fetching from api.redacto.io is talking to its own backend, and reporting
    that as an external recipient of personal data would be wrong in substance.

    The tracker condition is the part that matters. Registering a lookalike
    domain would otherwise be a way to have a tracker excused, so a host with a
    tracker category, or one a CNAME chain unmasked, is never treated this way
    however its name reads.
    """
    if not requests or not all(request.shares_entry_brand for request in requests):
        return False
    return not any(
        request.tracker_category or request.cname_cloaked for request in requests
    )


def same_operator_hosts(web_result: WebScanResult | None) -> list[str]:
    """Third party hosts that probably belong to the operator of the site itself.

    Reported separately rather than folded into the first party, because
    ownership cannot be observed from a page. The evidence says "probably the
    same operator" and names the host, which leaves a reviewer able to disagree.
    """
    if not web_observable(web_result):
        return []
    grouped = _third_party_requests_by_host(web_result)
    return sorted(
        host
        for host, requests in grouped.items()
        if not _serves_assets_only(host, requests) and _probably_same_operator(requests)
    )


def data_recipient_hosts(web_result: WebScanResult | None) -> list[str]:
    """Third party hosts that received personal data, so recipients under s.5(1).

    Every third party host except the asset CDNs and the hosts that carry the
    site's own brand under another suffix. An unknown host stays a recipient:
    this tool may under-claim what a host is, never under-report that the
    visitor's data reached it.
    """
    if not web_observable(web_result):
        return []
    grouped = _third_party_requests_by_host(web_result)
    return sorted(
        host
        for host, requests in grouped.items()
        if not _serves_assets_only(host, requests)
        and not _probably_same_operator(requests)
    )


# ------------------------------------------------------- scanner blind spots


def request_label(request: NetworkRequest) -> str:
    """One request, named the way a reviewer needs to see it.

    A cloaked host is written out as what it is: a name belonging to the site
    that resolves to somebody else. Rendering it as a plain third party host
    would hide the single most deliberate thing the scan found.
    """
    parts = [request.host]
    if request.tracker_category:
        parts.append(f"({request.tracker_category}, {request.resource_type})")
    else:
        parts.append(f"({request.resource_type})")
    label = " ".join(parts)
    if request.cname_cloaked and request.cname_target:
        label = (
            f"{label}, first party in name but resolving by CNAME to "
            f"{request.cname_target}"
        )
    return label


def cloaked_hosts(web_result: WebScanResult | None) -> list[str]:
    """First party hostnames whose DNS chain ends at a known tracker."""
    if not web_observable(web_result):
        return []
    return list(web_result.cloaked_hosts)


def cloaked_requests(web_result: WebScanResult | None) -> list[NetworkRequest]:
    if not web_observable(web_result):
        return []
    return [request for request in web_result.network_requests if request.cname_cloaked]


def cname_cloaking_note(web_result: WebScanResult | None) -> str | None:
    """How a first party name was found to be serving somebody else's tracker."""
    cloaked = cloaked_requests(web_result)
    if not cloaked:
        return None
    rendered = join_names(
        [
            f"{request.host} resolves to {request.cname_target} "
            f"({request.tracker_category})"
            for request in cloaked
        ],
        limit=4,
    )
    hosts = {request.host for request in cloaked}
    return (
        f"{len(hosts)} host(s) on the site's own domain resolve by CNAME to a third party "
        f"tracker: {rendered}. The requests read as first party from the URL alone, so they "
        "are counted here as what the DNS chain shows them to be."
    )


def server_side_tag_endpoints(web_result: WebScanResult | None) -> list:
    if not web_observable(web_result):
        return []
    return list(web_result.server_side_tag_endpoints)


def server_side_tagging_note(web_result: WebScanResult | None) -> str | None:
    """What this scan cannot see, said plainly.

    A first party endpoint that receives measurement traffic and forwards it to
    a vendor from the server hides the onward hop from every browser based
    scanner, this one included. Saying nothing would let the absence of a third
    party request read as a clean site, which is the way this tool must never
    be wrong.
    """
    endpoints = server_side_tag_endpoints(web_result)
    if not endpoints:
        return None
    rendered = join_names(
        [
            f"{endpoint.method} {endpoint.host}{endpoint.path} "
            f"(matched on {endpoint.matched_on}: {endpoint.marker})"
            for endpoint in endpoints
        ],
        limit=4,
    )
    carried = sorted({c for endpoint in endpoints for c in endpoint.payload_categories})
    payload_note = (
        f" The bodies read at these endpoints carried {join_names(carried, limit=6)}."
        if carried
        else ""
    )
    pre_consent = [endpoint for endpoint in endpoints if endpoint.before_consent]
    timing_note = (
        f" {len(pre_consent)} of them received traffic before the visitor was given any choice."
        if pre_consent
        else ""
    )
    return (
        f"{len(endpoints)} first party endpoint(s) received measurement shaped traffic: "
        f"{rendered}.{payload_note}{timing_note} Data leaves through a server-side path that "
        "this scan cannot follow: the browser sends it to the site's own domain and any "
        "forwarding to an analytics or advertising vendor happens on the server, out of reach "
        "of any browser based scanner. The absence of a third party request for these events "
        "is therefore not evidence that no third party received them."
    )


def payload_pii_requests(web_result: WebScanResult | None) -> list[NetworkRequest]:
    """Requests whose body carried a recognised category of personal data."""
    if not web_observable(web_result):
        return []
    return list(web_result.requests_with_payload_pii)


def payload_pii_categories(requests: list[NetworkRequest]) -> list[str]:
    return sorted(
        {finding.pii_category for request in requests for finding in request.payload_pii}
    )


def payload_pii_label(request: NetworkRequest) -> str:
    """What a body carried, by category only.

    Never the value. The category, the parameter name it sat under and a
    redacted indicator are the whole of what the scanner kept, and the whole of
    what a finding may say.
    """
    parts = []
    for finding in request.payload_pii:
        where = f" in \"{finding.field_hint}\"" if finding.field_hint else ""
        parts.append(
            f"{finding.pii_category} ({finding.sensitivity}, "
            f"{finding.occurrences} occurrence(s){where}, {finding.redacted})"
        )
    return f"{request.method} {request.host}: " + "; ".join(parts)


def policy_document(web_result: WebScanResult | None, kind: str) -> PolicyDocument | None:
    if not web_observable(web_result):
        return None
    return web_result.policy_of(kind)


def dpo_contact(web_result: WebScanResult | None) -> str | None:
    """The published contact for processing questions, Rules 2025 rule 9."""
    if not web_observable(web_result):
        return None
    return web_result.dpo_contact


def grievance_contact(web_result: WebScanResult | None) -> str | None:
    if not web_observable(web_result):
        return None
    return web_result.grievance_contact


def notice_body(web_result: WebScanResult | None) -> str | None:
    if not web_observable(web_result) or web_result.privacy_notice is None:
        return None
    return web_result.privacy_notice.body_text


def notice_text(web_result: WebScanResult | None) -> str:
    """Every scrap of published notice prose the crawl read.

    The notice linked beside a form and the privacy policy found by probing a
    conventional path are often the same document, and either one can be the
    only copy the crawl managed to load, so a content check reads both rather
    than reporting a gap over which copy it happened to find.
    """
    if not web_observable(web_result):
        return ""
    parts: list[str] = []
    if web_result.privacy_notice is not None and web_result.privacy_notice.body_text:
        parts.append(web_result.privacy_notice.body_text)
    for doc in web_result.policy_documents:
        if doc.reachable and doc.body_text and doc.kind in _NOTICE_POLICY_KINDS:
            parts.append(doc.body_text)
    return " ".join(parts)


def notice_url(web_result: WebScanResult | None) -> str | None:
    """Where the notice these checks read actually lives."""
    if not web_observable(web_result):
        return None
    notice = web_result.privacy_notice
    if notice is not None and notice.reachable:
        return notice.url
    policy = web_result.policy_of("privacy")
    return policy.url if policy is not None else None


def page_text(web_result: WebScanResult | None) -> str:
    if not web_observable(web_result):
        return ""
    return " ".join(page.text_content for page in web_result.pages if page.text_content)


# ---------------------------------------------------------------- pii flows


def flow_label(flow: PIIFlowPathInfo) -> str:
    sink = flow.sink_description or "unnamed sink"
    return f"{flow.pii_category} flow {flow.source_description} -> {sink}"


def flows_without(flows: list[PIIFlowPathInfo], attribute: str) -> list[PIIFlowPathInfo]:
    return [flow for flow in flows if not getattr(flow, attribute)]


def third_party_flows(flows: list[PIIFlowPathInfo]) -> list[PIIFlowPathInfo]:
    return [flow for flow in flows if flow.crosses_third_party]
