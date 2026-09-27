"""Stage 1 entry point: fetch what a site publishes, then read it.

The only module in the policy stage that touches the network, which is what
keeps the analyser a pure function over documents and testable without a socket.

A shallow link hunt rather than a measurement crawl. It walks a little of the
site because plenty of organisations never link their privacy notice from the
front page: it sits in a footer that only renders on an inner page, under an
About or Legal index, or on a contact page. Reading the homepage alone and then
guessing at conventional paths reports those sites as publishing no notice when
they publish one two clicks away.

What it does not do is anything Stage 2 owns. No browser, no tracker recording,
no cookie jar, no consent banner: what the page does is a different question and
this stage would only answer it worse. What it needs is prose, and prose arrives
over plain HTTP for the overwhelming majority of published policies.

The cost of that choice is a policy rendered entirely client side, which comes
back as an empty shell. That is why the conventional paths are probed even when
the homepage yields no links at all, and why a fetch that was turned away is
recorded as a blocked fetch rather than as a site with nothing to show.
"""

import asyncio
import logging
from typing import NamedTuple
from urllib.parse import urljoin

import httpx

from app.contracts import PolicyDocument, PolicyScanResult
from app.policy import analyzer, discovery
from app.scanner.url_guard import UnsafeURLError, same_site, validate_scan_url

logger = logging.getLogger(__name__)

# How much of a document's text decides whether it is the same document. Enough
# to tell two policies apart, short enough that a differing footer or build
# stamp does not make one page look like two.
_BODY_MATCH_CHARS = 3000

# The link hunt's budget. Small on purpose: this stage is looking for policy
# pages, not measuring the site, and every page opened is someone else's server
# answering a request nobody asked them for.
MAX_CRAWL_PAGES = 12
CRAWL_DEPTH = 2

# Path segments that tend to index the legal pages rather than be one.
_HUB_SEGMENTS = ("legal", "about", "policies", "policy", "help", "support", "contact", "footer")

USER_AGENT = "DPDPAReviewer/1.0 (compliance self-check scanner)"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
    "Accept-Language": "en-IN,en;q=0.9",
}

FETCH_TIMEOUT_SECONDS = discovery.POLICY_FETCH_TIMEOUT_MS / 1000
# Every hop is validated, so following one is not a way around the SSRF guard.
MAX_REDIRECTS = 5
# The raw markup budget. Four times the prose limit, because markup is mostly
# not prose and a policy page carries a lot of furniture.
RAW_BODY_LIMIT = discovery.POLICY_BODY_LIMIT * 4


class Fetched(NamedTuple):
    status: int
    content_type: str
    body: str
    url: str


_EMPTY = Fetched(0, "", "", "")


async def _fetch(client: httpx.AsyncClient, url: str) -> Fetched:
    """GET a URL, validating every hop. A status of 0 means no response at all.

    Redirects are followed by hand rather than by the client, because a URL that
    resolves publicly can redirect to one that does not, and letting the client
    chase it would hand an internal address the one thing the guard exists to
    prevent.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            safe = await asyncio.to_thread(validate_scan_url, current)
        except (UnsafeURLError, ValueError, OSError) as exc:
            logger.debug("Skipping %s: %s", current, exc)
            return _EMPTY

        try:
            response = await client.get(safe)
        except httpx.HTTPError as exc:
            logger.debug("Fetch failed for %s: %s", safe, exc)
            return _EMPTY

        location = response.headers.get("location")
        if response.is_redirect and location:
            current = urljoin(safe, location)
            continue

        status = int(response.status_code)
        content_type = (response.headers.get("content-type") or "").lower()
        if status >= 400:
            return Fetched(status, content_type, "", safe)
        if content_type and not ("text" in content_type or "html" in content_type):
            # A PDF notice is still a notice. Nothing here can read it, so the
            # body stays empty and the reachability judgement takes the hint.
            return Fetched(status, content_type, "", safe)
        try:
            return Fetched(status, content_type, response.text[:RAW_BODY_LIMIT], safe)
        except (UnicodeDecodeError, httpx.HTTPError) as exc:
            logger.debug("Could not read %s: %s", safe, exc)
            return Fetched(status, content_type, "", safe)

    logger.debug("Too many redirects from %s", url)
    return _EMPTY


async def scan_policies(
    entry_url: str,
    *,
    policy_urls: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PolicyScanResult:
    """Read everything the organisation has published about itself.

    Returns the documents found, a check for every applicable requirement
    whether or not it is satisfied, and every claim a later stage could test.

    policy_urls are documents the caller names directly. They are the fallback
    for a notice this stage cannot reach on its own: one rendered entirely client
    side comes back as an empty shell over plain HTTP, and no amount of guessing
    at paths fixes that. A supplied link is fetched ahead of everything else and
    is never crowded out of the budget, because the reason for supplying one is
    that discovery already failed.

    transport is injected so the fetch path can be exercised without a network,
    the same way the web scanner takes a resolver. Left unset, real HTTP is used.
    """
    safe_url = await asyncio.to_thread(validate_scan_url, entry_url)
    result = PolicyScanResult(entry_url=safe_url)

    limits = httpx.Limits(max_connections=discovery.POLICY_FETCH_CONCURRENCY)
    async with httpx.AsyncClient(
        headers=HEADERS,
        timeout=FETCH_TIMEOUT_SECONDS,
        follow_redirects=False,
        limits=limits,
        transport=transport,
    ) as client:
        home = await _fetch(client, safe_url)
        home_text = discovery.html_to_text(home.body)
        home_print = discovery.fingerprint(home_text)

        anchors = await _crawl_for_anchors(client, safe_url, home)
        ordered = discovery.order_candidates(
            discovery.build_candidates(
                safe_url,
                anchors,
                discovery.supplied_candidates(policy_urls),
                landed_url=home.url or safe_url,
            )
        )

        semaphore = asyncio.Semaphore(discovery.POLICY_FETCH_CONCURRENCY)

        async def fetch_one(meta: dict) -> tuple[dict, Fetched]:
            async with semaphore:
                return meta, await _fetch(client, meta["url"])

        fetched = await asyncio.gather(
            *(fetch_one(m) for m in ordered), return_exceptions=True
        )

    failed = 0
    # Keyed by where the fetch actually landed, not by where it was aimed. A
    # live read found /privacy, /privacy-policy and the footer link all
    # redirecting to one page, and three copies of one notice do not corroborate
    # each other: the analyser counted the same sentence three times and reported
    # it as three independent statements.
    settled: dict[str, PolicyDocument] = {}
    for item in fetched:
        if isinstance(item, BaseException):
            logger.debug("A policy fetch failed: %s", item)
            failed += 1
            continue
        meta, response = item
        document = _to_document(meta, response, home_print, home_text)
        if document is None:
            continue
        key = discovery.normalise_url(document.url)
        held = settled.get(key)
        if held is None:
            settled[key] = document
        else:
            _merge(held, document)

    result.documents = _dedupe_by_body(list(settled.values()))
    result.checks, result.claims = analyzer.analyse(result.documents)
    result.missing_policies = analyzer.missing_kinds(result.documents)
    _assess_coverage(result, home, home_text, failed=failed)
    return result


async def _crawl_for_anchors(
    client: httpx.AsyncClient, entry_url: str, home: Fetched
) -> list[dict]:
    """Walk a little of the site collecting links, not just the homepage.

    Plenty of sites never link their privacy notice from the front page. It sits
    in a footer that only renders on an inner page, or under an About or Legal
    index, or on a contact page. Reading the homepage alone and then guessing at
    conventional paths misses those entirely, and the result is a site reported
    as publishing no notice when it publishes one two clicks away.

    Deliberately shallow. This is a link hunt, not the Stage 2 crawl: it reads
    HTML for anchors, follows only same-site pages, and stops at a small budget.
    Pages that look like policies are preferred, so the walk spends its budget
    moving toward legal pages rather than through a product catalogue.
    """
    anchors = discovery.extract_anchors(home.body, home.url or entry_url)
    for anchor in anchors:
        anchor["from_entry"] = True

    seen = {discovery.normalise_url(home.url or entry_url)}
    frontier = _next_hops(anchors, entry_url, seen)

    for _ in range(CRAWL_DEPTH):
        if not frontier or len(seen) >= MAX_CRAWL_PAGES:
            break
        batch = frontier[: MAX_CRAWL_PAGES - len(seen)]
        frontier = []
        fetched = await asyncio.gather(
            *(_fetch(client, url) for url in batch), return_exceptions=True
        )
        for url, response in zip(batch, fetched, strict=False):
            seen.add(discovery.normalise_url(url))
            if isinstance(response, BaseException) or not response.body:
                continue
            found = discovery.extract_anchors(response.body, response.url or url)
            for anchor in found:
                # Only the homepage counts as the entry page. A notice reachable
                # only from an inner page is still a notice, but whether it is
                # presented before collection is a different question and this
                # must not answer it wrongly.
                anchor["from_entry"] = False
            anchors.extend(found)
            frontier.extend(_next_hops(found, entry_url, seen))

    return anchors


def _next_hops(anchors: list[dict], entry_url: str, seen: set[str]) -> list[str]:
    """Same-site pages worth opening, policy-ish ones first."""
    candidates: list[tuple[int, str]] = []
    for anchor in anchors:
        href = anchor.get("href") or ""
        if not discovery.is_fetchable(href) or not same_site(href, entry_url):
            continue
        key = discovery.normalise_url(href)
        if key in seen or any(key == c[1] for c in candidates):
            continue
        if discovery.looks_like_marketing_path(href):
            continue
        labelled = discovery.classify_link(
            anchor.get("text"), anchor.get("aria_label"), anchor.get("title"), href
        )
        hub = any(seg in href.lower() for seg in _HUB_SEGMENTS)
        rank = 0 if labelled else (1 if hub else 2)
        candidates.append((rank, key))

    candidates.sort(key=lambda c: c[0])
    return [url for rank, url in candidates if rank < 2][:MAX_CRAWL_PAGES]


def _dedupe_by_body(documents: list[PolicyDocument]) -> list[PolicyDocument]:
    """Collapse distinct URLs that serve the same document.

    Deduplicating on URL is not enough. A live read found the same terms of
    service at two paths differing by one character, with word counts of 4,734
    and 4,733, and the same notice reachable both by link and by two probes. The
    copies do not corroborate each other: analysing one document three times
    counts every sentence in it three times and lets one page outweigh the rest
    of the site's policies put together.

    Matched on the first part of the text rather than the whole, so a page that
    differs only in a footer, a build stamp or a locale switcher still collapses.
    """
    kept: dict[str, PolicyDocument] = {}
    ordered: list[PolicyDocument] = []
    for document in documents:
        body = (document.body_text or "").strip()
        key = f"{document.kind}:{discovery.fingerprint(body[:_BODY_MATCH_CHARS])}"
        if not body:
            ordered.append(document)
            continue
        held = kept.get(key)
        if held is None:
            kept[key] = document
            ordered.append(document)
            continue
        _merge(held, document)
    return ordered


def _merge(held: PolicyDocument, other: PolicyDocument) -> None:
    """Fold a second route to the same page into the record already held.

    Being linked is a property of the page, not of the route that found it, so
    one link to it makes it linked. Footer only is the opposite: it has to be
    true of every route before it is true at all.
    """
    held.linked_from_homepage = held.linked_from_homepage or other.linked_from_homepage
    held.in_footer_only = held.in_footer_only and other.in_footer_only
    if held.discovered_via != "link" and other.discovered_via == "link":
        held.discovered_via = "link"
    if other.word_count > held.word_count:
        held.body_text, held.word_count = other.body_text, other.word_count
        held.reachable = other.reachable


def _to_document(
    meta: dict, response: Fetched, home_print: str, home_text: str = ""
) -> PolicyDocument | None:
    landed = response.url or meta["url"]
    # A link label carries the right word far more often than a page carries a
    # policy. "CI/CD Privacy Scanner" under /products is a product, and reading
    # its marketing copy as the organisation's notice would credit the notice
    # with claims nobody made in it.
    supplied = meta["via"] == discovery.VIA_SUPPLIED
    if not supplied and (
        discovery.looks_like_marketing_path(landed)
        or discovery.looks_like_marketing_path(meta["url"])
    ):
        return None

    text = discovery.html_to_text(response.body)[: discovery.POLICY_BODY_LIMIT]
    words = discovery.word_count(text)
    reachable = discovery.judge_reachable(
        status=response.status,
        content_type=response.content_type,
        words=words,
        homepage_echo=discovery.echoes_homepage(text, home_print),
    )

    # A probed contact page only counts as grievance evidence when it names a
    # grievance route. Recorded as nothing at all otherwise, because a contact
    # form filed as a redressal mechanism reads as compliance nobody earned.
    if meta["gated"] and not discovery.counts_as_grievance_evidence(text):
        return None

    # A page that is nearly all header, menu and footer is the site's furniture,
    # not a document it published. Word count cannot tell the two apart: a
    # template wraps a placeholder in three hundred words of chrome.
    if not supplied and reachable and discovery.mostly_boilerplate(text, home_text):
        return None

    return PolicyDocument(
        url=landed,
        kind=meta["kind"],
        reachable=reachable,
        discovered_via=meta["via"],
        body_text=text or None,
        word_count=words,
        linked_from_homepage=meta["linked"],
        in_footer_only=meta["footer_only"],
        status_code=response.status,
    )


def _assess_coverage(
    result: PolicyScanResult, home: Fetched, home_text: str, *, failed: int
) -> None:
    """Say whether this result can be read as a picture of what the site publishes.

    The one sentence that has to be here: a scan the site turned away found no
    policies because it was not allowed to look, and reporting that as an
    organisation that publishes nothing would invent the most serious finding in
    the stage out of our own missing evidence.
    """
    notes: list[str] = []

    if home.status == 0:
        result.crawl_blocked = True
        notes.append(
            "the entry page returned no response at all, so any link the site "
            "publishes to a policy went unseen"
        )
    else:
        reasons = discovery.blocking_reasons(home.status, home_text)
        if reasons:
            result.crawl_blocked = True
            notes.append("coverage is not reliable because " + ", and ".join(reasons))

    readable = result.readable_documents
    if result.crawl_blocked:
        notes.append(
            f"{len(readable)} policy document(s) were read from conventional paths "
            "regardless. Absence of a published policy in this result is not evidence "
            "that the site publishes none"
        )
    elif not readable:
        notes.append(
            "no policy document could be read. This scan fetches pages without "
            "running their scripts, so a notice rendered entirely in the browser "
            "would look empty here and is worth opening by hand before the absence "
            "is treated as a finding"
        )

    if failed:
        notes.append(f"{failed} fetch(es) raised and were skipped, so coverage is partial")

    result.crawl_note = ". ".join(notes) + "." if notes else None
