"""Web scanner.

Playwright drives a real browser because modern signup forms are JavaScript
rendered. An HTTP fetch of a React app returns an empty mount div, so consent
checkboxes and form fields would be invisible to a requests-based scanner.

Three things decide whether this module sees anything at all:

1. When the snapshot is taken. domcontentloaded fires before the page's own
   scripts have finished, which on a real site means before the tag manager has
   injected anything, before a cookie has been written and before a client
   rendered navigation exists. A 440KB news homepage produced zero links, zero
   cookies and zero third party scripts that way. The load now waits for the
   network to settle, with a bounded timeout and a short settle delay after it.
2. Where it looks. Script elements miss most tracking: beacons, pixel images,
   XHR and iframes all carry data off-site without ever becoming a script tag.
   Every request the page makes is recorded instead.
3. Whether the visitor was asked first. Everything captured on a cold load with
   no interaction is flagged before_consent, because that is the state the Act
   cares about.

This module only collects evidence. It never decides compliance, that is the
rules engine's job. It also never submits a form, never signs in and never
clicks anything: the default scan is a read only cold load.
"""

import asyncio
import logging
import re
import time
from typing import NamedTuple
from urllib.parse import urljoin, urlparse

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from app.config import settings
from app.contracts import (
    ConsentBanner,
    ConsentElement,
    CookieInfo,
    FormField,
    FormInfo,
    NetworkRequest,
    NoticeInfo,
    PageInfo,
    PolicyDocument,
    ScriptInfo,
    ServerSideTagEndpoint,
    WebScanResult,
)
from app.policy import discovery
from app.scanner import cname, payload_pii, trackers
from app.scanner.url_guard import (
    UnsafeURLError,
    registrable_domain,
    same_site,
    shares_brand_label,
    validate_scan_url,
)

logger = logging.getLogger(__name__)

USER_AGENT = "DPDPAReviewer/1.0 (compliance self-check scanner)"

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

NOTICE_KEYWORDS = ("privacy", "data protection", "data policy")
RIGHTS_KEYWORDS = (
    "my data",
    "my account",
    "download my data",
    "delete my account",
    "delete account",
    "manage preferences",
    "data request",
    "correct my",
)
GRIEVANCE_KEYWORDS = ("grievance", "data protection officer", "nodal officer")
CONSENT_KEYWORDS = (
    "consent",
    "agree",
    "accept",
    "terms",
    "privacy",
    "marketing",
    "newsletter",
    "promotional",
    "i have read",
)
AGE_FIELD_KEYWORDS = ("age", "dob", "birth", "birthday")

# How long to let the network settle after the document is parsed. Bounded and
# separate from the navigation timeout, because plenty of real pages hold a
# socket open forever (chat widgets, live scores) and would never go idle.
NETWORK_IDLE_TIMEOUT_MS = 8000
# Tags injected by a tag manager land a beat after idle, so give them one.
SETTLE_DELAY_MS = 1200

# A heavy homepage can fire well over a thousand requests, and identical ones
# are already collapsed before this cap applies. Anything still dropped is
# counted and said out loud in crawl_note, because a tracker we stopped
# listening for must not read as a tracker that did not fire.
MAX_NETWORK_REQUESTS = 750

# A request body is read, classified for the category of personal data it
# carries, and dropped. The body itself is never stored on the result, never
# logged and never leaves the inspection call: this tool must not become
# another copy of the data it is auditing.
PAYLOAD_METHODS = frozenset({"POST", "PUT", "PATCH"})
# A measurement beacon is small. Past this it is an upload, and reading it
# would cost more than it could tell us.
MAX_PAYLOAD_BYTES = 8192
MAX_PAYLOADS_INSPECTED = 120

# Policy discovery is shared with the policy stage, so the thresholds, the
# conventional path list and the "is this a readable document" judgement all come
# from one module. Two stages disagreeing about what a site publishes is the one
# thing a cross-stage finding cannot survive.
MAX_POLICY_FETCHES = discovery.MAX_POLICY_FETCHES
MAX_POLICY_LINKS = discovery.MAX_POLICY_LINKS
POLICY_FETCH_CONCURRENCY = discovery.POLICY_FETCH_CONCURRENCY
POLICY_FETCH_TIMEOUT_MS = discovery.POLICY_FETCH_TIMEOUT_MS
POLICY_BODY_LIMIT = discovery.POLICY_BODY_LIMIT
MAX_POLICY_RENDERS = discovery.MAX_POLICY_RENDERS
MIN_POLICY_WORDS = discovery.MIN_POLICY_WORDS
POLICY_RENDER_KINDS = discovery.POLICY_RENDER_KINDS
POLICY_PRIORITY_KINDS = discovery.POLICY_PRIORITY_KINDS

BLOCKING_STATUS = discovery.BLOCKING_STATUS
THIN_PAGE_CHARS = discovery.THIN_PAGE_CHARS
BOT_WALL_TEXT_LIMIT = discovery.BOT_WALL_TEXT_LIMIT

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")
_PHONE_CANDIDATE_RE = re.compile(r"\+?\d[\d\s().-]{8,18}\d")
_NAME_TITLE_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Shri|Smt|Sh)\.?\s+"
    r"([A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+){0,3})"
)
_NAME_LABEL_RE = re.compile(r"\bname\s*[:\-]\s*([^\n,;|]{2,60})", re.I)

_RESOURCE_TYPES = frozenset(
    {
        "document",
        "stylesheet",
        "image",
        "media",
        "font",
        "script",
        "texttrack",
        "xhr",
        "fetch",
        "eventsource",
        "websocket",
        "manifest",
        "beacon",
        "iframe",
        "other",
    }
)


# --------------------------------------------------------- network observation


def _resource_type(request) -> str:
    try:
        raw = (request.resource_type or "other").lower()
    except Exception:  # noqa: BLE001 - a detached request must not break capture
        return "other"
    if raw == "ping":
        return "beacon"
    if raw == "document":
        try:
            frame = request.frame
            if frame is not None and frame.parent_frame is not None:
                return "iframe"
        except Exception:  # noqa: BLE001
            pass
        return "document"
    return raw if raw in _RESOURCE_TYPES else "other"


class NetworkRecorder:
    """Records every request the browser makes, and whether consent preceded it.

    Attached before the first navigation on purpose. A tracker that fires during
    the initial load is the finding, so the listener has to exist before there
    is anything to listen to.
    """

    def __init__(
        self,
        entry_url: str,
        limit: int = MAX_NETWORK_REQUESTS,
        payload_limit: int = MAX_PAYLOADS_INSPECTED,
    ) -> None:
        self.entry_url = entry_url
        self.entry_host = trackers.normalise_host(urlparse(entry_url).hostname)
        self.limit = limit
        self.payload_limit = payload_limit
        self.requests: list[NetworkRequest] = []
        self.dropped = 0
        self.payloads_inspected = 0
        # A cold load with nobody clicking anything is the default scan, so
        # everything is pre consent until something explicitly says otherwise.
        self.before_consent = True
        self._seen: set[tuple[str, str]] = set()

    def attach(self, page) -> None:
        page.on("request", self.record)

    def mark_consent_interaction(self) -> None:
        """Flip to post consent. Nothing in a default scan calls this."""
        self.before_consent = False

    def record(self, request) -> None:
        # Playwright dispatches this from the event loop, so an exception here
        # would surface far from its cause. Swallow and keep crawling.
        try:
            url = request.url or ""
            if not url or url.startswith(
                ("data:", "blob:", "about:", "chrome-extension:", "javascript:")
            ):
                return
            try:
                method = (request.method or "GET").upper()
            except Exception:  # noqa: BLE001
                method = "GET"
            key = (method, url)
            if key in self._seen:
                return
            if len(self.requests) >= self.limit:
                self.dropped += 1
                return
            self._seen.add(key)
            host = trackers.normalise_host(urlparse(url).hostname)
            record = NetworkRequest(
                url=url[:2000],
                host=host,
                resource_type=_resource_type(request),
                method=method,
                is_third_party=bool(host) and not same_site(url, self.entry_url),
                before_consent=self.before_consent,
                tracker_category=trackers.classify_tracker(host),
                shares_entry_brand=shares_brand_label(host, self.entry_host),
            )
            self.requests.append(record)
            self.inspect_payload(request, record)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not record a request: %s", exc)

    def inspect_payload(self, request, record: NetworkRequest) -> None:
        """Read a request body, keep what it means, and drop what it said.

        Only the size, the categories of personal data in it and the
        measurement parameter names it used survive this call. The body is a
        local that goes out of scope, and it is never logged: the raw value is
        the one thing this tool must not carry forward.

        First party bodies are inspected too, not only third party ones. A
        cloaked host is not known to be third party until after the crawl, and
        a first party endpoint forwarding data onward from the server is only
        recognisable from the shape of what it receives.
        """
        if self.payloads_inspected >= self.payload_limit:
            return
        if record.method not in PAYLOAD_METHODS and record.resource_type != "beacon":
            return
        try:
            body = request.post_data
        except Exception as exc:  # noqa: BLE001 - a detached request has no body
            logger.debug("Could not read a request body: %s", exc)
            return
        if not body:
            return

        self.payloads_inspected += 1
        record.payload_captured = True
        record.payload_bytes = len(body.encode("utf-8", "ignore"))
        trimmed = body[:MAX_PAYLOAD_BYTES]
        record.payload_pii = payload_pii.scan_payload(trimmed)
        record.payload_shape = trackers.beacon_payload_marker(
            payload_pii.payload_keys(trimmed)
        )


def detect_server_side_tagging(
    requests: list[NetworkRequest],
) -> list[ServerSideTagEndpoint]:
    """First party endpoints that receive measurement traffic.

    Server-side tagging moves the onward hop off the page. The browser posts to
    the site's own domain and the site's server forwards to the analytics or
    advertising vendor, so the destination is not observable from a browser at
    all. That is by design, and the commercial scanners have the same limit.

    What is observable is the pattern: a first party endpoint taking POST or
    beacon traffic on a measurement shaped path, or carrying a measurement
    shaped payload. The pattern is what gets recorded. The destination is not
    guessed at, because guessing would put a recipient in a report that nobody
    observed, and this module records only what it saw.

    Requests already known to be third party are excluded, including the ones
    reclassified by CNAME resolution, so resolve the chains first.
    """
    grouped: dict[tuple[str, str], ServerSideTagEndpoint] = {}
    for request in requests:
        if request.is_third_party or not request.host:
            continue
        if request.method not in PAYLOAD_METHODS and request.resource_type != "beacon":
            continue

        path = urlparse(request.url).path or "/"
        path_marker = trackers.server_side_tag_marker(path)
        payload_marker = request.payload_shape
        if not path_marker and not payload_marker:
            continue

        if path_marker and payload_marker:
            matched_on = "path and payload"
            marker = f"{path_marker} carrying {payload_marker}"
        elif path_marker:
            matched_on, marker = "path", path_marker
        else:
            matched_on, marker = "payload", payload_marker

        key = (request.host, path)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = ServerSideTagEndpoint(
                host=request.host,
                path=path,
                url=request.url,
                method=request.method,
                resource_type=request.resource_type,
                matched_on=matched_on,
                marker=marker,
                before_consent=request.before_consent,
                payload_categories=payload_pii.categories(request.payload_pii),
            )
            continue
        existing.request_count += 1
        existing.before_consent = existing.before_consent or request.before_consent
        if matched_on == "path and payload":
            existing.matched_on, existing.marker = matched_on, marker
        existing.payload_categories = sorted(
            set(existing.payload_categories) | set(payload_pii.categories(request.payload_pii))
        )
    return list(grouped.values())


class LoadOutcome(NamedTuple):
    response: object | None
    error: str | None
    partial: bool = False


async def goto_and_settle(page, url: str, timeout_ms: int | None = None) -> LoadOutcome:
    """Navigate, then let the page's own scripts actually run.

    The error is set only when there is nothing to read. The idle wait and the
    settle delay swallow their own timeouts, and so does the navigation itself
    when the document turns out to be usable anyway: a page that never goes
    quiet still yields everything it fired, and one slow page must not cost the
    crawl what it already captured.
    """
    timeout = timeout_ms if timeout_ms is not None else settings.crawl_timeout_seconds * 1000
    partial = False
    try:
        response = await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
    except PlaywrightTimeoutError:
        # An ad heavy homepage can blow the whole navigation budget and still
        # have rendered most of itself. Reporting that as a failure would throw
        # away real evidence and, worse, read as a site that served nothing.
        if not await _has_usable_document(page):
            return LoadOutcome(None, f"navigation timed out after {timeout}ms")
        logger.warning("%s exceeded its navigation budget; using the partial document", url)
        response, partial = None, True
    except PlaywrightError as exc:
        message = str(exc).strip().splitlines()[0] if str(exc).strip() else "navigation failed"
        logger.warning("Failed to load %s: %s", url, message)
        return LoadOutcome(None, message)

    try:
        await page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_TIMEOUT_MS)
    except PlaywrightError:
        logger.debug("%s never reached network idle, continuing", url)
    try:
        await page.wait_for_timeout(SETTLE_DELAY_MS)
    except PlaywrightError:
        pass
    return LoadOutcome(response, None, partial)


async def _has_usable_document(page) -> bool:
    return len((await _inner_text(page)).strip()) >= THIN_PAGE_CHARS


# ------------------------------------------------------------------- the crawl


async def scan_url(
    entry_url: str, *, dns_resolver: cname.Resolver | None = None
) -> WebScanResult:
    """Crawl a site and return what was observed, never what it means.

    dns_resolver is injected so CNAME resolution can be exercised without a
    network. Left unset, the system resolver is used.
    """
    safe_url = validate_scan_url(entry_url)
    result = WebScanResult(
        entry_url=safe_url,
        served_over_https=urlparse(safe_url).scheme == "https",
    )
    entry_error: str | None = None
    failed_pages = 0
    slow_pages = 0
    all_anchors: list[dict] = []
    pre_consent_cookies: set[tuple[str, str]] = set()
    # Full cookie records as they stood once the entry page had settled, not
    # just their keys. The jar is point in time, and a cookie written on first
    # paint can be gone by the end of a crawl: a consent manager that finds no
    # stored choice on the second page view will clear what the first page set.
    # Reading only the final jar reports that cookie as never written, which is
    # a different and much weaker finding than written and later withdrawn.
    entry_cookie_snapshot: dict[tuple[str, str], dict] = {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--disable-dev-shm-usage"])
        context = await browser.new_context(user_agent=USER_AGENT, locale="en-IN")
        page = await context.new_page()

        recorder = NetworkRecorder(safe_url)
        recorder.attach(page)

        queue = [safe_url]
        visited: set[str] = set()

        while queue and len(visited) < settings.max_crawl_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            is_entry = url == safe_url

            response, error, partial = await goto_and_settle(page, url)
            if error is not None:
                failed_pages += 1
                if is_entry:
                    entry_error = error
                continue
            if partial:
                slow_pages += 1

            status = _status_of(response)
            if is_entry:
                if response is not None:
                    result.security_headers = await _security_headers(response)
                else:
                    # A timed out navigation hands back no response. Headers
                    # nobody read must not be reported as headers nobody sent,
                    # and the status matters for the same reason.
                    status, result.security_headers = await _entry_response_facts(context, url)

            body_text = await _inner_text(page)
            result.pages.append(
                PageInfo(
                    url=url,
                    title=await _page_title(page),
                    status_code=status,
                    text_content=body_text[:20000],
                )
            )

            anchors: list[dict] = []
            try:
                result.forms.extend(await _extract_forms(page, url))
                result.third_party_scripts.extend(await _extract_scripts(page, url))
                result.age_gate_fields.extend(await _extract_age_fields(page))
                result.sensitive_fields.extend(await _extract_sensitive_fields(page))
                result.marketing_optins.extend(await _extract_marketing_optins(page))
                anchors = await _extract_anchors(page, url)
            except PlaywrightError as exc:
                logger.warning("Evidence collection incomplete on %s: %s", url, exc)

            for anchor in anchors:
                anchor["from_entry"] = is_entry
            all_anchors.extend(anchors)

            if is_entry:
                result.consent_banner = await _detect_consent_banner(page)
                # Snapshot the jar before anything could be interacted with, so
                # set_before_consent means what it says even if a later version
                # of this module starts clicking Accept.
                entry_cookie_snapshot = {
                    _cookie_key(raw): raw for raw in await _cookies(context)
                }
                pre_consent_cookies = set(entry_cookie_snapshot)

            if result.privacy_notice is None:
                result.privacy_notice = _find_privacy_notice(anchors)
            result.rights_links.extend(
                a["href"] for a in anchors if _matches(f"{a['text']} {a['href']}", RIGHTS_KEYWORDS)
            )
            if result.grievance_contact is None:
                result.grievance_contact = _find_grievance_contact(body_text)

            for anchor in anchors:
                href = anchor["href"]
                if href not in visited and same_site(href, safe_url):
                    queue.append(href)

        page_texts = {p.url: p.text_content for p in result.pages}
        result.policy_documents = await _discover_policies(
            context, page, safe_url, all_anchors, page_texts
        )

        now = time.time()
        entry_host = trackers.normalise_host(urlparse(safe_url).hostname)

        # Union of what the entry page wrote and what survived the crawl. A
        # cookie present in only the first snapshot was still set without a
        # choice having been offered, so it is reported, and flagged as having
        # been withdrawn later so the two cases stay distinguishable.
        final_raw = {_cookie_key(raw): raw for raw in await _cookies(context)}
        merged: dict[tuple[str, str], dict] = dict(entry_cookie_snapshot)
        merged.update(final_raw)

        for key, raw in merged.items():
            # While nothing has been interacted with, the whole jar is pre
            # consent by definition. The snapshot only starts to matter if a
            # caller ever chooses to click through a banner.
            before_consent = recorder.before_consent or key in pre_consent_cookies
            cookie = _cookie_info(raw, entry_host, before_consent=before_consent, now=now)
            cookie.withdrawn_during_crawl = key in entry_cookie_snapshot and key not in final_raw
            result.cookies.append(cookie)

        await browser.close()

    result.network_requests = recorder.requests
    # Runs before anything reads the third party evidence. A tracker on a first
    # party subdomain is invisible to every host based check until the DNS
    # chain is followed, and the reclassification has to be in place before
    # scripts, recipients and pre-consent findings are derived from it.
    await cname.resolve_and_mark(result.network_requests, resolver=dns_resolver)
    result.server_side_tag_endpoints = detect_server_side_tagging(result.network_requests)
    result.third_party_scripts = _dedupe_scripts(
        result.third_party_scripts + _scripts_from_network(recorder.requests)
    )
    result.rights_links = sorted(set(result.rights_links))
    result.sensitive_fields = _dedupe_fields(result.sensitive_fields)
    result.age_gate_fields = _dedupe_fields(result.age_gate_fields)
    result.marketing_optins = _dedupe_consent_elements(result.marketing_optins)

    policy_texts = [d.body_text or "" for d in result.policy_documents if d.reachable]
    result.dpo_contact = _extract_dpo_contact(
        policy_texts + [p.text_content for p in result.pages]
    )
    if result.grievance_contact is None:
        result.grievance_contact = _find_grievance_contact("\n".join(policy_texts))
    _backfill_notice_body(result)

    assess_crawl_health(
        result,
        entry_error=entry_error,
        failed_pages=failed_pages,
        slow_pages=slow_pages,
        dropped_requests=recorder.dropped,
    )
    return result


# ------------------------------------------------------------- crawl integrity


def assess_crawl_health(
    result: WebScanResult,
    *,
    entry_error: str | None = None,
    failed_pages: int = 0,
    slow_pages: int = 0,
    dropped_requests: int = 0,
) -> None:
    """Record whether this result can be read as a picture of the site.

    Blocked means the site turned the scanner away or served it nothing: a 403
    or 429, a challenge page, or a document with no text in it. It deliberately
    does NOT mean "we extracted nothing", because an empty result is far more
    often a bug on this side than a bot wall, and mislabelling our own gap as
    someone else's block hides the bug and lies about the site.
    """
    if not result.pages:
        detail = f" ({entry_error})" if entry_error else ""
        result.crawl_blocked = True
        result.crawl_note = (
            f"The entry page never loaded{detail}, so nothing that happens on the page was "
            "observed. An empty result here is missing evidence, not a clean site."
        )
        return

    entry = result.pages[0]
    reasons = discovery.blocking_reasons(entry.status_code, entry.text_content or "")

    if not reasons:
        notes: list[str] = []
        if failed_pages:
            notes.append(
                f"{failed_pages} page(s) beyond the entry page did not load in time, so coverage "
                "of the site is partial"
            )
        if slow_pages:
            notes.append(
                f"{slow_pages} page(s) exceeded the navigation budget and were read from a "
                "partly loaded document, so some later loading elements may be missing"
            )
        if dropped_requests:
            notes.append(
                f"{dropped_requests} further network request(s) went unrecorded after the "
                f"{MAX_NETWORK_REQUESTS} request cap"
            )
        result.crawl_note = ". ".join(notes) + "." if notes else None
        return

    result.crawl_blocked = True
    result.crawl_note = (
        "Coverage is not reliable because " + ", and ".join(reasons) + ". Absence of trackers, "
        "cookies or forms in this result is therefore not evidence that the site has none."
    )


# ------------------------------------------------------------------- utilities


def _matches(text: str, keywords: tuple[str, ...]) -> bool:
    lowered = (text or "").lower()
    return any(k in lowered for k in keywords)


def _status_of(response) -> int:
    if response is None:
        return 0
    try:
        return int(response.status)
    except Exception:  # noqa: BLE001
        return 0


async def _security_headers(response) -> dict[str, str]:
    try:
        headers = {k.lower(): v for k, v in (await response.all_headers()).items()}
    except PlaywrightError:
        headers = {}
    return {h: headers.get(h, "") for h in SECURITY_HEADERS}


async def _entry_response_facts(context, url: str) -> tuple[int, dict[str, str]]:
    """Status and headers for a navigation that never returned a response."""
    status, _, _, headers = await _fetch(context, url)
    if not status:
        return 0, {}
    return status, {h: headers.get(h, "") for h in SECURITY_HEADERS}


async def _inner_text(page) -> str:
    try:
        return await page.inner_text("body")
    except PlaywrightError:
        return ""


async def _page_title(page) -> str:
    try:
        return await page.title()
    except PlaywrightError:
        return ""


# URL and prose shaping live in the policy discovery module so that both stages
# reduce a document the same way. Kept under their local names because they are
# used throughout the crawl.
_origin = discovery.origin
_normalise_url = discovery.normalise_url
_html_to_text = discovery.html_to_text
_fingerprint = discovery.fingerprint


# ------------------------------------------------------------------- DOM reads


async def _extract_anchors(page, base_url: str) -> list[dict]:
    raw = await page.evaluate(
        """() => [...document.querySelectorAll('a[href]')].map(a => ({
            href: a.getAttribute('href') || '',
            text: (a.innerText || a.textContent || '').trim().slice(0, 200),
            ariaLabel: a.getAttribute('aria-label') || '',
            title: a.getAttribute('title') || '',
            inFooter: Boolean(a.closest(
                'footer, [class*="footer" i], [id*="footer" i], [role="contentinfo"]')),
        }))"""
    )
    anchors: list[dict] = []
    for item in raw:
        href = item.get("href") or ""
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        anchors.append(
            {
                "href": urljoin(base_url, href),
                "text": item.get("text") or "",
                "aria_label": item.get("ariaLabel") or "",
                "title": item.get("title") or "",
                "in_footer": bool(item.get("inFooter")),
            }
        )
    return anchors


def _find_privacy_notice(anchors: list[dict]) -> NoticeInfo | None:
    for anchor in anchors:
        haystack = f"{anchor['text']} {anchor['aria_label']} {anchor['href']}"
        if not _matches(haystack, NOTICE_KEYWORDS):
            continue
        # Rule 3 is about timing as much as existence. A notice reachable only
        # from the footer does not meet "before collection".
        return NoticeInfo(
            url=anchor["href"],
            link_text=anchor["text"] or anchor["aria_label"] or anchor["href"],
            in_footer_only=anchor["in_footer"],
            reachable=True,
        )
    return None


def _find_grievance_contact(body_text: str) -> str | None:
    if not _matches(body_text, GRIEVANCE_KEYWORDS):
        return None
    hits = [
        line.strip()
        for line in (body_text or "").splitlines()
        if line.strip() and _matches(line, GRIEVANCE_KEYWORDS)
    ]
    for line in hits:
        email = _EMAIL_RE.search(line)
        if email:
            return email.group(0)
    # No address on any of them, so return the text around the keyword. A footer
    # navigation row reads as one long line, and returning all of it would bury
    # the only part a reviewer needs to see.
    for line in hits:
        lowered = line.lower()
        positions = [lowered.find(k) for k in GRIEVANCE_KEYWORDS if k in lowered]
        start = max(0, min(positions) - 40) if positions else 0
        return line[start : start + 200].strip()
    return None


async def _extract_forms(page, page_url: str) -> list[FormInfo]:
    raw_forms = await page.evaluate(
        """() => [...document.querySelectorAll('form')].map(form => ({
            action: form.getAttribute('action') || '',
            method: (form.getAttribute('method') || 'get').toLowerCase(),
            hasSubmit: Boolean(form.querySelector(
                'button[type=submit], input[type=submit], button:not([type])')),
            fields: [...form.querySelectorAll('input, select, textarea')].map(el => {
                let label = '';
                if (el.id) {
                    const l = document.querySelector(`label[for="${el.id}"]`);
                    if (l) label = (l.innerText || '').trim();
                }
                if (!label && el.closest('label')) {
                    label = (el.closest('label').innerText || '').trim();
                }
                if (!label) label = el.getAttribute('aria-label') || el.placeholder || '';
                return {
                    name: el.getAttribute('name') || el.id || '',
                    type: (el.getAttribute('type') || el.tagName).toLowerCase(),
                    label: label,
                    required: el.hasAttribute('required'),
                    autocomplete: el.getAttribute('autocomplete') || '',
                    checked: el.checked === true,
                    hasCheckedAttr: el.hasAttribute('checked'),
                };
            }),
        }))"""
    )

    forms: list[FormInfo] = []
    for raw in raw_forms:
        action_url = urljoin(page_url, raw["action"]) if raw["action"] else page_url
        form = FormInfo(
            action=action_url,
            method=raw["method"],
            submits_over_https=urlparse(action_url).scheme == "https",
        )
        for f in raw["fields"]:
            if f["type"] == "checkbox":
                if _matches(f"{f['name']} {f['label']}", CONSENT_KEYWORDS):
                    form.consent_elements.append(
                        ConsentElement(
                            field_name=f["name"],
                            label_text=f["label"],
                            pre_checked=f["checked"] or f["hasCheckedAttr"],
                            near_submit=raw["hasSubmit"],
                        )
                    )
                    continue
            if f["type"] in ("hidden", "submit", "button"):
                continue
            if not f["name"]:
                continue
            form.fields.append(
                FormField(
                    name=f["name"],
                    input_type=f["type"],
                    label=f["label"] or None,
                    required=f["required"],
                    autocomplete=f["autocomplete"] or None,
                )
            )
        forms.append(form)
    return forms


# Inputs anywhere on the page, not only inside a form element, because a client
# rendered signup often has no form element at all.
_ALL_INPUTS_JS = """() => [...document.querySelectorAll('input, select, textarea')].map(el => {
    let label = '';
    if (el.id) {
        const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
        if (l) label = (l.innerText || '').trim();
    }
    if (!label && el.closest('label')) label = (el.closest('label').innerText || '').trim();
    if (!label) label = el.getAttribute('aria-label') || el.placeholder || '';
    return {
        name: el.getAttribute('name') || el.id || '',
        type: (el.getAttribute('type') || el.tagName).toLowerCase(),
        label: (label || '').replace(/\\s+/g, ' ').slice(0, 300),
        required: el.hasAttribute('required'),
        autocomplete: el.getAttribute('autocomplete') || '',
    };
})"""


async def _extract_age_fields(page) -> list[FormField]:
    raw = await page.evaluate(_ALL_INPUTS_JS)
    fields: list[FormField] = []
    for f in raw:
        if _matches(f"{f['name']} {f['label']}", AGE_FIELD_KEYWORDS) or f["type"] == "date":
            fields.append(
                FormField(name=f["name"], input_type=f["type"], label=f["label"] or None)
            )
    return fields


async def _extract_sensitive_fields(page) -> list[FormField]:
    raw = await page.evaluate(_ALL_INPUTS_JS)
    fields: list[FormField] = []
    for f in raw:
        if f["type"] in ("hidden", "submit", "button", "image", "reset"):
            continue
        if not (f["name"] or f["label"]):
            continue
        category = trackers.sensitive_category(f["name"], f["label"], f["autocomplete"])
        if category is None:
            continue
        fields.append(
            FormField(
                name=f["name"] or f["label"][:60],
                input_type=f["type"],
                label=f["label"] or None,
                required=bool(f["required"]),
                autocomplete=f["autocomplete"] or None,
            )
        )
    return fields


async def _extract_marketing_optins(page) -> list[ConsentElement]:
    raw = await page.evaluate(
        """() => [...document.querySelectorAll('input[type=checkbox], input[type=radio]')]
            .map(el => {
                let label = '';
                if (el.id) {
                    const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
                    if (l) label = (l.innerText || '').trim();
                }
                if (!label && el.closest('label')) {
                    label = (el.closest('label').innerText || '').trim();
                }
                if (!label) label = el.getAttribute('aria-label') || '';
                if (!label && el.parentElement) {
                    label = (el.parentElement.innerText || '').trim();
                }
                const scope = el.closest('form') || el.closest('section, fieldset, div');
                return {
                    name: el.getAttribute('name') || el.id || '',
                    label: (label || '').replace(/\\s+/g, ' ').slice(0, 300),
                    checked: el.checked === true || el.hasAttribute('checked'),
                    nearSubmit: Boolean(scope && scope.querySelector(
                        'button[type=submit], input[type=submit], button:not([type])')),
                };
            })"""
    )
    optins: list[ConsentElement] = []
    for item in raw:
        if not trackers.is_marketing_optin(item["name"], item["label"]):
            continue
        optins.append(
            ConsentElement(
                field_name=item["name"],
                label_text=item["label"],
                pre_checked=bool(item["checked"]),
                near_submit=bool(item["nearSubmit"]),
            )
        )
    return optins


async def _extract_scripts(page, page_url: str) -> list[ScriptInfo]:
    srcs = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
    scripts: list[ScriptInfo] = []
    for src in srcs:
        host = trackers.normalise_host(urlparse(src).hostname)
        if not host:
            continue
        scripts.append(
            ScriptInfo(
                src=src, domain=host, is_third_party=not same_site(src, page_url)
            )
        )
    return scripts


def _scripts_from_network(requests: list[NetworkRequest]) -> list[ScriptInfo]:
    """Third party scripts the DOM never showed, because a tag manager added
    them after parsing or an iframe loaded them out of reach."""
    return [
        ScriptInfo(src=r.url, domain=r.host, is_third_party=True)
        for r in requests
        if r.is_third_party and r.resource_type == "script"
    ]


def _dedupe_scripts(scripts: list[ScriptInfo]) -> list[ScriptInfo]:
    seen: dict[str, ScriptInfo] = {}
    for s in scripts:
        seen.setdefault(s.src, s)
    return list(seen.values())


def _dedupe_fields(fields: list[FormField]) -> list[FormField]:
    seen: dict[tuple[str, str, str], FormField] = {}
    for f in fields:
        seen.setdefault((f.name, f.input_type, f.label or ""), f)
    return list(seen.values())


def _dedupe_consent_elements(elements: list[ConsentElement]) -> list[ConsentElement]:
    seen: dict[tuple[str, str], ConsentElement] = {}
    for e in elements:
        seen.setdefault((e.field_name, e.label_text), e)
    return list(seen.values())


# --------------------------------------------------------------- consent banner

_BANNER_JS = """(cfg) => {
    const visible = (el) => {
        if (!el) return false;
        const s = getComputedStyle(el);
        if (s.visibility === 'hidden' || s.display === 'none') return false;
        if (parseFloat(s.opacity || '1') < 0.05) return false;
        const r = el.getBoundingClientRect();
        return r.width > 40 && r.height > 20;
    };
    const describe = (el) => {
        if (el.id) return '#' + el.id;
        const cls = (typeof el.className === 'string' ? el.className : '').trim();
        return el.tagName.toLowerCase() + (cls ? '.' + cls.split(/\\s+/)[0] : '');
    };

    let container = null;
    let selector = null;
    for (const sel of cfg.selectors) {
        let el = null;
        try { el = document.querySelector(sel); } catch (e) { continue; }
        if (el && visible(el)) { container = el; selector = sel; break; }
    }

    if (!container) {
        const candidates = [...document.querySelectorAll(
            'div, section, aside, dialog, form, [role=dialog], [aria-modal=true]')];
        for (const el of candidates) {
            const s = getComputedStyle(el);
            const pinned = s.position === 'fixed' || s.position === 'sticky'
                || (el.tagName === 'DIALOG' && el.open)
                || el.getAttribute('aria-modal') === 'true';
            if (!pinned || !visible(el)) continue;
            const text = (el.innerText || '').toLowerCase();
            if (!text || !cfg.textHints.some(h => text.includes(h))) continue;
            if (!el.querySelector('button, a, input[type=button], [role=button]')) continue;
            container = el;
            selector = describe(el);
            break;
        }
    }

    if (!container) return { present: false };

    const controls = [...container.querySelectorAll(
        'button, a, input[type=button], input[type=submit], [role=button]')]
        .map(el => ({
            text: (el.innerText || el.value || el.getAttribute('aria-label') || '')
                .replace(/\\s+/g, ' ').trim().slice(0, 120),
            href: el.getAttribute('href') || '',
        }))
        .filter(c => c.text);

    const vw = window.innerWidth || 1280;
    const vh = window.innerHeight || 720;
    const rect = container.getBoundingClientRect();
    const cs = getComputedStyle(container);
    const bodyLocked = ['hidden', 'clip'].includes(getComputedStyle(document.body).overflow)
        || ['hidden', 'clip'].includes(getComputedStyle(document.documentElement).overflow);
    const modal = container.getAttribute('aria-modal') === 'true'
        || (container.tagName === 'DIALOG' && container.open);
    const coversViewport = (cs.position === 'fixed' || modal)
        && rect.width * rect.height >= vw * vh * 0.6;
    let backdrop = false;
    for (const el of document.querySelectorAll(
        '[class*="overlay" i], [class*="backdrop" i], [class*="scrim" i], [class*="modal" i]')) {
        const s = getComputedStyle(el);
        if (s.position !== 'fixed' || s.pointerEvents === 'none') continue;
        if (parseFloat(s.opacity || '1') < 0.05) continue;
        const r = el.getBoundingClientRect();
        if (r.width * r.height >= vw * vh * 0.6) { backdrop = true; break; }
    }

    return {
        present: true,
        selector: selector,
        controls: controls,
        text: (container.innerText || '').replace(/\\s+/g, ' ').slice(0, 2000),
        hasToggles: Boolean(container.querySelector(
            'input[type=checkbox], input[type=radio], [role=switch], select')),
        blocking: Boolean(bodyLocked || modal || coversViewport || backdrop),
    };
}"""


async def _detect_consent_banner(page) -> ConsentBanner:
    try:
        raw = await page.evaluate(
            _BANNER_JS,
            {
                "selectors": list(trackers.CMP_CONTAINER_SELECTORS),
                "textHints": list(trackers.BANNER_TEXT_HINTS),
            },
        )
    except PlaywrightError as exc:
        logger.warning("Consent banner detection failed: %s", exc)
        return ConsentBanner()

    if not raw or not raw.get("present"):
        return ConsentBanner()

    banner = ConsentBanner(present=True, selector=raw.get("selector"))
    for control in raw.get("controls") or []:
        label = control.get("text") or ""
        # Refusal is checked first: "Accept only necessary cookies" refuses the
        # rest, and reading it as an accept button would erase the finding.
        if trackers.is_reject_label(label):
            banner.has_reject = True
            banner.reject_label = banner.reject_label or label
        elif trackers.is_manage_label(label):
            banner.has_manage_link = True
        elif trackers.is_accept_label(label):
            banner.has_accept = True
            banner.accept_label = banner.accept_label or label

    text = raw.get("text") or ""
    banner.has_granular_options = bool(raw.get("hasToggles")) or (
        trackers.cookie_category_mentions(text) >= 2
    )
    banner.blocks_page_until_choice = bool(raw.get("blocking"))
    return banner


# ----------------------------------------------------------------- cookie jar


async def _cookies(context) -> list[dict]:
    try:
        return list(await context.cookies())
    except PlaywrightError as exc:
        logger.warning("Could not read the cookie jar: %s", exc)
        return []


def _cookie_key(raw: dict) -> tuple[str, str]:
    return (raw.get("name", ""), raw.get("domain", ""))


async def _cookie_keys(context) -> set[tuple[str, str]]:
    return {_cookie_key(c) for c in await _cookies(context)}


def _cookie_info(
    raw: dict, entry_host: str, *, before_consent: bool, now: float
) -> CookieInfo:
    name = raw.get("name", "")
    domain = raw.get("domain", "") or ""
    expires = raw.get("expires")
    expiry_days: float | None = None
    if isinstance(expires, (int, float)) and expires > 0:
        expiry_days = round((float(expires) - now) / 86400.0, 2)
    return CookieInfo(
        name=name,
        domain=domain,
        secure=bool(raw.get("secure")),
        http_only=bool(raw.get("httpOnly")),
        same_site=raw.get("sameSite"),
        set_before_consent=before_consent,
        is_third_party=_host_is_third_party(domain, entry_host),
        expiry_days=expiry_days,
        classification=trackers.classify_cookie(name),
    )


def _host_is_third_party(cookie_domain: str, entry_host: str) -> bool:
    """Third party means another organisation, not merely another hostname.

    A cookie scoped to a sibling subdomain belongs to the site itself, and
    calling it third party invents a recipient of personal data. The
    organisational domain comes from url_guard, which is also what same_site
    uses, so requests, scripts and cookies all answer this question the same
    way.
    """
    host = registrable_domain(trackers.normalise_host((cookie_domain or "").lstrip(".")))
    entry = registrable_domain(trackers.normalise_host(entry_host))
    if not host or not entry:
        return False
    return host != entry


# ------------------------------------------------------------ policy documents


async def _discover_policies(
    context,
    page,
    entry_url: str,
    anchors: list[dict],
    page_texts: dict[str, str],
) -> list[PolicyDocument]:
    """Find policies by link and by probing conventional paths.

    Probing matters because a site that publishes a policy but links it from
    nowhere is a different finding from a site that has none, and only a probe
    tells the two apart.

    Links from every crawled page count, not only the entry page: plenty of
    homepages render their footer after a scroll, so the privacy link first
    becomes visible on an inner page.
    """
    ordered = discovery.order_candidates(discovery.build_candidates(entry_url, anchors))

    semaphore = asyncio.Semaphore(POLICY_FETCH_CONCURRENCY)

    async def fetch(meta: dict) -> tuple[dict, tuple[int, str, str, dict[str, str]]]:
        async with semaphore:
            return meta, await _fetch(context, meta["url"])

    fetched = await asyncio.gather(*(fetch(m) for m in ordered), return_exceptions=True)

    crawled = {_normalise_url(u): t for u, t in page_texts.items() if t}
    homepage_print = _fingerprint(page_texts.get(entry_url, ""))
    documents: list[PolicyDocument] = []
    thin: list[PolicyDocument] = []

    for item in fetched:
        if isinstance(item, BaseException):
            logger.debug("A policy fetch failed: %s", item)
            continue
        meta, (status, content_type, body, _headers) = item
        text = _html_to_text(body)[:POLICY_BODY_LIMIT]
        word_count = discovery.word_count(text)

        # The crawl may already have rendered this page. Its text beats anything
        # a plain GET returns, and costs the site nothing extra.
        rendered = (crawled.get(_normalise_url(meta["url"])) or "")[:POLICY_BODY_LIMIT]
        from_crawl = False
        if discovery.word_count(rendered) > word_count:
            text, word_count, from_crawl = rendered, discovery.word_count(rendered), True

        echoes_homepage = discovery.echoes_homepage(text, homepage_print)
        reachable = discovery.judge_reachable(
            status=status,
            content_type=content_type,
            words=word_count,
            homepage_echo=echoes_homepage,
            from_rendered=from_crawl,
        )

        if meta["gated"] and not discovery.counts_as_grievance_evidence(text):
            continue

        document = PolicyDocument(
            url=meta["url"],
            kind=meta["kind"],
            reachable=reachable,
            discovered_via=meta["via"],
            body_text=text or None,
            word_count=word_count,
            linked_from_homepage=meta["linked"],
            in_footer_only=meta["footer_only"],
        )
        documents.append(document)
        if (
            not reachable
            and status
            and status < 400
            and not echoes_homepage
            and document.kind in POLICY_RENDER_KINDS
            and same_site(document.url, entry_url)
        ):
            thin.append(document)

    # A policy rendered entirely in JavaScript comes back as an empty shell over
    # HTTP, so the thinnest few are given one pass through the browser.
    for document in thin[:MAX_POLICY_RENDERS]:
        if (await goto_and_settle(page, document.url)).error is not None:
            continue
        text = (await _inner_text(page))[:POLICY_BODY_LIMIT]
        if discovery.word_count(text) <= document.word_count:
            continue
        document.body_text = text
        document.word_count = discovery.word_count(text)
        document.reachable = document.word_count >= MIN_POLICY_WORDS

    return documents


async def _fetch(context, url: str) -> tuple[int, str, str, dict[str, str]]:
    """GET a URL with the crawl's own context, without rendering it.

    Returns (status, content type, body, headers). A status of 0 means the
    request never produced a response.
    """
    empty: dict[str, str] = {}
    try:
        # The URL came off a scanned page, not from the user, so it goes through
        # the same guard as the entry point rather than being trusted.
        safe = await asyncio.to_thread(validate_scan_url, url)
    except (UnsafeURLError, ValueError, OSError) as exc:
        logger.debug("Skipping %s: %s", url, exc)
        return 0, "", "", empty

    try:
        response = await context.request.get(
            safe, timeout=POLICY_FETCH_TIMEOUT_MS, max_redirects=5
        )
    except PlaywrightError as exc:
        logger.debug("Fetch failed for %s: %s", url, exc)
        return 0, "", "", empty

    try:
        status = int(response.status)
        headers = {k.lower(): v for k, v in (response.headers or {}).items()}
        content_type = headers.get("content-type", "").lower()
        if status >= 400:
            return status, content_type, "", headers
        if content_type and not ("text" in content_type or "html" in content_type):
            return status, content_type, "", headers
        body = (await response.text())[: POLICY_BODY_LIMIT * 4]
        return status, content_type, body, headers
    except PlaywrightError as exc:
        logger.debug("Could not read %s: %s", url, exc)
        return 0, "", "", empty


def _backfill_notice_body(result: WebScanResult) -> None:
    """Give the linked notice its prose from whichever copy the crawl read."""
    notice = result.privacy_notice
    if notice is None or notice.body_text:
        return
    key = _normalise_url(notice.url)
    match = next(
        (
            d
            for d in result.policy_documents
            if d.reachable and d.body_text and _normalise_url(d.url) == key
        ),
        None,
    )
    if match is None:
        match = next(
            (
                d
                for d in result.policy_documents
                if d.kind == trackers.KIND_PRIVACY and d.reachable and d.body_text
            ),
            None,
        )
    if match is not None:
        notice.body_text = match.body_text


# -------------------------------------------------------------- officer contact


def _phone_in(text: str) -> str | None:
    for match in _PHONE_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 10 <= len(digits) <= 13:
            return re.sub(r"\s+", " ", match.group(0)).strip()
    return None


def _name_in(text: str) -> str | None:
    titled = _NAME_TITLE_RE.search(text)
    if titled:
        return titled.group(0).strip()
    labelled = _NAME_LABEL_RE.search(text)
    if labelled:
        return labelled.group(1).strip()
    return None


def _extract_dpo_contact(texts: list[str]) -> str | None:
    """Name, email and phone published against an officer title, if any.

    Ranked rather than first-past-the-post, because a policy often names the
    officer in a heading and gives the email several paragraphs later.
    """
    best: tuple[int, str] | None = None
    for text in texts:
        if not text:
            continue
        for keyword in trackers.DPO_KEYWORDS:
            pattern = re.compile(r"\b" + trackers.escape_phrase(keyword) + r"\b", re.I)
            for match in pattern.finditer(text):
                start = match.start()
                window = text[max(0, start - 200) : start + 700]
                email = _EMAIL_RE.search(window)
                phone = _phone_in(window)
                name = _name_in(window)
                if not (email or phone or name):
                    continue
                parts = [match.group(0).strip()]
                if name:
                    parts.append(name)
                if email:
                    parts.append(email.group(0))
                if phone:
                    parts.append(phone)
                score = (2 if email else 0) + (1 if phone else 0)
                candidate = " | ".join(parts)[:240]
                if best is None or score > best[0]:
                    best = (score, candidate)
                if score == 3:
                    return candidate
    return best[1] if best else None
