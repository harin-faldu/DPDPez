"""Finding a site's published policies, as the single source of truth.

Two stages need to do this. The web scanner discovers policies inside its crawl
because it already has a browser open, and the policy stage discovers them on
its own with a light fetch. Two implementations of "is this a policy" would
drift, and the moment they drift the two stages disagree about what the site
publishes, which is the one thing a cross-stage finding cannot survive.

So everything decidable without a network lives here: the candidate list, kind
classification, the soft 404 and homepage echo tests, turning markup into prose,
counting words, and judging whether a fetched body is a document at all. The
browser driving and the fetching stay with their callers.

Nothing in this module performs IO, which is what makes it testable against
fixture HTML rather than against a live site.
"""

import html as html_lib
import re
from urllib.parse import urljoin, urlparse, urlunparse

from app.scanner import trackers

# A policy body past this is being quoted, not read. The cap is generous because
# a real notice from a large organisation runs to tens of thousands of words.
POLICY_BODY_LIMIT = 60000

# Below this a "policy" is a soft 404, a client side shell or a stub, not a
# document a Data Principal could read.
MIN_POLICY_WORDS = 40

MAX_POLICY_FETCHES = 24
MAX_POLICY_LINKS = 10
POLICY_FETCH_CONCURRENCY = 4
POLICY_FETCH_TIMEOUT_MS = 10000
MAX_POLICY_RENDERS = 2

POLICY_RENDER_KINDS: tuple[str, ...] = (
    trackers.KIND_PRIVACY,
    trackers.KIND_COOKIE,
    trackers.KIND_GRIEVANCE,
    trackers.KIND_CHILDREN,
)
# The kinds the rules engine reads by name, so the ones worth the fetch budget.
POLICY_PRIORITY_KINDS: tuple[str, ...] = POLICY_RENDER_KINDS

# Statuses that mean the scanner was turned away rather than served.
BLOCKING_STATUS = frozenset({401, 403, 406, 407, 429, 451})
# A body this short is not a page. Compare against rendered text, not HTML, so a
# large JavaScript bundle that renders nothing still counts as empty.
THIN_PAGE_CHARS = 200
# A long page that merely mentions a captcha is still the page, so the bot wall
# markers are only trusted on a short body.
BOT_WALL_TEXT_LIMIT = 1500

_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript|template)\b[^>]*>.*?</\1\s*>", re.I | re.S
)
_BLOCK_END_RE = re.compile(r"<br\s*/?>|</(?:p|div|li|tr|h[1-6]|section)\s*>", re.I)
_TAG_RE = re.compile(r"<[^>]+>")
_HREF_RE = re.compile(r"""<a\b[^>]*?href\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)[^>]*>""", re.I)
_ATTR_RE = re.compile(r"""(aria-label|title)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", re.I)
_ANCHOR_TEXT_RE = re.compile(r"<a\b[^>]*>(.*?)</a\s*>", re.I | re.S)

# Schemes and pseudo-links that never point at a document.
_UNFETCHABLE_PREFIXES = ("#", "javascript:", "mailto:", "tel:", "data:", "sms:", "blob:")


# ------------------------------------------------------------------ url shaping


def origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def normalise_url(url: str) -> str:
    """Key for deduplication: no fragment, no query, no trailing slash."""
    parsed = urlparse(url)
    path = (parsed.path or "/").rstrip("/") or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", "", ""))


def is_fetchable(href: str) -> bool:
    return bool(href) and not href.startswith(_UNFETCHABLE_PREFIXES)


# ------------------------------------------------------------------ text shaping


def html_to_text(html: str) -> str:
    """Markup reduced to the prose a reader would see.

    Scripts and styles go first, because their contents are not prose and a
    minified bundle would otherwise dominate the word count and make an empty
    shell look like a substantial document.
    """
    if not html:
        return ""
    stripped = _SCRIPT_STYLE_RE.sub(" ", html)
    stripped = _BLOCK_END_RE.sub("\n", stripped)
    stripped = _TAG_RE.sub(" ", stripped)
    text = html_lib.unescape(stripped)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n", text).strip()


def word_count(text: str | None) -> int:
    return len((text or "").split())


def fingerprint(text: str) -> str:
    """A cheap identity for a page's opening prose.

    Used only to notice that two different URLs returned the same document,
    which is how a soft 404 that serves the homepage gives itself away.
    """
    return re.sub(r"\s+", " ", (text or "")).strip().lower()[:300]


def echoes_homepage(text: str, homepage_fingerprint: str) -> bool:
    """True when a fetched policy is really the homepage served again.

    A site that answers every unknown path with its homepage, rather than a 404,
    would otherwise have every probed path recorded as a policy it publishes.
    """
    return bool(homepage_fingerprint) and fingerprint(text) == homepage_fingerprint


# Above this share of a page's own lines also appearing on the homepage, what
# was fetched is the site's furniture rather than a document.
_BOILERPLATE_SHARE = 0.75
# Shorter lines than this are punctuation and separators, not content.
_MIN_CHROME_LINE = 3


def _content_lines(text: str) -> list[str]:
    lines = [re.sub(r"\s+", " ", ln).strip().lower() for ln in (text or "").splitlines()]
    return [ln for ln in lines if len(ln.split()) >= _MIN_CHROME_LINE]


def mostly_boilerplate(text: str, home_text: str) -> bool:
    """True when a page is nearly all header, navigation and footer.

    echoes_homepage only catches a page that IS the homepage. A site whose
    template wraps every route in the same menus produces pages that are not
    identical to the homepage but carry almost none of their own words, and a
    word count alone cannot tell those from a short policy.

    A live scan found a university's "Under Construction" placeholder and its
    SC/ST cell page both recorded as grievance policies at around three hundred
    words each, every one of which was the shared header and footer. Counting
    those as published policies credits an organisation with a redressal
    mechanism it has not written.
    """
    own = _content_lines(text)
    if not own:
        return True
    shared = set(_content_lines(home_text))
    if not shared:
        return False
    overlap = sum(1 for line in own if line in shared)
    return overlap / len(own) >= _BOILERPLATE_SHARE


# ----------------------------------------------------------- kind and readiness


def classify_link(
    text: str | None = None,
    aria_label: str | None = None,
    title: str | None = None,
    href: str | None = None,
) -> str | None:
    """Which policy kind a link reads like, or None.

    Only the path of href is considered. A host contributes tokens without
    contributing meaning, and it is the token cap inside policy_kind_for_link
    that keeps article URLs from being filed as policies.
    """
    return trackers.policy_kind_for_link(
        text, aria_label, title, urlparse(href or "").path
    )


# Path segments that mean a page is marketing or editorial content, whatever its
# link label says. A live read of a privacy tooling vendor filed three of its own
# product pages as privacy notices, because "CI/CD Privacy Scanner" is a link
# label full of the right word, and their marketing prose then fed the statutory
# checks as though the organisation had written it about itself.
#
# Offered rather than applied by default: the web scanner has its own tests
# pinning what it files, so only the policy stage filters on this today.
MARKETING_PATH_SEGMENTS = frozenset(
    {
        "product", "products", "solution", "solutions", "feature", "features",
        "pricing", "plans", "blog", "blogs", "post", "posts", "article",
        "articles", "news", "newsroom", "press", "resources", "resource",
        "case-study", "case-studies", "customers", "customer-stories",
        "testimonials", "integrations", "integration", "compare", "comparison",
        "alternatives", "webinar", "webinars", "ebook", "ebooks", "whitepaper",
        "whitepapers", "guide", "guides", "glossary", "academy", "learn",
        "templates", "tools", "downloads", "events", "demo", "use-case",
        "use-cases", "industries", "industry", "careers", "jobs", "team",
        "partners", "docs", "documentation", "changelog", "roadmap", "pages",
    }
)


def looks_like_marketing_path(url: str) -> bool:
    """True when the URL sits under a content or product section of the site.

    Matched on whole path segments, so /legal/privacy and /privacy-policy are
    untouched while /products/privacy-scanner and /blog/privacy-in-2026 are not.
    """
    segments = [s for s in urlparse(url).path.lower().split("/") if s]
    return any(s in MARKETING_PATH_SEGMENTS for s in segments)


def counts_as_grievance_evidence(text: str | None) -> bool:
    """Whether a probed contact page actually names a grievance route.

    A bare contact form is not a redressal mechanism, and recording it as one
    would read as compliance nobody earned.
    """
    return trackers.mentions_grievance_route(text)


def judge_reachable(
    *,
    status: int,
    content_type: str,
    words: int,
    homepage_echo: bool,
    from_rendered: bool = False,
) -> bool:
    """Whether a fetched body is a document a Data Principal could read.

    Rendered text is trusted on its own: if a browser produced prose, the status
    of the plain GET that also happened is beside the point. A non-text body is
    taken at its word, because a PDF notice is a notice even though no word count
    can be taken from it here.
    """
    if from_rendered:
        return words >= MIN_POLICY_WORDS and not homepage_echo
    if status == 0 or status >= 400:
        return False
    text_like = (not content_type) or "text" in content_type or "html" in content_type
    if not text_like:
        return True
    return words >= MIN_POLICY_WORDS and not homepage_echo


# ----------------------------------------------------------------- the candidates


# How many leading path segments of the landed URL count as a locale or section
# prefix worth probing beneath. Two covers /en/in and /en-in/legal.
_MAX_PREFIX_SEGMENTS = 2


def probe_bases(entry_url: str, landed_url: str | None = None) -> list[str]:
    """The roots the conventional paths are tried against.

    The origin alone is not enough. A great many Indian sites serve everything
    under a locale prefix, so the notice lives at /en/in/privacy-statement and
    the origin probe for /privacy-statement returns a soft 404. A live scan
    reported a large payments site as publishing no policy at all for exactly
    that reason, while its notice sat two segments in.
    """
    bases = [origin(entry_url)]
    for candidate in (landed_url, entry_url):
        segments = [s for s in urlparse(candidate or "").path.split("/") if s]
        for depth in range(1, min(len(segments), _MAX_PREFIX_SEGMENTS) + 1):
            base = urljoin(origin(entry_url), "/".join(segments[:depth]) + "/")
            if base not in bases:
                bases.append(base)
    return bases


def probe_candidates(entry_url: str, landed_url: str | None = None) -> list[dict]:
    """The conventional paths, as candidate records against each base.

    Probing matters because a site that publishes a policy but links it from
    nowhere is a different finding from a site that has none, and only a probe
    tells the two apart.
    """
    probes = [(p, k, False) for p, k in trackers.POLICY_PROBE_PATHS]
    probes += [(p, trackers.KIND_GRIEVANCE, True) for p in trackers.CONTACT_PROBE_PATHS]
    records: list[dict] = []
    seen: set[str] = set()
    for base in probe_bases(entry_url, landed_url):
        for path, kind, gated in probes:
            url = urljoin(base, path.lstrip("/"))
            key = normalise_url(url)
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "url": url,
                    "kind": kind,
                    "via": "well_known_path",
                    "linked": False,
                    "footer_only": False,
                    "gated": gated,
                }
            )
    return records


# Where a candidate came from. A supplied URL is a person telling us where the
# policy is, which outranks anything guessed or scraped.
VIA_SUPPLIED = "supplied"


def supplied_candidates(urls: list[str] | None) -> list[dict]:
    """Policy URLs handed over by whoever asked for the scan.

    The fallback for a notice this stage cannot find on its own: one rendered
    entirely client side comes back as an empty shell over plain HTTP, and
    guessing harder does not fix that. Rather than report such a site as
    publishing nothing, the caller can say where the document is.

    Kind is inferred from the path, defaulting to the privacy notice, because
    that is what someone supplying a single link almost always means.
    """
    records: list[dict] = []
    for raw in urls or []:
        url = (raw or "").strip()
        if not url or not is_fetchable(url):
            continue
        records.append(
            {
                "url": url,
                "kind": classify_link(href=url) or "privacy",
                "via": VIA_SUPPLIED,
                # Says nothing about where it sits on the site. Someone pasting
                # a link is not evidence the site links it before collection,
                # and recording it as linked would invent that.
                "linked": False,
                "footer_only": False,
                "gated": False,
            }
        )
    return records


def build_candidates(
    entry_url: str,
    anchors: list[dict],
    supplied: list[dict] | None = None,
    landed_url: str | None = None,
) -> dict[str, dict]:
    """Merge policy links with the probe list, keyed by normalised URL.

    Each anchor is a dict with href, text, aria_label, title, in_footer and an
    optional from_entry. Links from every page count, not only the entry page:
    plenty of homepages render their footer after a scroll, so the privacy link
    first becomes visible on an inner page.
    """
    candidates: dict[str, dict] = {}
    supplied = supplied or []

    for anchor in anchors:
        href = anchor.get("href") or ""
        if not is_fetchable(href):
            continue
        kind = classify_link(
            anchor.get("text"), anchor.get("aria_label"), anchor.get("title"), href
        )
        if kind is None:
            continue
        # A page under /products or /blog that happens to carry a policy word is
        # marketing about privacy, not a privacy notice. Live run: a site's
        # /products/privacy-pia-audit and /products/ci-cd-privacy pages were
        # read as its privacy policy, and 500 words of product copy was then
        # assessed against the notice requirements.
        if looks_like_marketing_path(href):
            continue
        from_entry = bool(anchor.get("from_entry", True))
        key = normalise_url(href)
        existing = candidates.get(key)
        if existing is None:
            candidates[key] = {
                "url": href,
                "kind": kind,
                "via": "link",
                "linked": from_entry,
                "footer_only": bool(anchor.get("in_footer")),
                "gated": False,
            }
        else:
            # Footer only is an all-or-nothing claim about every link to it.
            existing["footer_only"] = existing["footer_only"] and bool(
                anchor.get("in_footer")
            )
            existing["linked"] = existing["linked"] or from_entry

    for probe in probe_candidates(entry_url, landed_url):
        candidates.setdefault(normalise_url(probe["url"]), probe)

    for given in supplied:
        # Overwrites rather than defers. If a person names a URL, their say on
        # what it is beats a guess made from its path.
        candidates[normalise_url(given["url"])] = given

    return candidates


def order_candidates(candidates: dict[str, dict]) -> list[dict]:
    """Spend the fetch budget on links first, without crowding out the probes.

    A document the site points at is worth more than a guessed path, but the
    guesses cannot be dropped either: a site with many policy links is exactly
    the kind that also hides one behind an unlinked path.
    """
    given = [m for m in candidates.values() if m["via"] == VIA_SUPPLIED]
    links = [m for m in candidates.values() if m["via"] == "link"]
    links.sort(key=lambda m: (m["kind"] not in POLICY_PRIORITY_KINDS, not m["linked"]))
    probes = [
        m for m in candidates.values() if m["via"] not in ("link", VIA_SUPPLIED)
    ]
    # Supplied first and never truncated: the whole point of handing one over is
    # that discovery already failed.
    return given + (links[:MAX_POLICY_LINKS] + probes)[:MAX_POLICY_FETCHES]


# ------------------------------------------------------ anchors from plain HTML


def extract_anchors(html: str, base_url: str) -> list[dict]:
    """Links out of raw markup, for a caller with no browser.

    Deliberately coarse. It exists so the policy stage can find a footer privacy
    link in server rendered HTML, not to reproduce a DOM. A link only reachable
    after JavaScript runs is invisible here, and the conventional path probes are
    what stops that becoming a false "publishes nothing".
    """
    anchors: list[dict] = []
    for match in _ANCHOR_TEXT_RE.finditer(html or ""):
        tag = match.group(0)
        href_match = _HREF_RE.match(tag)
        if href_match is None:
            continue
        href = _unquote_attr(href_match.group(1))
        if not is_fetchable(href):
            continue
        attrs = {k.lower(): _unquote_attr(v) for k, v in _ATTR_RE.findall(tag)}
        anchors.append(
            {
                "href": urljoin(base_url, href),
                "text": html_to_text(match.group(1))[:200],
                "aria_label": attrs.get("aria-label", ""),
                "title": attrs.get("title", ""),
                "in_footer": False,
                "from_entry": True,
            }
        )
    return anchors


def _unquote_attr(raw: str) -> str:
    value = (raw or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return html_lib.unescape(value).strip()


# ------------------------------------------------------------- coverage honesty


def blocking_reasons(status_code: int, text: str) -> list[str]:
    """Why this response cannot be read as a picture of the site, if it cannot.

    Blocked means the site turned the scanner away or served it nothing: a 403
    or 429, a challenge page, or a document with no text in it. It deliberately
    does NOT mean "we extracted nothing", because an empty result is far more
    often a bug on this side than a bot wall, and mislabelling our own gap as
    someone else's block hides the bug and misdescribes the site.
    """
    body = (text or "").strip()
    lowered = body.lower()
    reasons: list[str] = []

    if status_code in BLOCKING_STATUS or status_code >= 500:
        reasons.append(f"the site answered HTTP {status_code}")
    if len(body) < BOT_WALL_TEXT_LIMIT:
        marker = next((m for m in trackers.BOT_WALL_MARKERS if m in lowered), None)
        if marker is not None:
            reasons.append(
                f"the response reads like a challenge or refusal page ('{marker}')"
            )
    if len(body) < THIN_PAGE_CHARS:
        reasons.append(f"the rendered document held only {len(body)} characters of text")

    return reasons
