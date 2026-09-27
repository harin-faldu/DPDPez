"""CNAME chain resolution for first party subdomains.

A tracker served from metrics.example.com whose DNS chain ends at an analytics
provider is first party by name only. registrable_domain sees example.com, so
without this the request never reaches the third party evidence, the
pre-consent evidence or the list of recipients: it vanishes. The technique
exists to defeat exactly this kind of scanner and the browser cookie controls
behind it, which makes a host using it the most deliberate evasion a crawl can
catch and its absence from a report the worst kind of false negative.

Cost is capped on purpose. Only distinct first party subdomains that actually
sent a beacon, xhr, fetch or script request are resolved, no more than
MAX_CNAME_LOOKUPS of them, concurrently, with a short timeout each and one
cache for the whole scan. A zone apex is skipped because DNS cannot carry a
CNAME there, which removes the most requested host on every site from the
budget for free.

Resolution failure degrades to "not cloaked". It never blocks a scan, never
fails one and never turns a lookup problem into a finding about the site.

The resolver is injected so the test suite never touches DNS.
"""

import asyncio
import inspect
import logging
import socket
from collections.abc import Callable, Iterable, Sequence

from app.contracts import NetworkRequest
from app.scanner import trackers
from app.scanner.url_guard import registrable_domain

logger = logging.getLogger(__name__)

# Twelve is enough for the handful of subdomains a page really beacons to, and
# small enough that a scan never turns into a DNS sweep of someone's zone.
MAX_CNAME_LOOKUPS = 12
CNAME_LOOKUP_CONCURRENCY = 6
CNAME_TIMEOUT_SECONDS = 2.0

# Cloaking is used to get a tracker's own traffic through, so only the request
# kinds that carry measurement are worth a lookup. Images, fonts and
# stylesheets on a first party subdomain are the site serving its own assets.
CLOAKABLE_RESOURCE_TYPES = frozenset({"beacon", "xhr", "fetch", "script"})

# A resolver takes a hostname and returns the chain of canonical names it
# resolves through, nearest hop first. Sync or async, both are accepted.
Resolver = Callable[[str], object]


def system_resolver(host: str) -> list[str]:
    """The CNAME chain for a host, from the system resolver.

    The standard library exposes no per hop record, so the chain is
    reconstructed from what gethostbyname_ex reports: the canonical name the
    chain ends at, plus the aliases walked to reach it. That is enough to see
    where a name lands, which is the whole question here. Platforms differ in
    how much alias detail they return, and one that returns none simply yields
    an empty chain and the host reads as not cloaked.
    """
    try:
        canonical, aliases, _addresses = socket.gethostbyname_ex(host)
    except (OSError, UnicodeError, ValueError):
        return []
    chain: list[str] = []
    for name in [*aliases, canonical]:
        hop = trackers.normalise_host(name)
        if hop and hop != host and hop not in chain:
            chain.append(hop)
    return chain


def candidate_hosts(
    requests: Iterable[NetworkRequest], *, limit: int = MAX_CNAME_LOOKUPS
) -> list[str]:
    """Distinct subdomains that sent a request worth resolving.

    First party subdomains, plus the third party ones carrying the entry site's
    own brand under another suffix. The second group is here because the
    sharing evidence treats those as a probable same operator, so they are
    exactly the hosts where cloaking would otherwise buy an exemption. A host
    the evidence is prepared to excuse is a host worth resolving.
    """
    found: list[str] = []
    for request in requests:
        if request.resource_type not in CLOAKABLE_RESOURCE_TYPES:
            continue
        if request.is_third_party and not request.shares_entry_brand:
            continue
        host = trackers.normalise_host(request.host)
        # The apex cannot carry a CNAME, so resolving it would spend the budget
        # on the one host every page contacts and learn nothing.
        if not host or host == registrable_domain(host) or host in found:
            continue
        found.append(host)
        if len(found) >= limit:
            break
    return found


def cloaked_target(chain: Sequence[str], host: str) -> tuple[str, str] | None:
    """The first hop off the organisation that is a known tracker, and its category."""
    origin = registrable_domain(trackers.normalise_host(host))
    for hop in chain:
        if not hop or registrable_domain(hop) == origin:
            continue
        category = trackers.classify_tracker(hop)
        if category:
            return hop, category
    return None


async def _resolve_one(resolve: Resolver, host: str, timeout: float) -> list[str]:
    try:
        if inspect.iscoroutinefunction(resolve):
            chain = await asyncio.wait_for(resolve(host), timeout=timeout)
        else:
            chain = await asyncio.wait_for(asyncio.to_thread(resolve, host), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - a DNS problem is not a finding
        logger.debug("CNAME lookup for %s did not complete: %s", host, exc)
        return []
    if inspect.isawaitable(chain):
        chain = await chain
    return [hop for hop in (trackers.normalise_host(h) for h in (chain or [])) if hop]


async def resolve_chains(
    hosts: Sequence[str],
    *,
    resolver: Resolver | None = None,
    timeout: float = CNAME_TIMEOUT_SECONDS,
    concurrency: int = CNAME_LOOKUP_CONCURRENCY,
    cache: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Resolve every host once, concurrently, and cache the result per scan."""
    resolve = resolver or system_resolver
    chains: dict[str, list[str]] = {} if cache is None else cache
    pending = [h for h in dict.fromkeys(hosts) if h not in chains]
    if not pending:
        return chains

    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(host: str) -> tuple[str, list[str]]:
        async with semaphore:
            return host, await _resolve_one(resolve, host, timeout)

    for outcome in await asyncio.gather(*(one(h) for h in pending), return_exceptions=True):
        if isinstance(outcome, BaseException):
            logger.debug("A CNAME lookup failed: %s", outcome)
            continue
        host, chain = outcome
        chains[host] = chain
    return chains


def mark_cloaked_requests(
    requests: Iterable[NetworkRequest], chains: dict[str, list[str]]
) -> list[str]:
    """Record every chain, and reclassify the requests whose chain ends at a tracker.

    A cloaked request becomes third party and carries the tracker's category,
    because that is what it is: the data left the organisation. The chain is
    kept on every resolved request, cloaked or not, so a reviewer can see what
    was checked rather than only what was found.
    """
    by_host: dict[str, list[NetworkRequest]] = {}
    for request in requests:
        by_host.setdefault(trackers.normalise_host(request.host), []).append(request)

    cloaked: set[str] = set()
    for host, chain in chains.items():
        matching = by_host.get(host)
        if not matching or not chain:
            continue
        target = cloaked_target(chain, host)
        for request in matching:
            request.cname_chain = list(chain)
            if target is None:
                continue
            request.cname_cloaked = True
            request.cname_target = target[0]
            request.is_third_party = True
            request.tracker_category = request.tracker_category or target[1]
        if target is not None:
            cloaked.add(host)
    return sorted(cloaked)


async def resolve_and_mark(
    requests: list[NetworkRequest],
    *,
    resolver: Resolver | None = None,
    limit: int = MAX_CNAME_LOOKUPS,
    timeout: float = CNAME_TIMEOUT_SECONDS,
) -> list[str]:
    """Resolve the worthwhile first party subdomains and reclassify what is cloaked."""
    hosts = candidate_hosts(requests, limit=limit)
    if not hosts:
        return []
    chains = await resolve_chains(hosts, resolver=resolver, timeout=timeout)
    return mark_cloaked_requests(requests, chains)
