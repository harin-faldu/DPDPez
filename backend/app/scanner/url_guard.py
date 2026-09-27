"""SSRF guard for the web scanner.

The scanner fetches a URL the user supplies, so it must not be usable as a proxy
into private networks or cloud metadata endpoints. Resolution happens before the
check because a public hostname can point at 127.0.0.1.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from app.config import settings

BLOCKED_HOSTNAMES = frozenset(
    {"metadata.google.internal", "metadata.goog", "instance-data"}
)

BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, includes cloud metadata
    ipaddress.ip_network("fe80::/10"),
)


class UnsafeURLError(ValueError):
    pass


def validate_scan_url(url: str) -> str:
    """Return a normalised URL, or raise UnsafeURLError."""
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")

    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError(f"Only http and https are allowed, got '{parsed.scheme}'")
    if not parsed.hostname:
        raise UnsafeURLError("URL has no hostname")

    hostname = parsed.hostname.lower().rstrip(".")
    if hostname in BLOCKED_HOSTNAMES:
        raise UnsafeURLError(f"Host '{hostname}' is not a permitted scan target")

    try:
        resolved = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"Could not resolve '{hostname}'") from exc

    # The product is a self-check, so scanning your own application on localhost
    # is the primary use, not an attack. The guard exists to stop a HOSTED
    # instance being used as a proxy into a private network, which is a
    # different deployment. Off by default; a hosted instance leaves it off.
    if settings.allow_private_scan_targets:
        return parsed.geturl()

    for *_, sockaddr in resolved:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
            raise UnsafeURLError(
                f"'{hostname}' resolves to a non-public address ({ip}); "
                "scanning internal hosts is not permitted"
            )
        for network in BLOCKED_NETWORKS:
            if ip.version == network.version and ip in network:
                raise UnsafeURLError(
                    f"'{hostname}' resolves into a blocked range ({network})"
                )

    return parsed.geturl()


# Suffixes under which the next label is the registrable name. Without these,
# "last two labels" makes every .ac.in university look like the same site as
# every other one, and Indian targets are exactly what this tool scans.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
        "ac.in", "edu.in", "res.in", "gov.in", "nic.in", "mil.in",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.br", "com.cn", "com.sg", "com.my", "co.za", "co.nz",
        "com.tr", "com.mx", "co.id", "co.kr", "com.hk", "com.tw",
        "github.io", "pages.dev", "workers.dev", "vercel.app",
        "netlify.app", "herokuapp.com", "appspot.com", "azurewebsites.net",
        "cloudfront.net", "s3.amazonaws.com", "blob.core.windows.net",
    }
)


def registrable_domain(host: str | None) -> str:
    """The organisational domain: analytics.python.org and www.python.org
    both yield python.org, while a.ac.in and b.ac.in stay distinct.

    This decides whether a request left the organisation, which drives the
    third-party and data-sharing findings, so getting it wrong either invents
    recipients or hides them.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h or h.replace(".", "").isdigit():
        return h
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    for depth in (3, 2):
        if len(labels) > depth and ".".join(labels[-depth:]) in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-(depth + 1) :])
    return ".".join(labels[-2:])


def same_site(candidate: str, entry: str) -> bool:
    """True when candidate belongs to the same organisation as entry."""
    c, e = urlparse(candidate), urlparse(entry)
    if not c.hostname or not e.hostname:
        return False
    return registrable_domain(c.hostname) == registrable_domain(e.hostname)


# Brand labels too generic to mean common ownership. A company that registered
# cloud.io has nothing to do with whoever holds cloud.ai, while two holders of
# the same invented word almost always do. Short labels are excluded by length
# rather than listed, since collisions among them are the rule.
GENERIC_BRAND_LABELS = frozenset(
    {
        "cloud", "static", "assets", "email", "mail", "store", "shop", "online",
        "digital", "global", "support", "service", "services", "payment",
        "payments", "secure", "login", "portal", "group", "india", "network",
        "content", "images", "video", "search", "media", "data", "analytics",
        "software", "systems", "solutions", "technology", "platform", "studio",
        "agency", "company", "market", "finance", "health", "travel", "news",
    }
)

# Below this, a shared label is a coincidence more often than a company.
MIN_BRAND_LABEL_LENGTH = 4


def brand_label(host: str | None) -> str:
    """The registrable name with its public suffix removed.

    redacto.ai and redacto.io both yield "redacto", and shop.co.in yields
    "shop". Says nothing on its own about who owns either.
    """
    domain = registrable_domain(host)
    if not domain or domain.replace(".", "").isdigit():
        return ""
    return domain.split(".", 1)[0]


def shares_brand_label(candidate: str | None, entry: str | None) -> bool:
    """True when two different domains carry the same brand under another suffix.

    Evidence of a probable common operator, not proof of one. A live scan found
    a site on redacto.ai loading api.redacto.io, which registrable_domain
    correctly calls a different domain and which the sharing evidence would
    then have reported as an external recipient of personal data: wrong in
    substance, because it is the site talking to its own backend.

    This deliberately does not merge the two. The registrable domains stay
    different, the request stays third party, and the caller is expected to say
    "probably the same operator" out loud rather than quietly folding the host
    into the first party. Ownership is not observable from a page, so the claim
    made has to stay as weak as the evidence for it.
    """
    left, right = registrable_domain(candidate), registrable_domain(entry)
    if not left or not right or left == right:
        return False
    label = brand_label(candidate)
    if label != brand_label(entry):
        return False
    if len(label) < MIN_BRAND_LABEL_LENGTH or label in GENERIC_BRAND_LABELS:
        return False
    return True
