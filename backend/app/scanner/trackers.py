"""Curated lookup tables the web scanner matches its evidence against.

These live outside web_scanner so the lists can be extended by anyone without
touching crawl logic, and so every matching rule stays unit testable without a
browser.

Host matching is registrable suffix based, never substring. Trackers shard
across regional and per customer subdomains (in.hotjar.com, cdn-eu.clarity.ms,
in1.api.clevertap.com), while substring matching would file
socialmedia.network under media.net.

This module records what a thing is, never whether it is allowed. The rules
engine decides that.
"""

import re
from collections.abc import Iterable

# Categories. These strings are read by the rules engine, so they are fixed.
ANALYTICS = "analytics"
ADVERTISING = "advertising"
SOCIAL = "social"
REPLAY = "replay"
TAG_MANAGER = "tag_manager"

NECESSARY = "necessary"
UNKNOWN = "unknown"

# Policy kinds. The first four are the ones the rules engine asks for by name.
KIND_PRIVACY = "privacy"
KIND_COOKIE = "cookie"
KIND_GRIEVANCE = "grievance"
KIND_CHILDREN = "children"
KIND_TERMS = "terms"
KIND_REFUND = "refund"
KIND_SECURITY = "security"


# --------------------------------------------------------------- tracker hosts

_TRACKER_HOSTS_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    # A tag manager is listed on its own because it rarely carries data itself,
    # it loads everything else. A page that fires only a container still tells
    # you the rest of the stack is one publish away.
    TAG_MANAGER: (
        "googletagmanager.com",
        "tagmanager.google.com",
        "tealiumiq.com",
        "tiqcdn.com",
        "adobedtm.com",
        "ensighten.com",
        "signalfx-tag.com",
        "tagcommander.com",
        "cdn.optimizely.com",
    ),
    ANALYTICS: (
        "google-analytics.com",
        "analytics.google.com",
        "googleoptimize.com",
        "mixpanel.com",
        "amplitude.com",
        "segment.com",
        "segment.io",
        "segmentapis.com",
        "heapanalytics.com",
        "matomo.cloud",
        "piwik.pro",
        "plausible.io",
        "statcounter.com",
        "scorecardresearch.com",
        "chartbeat.com",
        "chartbeat.net",
        "parsely.com",
        "mc.yandex.ru",
        "yandex.ru",
        "getclicky.com",
        "kissmetrics.io",
        "woopra.com",
        "countly.com",
        "mparticle.com",
        "snowplowanalytics.com",
        "2o7.net",
        "omtrdc.net",
        "visualwebsiteoptimizer.com",
        "vwo.com",
        "optimizely.com",
        "clevertap.com",
        "wzrk.net",
        "moengage.com",
        "moengage.co",
        "webengage.com",
        "webengage.co",
        "netcorecloud.com",
        "netcoresmartech.com",
        "shopify.com/api/analytics",
        "posthog.com",
        "cloudflareinsights.com",
        "vercel-insights.com",
        "vercel-analytics.com",
        "fastly-insights.com",
        "usefathom.com",
        "simpleanalytics.com",
        "simpleanalyticscdn.com",
        "goatcounter.com",
        "umami.is",
        "pirsch.io",
        "splitbee.io",
        # Error and performance telemetry. It is listed here because a crash or
        # a page timing report carries the visitor's IP, user agent, URL and
        # often a user id, and it is sent from the page like any other beacon.
        # Sentry's per customer ingest hosts (o12345.ingest.us.sentry.io and the
        # regional variants) are all covered by the suffix.
        "sentry.io",
        "sentry-cdn.com",
        "bugsnag.com",
        "datadoghq.com",
        "datadoghq.eu",
        "dynatrace.com",
        "rollbar.com",
        "raygun.io",
        "trackjs.com",
        "honeybadger.io",
        "airbrake.io",
        "instana.io",
        "appdynamics.com",
        "eum-appdynamics.com",
        "newrelic.com",
        "nr-data.net",
        "bam.nr-data.net",
        # Marketing automation and CRM. The list was thin here, and a live scan
        # of a compliance vendor's own site showed why: HubSpot loaded three
        # hosts before any consent and every one of them came back
        # unclassified. These suites identify a named visitor, follow them
        # across pages and write that into a CRM record, which is further from
        # functional than plain page measurement, not closer to it.
        "hs-scripts.com",
        "hs-analytics.net",
        "hscollectedforms.net",
        "hsleadflows.net",
        "hsforms.com",
        "hsforms.net",
        "usemessages.com",
        "hubspot.com",
        "hubapi.com",
        "marketo.com",
        "marketo.net",
        "mktoresp.com",
        "mktoweb.com",
        "pardot.com",
        "eloqua.com",
        "en25.com",
        "evgnet.com",
        "cquotient.com",
        "activecampaign.com",
        "trackcmp.net",
        "klaviyo.com",
        "klaviyodata.com",
        "list-manage.com",
        "chimpstatic.com",
        "braze.com",
        "braze.eu",
        "appboycdn.com",
        "iterable.com",
        "customer.io",
        "getdrip.com",
        "convertkit.com",
        "intercom.io",
        "intercomcdn.com",
        "drift.com",
        "driftt.com",
        "sendinblue.com",
        "brevo.com",
        "omnisend.com",
        "attentivemobile.com",
        "emarsys.net",
        "scarabresearch.com",
        "exponea.com",
        "dotdigital.com",
        "dotmailer.com",
        "sharpspring.com",
        "autopilothq.com",
        "ortto.com",
        "useinsider.com",
        "freshmarketer.com",
        # Indian marketing and customer data platforms, which is what this tool
        # actually meets on the sites it is pointed at.
        "leadsquared.com",
        "salesiq.zoho.com",
        "salesiq.zoho.in",
        "zohopublic.com",
        "zeotap.com",
        "lemnisk.co",
        "lemnisk.com",
    ),
    ADVERTISING: (
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "adservice.google.com",
        "admob.com",
        "amazon-adsystem.com",
        "criteo.com",
        "criteo.net",
        "taboola.com",
        "taboolasyndication.com",
        "outbrain.com",
        "outbrainimg.com",
        "adnxs.com",
        "adnxs-simple.com",
        "rubiconproject.com",
        "pubmatic.com",
        "openx.net",
        "adform.net",
        "casalemedia.com",
        "33across.com",
        "bidswitch.net",
        "sharethrough.com",
        "smartadserver.com",
        "media.net",
        "adroll.com",
        "quantserve.com",
        "quantcount.com",
        "bing.com/action",
        "bat.bing.com",
        "clarity.bing.com",
        "adsrvr.org",
        "everesttech.net",
        "demdex.net",
        "appsflyer.com",
        "adjust.com",
        "branch.io",
        "app.link",
        "singular.net",
        "kochava.com",
        "onesignal.com",
        "izooto.com",
        "vdo.ai",
        "adpushup.com",
        "revcontent.com",
        "mgid.com",
        "zedo.com",
        "teads.tv",
        "smaato.net",
        "inmobi.com",
        "applovin.com",
        "unityads.unity3d.com",
        # Ad networks that sell to developer and documentation audiences, so
        # they turn up on exactly the open source sites nobody expects to carry
        # advertising.
        "ethicalads.io",
        "carbonads.com",
        "carbonads.net",
        "buysellads.com",
        "buysellads.net",
        "servedby-buysellads.com",
        "codefund.io",
        "adsterra.com",
        "propellerads.com",
        "exoclick.com",
        # Ad pixels shipped by the marketing automation suites listed under
        # analytics. Same vendors, different purpose, so a different category.
        "hsadspixel.net",
        "krxd.net",
        "bluekai.com",
    ),
    SOCIAL: (
        "facebook.com",
        "facebook.net",
        "fbcdn.net",
        "instagram.com",
        "twitter.com",
        "ads-twitter.com",
        "x.com",
        "t.co",
        "linkedin.com",
        "licdn.com",
        "pinterest.com",
        "pinimg.com",
        "tiktok.com",
        "tiktokcdn.com",
        "snapchat.com",
        "sc-static.net",
        "reddit.com",
        "redditstatic.com",
        "sharethis.com",
        "addthis.com",
        "addtoany.com",
        "vk.com",
        "sharaget.com",
    ),
    REPLAY: (
        "hotjar.com",
        "hotjar.io",
        "clarity.ms",
        "fullstory.com",
        "fs.com/s",
        "mouseflow.com",
        "smartlook.com",
        "smartlook.cloud",
        "luckyorange.com",
        "luckyorange.net",
        "inspectlet.com",
        "crazyegg.com",
        "logrocket.com",
        "lr-ingest.io",
        "lr-in.com",
        "quantummetric.com",
        "contentsquare.net",
        "decibelinsight.net",
        "glassboxdigital.io",
        "sessioncam.com",
        "userreplay.net",
        "zipy.ai",
        "highlight.io",
        "highlight.run",
    ),
}

TRACKER_HOSTS: dict[str, str] = {
    host: category
    for category, hosts in _TRACKER_HOSTS_BY_CATEGORY.items()
    for host in hosts
}

# Consent platforms. Deliberately NOT trackers: the script that draws the banner
# has to load before any choice exists, so counting it as a pre consent tracker
# would flag the one vendor on the page that is there to ask permission.
CONSENT_MANAGER_HOSTS: frozenset[str] = frozenset(
    {
        "cookielaw.org",
        "onetrust.com",
        "cookiebot.com",
        "cookiebot.eu",
        "consensu.org",
        "cookieyes.com",
        "termly.io",
        "iubenda.com",
        "usercentrics.eu",
        "trustarc.com",
        "truste.com",
        "secureprivacy.ai",
        "osano.com",
        "didomi.io",
        "sourcepoint.mgr.consensu.org",
        "sp-prod.net",
        "quantcast.com",
        "consentmanager.net",
        "civicuk.com",
        "cookie-script.com",
        "cookiefirst.com",
        "cookiepro.com",
        "complianz.io",
        # HubSpot's banner script, which is the same exception as every other
        # platform here: it has to load before a choice exists in order to ask
        # for one. The rest of the HubSpot hosts are trackers.
        "hs-banner.com",
    }
)


def normalise_host(host: str | None) -> str:
    """Lowercase, strip a port, a trailing dot and any credentials."""
    h = (host or "").strip().lower()
    if "@" in h:
        h = h.rsplit("@", 1)[-1]
    h = h.split("/", 1)[0].split(":", 1)[0]
    return h.rstrip(".")


def host_suffixes(host: str) -> list[str]:
    """['a.b.example.com', 'b.example.com', 'example.com', 'com']."""
    parts = [p for p in host.split(".") if p]
    return [".".join(parts[i:]) for i in range(len(parts))]


def is_consent_manager(host: str | None) -> bool:
    h = normalise_host(host)
    return any(s in CONSENT_MANAGER_HOSTS for s in host_suffixes(h)) if h else False


def classify_tracker(host: str | None) -> str | None:
    """Category for a request host, or None when the host is not a known tracker.

    None is not a clean bill of health, it only means this list does not know
    the host. third_party_hosts carries the unclassified ones so a reviewer can
    still see every recipient of data.
    """
    h = normalise_host(host)
    if not h:
        return None
    for suffix in host_suffixes(h):
        if suffix in CONSENT_MANAGER_HOSTS:
            return None
        category = TRACKER_HOSTS.get(suffix)
        if category:
            return category
    return None


# --------------------------------------------------------- server-side tagging

# Path segments a first party endpoint uses when it is receiving measurement
# traffic. Server-side tagging posts to the site's own domain and forwards to
# the vendor from the server, so no browser based scanner can see the onward
# hop. The pattern is recorded, never the destination, because the destination
# is not observable from the page and guessing at it would invent evidence.
#
# Matched as whole path segments so "/events" matches and "/past-events" does
# not, and "/g/collect" matches on its "collect" segment.
SERVER_SIDE_TAG_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "collect",
        "sgtm",
        "gtm",
        "gtag",
        "tr",
        "event",
        "events",
        "metrics",
        "beacon",
        "pixel",
        "track",
        "telemetry",
        "measure",
        "analytics",
    }
)

# Segments that only mean anything in front of one of the above, so "/g/collect"
# reads back whole rather than losing the half that names the protocol.
SERVER_SIDE_TAG_PATH_PREFIXES: frozenset[str] = frozenset({"g", "mp"})

# Parameter names that mean a body is measurement traffic rather than an
# ordinary form post. These are names, never values: nothing here could carry
# personal data.
BEACON_PAYLOAD_MARKERS: frozenset[str] = frozenset(
    {
        "tid",
        "cid",
        "gtm",
        "gcs",
        "gclid",
        "dl",
        "dr",
        "dt",
        "en",
        "ep",
        "_p",
        "_s",
        "sct",
        "seg",
        "measurement_id",
        "client_id",
        "session_id",
        "event_name",
        "event_id",
        "event_time",
        "event_source_url",
        "action_source",
        "user_data",
        "custom_data",
        "pixel_id",
        "app_id",
        "device_id",
        "advertiser_id",
        "anonymous_id",
        "distinct_id",
        "anonymousid",
        "writekey",
        "page_location",
        "page_referrer",
        "page_title",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "properties",
        "context",
        "messageid",
        "insert_id",
    }
)

# One marker is a coincidence. Measurement protocols send a cluster of them, and
# requiring a cluster is what keeps an ordinary form post out of this signal.
MIN_BEACON_PAYLOAD_MARKERS = 2


def server_side_tag_marker(path: str | None) -> str | None:
    """The tracking shaped fragment of a URL path, or None.

    Returns the fragment as it would be quoted in evidence, so "/g/collect"
    rather than "collect".
    """
    segments = [s for s in (path or "").lower().split("/") if s]
    if not segments:
        return None
    for index, segment in enumerate(segments):
        if segment not in SERVER_SIDE_TAG_PATH_SEGMENTS:
            continue
        if index and segments[index - 1] in (
            SERVER_SIDE_TAG_PATH_SEGMENTS | SERVER_SIDE_TAG_PATH_PREFIXES
        ):
            return f"/{segments[index - 1]}/{segment}"
        return f"/{segment}"
    return None


def beacon_payload_marker(keys: Iterable[str | None]) -> str | None:
    """Which measurement parameter names a body carried, or None.

    Takes the keys rather than the body, so this module never handles a value.
    """
    found = sorted(
        {
            cleaned
            for key in keys
            if (cleaned := (key or "").strip().lower().split("[", 1)[0].split(".", 1)[0])
            in BEACON_PAYLOAD_MARKERS
        }
    )
    if len(found) < MIN_BEACON_PAYLOAD_MARKERS:
        return None
    return ", ".join(found[:6])


# -------------------------------------------------------------------- cookies

COOKIE_NAMES: dict[str, str] = {
    # Session, security and state. The only class that may precede a choice.
    "sid": NECESSARY,
    "sessionid": NECESSARY,
    "session_id": NECESSARY,
    "session": NECESSARY,
    "sess": NECESSARY,
    "jsessionid": NECESSARY,
    "phpsessid": NECESSARY,
    "asp.net_sessionid": NECESSARY,
    "connect.sid": NECESSARY,
    "csrftoken": NECESSARY,
    "csrf_token": NECESSARY,
    "csrf": NECESSARY,
    "xsrf-token": NECESSARY,
    "_csrf": NECESSARY,
    "ci_session": NECESSARY,
    "laravel_session": NECESSARY,
    "remember_token": NECESSARY,
    "access_token": NECESSARY,
    "refresh_token": NECESSARY,
    "auth_token": NECESSARY,
    "cf_clearance": NECESSARY,
    "__cf_bm": NECESSARY,
    "awsalb": NECESSARY,
    "awsalbcors": NECESSARY,
    "incap_ses": NECESSARY,
    "visid_incap": NECESSARY,
    "lang": NECESSARY,
    "locale": NECESSARY,
    "currency": NECESSARY,
    "cart": NECESSARY,
    "cartid": NECESSARY,
    "optanonconsent": NECESSARY,
    "optanonalertboxclosed": NECESSARY,
    "cookieconsent": NECESSARY,
    "cookieconsent_status": NECESSARY,
    "cookie_consent": NECESSARY,
    "cookieyes-consent": NECESSARY,
    "euconsent-v2": NECESSARY,
    "cookielawinfoconsent": NECESSARY,
    # Measurement.
    "_ga": ANALYTICS,
    "_gid": ANALYTICS,
    "_gat": ANALYTICS,
    "__utma": ANALYTICS,
    "__utmb": ANALYTICS,
    "__utmc": ANALYTICS,
    "__utmt": ANALYTICS,
    "__utmv": ANALYTICS,
    "__utmz": ANALYTICS,
    "_clck": ANALYTICS,
    "_clsk": ANALYTICS,
    "clck": ANALYTICS,
    "ajs_anonymous_id": ANALYTICS,
    "ajs_user_id": ANALYTICS,
    "amplitude_id": ANALYTICS,
    "_fs_uid": ANALYTICS,
    "_vwo_uuid": ANALYTICS,
    "_vis_opt_s": ANALYTICS,
    "wzrk_uuid": ANALYTICS,
    "moe_uuid": ANALYTICS,
    "_we_uuid": ANALYTICS,
    "yandexuid": ANALYTICS,
    "_ym_uid": ANALYTICS,
    "_ym_d": ANALYTICS,
    # Targeting.
    "_gcl_au": ADVERTISING,
    "_gcl_aw": ADVERTISING,
    "_gcl_dc": ADVERTISING,
    "ide": ADVERTISING,
    "dsid": ADVERTISING,
    "test_cookie": ADVERTISING,
    "nid": ADVERTISING,
    "1p_jar": ADVERTISING,
    "__gads": ADVERTISING,
    "__gpi": ADVERTISING,
    "gps": ADVERTISING,
    "visitor_info1_live": ADVERTISING,
    "ysc": ADVERTISING,
    "_fbp": ADVERTISING,
    "_fbc": ADVERTISING,
    "fr": ADVERTISING,
    "muid": ADVERTISING,
    "mr": ADVERTISING,
    "srm_b": ADVERTISING,
    "_uetsid": ADVERTISING,
    "_uetvid": ADVERTISING,
    "personalization_id": ADVERTISING,
    "_ttp": ADVERTISING,
    "_pin_unauth": ADVERTISING,
    "_pinterest_ct_ua": ADVERTISING,
    "_scid": ADVERTISING,
    "sc_at": ADVERTISING,
    "li_sugr": ADVERTISING,
    "bcookie": ADVERTISING,
    "bscookie": ADVERTISING,
    "usermatchhistory": ADVERTISING,
    "lidc": ADVERTISING,
    "uuid2": ADVERTISING,
    "anj": ADVERTISING,
    "cto_bundle": ADVERTISING,
    "cto_lwid": ADVERTISING,
    "t_gid": ADVERTISING,
    "tbla_id": ADVERTISING,
    "obuid": ADVERTISING,
    "demdex": ADVERTISING,
    "everest_g_v2": ADVERTISING,
    "tuuid": ADVERTISING,
    "khaos": ADVERTISING,
}

# Order matters: the longest prefix wins, so _gac beats _ga.
COOKIE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("_ga_", ANALYTICS),
    ("_gat_", ANALYTICS),
    ("_gid_", ANALYTICS),
    ("__utm", ANALYTICS),
    ("_hj", ANALYTICS),
    ("mp_", ANALYTICS),
    ("_pk_", ANALYTICS),
    ("_hp2_", ANALYTICS),
    ("__insp_", ANALYTICS),
    ("mf_", ANALYTICS),
    ("_sl_", ANALYTICS),
    ("_vwo", ANALYTICS),
    ("_vis_opt", ANALYTICS),
    ("wzrk", ANALYTICS),
    ("moe_", ANALYTICS),
    ("_ym_", ANALYTICS),
    ("amplitude_", ANALYTICS),
    ("ajs_", ANALYTICS),
    ("_gac_", ADVERTISING),
    ("_gcl_", ADVERTISING),
    ("_uet", ADVERTISING),
    ("_fb", ADVERTISING),
    ("_ttp", ADVERTISING),
    ("cto_", ADVERTISING),
    ("criteo", ADVERTISING),
    ("taboola", ADVERTISING),
    ("outbrain", ADVERTISING),
    ("__sharethis", ADVERTISING),
    ("_pin_", ADVERTISING),
    ("optanon", NECESSARY),
    ("cookieyes", NECESSARY),
    ("cookielawinfo", NECESSARY),
    ("__host-", NECESSARY),
    ("__secure-", NECESSARY),
    ("xsrf", NECESSARY),
    ("csrf", NECESSARY),
)

# Last resort. Weaker than the two tables above, so it runs last.
COOKIE_SUBSTRINGS: tuple[tuple[str, str], ...] = (
    ("sessionid", NECESSARY),
    ("session", NECESSARY),
    ("sessid", NECESSARY),
    ("csrf", NECESSARY),
    ("xsrf", NECESSARY),
    ("consent", NECESSARY),
    ("login", NECESSARY),
    ("logged_in", NECESSARY),
    ("cart", NECESSARY),
    ("analytics", ANALYTICS),
    ("utm_", ANALYTICS),
    ("_stat", ANALYTICS),
    ("adid", ADVERTISING),
    ("adsid", ADVERTISING),
    ("audience", ADVERTISING),
)


def classify_cookie(name: str | None) -> str:
    """necessary, analytics, advertising or unknown, from the cookie name.

    unknown is returned rather than guessed at, because the rules engine treats
    an unclassified cookie as needing consent. Guessing "necessary" here would
    quietly excuse it.
    """
    lowered = (name or "").strip().lower()
    if not lowered:
        return UNKNOWN
    direct = COOKIE_NAMES.get(lowered)
    if direct:
        return direct
    for prefix, category in sorted(COOKIE_PREFIXES, key=lambda p: -len(p[0])):
        if lowered.startswith(prefix):
            return category
    for fragment, category in COOKIE_SUBSTRINGS:
        if fragment in lowered:
            return category
    return UNKNOWN


# ------------------------------------------------------------ sensitive fields

# Names and labels that mean the form is collecting one of the categories the
# Act and the Rules expect extra care around. Keys are descriptive only, the
# scanner stores the field itself.
SENSITIVE_FIELD_PATTERNS: dict[str, tuple[str, ...]] = {
    "government_id": (
        "aadhaar",
        "aadhar",
        "adhaar",
        "uidai",
        "uid number",
        "vid number",
        "pan",
        "pan card",
        "pancard",
        "passport",
        "voter id",
        "voterid",
        "epic no",
        "epic number",
        "driving licence",
        "driving license",
        "licence number",
        "license number",
        "dl no",
        "dl number",
        "ration card",
        "national id",
        "ssn",
        "social security",
        "gstin",
        "tan",
        "abha",
        "abha number",
        "government id",
        "govt id",
        "identity proof",
        "id proof",
        "kyc document",
    ),
    "financial": (
        "account number",
        "accountnumber",
        "bank account",
        "bankaccount",
        "ifsc",
        "micr",
        "swift code",
        "card number",
        "cardnumber",
        "cc number",
        "cc num",
        "cvv",
        "cvc",
        "cc csc",
        "card expiry",
        "credit card",
        "debit card",
        "creditcard",
        "debitcard",
        "upi",
        "upi id",
        "vpa",
        "net banking",
        "netbanking",
        "salary",
        "annual income",
        "monthly income",
        "income",
        "itr",
        "net worth",
        "loan amount",
        "emi",
        "cibil",
        "credit score",
    ),
    "health": (
        "health",
        "healthcare",
        "medical",
        "medication",
        "medicine",
        "diagnosis",
        "disease",
        "illness",
        "ailment",
        "prescription",
        "blood group",
        "bloodgroup",
        "allergy",
        "allergies",
        "disability",
        "differently abled",
        "pregnant",
        "pregnancy",
        "hiv",
        "mental health",
        "therapy",
        "treatment",
        "symptom",
        "symptoms",
        "smoking",
        "alcohol consumption",
        "bmi",
        "body mass",
    ),
    "biometric": (
        "biometric",
        "fingerprint",
        "finger print",
        "thumb impression",
        "iris scan",
        "retina scan",
        "face scan",
        "facescan",
        "faceid",
        "face id",
        "facial recognition",
        "voiceprint",
        "voice print",
        "selfie",
        "live photo",
        "liveness",
    ),
    "religion": (
        "religion",
        "religious",
        "faith",
        "dharma",
        "madhab",
    ),
    "caste": (
        "caste",
        "jati",
        "sub caste",
        "subcaste",
        "sc st",
        "obc",
        "reservation category",
        "social category",
    ),
    "sexual_orientation": (
        "sexual orientation",
        "sexualorientation",
        "sexual preference",
        "gender identity",
        "lgbt",
        "lgbtq",
        "transgender",
    ),
}

# Labels that mean the box asks to be marketed to, which is a separate purpose
# from the one the form exists for and so needs consent of its own.
MARKETING_OPTIN_KEYWORDS: tuple[str, ...] = (
    "newsletter",
    "marketing",
    "promotional",
    "promotions",
    "promo emails",
    "special offers",
    "offers and discounts",
    "offers and updates",
    "discounts",
    "deals",
    "subscribe",
    "subscription to our",
    "mailing list",
    "email list",
    "keep me posted",
    "keep me updated",
    "product updates",
    "receive updates",
    "email updates",
    "sms updates",
    "sms alerts",
    "whatsapp updates",
    "whatsapp alerts",
    "push notifications",
    "personalised ads",
    "personalized ads",
    "personalised offers",
    "personalized offers",
    "targeted ads",
    "targeted advertising",
    "third party offers",
    "partner offers",
    "our partners to contact",
    "contact me about",
    "send me",
    "brochure",
    "webinar invites",
    "event invites",
)

# Labels that are an acceptance of terms rather than a marketing opt in. A box
# matching only these is not a marketing opt in.
TERMS_ACCEPTANCE_KEYWORDS: tuple[str, ...] = (
    "terms",
    "terms and conditions",
    "terms of use",
    "terms of service",
    "conditions of use",
    "user agreement",
    "privacy policy",
    "privacy notice",
    "cookie policy",
    "refund policy",
    "i have read",
    "i confirm",
    "i certify",
    "i declare",
    "declaration",
    "disclaimer",
    "18 years",
    "age of 18",
    "legal age",
)


def normalise_label(*parts: str | None) -> str:
    """Join, split camelCase, drop separators and collapse whitespace."""
    joined = " ".join(p for p in parts if p)
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", joined)
    cleaned = re.sub(r"[^0-9a-zऀ-ॿ]+", " ", spaced.lower())
    return re.sub(r"\s+", " ", cleaned).strip()


def escape_phrase(keyword: str) -> str:
    """Escape a keyword, letting any run of whitespace stand in for its spaces.

    re.escape escapes the space itself, so escaping first and substituting after
    leaves a literal backslash in the pattern and the phrase never matches.
    """
    return r"\s+".join(re.escape(token) for token in keyword.split())


def _word_pattern(keywords: tuple[str, ...]) -> re.Pattern[str]:
    alternatives = sorted((escape_phrase(k) for k in keywords if k.strip()), key=len, reverse=True)
    return re.compile(r"\b(?:" + "|".join(alternatives) + r")\b")


def _squash(text: str) -> str:
    return re.sub(r"[^0-9a-zऀ-ॿ]+", "", text.lower())


# Matched without word boundaries, so they must not be words that live inside
# other words: "health" would fire on "healthy recipes", "income" on "incoming".
_SQUASH_DENYLIST = frozenset({"health", "income", "salary", "session"})


def _squashed_keywords(keywords: tuple[str, ...]) -> tuple[str, ...]:
    # Catches run together names like "aadhaarnumber", where the boundary the
    # spaced pattern needs does not exist. Short keywords stay out, so "pan" and
    # "cvv" never fire inside "company" or "cvvalue".
    return tuple(
        {
            squashed
            for k in keywords
            if len(squashed := _squash(k)) >= 6 and squashed not in _SQUASH_DENYLIST
        }
    )


_SENSITIVE_PATTERNS: dict[str, re.Pattern[str]] = {
    category: _word_pattern(keywords)
    for category, keywords in SENSITIVE_FIELD_PATTERNS.items()
}
_SENSITIVE_SQUASHED: dict[str, tuple[str, ...]] = {
    category: _squashed_keywords(keywords)
    for category, keywords in SENSITIVE_FIELD_PATTERNS.items()
}

_MARKETING_PATTERN = _word_pattern(MARKETING_OPTIN_KEYWORDS)
_TERMS_PATTERN = _word_pattern(TERMS_ACCEPTANCE_KEYWORDS)


def sensitive_category(*parts: str | None) -> str | None:
    """Which sensitive category a field name or label reads like, or None."""
    spaced = normalise_label(*parts)
    if not spaced:
        return None
    squashed = _squash(spaced)
    for category, pattern in _SENSITIVE_PATTERNS.items():
        if pattern.search(spaced):
            return category
        if any(k in squashed for k in _SENSITIVE_SQUASHED[category]):
            return category
    return None


def is_marketing_optin(*parts: str | None) -> bool:
    return bool(_MARKETING_PATTERN.search(normalise_label(*parts)))


def is_terms_acceptance(*parts: str | None) -> bool:
    return bool(_TERMS_PATTERN.search(normalise_label(*parts)))


# ------------------------------------------------------------- consent banners

# Containers the known consent platforms render into, plus the generic patterns
# hand rolled banners use.
CMP_CONTAINER_SELECTORS: tuple[str, ...] = (
    "#onetrust-banner-sdk",
    "#onetrust-consent-sdk",
    ".ot-sdk-row",
    "#CybotCookiebotDialog",
    "#cookiebot",
    "#cookieyes",
    ".cky-consent-container",
    ".cky-consent-bar",
    "#usercentrics-root",
    "#uc-banner",
    "#qc-cmp2-container",
    "#qc-cmp2-ui",
    "#iubenda-cs-banner",
    ".iubenda-cs-container",
    "#termly-code-snippet-support",
    "#truste-consent-track",
    "#consent_blackbar",
    "#cmpbox",
    "#cmpwrapper",
    "#didomi-host",
    ".didomi-popup-container",
    "[id^='sp_message_container']",
    "#osano-cm-window",
    ".osano-cm-dialog",
    "#cc-main",
    ".cc-window",
    "#cookie-law-info-bar",
    "#gdpr-cookie-message",
    "#cookie-consent",
    "#cookie-banner",
    "#cookieBanner",
    "#cookie-notice",
    ".cookie-consent",
    ".cookie-banner",
    ".cookie-notice",
    ".cookie-bar",
    ".consent-banner",
    "[data-cookiebanner]",
    "[data-testid*='cookie' i]",
    "[class*='cookie-consent' i]",
    "[class*='cookie-banner' i]",
    "[class*='consent-banner' i]",
    "[id*='cookie-consent' i]",
    "[id*='cookie-banner' i]",
    "[aria-label*='cookie' i]",
    "[aria-label*='consent' i]",
)

# Used by the fallback sweep over pinned elements, so a hand rolled banner with
# no recognisable class is still found.
BANNER_TEXT_HINTS: tuple[str, ...] = (
    "cookie",
    "cookies",
    "consent",
    "we use",
    "your privacy",
    "privacy preferences",
    "tracking technologies",
)

ACCEPT_LABELS: tuple[str, ...] = (
    "accept",
    "accept all",
    "accept cookies",
    "accept and continue",
    "i accept",
    "allow",
    "allow all",
    "allow cookies",
    "agree",
    "i agree",
    "ok",
    "okay",
    "got it",
    "understood",
    "enable all",
    "yes i agree",
    "sounds good",
    "continue",
    "स्वीकार",
    "सहमत",
)

# Whether a refusal is offered at all, and how it is labelled, is the part of a
# banner that carries legal weight: refusing must be no harder than accepting.
REJECT_LABELS: tuple[str, ...] = (
    "reject",
    "reject all",
    "reject cookies",
    "decline",
    "decline all",
    "deny",
    "refuse",
    "disagree",
    "do not accept",
    "do not consent",
    "only necessary",
    "necessary only",
    "only essential",
    "essential only",
    "strictly necessary only",
    "use necessary cookies only",
    "no thanks",
    "not now",
    "opt out",
    "disable all",
    "continue without accepting",
    "अस्वीकार",
)

MANAGE_LABELS: tuple[str, ...] = (
    "manage",
    "manage cookies",
    "manage preferences",
    "manage options",
    "cookie settings",
    "cookie preferences",
    "privacy settings",
    "privacy preferences",
    "preferences",
    "settings",
    "customise",
    "customize",
    "configure",
    "more options",
    "let me choose",
    "choose cookies",
    "show purposes",
    "vendor list",
)

# Words that mean the banner offers per purpose choices rather than one button.
COOKIE_CATEGORY_WORDS: tuple[str, ...] = (
    "strictly necessary",
    "necessary cookies",
    "essential cookies",
    "functional",
    "functionality cookies",
    "performance",
    "performance cookies",
    "analytics cookies",
    "analytical cookies",
    "statistics",
    "targeting",
    "targeting cookies",
    "advertising cookies",
    "marketing cookies",
    "social media cookies",
    "unclassified",
)

_ACCEPT_PATTERN = _word_pattern(ACCEPT_LABELS)
_REJECT_PATTERN = _word_pattern(REJECT_LABELS)
_MANAGE_PATTERN = _word_pattern(MANAGE_LABELS)
_CATEGORY_PATTERN = _word_pattern(COOKIE_CATEGORY_WORDS)


def is_accept_label(text: str | None) -> bool:
    return bool(_ACCEPT_PATTERN.search(normalise_label(text)))


def is_reject_label(text: str | None) -> bool:
    return bool(_REJECT_PATTERN.search(normalise_label(text)))


def is_manage_label(text: str | None) -> bool:
    return bool(_MANAGE_PATTERN.search(normalise_label(text)))


def cookie_category_mentions(text: str | None) -> int:
    return len(set(_CATEGORY_PATTERN.findall(normalise_label(text))))


# ----------------------------------------------------------------- policy docs

# Conventional paths, probed when nothing on the page links to a policy. A site
# that has the document but does not link it is a different finding from a site
# that does not have it, and only probing can tell the two apart.
POLICY_PROBE_PATHS: tuple[tuple[str, str], ...] = (
    ("/privacy", KIND_PRIVACY),
    ("/privacy-policy", KIND_PRIVACY),
    ("/legal/privacy", KIND_PRIVACY),
    ("/policies/privacy", KIND_PRIVACY),
    ("/privacy-notice", KIND_PRIVACY),
    # Organisations name this document at least four ways. A live scan missed a
    # large payments site's notice entirely because it is published as a privacy
    # STATEMENT, and the site was reported as publishing nothing.
    ("/privacy-statement", KIND_PRIVACY),
    ("/data-protection", KIND_PRIVACY),
    ("/data-privacy", KIND_PRIVACY),
    ("/legal/privacy-policy", KIND_PRIVACY),
    ("/policy", KIND_PRIVACY),
    ("/cookie-policy", KIND_COOKIE),
    ("/cookie-notice", KIND_COOKIE),
    ("/cookies", KIND_COOKIE),
    ("/terms", KIND_TERMS),
    ("/terms-and-conditions", KIND_TERMS),
    ("/terms-of-service", KIND_TERMS),
    ("/grievance", KIND_GRIEVANCE),
    ("/grievance-redressal", KIND_GRIEVANCE),
    ("/grievance-officer", KIND_GRIEVANCE),
)

# Probed like the rest, but only recorded as grievance evidence when the page
# actually names a grievance route. A bare contact form is not a redressal
# mechanism, and recording it as one would read as compliance nobody earned.
CONTACT_PROBE_PATHS: tuple[str, ...] = ("/contact", "/contact-us")

GRIEVANCE_EVIDENCE_KEYWORDS: tuple[str, ...] = (
    "grievance",
    "grievance officer",
    "grievance redressal",
    "nodal officer",
    "data protection officer",
    "privacy officer",
    "complaint",
    "complaints",
    "redressal",
)

# Ordered: the first kind whose keywords match wins, so "Privacy and Cookie
# Policy" is filed as the privacy document rather than the cookie one.
POLICY_LINK_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        KIND_GRIEVANCE,
        (
            "grievance",
            "grievance redressal",
            "nodal officer",
            "data protection officer",
            "dpo",
            "redressal",
        ),
    ),
    (
        # Deliberately phrase based. A bare "children" matches half the
        # headlines on a news homepage, which is how a Bigg Boss article ends up
        # filed as a children's privacy policy.
        KIND_CHILDREN,
        (
            "child privacy",
            "children privacy",
            "children s privacy",
            "childrens privacy",
            "kids privacy",
            "minor privacy",
            "minors privacy",
            "child data",
            "children data",
            "parental consent",
            "policy for children",
        ),
    ),
    (
        KIND_PRIVACY,
        (
            "privacy",
            "privacy policy",
            "privacy notice",
            "privacy statement",
            "data protection",
            "data policy",
            "गोपनीयता",
        ),
    ),
    (KIND_COOKIE, ("cookie", "cookies", "cookie policy", "cookie notice")),
    (KIND_REFUND, ("refund", "cancellation policy", "return policy")),
    (
        KIND_SECURITY,
        ("security policy", "responsible disclosure", "vulnerability disclosure"),
    ),
    (
        KIND_TERMS,
        (
            "terms",
            "terms of use",
            "terms and conditions",
            "terms of service",
            "user agreement",
            "tnc",
        ),
    ),
)

_POLICY_LINK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kind, _word_pattern(keywords)) for kind, keywords in POLICY_LINK_KEYWORDS
)
_GRIEVANCE_PATTERN = _word_pattern(GRIEVANCE_EVIDENCE_KEYWORDS)


# A policy link is a short label pointing at a short path. An article headline,
# or an article URL whose slug happens to contain "terms", is neither, and
# without this cap a news homepage files a dozen stories as policy documents.
POLICY_LINK_MAX_TOKENS = 8


def policy_kind_for_link(*parts: str | None) -> str | None:
    """Which policy kind a link label or URL path reads like, or None.

    Each part is judged on its own and the earlier parts win, so a label beats
    the path it points at. Pass a URL path rather than a whole URL: the host
    contributes tokens without contributing meaning.
    """
    for part in parts:
        text = normalise_label(part)
        if not text or len(text.split()) > POLICY_LINK_MAX_TOKENS:
            continue
        for kind, pattern in _POLICY_LINK_PATTERNS:
            if pattern.search(text):
                return kind
    return None


def mentions_grievance_route(text: str | None) -> bool:
    return bool(_GRIEVANCE_PATTERN.search(normalise_label(text)))


# Officer titles the Rules expect a contact to be published against.
DPO_KEYWORDS: tuple[str, ...] = (
    "data protection officer",
    "data privacy officer",
    "grievance officer",
    "grievance redressal officer",
    "nodal officer",
    "privacy officer",
    "chief privacy officer",
    "compliance officer",
    "dpo",
)


# ------------------------------------------------------------------- bot walls

# Text that means the response is a challenge or a refusal rather than the site.
# Matched only against a short body, because a long page that happens to mention
# a captcha is still the site.
BOT_WALL_MARKERS: tuple[str, ...] = (
    "just a moment",
    "checking your browser",
    "enable javascript and cookies to continue",
    "verify you are human",
    "verifying you are human",
    "are you a robot",
    "access denied",
    "access to this page has been denied",
    "attention required",
    "unusual traffic",
    "request blocked",
    "your request has been blocked",
    "this request was blocked",
    "blocked by",
    "ddos protection by",
    "security check",
    "captcha",
    "recaptcha",
    "cloudflare ray id",
    "incident id",
    "rate limit exceeded",
    "too many requests",
    "403 forbidden",
    "429 too many requests",
    "please enable javascript",
    "javascript is required",
)
