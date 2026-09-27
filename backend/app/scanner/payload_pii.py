"""What category of personal data a request body carried.

Recording only a request URL turns a beacon carrying an email address into "a
beacon was sent". The body is where the payload actually is, so it is read,
classified and dropped.

CRITICAL: nothing here returns, stores or logs a raw value. A finding carries
the category, how often it appeared, the parameter name it sat under and a
redacted indicator of length, and nothing else. A tool that audits how personal
data is handled must not become another copy of that data, and a finding that
quoted a value would put that value into a report, a database row and a PDF.

Classification reuses app.pii rather than inventing a second taxonomy, so a
payload category means the same thing as a code scan category.

Precision is chosen over reach in two places, both deliberate:

1. A value only proves a category when it cannot be mistaken for an ordinary
   identifier: an email address, an Indian mobile written with its country
   prefix, or an identity format that mixes letters with digits. A bare run of
   digits proves nothing, because a millisecond timestamp passes a Luhn check
   about one time in ten and a finding invented that way would be worse than
   the gap it filled.
2. In a body that is measurement traffic, the control parameters are read as
   control parameters. A tag manager's event name is not the visitor's name.
   The same body's documented advanced matching parameters are read for what
   the platforms document them as, because "em" in a measurement payload is an
   email field and nothing else.
"""

import json
import re
from collections.abc import Iterable
from urllib.parse import parse_qsl

from app.contracts import PayloadPII
from app.pii import field_classifier, indian_ids, taxonomy
from app.scanner import trackers

# A beacon body is small. Anything past this is an upload or a bundle, and
# scanning it would cost more than it could tell us.
MAX_PAYLOAD_SCAN_CHARS = 8000
MAX_PAIRS = 400
MAX_FINDINGS = 8
# Past this a "value" is a blob, a token or an encoded attachment, not a field.
MAX_VALUE_CHARS = 512

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+")
# Only the prefixed form is trusted on a value nobody named, because a bare ten
# digit run starting 6 to 9 is also what half the numeric ids on a page look
# like. A field actually called "phone" is caught by its name instead.
_PREFIXED_MOBILE_RE = re.compile(r"(?:\+91|0091|91|0)[\s-]?[6-9]\d{9}")
_SAFE_KEY_RE = re.compile(r"[^A-Za-z0-9_.\-\[\]]+")

# Formats that mix letters with digits in a fixed shape, so a random identifier
# cannot fall into them. Checksum only formats stay out of value detection.
_VALUE_VALIDATORS: tuple[tuple[str, object], ...] = (
    ("gstin", indian_ids.is_valid_gstin),
    ("pan", indian_ids.is_valid_pan),
    ("voter_id", indian_ids.is_valid_voter_id),
    ("financial", indian_ids.is_valid_ifsc),
)

# Parameter names the advertising platforms document for advanced matching. The
# value is normally a hash, so the value proves nothing on its own, but the
# name is documented and unambiguous inside a measurement payload.
_ADVANCED_MATCHING_KEYS: dict[str, str] = {
    "em": "email",
    "email_address": "email",
    "sha256_email_address": "email",
    "hashed_email": "email",
    "ph": "phone",
    "phone_number": "phone",
    "sha256_phone_number": "phone",
    "hashed_phone": "phone",
    "fn": "name",
    "ln": "name",
    "first_name": "name",
    "last_name": "name",
    "ct": "address",
    "st": "address",
    "zp": "address",
    "db": "dob",
}

# Leaf names a measurement payload uses to describe the page or the event
# rather than the visitor. Reading "event_name" as the visitor's name would put
# an invented category of personal data into a report. Outside a measurement
# body these are ordinary form fields and are classified normally.
_CONTROL_KEY_LEAVES: frozenset[str] = frozenset(
    {
        "name",
        "event_name",
        "event",
        "title",
        "page_title",
        "screen_name",
        "app_name",
        "item_name",
        "product_name",
        "brand_name",
        "campaign_name",
        "form_name",
        "list_name",
        "class_name",
        "tag_name",
        "file_name",
        "host_name",
        "currency_name",
        "country_name",
        "city_name",
        "state_name",
    }
)


def payload_keys(body: str | None) -> list[str]:
    """The parameter names in a body. Names only, so no value is ever returned."""
    return [key for key, _ in _pairs(body) if key]


def scan_payload(body: str | None) -> list[PayloadPII]:
    """Categories of personal data in a request body, with no value kept."""
    text = (body or "")[:MAX_PAYLOAD_SCAN_CHARS]
    if not text.strip():
        return []

    pairs = _pairs(text)
    measurement = trackers.beacon_payload_marker(key for key, _ in pairs) is not None

    findings: dict[str, PayloadPII] = {}
    for key, value in pairs:
        category, via = _classify(key, value, measurement=measurement)
        if category is not None:
            _record(findings, category, via, key, len(value.strip()))

    # A body this pass could not take apart, or a value that was itself an
    # encoded document, still gets a sweep for the two patterns that cannot be
    # anything else. A category already found keeps its richer finding.
    for category, count, length in _sweep(text):
        if category not in findings:
            _record(findings, category, "value", None, length, occurrences=count)

    ordered = sorted(findings.values(), key=lambda f: (-f.occurrences, f.pii_category))
    return ordered[:MAX_FINDINGS]


def categories(findings: Iterable[PayloadPII]) -> list[str]:
    """Distinct categories across a set of findings, in a stable order."""
    return sorted({f.pii_category for f in findings})


# ------------------------------------------------------------------ internals


def _pairs(body: str | None) -> list[tuple[str, str]]:
    """Flatten a body into key and value pairs, whatever shape it arrived in."""
    text = (body or "")[:MAX_PAYLOAD_SCAN_CHARS].strip()
    if not text:
        return []

    if text[:1] in ("{", "["):
        try:
            return _flatten(json.loads(text))[:MAX_PAIRS]
        except (ValueError, RecursionError):
            pass

    try:
        pairs = [(str(k), str(v)) for k, v in parse_qsl(text, keep_blank_values=True)]
    except ValueError:
        pairs = []
    if len(pairs) > 1 or (pairs and pairs[0][1]):
        return pairs[:MAX_PAIRS]

    # Newline delimited measurement protocol bodies, one payload per line.
    if "\n" in text and "=" in text:
        flattened: list[tuple[str, str]] = []
        for line in text.splitlines():
            try:
                flattened.extend(
                    (str(k), str(v)) for k, v in parse_qsl(line, keep_blank_values=True)
                )
            except ValueError:
                continue
        if flattened:
            return flattened[:MAX_PAIRS]
    return pairs[:MAX_PAIRS]


def _flatten(node: object, prefix: str = "", depth: int = 0) -> list[tuple[str, str]]:
    if depth > 6:
        return []
    if isinstance(node, dict):
        pairs: list[tuple[str, str]] = []
        for key, value in node.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            pairs.extend(_flatten(value, name, depth + 1))
        return pairs
    if isinstance(node, (list, tuple)):
        pairs = []
        for item in list(node)[:50]:
            pairs.extend(_flatten(item, prefix, depth + 1))
        return pairs
    if node is None or isinstance(node, bool):
        return []
    return [(prefix, str(node))]


def _classify(key: str, value: str, *, measurement: bool) -> tuple[str | None, str]:
    """A category for one pair, and whether the name or the value proved it."""
    text = (value or "").strip()
    if not text or len(text) > MAX_VALUE_CHARS:
        return None, "value"

    leaf = field_classifier.normalise((key or "").rsplit(".", 1)[-1])

    if measurement:
        documented = _ADVANCED_MATCHING_KEYS.get(leaf)
        if documented is not None:
            return documented, "field_name"
        if leaf in _CONTROL_KEY_LEAVES:
            # The name describes the event, so only the value can prove anything.
            return _value_category(text), "value"

    named = field_classifier.classify(leaf) if leaf else None
    if named is not None:
        # The name already says this is personal data, so the full validator set
        # may refine which kind it is. That is the existing rule in app.pii,
        # not a second one invented here.
        refined = field_classifier.classify(leaf, nearby_literal=text)
        if refined is not None and refined != named:
            return refined, "value"
        return named, "field_name"

    return _value_category(text), "value"


def _value_category(value: str) -> str | None:
    """A category a value proves on its own, or None. High precision only."""
    if _EMAIL_RE.fullmatch(value):
        return "email"
    if _PREFIXED_MOBILE_RE.fullmatch(re.sub(r"\s+", "", value)):
        return "phone"
    if len(value) <= 32:
        for category, validator in _VALUE_VALIDATORS:
            if validator(value):
                return category
    return None


def _sweep(text: str) -> list[tuple[str, int, int]]:
    """Category, count and longest match length for the unmistakable patterns."""
    found: list[tuple[str, int, int]] = []
    for category, pattern in (("email", _EMAIL_RE), ("phone", _PREFIXED_MOBILE_RE)):
        lengths = [len(match.group(0)) for match in pattern.finditer(text)]
        if lengths:
            found.append((category, len(lengths), max(lengths)))
    return found


def _record(
    findings: dict[str, PayloadPII],
    category: str,
    via: str,
    key: str | None,
    length: int,
    *,
    occurrences: int = 1,
) -> None:
    existing = findings.get(category)
    if existing is not None:
        existing.occurrences += occurrences
        if existing.field_hint is None:
            existing.field_hint = _safe_key(key)
        return
    findings[category] = PayloadPII(
        pii_category=category,
        sensitivity=_sensitivity(category),
        occurrences=occurrences,
        field_hint=_safe_key(key),
        detected_via=via,
        redacted=f"[redacted {category}, {length} character(s)]",
    )


def _sensitivity(category: str) -> str:
    try:
        return taxonomy.sensitivity_for(category)
    except KeyError:
        return taxonomy.MEDIUM


def _safe_key(key: str | None) -> str | None:
    """A parameter name, stripped to the characters a name can contain.

    A key is a name rather than a value, but it is sanitised and truncated
    anyway so a body with an unusual shape cannot smuggle a value into this
    field.
    """
    cleaned = _SAFE_KEY_RE.sub("", (key or "").strip())[:48]
    return cleaned or None
