"""Field name to PII category classifier.  OWNER: Harin"""

import re

from app.contracts import PIIFieldRef
from app.pii import taxonomy
from app.pii.indian_ids import VALIDATORS

# Categories whose membership a literal can actually prove, because they have a
# checksum or a strict format behind them.
_VALIDATOR_BACKED = frozenset(category for category, _ in VALIDATORS)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM_BOUNDARY = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _build_alias_index() -> dict[str, str]:
    index: dict[str, str] = {}
    for category, entry in taxonomy.PII_TAXONOMY.items():
        for alias in entry["aliases"]:
            index.setdefault(normalise(alias), category)
    return index


def normalise(field_name: str) -> str:
    """Lowercase snake_case form of an identifier, whatever convention it used.

    userEmail, user-email, USER_EMAIL and user.email all collapse to user_email
    so the taxonomy only has to list one spelling.
    """
    if not isinstance(field_name, str):
        return ""
    spaced = _ACRONYM_BOUNDARY.sub("_", _CAMEL_BOUNDARY.sub("_", field_name))
    return _NON_ALNUM.sub("_", spaced.lower()).strip("_")


def _tokens(normalised: str) -> list[str]:
    return [token for token in normalised.split("_") if token]


def _is_negative(tokens: list[str]) -> bool:
    """True when the field only describes personal data instead of holding it.

    Filters match whole token runs rather than raw substrings, otherwise the
    file_name filter would also reject profile_name.
    """
    for wanted in _NEGATIVE_TOKEN_RUNS:
        if len(wanted) > len(tokens):
            continue
        span = len(wanted)
        for start in range(len(tokens) - span + 1):
            window = tokens[start : start + span]
            if all(_token_matches(actual, expected) for actual, expected in zip(window, wanted)):
                return True
    return False


def _token_matches(actual: str, expected: str) -> bool:
    # Plural forms are the same word for this purpose: email_templates is as
    # much a template as email_template.
    return actual == expected or (actual.endswith("s") and actual[:-1] == expected)


def _category_from_name(normalised: str) -> str | None:
    exact = _ALIAS_INDEX.get(normalised)
    if exact is not None:
        return exact
    tokens = _tokens(normalised)
    # Longest run first, so user_pin_code resolves to address (pin_code) rather
    # than to password (pin).
    for span in range(len(tokens), 0, -1):
        for start in range(len(tokens) - span + 1):
            hit = _ALIAS_INDEX.get("_".join(tokens[start : start + span]))
            if hit is not None:
                return hit
    return None


def _category_from_literal(literal: object) -> str | None:
    # The scanner hands over whatever the AST node held, which for a bare
    # 12-digit assignment is an int rather than a string.
    candidate = str(literal).strip()
    if not candidate or len(candidate) > 32:
        return None
    for category, validator in VALIDATORS:
        if validator(candidate):
            return category
    return None


_ALIAS_INDEX: dict[str, str] = _build_alias_index()
_NEGATIVE_TOKEN_RUNS: tuple[tuple[str, ...], ...] = tuple(
    run for run in (tuple(_tokens(normalise(entry))) for entry in taxonomy.NEGATIVE_FILTERS) if run
)


def classify(field_name: str, *, nearby_literal: str | None = None) -> str | None:
    """Return a PII category for a field name, or None."""
    normalised = normalise(field_name)
    if not normalised:
        return None

    tokens = _tokens(normalised)
    if _is_negative(tokens):
        return None

    category = _category_from_name(normalised)

    if nearby_literal:
        proven = _category_from_literal(nearby_literal)
        # A checksum-valid literal outranks the field name, but only where the
        # name was silent or was itself guessing at a document number. It must
        # not turn a customer_name column into a PAN column.
        if proven and (category is None or category in _VALIDATOR_BACKED):
            return proven

    return category


def build_field_ref(
    field_name: str,
    *,
    file_path: str | None = None,
    line_number: int | None = None,
    location_kind: str | None = None,
    context: str | None = None,
    nearby_literal: str | None = None,
) -> PIIFieldRef | None:
    """classify() plus sensitivity lookup, packaged as a PIIFieldRef."""
    category = classify(field_name, nearby_literal=nearby_literal)
    if category is None:
        return None
    return PIIFieldRef(
        field_name=field_name,
        pii_category=category,
        sensitivity=taxonomy.sensitivity_for(category),
        file_path=file_path,
        line_number=line_number,
        location_kind=location_kind,
        context=context,
    )
