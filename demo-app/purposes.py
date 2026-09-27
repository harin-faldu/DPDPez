"""The purpose register for Bharat Bazaar.

Every purpose the platform processes personal data for is declared here once.
The signup page, the consent banner, the preference centre, the notice page and
the retention job all read this table, so a purpose cannot exist in the product
without also existing in the notice served to the Data Principal.

Lawful basis values:
  consent           section 6, requires a recorded act of the Data Principal
  legitimate_use    section 7, no consent taken, still notified
"""

ESSENTIAL = "essential"
CONSENT = "consent"
LEGITIMATE_USE = "legitimate_use"

# key, label shown to the visitor, basis, retention in days, itemised purpose
PURPOSE_REGISTER: tuple[tuple[str, str, str, int, str], ...] = (
    (
        "account_management",
        "Account creation and sign in",
        LEGITIMATE_USE,
        1825,
        "Account creation, authentication and order history for the account you asked us to open.",
    ),
    (
        "order_fulfilment",
        "Order processing and delivery",
        LEGITIMATE_USE,
        2920,
        "Payment, billing, invoicing and delivery of the goods you buy.",
    ),
    (
        "kyc_verification",
        "Seller and high value buyer verification",
        LEGITIMATE_USE,
        2920,
        "Identity verification required by law before a seller payout is released.",
    ),
    (
        "customer_support",
        "Customer support and grievance redressal",
        LEGITIMATE_USE,
        1095,
        "Customer support tickets and grievance redressal correspondence.",
    ),
    (
        "analytics",
        "Usage analytics",
        CONSENT,
        395,
        "Analytics on how pages are used, to decide what to improve.",
    ),
    (
        "marketing",
        "Offers and promotional email",
        CONSENT,
        395,
        "Promotional and newsletter email about offers you may want.",
    ),
)

# Purposes a visitor chooses for themselves. Everything else is notified, not
# asked, because consent that cannot be refused is not consent.
OPTIONAL_PURPOSE_KEYS: tuple[str, ...] = tuple(
    key for key, _label, basis, _days, _text in PURPOSE_REGISTER if basis == CONSENT
)

ALL_PURPOSE_KEYS: tuple[str, ...] = tuple(key for key, *_rest in PURPOSE_REGISTER)


def purpose_entry(purpose_key: str) -> tuple[str, str, str, int, str] | None:
    """The register row for one purpose key."""
    for entry in PURPOSE_REGISTER:
        if entry[0] == purpose_key:
            return entry
    return None


def purpose_label(purpose_key: str) -> str:
    entry = purpose_entry(purpose_key)
    return entry[1] if entry else purpose_key


def purpose_basis(purpose_key: str) -> str:
    entry = purpose_entry(purpose_key)
    return entry[2] if entry else LEGITIMATE_USE


def requires_consent(purpose_key: str) -> bool:
    """True when section 6 consent is the basis, so processing must be gated."""
    return purpose_basis(purpose_key) == CONSENT


def optional_purposes() -> list[dict]:
    """Rows the consent banner and the preference centre render."""
    return [
        {"key": key, "shown_as": label, "basis": basis, "explains": text}
        for key, label, basis, _days, text in PURPOSE_REGISTER
        if basis == CONSENT
    ]


def notified_purposes() -> list[dict]:
    """Rows the notice page itemises, in register order."""
    return [
        {
            "key": key,
            "shown_as": label,
            "basis": basis,
            "keep_for_days": days,
            "explains": text,
        }
        for key, label, basis, days, text in PURPOSE_REGISTER
    ]


def consent_purposes_for(activity_key: str) -> tuple[str, ...]:
    """Purpose keys a stored activity is allowed to be processed under.

    Each table binds itself to this at class definition time, which is what lets
    the preference centre, the retention job and the record of processing all
    agree on why a row exists without any of them restating the mapping.
    """
    bindings = {
        "account_management": ("account_management", "order_fulfilment"),
        "order_fulfilment": ("order_fulfilment",),
        "kyc_verification": ("kyc_verification",),
        "customer_support": ("customer_support",),
        "analytics": ("analytics",),
        "marketing": ("marketing",),
        "compliance_record": ("account_management", "customer_support"),
    }
    return bindings.get(activity_key, (activity_key,))
