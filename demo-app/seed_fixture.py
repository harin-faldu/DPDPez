"""Synthetic rows so the fixture has something to show on first run.

Every value here is invented. The addresses use the reserved .invalid top level
domain, which can never resolve, and the identifiers are obvious placeholders
rather than anything that could belong to a person.
"""

import logging

from auth_guard import STAFF_LOGIN
from consent_service import record_consent
from crypto_box import hash_password, lookup_digest
from models import DataPrincipal, Product, now_utc, open_session
from retention_policy import retain_until_for

logger = logging.getLogger("bharat_bazaar.seed")

BUYER_LOGIN = "buyer.one@example.invalid"
BUYER_SECRET = "FixturePass!2026"
STAFF_SECRET = "FixtureOps!2026"

CATALOGUE = (
    ("BB-1001", "Brass table lamp", 249000, 18),
    ("BB-1002", "Cotton bedsheet set", 189900, 5),
    ("BB-1003", "Stainless steel tiffin", 89900, 12),
    ("BB-1004", "Jute shopping bag", 39900, 5),
    ("BB-1005", "Terracotta planter pair", 129900, 12),
    ("BB-1006", "Handloom cotton stole", 159900, 5),
)

# Placeholder account rows: login address, shown name, contact number, birth date.
FIXTURE_ACCOUNTS = (
    (BUYER_LOGIN, "Buyer One", "+91 90000 00001", "1994-05-17", BUYER_SECRET),
    (STAFF_LOGIN, "Privacy Ops", "+91 90000 00002", "1988-11-02", STAFF_SECRET),
)


def ensure_seed_rows() -> None:
    """Idempotent. Safe to call on every start."""
    session = open_session()
    try:
        if session.query(Product).count() == 0:
            for sku, shown_as, paise, tax_percent in CATALOGUE:
                session.add(
                    Product(
                        sku=sku,
                        display_label=shown_as,
                        price_paise=paise,
                        tax_rate_percent=tax_percent,
                    )
                )
            session.commit()
            logger.info("catalogue seeded with %d placeholder item(s)", len(CATALOGUE))

        created = 0
        for login_address, shown_as, contact_number, born_on, secret in FIXTURE_ACCOUNTS:
            digest = lookup_digest(login_address)
            existing = (
                session.query(DataPrincipal)
                .filter(DataPrincipal.email_digest == digest)
                .first()
            )
            if existing is not None:
                continue
            row = DataPrincipal(
                email=login_address,
                email_digest=digest,
                full_name=shown_as,
                phone=contact_number,
                dob=born_on,
                password_hash=hash_password(secret),
                is_minor=False,
                marketing_suppressed=False,
                created_at=now_utc(),
                retain_until=retain_until_for("account_management"),
            )
            session.add(row)
            session.commit()
            record_consent(session, row.id, "analytics", False, channel="fixture")
            record_consent(session, row.id, "marketing", False, channel="fixture")
            session.commit()
            created += 1
        if created:
            logger.info("seeded %d placeholder account(s), consent recorded as refused", created)
    finally:
        session.close()
