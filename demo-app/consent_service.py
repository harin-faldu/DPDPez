"""Consent capture, enforcement and withdrawal.

The rule this module exists to enforce: no purpose whose basis is consent may be
processed unless a ConsentRecord for that purpose is currently granted. The check
is server side. A checkbox in the page is how the visitor tells us, not how we
decide, so every processing path calls has_consent or require_consent before it
touches anything.

Section 6(4) also makes withdrawal as easy as giving, which is why withdraw
takes exactly the same shape as grant and is reachable from the same page.
"""

import logging

from models import ConsentRecord, now_utc, open_session
from purposes import OPTIONAL_PURPOSE_KEYS, purpose_basis, requires_consent
from retention_policy import retain_until_for

logger = logging.getLogger("bharat_bazaar.consent")

# Bumped whenever the notice text changes, and stored on every consent row so a
# recorded consent can be tied to the exact wording it was given against.
POLICY_VERSION = "2026-09-01.3"

BANNER_COOKIE = "bb_consent_choice"


class ConsentRequired(Exception):
    """Raised when a consent gated purpose is reached without a granted record."""

    def __init__(self, purpose_key: str) -> None:
        super().__init__(f"no granted consent for purpose {purpose_key}")
        self.purpose_key = purpose_key


def has_consent(session, principal_id: int, purpose_key: str) -> bool:
    """True when this account currently permits this purpose.

    A purpose on the legitimate use basis returns True without a record, because
    section 7 does not ask for consent and a fake consent record for it would
    misrepresent the basis.
    """
    if not requires_consent(purpose_key):
        return True
    if not principal_id:
        return False
    row = (
        session.query(ConsentRecord)
        .filter(
            ConsentRecord.principal_id == principal_id,
            ConsentRecord.purpose == purpose_key,
        )
        .order_by(ConsentRecord.consented_at.desc())
        .first()
    )
    if row is None:
        return False
    return bool(row.granted) and row.withdrawn_at is None


def require_consent(session, principal_id: int, purpose_key: str) -> None:
    """Guard clause for a consent gated path. Raises rather than returns False."""
    if not has_consent(session, principal_id, purpose_key):
        raise ConsentRequired(purpose_key)


def assert_lawful_basis(purpose_key: str) -> str:
    """Record which basis a path is relying on, for the paths consent does not cover.

    Returning the basis rather than a boolean forces the caller to have an answer
    for section 4, instead of processing with no stated basis at all.
    """
    basis = purpose_basis(purpose_key)
    logger.debug("processing under basis %s for purpose %s", basis, purpose_key)
    return basis


def record_consent(
    session,
    principal_id: int,
    purpose_key: str,
    granted: bool,
    channel: str = "web",
) -> ConsentRecord:
    """Write one immutable consent event. Never updates an earlier row."""
    row = ConsentRecord(
        principal_id=principal_id,
        purpose=purpose_key,
        granted=bool(granted),
        consented_at=now_utc(),
        policy_version=POLICY_VERSION,
        channel=channel,
        retain_until=retain_until_for("customer_support"),
    )
    session.add(row)
    logger.info(
        "consent recorded: purpose=%s granted=%s version=%s",
        purpose_key,
        bool(granted),
        POLICY_VERSION,
    )
    return row


def withdraw_consent(session, principal_id: int, purpose_key: str) -> bool:
    """Close out every granted record for a purpose and log the withdrawal.

    The earlier grant is kept with a withdrawn_at stamp rather than deleted, so
    the history stays auditable while the current answer becomes no.
    """
    rows = (
        session.query(ConsentRecord)
        .filter(
            ConsentRecord.principal_id == principal_id,
            ConsentRecord.purpose == purpose_key,
            ConsentRecord.granted.is_(True),
            ConsentRecord.withdrawn_at.is_(None),
        )
        .all()
    )
    stamp = now_utc()
    for row in rows:
        row.withdrawn_at = stamp
    record_consent(session, principal_id, purpose_key, False, channel="withdrawal")
    logger.info("consent withdrawn for purpose=%s rows=%d", purpose_key, len(rows))
    return bool(rows)


def consent_state(session, principal_id: int) -> dict[str, bool]:
    """Current answer for every optional purpose, for the preference centre."""
    return {
        purpose_key: has_consent(session, principal_id, purpose_key)
        for purpose_key in OPTIONAL_PURPOSE_KEYS
    }


def apply_preference_form(session, principal_id: int, submitted) -> dict[str, bool]:
    """Set every optional purpose from a preference centre submission.

    An unticked box is a withdrawal, not an absence of information, because the
    form always posts the full set of optional purposes.
    """
    outcome: dict[str, bool] = {}
    for purpose_key in OPTIONAL_PURPOSE_KEYS:
        wants = submitted.get(purpose_key) is not None
        if wants:
            record_consent(session, principal_id, purpose_key, True)
        else:
            withdraw_consent(session, principal_id, purpose_key)
        outcome[purpose_key] = wants
    session.commit()
    return outcome


def banner_choice_from_form(submitted) -> dict[str, bool]:
    """Read the cookie banner submission.

    Accept and Reject post to the same endpoint with the same shape, so refusing
    is exactly one click, the same as accepting. Reject clears every optional
    purpose regardless of what the checkboxes said.
    """
    rejected = submitted.get("choice") == "reject"
    chosen: dict[str, bool] = {}
    for purpose_key in OPTIONAL_PURPOSE_KEYS:
        chosen[purpose_key] = False if rejected else submitted.get(purpose_key) is not None
    return chosen


def record_banner_choice(submitted, principal_id: int | None = None) -> dict[str, bool]:
    """Persist a banner choice for a signed in account, or return it for the cookie."""
    chosen = banner_choice_from_form(submitted)
    if not principal_id:
        return chosen
    session = open_session()
    try:
        for purpose_key, wants in chosen.items():
            if wants:
                record_consent(session, principal_id, purpose_key, True, channel="banner")
            else:
                withdraw_consent(session, principal_id, purpose_key)
        session.commit()
    finally:
        session.close()
    return chosen
