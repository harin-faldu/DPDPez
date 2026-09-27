"""Age evaluation, guardian consent and the tracking gate for children.

Section 9 does three separate things and this module answers all three:

  9(1)  a child's personal data needs verifiable consent of a parent or guardian
  9(3)  tracking and behavioural monitoring of a child is prohibited outright,
        not merely without consent
  9(3)  targeted advertising directed at a child is prohibited

Collecting a date of birth is not compliance on its own. The value has to change
what the system does, so calculate_age feeds is_minor, is_minor feeds the
guardian flow and tracking_allowed_for, and tracking_allowed_for is what the
analytics recorder actually calls.
"""

import logging
import secrets
from datetime import date, datetime

from consent_service import has_consent
from crypto_box import lookup_digest
from models import GuardianVerification, now_utc, open_session
from retention_policy import retain_until_for

logger = logging.getLogger("bharat_bazaar.children")

MINOR_YEARS_THRESHOLD = 18
GUARDIAN_CHALLENGE_BYTES = 16


def parse_supplied_date(supplied_value: str) -> date | None:
    """Accept an ISO date from the signup form, or None if it is not one."""
    if not supplied_value:
        return None
    try:
        return datetime.strptime(str(supplied_value).strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def calculate_age(supplied_value: str, as_of: date | None = None) -> int | None:
    """Completed years between the supplied date and today."""
    parsed = parse_supplied_date(supplied_value)
    if parsed is None:
        return None
    today = as_of or now_utc().date()
    years = today.year - parsed.year
    if (today.month, today.day) < (parsed.month, parsed.day):
        years -= 1
    return max(years, 0)


def is_minor(supplied_value: str, as_of: date | None = None) -> bool:
    """True when the supplied date puts this person inside the section 9 regime."""
    years = calculate_age(supplied_value, as_of=as_of)
    if years is None:
        # An unreadable date is treated as a child. Guessing the other way would
        # put the burden of the mistake on the person with the least power.
        return True
    return years < MINOR_YEARS_THRESHOLD


def record_parental_consent(principal_id: int, guardian_contact: str, guardian_label: str) -> str:
    """Open a verifiable guardian consent challenge for a minor's account.

    The account stays unusable for anything beyond sign in until the guardian
    answers the challenge, which is what makes the consent verifiable rather than
    self declared.
    """
    challenge_value = secrets.token_urlsafe(GUARDIAN_CHALLENGE_BYTES)
    session = open_session()
    try:
        row = GuardianVerification(
            principal_id=principal_id,
            guardian_email=guardian_contact,
            guardian_name=guardian_label,
            verification_method="email_challenge",
            challenge_digest=lookup_digest(challenge_value),
            retain_until=retain_until_for("customer_support"),
        )
        session.add(row)
        session.commit()
        logger.info(
            "guardian consent challenge opened for principal=%s method=%s",
            principal_id,
            "email_challenge",
        )
    finally:
        session.close()
    return challenge_value


def verify_guardian_challenge(principal_id: int, challenge_value: str) -> bool:
    """Mark guardian consent verified when the challenge value matches."""
    digest = lookup_digest(challenge_value)
    session = open_session()
    try:
        row = (
            session.query(GuardianVerification)
            .filter(
                GuardianVerification.principal_id == principal_id,
                GuardianVerification.challenge_digest == digest,
            )
            .first()
        )
        if row is None:
            return False
        row.verified_at = now_utc()
        session.commit()
        return True
    finally:
        session.close()


def guardian_consent_verified(principal_id: int) -> bool:
    session = open_session()
    try:
        row = (
            session.query(GuardianVerification)
            .filter(GuardianVerification.principal_id == principal_id)
            .order_by(GuardianVerification.id.desc())
            .first()
        )
        return bool(row and row.verified_at)
    finally:
        session.close()


def tracking_allowed_for(session, principal_id: int, minor_flag: bool) -> bool:
    """The single gate every analytics and advertising path has to pass.

    Two independent reasons to refuse, and either one is enough:
      the account is a child, which section 9(3) prohibits outright
      analytics consent is absent or withdrawn, which section 6 requires
    """
    if minor_flag:
        logger.info("tracking suppressed: account is flagged as a child")
        return False
    return has_consent(session, principal_id, "analytics")
