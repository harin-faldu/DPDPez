"""Promotional mail.

Nothing is sent from this fixture. Messages are written to mail_outbox and left
there, so no address ever leaves the machine.

Read KNOWN_GAPS.md before using this module as a pattern. The audience is filtered
on consent when it is built, and the send step trusts that filter instead of
reading the consent record again, so a withdrawal that lands between the two steps
is not honoured on the batch already in flight.
"""

import logging

from consent_service import has_consent
from models import DataPrincipal, MailOutbox, now_utc, open_session
from retention_policy import retain_until_for

logger = logging.getLogger("bharat_bazaar.marketing")

CAMPAIGN_BODY = (
    "Offers picked for you this week at Bharat Bazaar. "
    "To stop receiving these, open Manage preferences in your account."
)


def build_campaign_audience(campaign_key: str) -> list[int]:
    """Account ids that have granted marketing consent at the time of the build."""
    session = open_session()
    try:
        chosen: list[int] = []
        rows = session.query(DataPrincipal).filter(
            DataPrincipal.deleted_at.is_(None),
            DataPrincipal.marketing_suppressed.is_(False),
            DataPrincipal.is_minor.is_(False),
        ).all()
        for row in rows:
            if has_consent(session, row.id, "marketing"):
                chosen.append(row.id)
        logger.info(
            "campaign audience built campaign=%s size=%d", campaign_key, len(chosen)
        )
        return chosen
    finally:
        session.close()


def queue_promotional_email(principal_id: int, campaign_key: str) -> bool:
    """Queue one promotional message for an account already in the audience.

    The audience build is the only place marketing consent is read. This step does
    not re-read it, which is the gap written up in KNOWN_GAPS.md.
    """
    session = open_session()
    try:
        principal = session.get(DataPrincipal, principal_id)
        if principal is None or principal.deleted_at is not None:
            return False

        recipient_email = principal.email
        row = MailOutbox(
            recipient_email=recipient_email,
            purpose="marketing",
            summary=f"Weekly offers: {campaign_key}",
            body=CAMPAIGN_BODY,
            queued_at=now_utc(),
            retain_until=retain_until_for("marketing"),
        )
        session.add(row)
        session.commit()
        return True
    finally:
        session.close()


def run_campaign(campaign_key: str) -> int:
    """Build the audience, then queue one message per account in it."""
    audience = build_campaign_audience(campaign_key)
    queued = 0
    for principal_id in audience:
        if queue_promotional_email(principal_id, campaign_key):
            queued += 1
    logger.info("campaign queued campaign=%s messages=%d", campaign_key, queued)
    return queued


def suppress_marketing(principal_id: int) -> None:
    """Hard suppression flag, set when an account withdraws marketing consent."""
    session = open_session()
    try:
        principal = session.get(DataPrincipal, principal_id)
        if principal is not None:
            principal.marketing_suppressed = True
            session.commit()
    finally:
        session.close()
