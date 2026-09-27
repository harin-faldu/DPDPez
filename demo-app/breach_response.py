"""Personal data breach response.

Section 8(6) requires two intimations, not one: the Board, and every affected Data
Principal. Both are separate functions here because in practice they happen at
different times, to different recipients, with different content, and a system
that only has one of them will quietly skip the other.

The clock is on the row. notify_by is written when the incident is opened, so the
72 hour position is a stored fact rather than something reconstructed later from
a chat thread.
"""

import logging
from datetime import timedelta

from audit_trail import WRITE, record_data_access
from models import (
    BreachIncident,
    DataPrincipal,
    MailOutbox,
    now_utc,
    open_session,
)
from retention_policy import retain_until_for

logger = logging.getLogger("bharat_bazaar.breach")

BREACH_INTIMATION_WINDOW_HOURS = 72
BOARD_INTIMATION_MAILBOX = "intimation@board-filing.invalid"

BOARD_FILING_FIELDS: tuple[str, ...] = (
    "nature and extent of the breach",
    "when and where it was detected",
    "the likely consequences",
    "the measures taken to remedy it",
    "the contact able to answer questions",
)


def open_incident(summary: str, severity: str, records_affected: int) -> int:
    """Record a breach and start the intimation clock in the same transaction."""
    session = open_session()
    try:
        detected = now_utc()
        row = BreachIncident(
            summary=summary[:300],
            severity=severity,
            status="open",
            records_affected=records_affected,
            detected_at=detected,
            notify_by=detected + timedelta(hours=BREACH_INTIMATION_WINDOW_HOURS),
            retain_until=retain_until_for("customer_support"),
        )
        session.add(row)
        session.commit()
        logger.warning(
            "breach incident opened id=%s severity=%s rows=%d window_hours=%d",
            row.id,
            severity,
            records_affected,
            BREACH_INTIMATION_WINDOW_HOURS,
        )
        return row.id
    finally:
        session.close()


def hours_remaining_to_intimate(incident_id: int) -> float | None:
    """Hours left before the intimation window closes. Negative once it has."""
    session = open_session()
    try:
        row = session.get(BreachIncident, incident_id)
        if row is None:
            return None
        return (row.notify_by - now_utc()).total_seconds() / 3600.0
    finally:
        session.close()


def notify_board(incident_id: int) -> bool:
    """Intimate the Data Protection Board and stamp when it was done.

    The filing carries the fields BOARD_FILING_FIELDS lists. In this fixture it is
    written to the outbox instead of being transmitted, so nothing leaves the host.
    """
    session = open_session()
    try:
        row = session.get(BreachIncident, incident_id)
        if row is None:
            return False

        filing = MailOutbox(
            recipient_email=BOARD_INTIMATION_MAILBOX,
            purpose="breach_intimation",
            summary=f"Breach intimation, incident {incident_id}",
            body="\n".join(BOARD_FILING_FIELDS),
            queued_at=now_utc(),
            retain_until=retain_until_for("customer_support"),
        )
        session.add(filing)
        row.board_notified_at = now_utc()
        record_data_access(session, None, WRITE, f"breach_incidents:{incident_id}", "compliance")
        session.commit()
        logger.warning(
            "board intimation filed for incident=%s within_window=%s",
            incident_id,
            row.board_notified_at <= row.notify_by,
        )
        return True
    finally:
        session.close()


def notify_affected_principals(incident_id: int, affected_ids: list[int]) -> int:
    """Intimate each affected Data Principal and stamp the incident when done."""
    session = open_session()
    sent = 0
    try:
        row = session.get(BreachIncident, incident_id)
        if row is None:
            return 0

        for target_id in affected_ids:
            principal = session.get(DataPrincipal, target_id)
            if principal is None or principal.deleted_at is not None:
                continue
            session.add(
                MailOutbox(
                    recipient_email=principal.email,
                    purpose="breach_intimation",
                    summary=f"Important notice about your account, incident {incident_id}",
                    body=(
                        "We are telling you directly about a personal data breach that "
                        "affected your account, what it involved, and what we have done "
                        "about it. The contact for questions is on our privacy page."
                    ),
                    queued_at=now_utc(),
                    retain_until=retain_until_for("customer_support"),
                )
            )
            sent += 1

        row.principals_notified_at = now_utc()
        row.status = "intimated"
        session.commit()
        logger.warning(
            "data principal intimation queued incident=%s recipients=%d", incident_id, sent
        )
        return sent
    finally:
        session.close()


def overdue_incidents() -> list[dict]:
    """Incidents past the window with no Board intimation stamp."""
    session = open_session()
    try:
        rows = (
            session.query(BreachIncident)
            .filter(BreachIncident.board_notified_at.is_(None))
            .all()
        )
        cutoff = now_utc()
        return [
            {
                "incident": row.id,
                "summary": row.summary,
                "overdue_hours": round((cutoff - row.notify_by).total_seconds() / 3600.0, 1),
            }
            for row in rows
            if row.notify_by < cutoff
        ]
    finally:
        session.close()
