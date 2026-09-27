"""Retention periods and the job that enforces them.

Section 8(7) makes erasure the default once the purpose is served, so a row gets
an end date when it is written rather than when somebody remembers to look. The
period comes from the purpose register, which means the number shown on the
notice page and the number the sweep uses are the same number.

Coverage is deliberately explicit in COVERED_TABLES. Two stores are not in it
and that is written up in KNOWN_GAPS.md instead of being quietly ignored.
"""

import logging
import threading
from datetime import timedelta

from models import (
    ConsentRecord,
    DataPrincipal,
    GrievanceTicket,
    GuardianVerification,
    KycVerification,
    MailOutbox,
    Order,
    now_utc,
    open_session,
)
from purposes import PURPOSE_REGISTER

logger = logging.getLogger("bharat_bazaar.retention")

DEFAULT_RETENTION_DAYS = 1095
SWEEP_INTERVAL_SECONDS = 3600

# Table, the purpose its rows are held under, and the column carrying the clock.
COVERED_TABLES: tuple[tuple[type, str], ...] = (
    (DataPrincipal, "account_management"),
    (KycVerification, "kyc_verification"),
    (ConsentRecord, "customer_support"),
    (GuardianVerification, "customer_support"),
    (GrievanceTicket, "customer_support"),
    (MailOutbox, "marketing"),
    (Order, "order_fulfilment"),
)

_sweep_timer: threading.Timer | None = None


def retention_period_days(purpose_key: str) -> int:
    """How long a purpose may keep personal data, in days."""
    for key, _label, _basis, days, _text in PURPOSE_REGISTER:
        if key == purpose_key:
            return days
    return DEFAULT_RETENTION_DAYS


def retain_until_for(purpose_key: str, starting_at=None):
    """The end date a new row gets, computed from the register."""
    base = starting_at or now_utc()
    return base + timedelta(days=retention_period_days(purpose_key))


def purge_expired_records() -> dict[str, int]:
    """Delete every row in a covered table whose retention clock has run out.

    Returns a per table count so the run can be reported rather than assumed.
    """
    removed: dict[str, int] = {}
    session = open_session()
    try:
        cutoff = now_utc()
        for table, purpose_key in COVERED_TABLES:
            stale = (
                session.query(table).filter(table.retain_until <= cutoff).all()
            )
            for row in stale:
                session.delete(row)
            if stale:
                removed[table.__tablename__] = len(stale)
                logger.info(
                    "retention sweep removed %d row(s) from %s under purpose %s",
                    len(stale),
                    table.__tablename__,
                    purpose_key,
                )
        session.commit()
    finally:
        session.close()
    return removed


def run_sweep_and_reschedule() -> None:
    try:
        purge_expired_records()
    except Exception:
        logger.exception("retention sweep failed, will retry on the next interval")
    start_retention_scheduler()


def start_retention_scheduler() -> None:
    """Arm the next sweep. A daemon timer, so the process still exits cleanly."""
    global _sweep_timer
    if _sweep_timer is not None:
        _sweep_timer.cancel()
    _sweep_timer = threading.Timer(SWEEP_INTERVAL_SECONDS, run_sweep_and_reschedule)
    _sweep_timer.daemon = True
    _sweep_timer.start()


def stop_retention_scheduler() -> None:
    global _sweep_timer
    if _sweep_timer is not None:
        _sweep_timer.cancel()
        _sweep_timer = None
