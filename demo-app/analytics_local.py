"""Usage analytics, counted locally and only with consent.

Nothing in this module talks to a network. There is no vendor tag, no pixel and no
beacon: the counters are rows in analytics_rollup and the browser side is a static
script served from this same origin. That is deliberate, because a third party tag
that fires before a choice is made cannot have been consented to, and once it has
fired the breach has already happened.

Two conditions are checked server side before a single counter moves:
  the account is not flagged as a child, section 9(3)
  analytics consent is currently granted, section 6
"""

import logging

from children import tracking_allowed_for
from crypto_box import principal_reference
from models import AnalyticsRollup, now_utc, open_session

logger = logging.getLogger("bharat_bazaar.analytics")

ALLOWED_EVENT_KEYS: tuple[str, ...] = (
    "page_view",
    "search",
    "product_view",
    "add_to_cart",
    "checkout_start",
)


def record_event(principal_id: int | None, minor_flag: bool, event_key: str) -> bool:
    """Increment one daily counter, or refuse and say nothing was recorded."""
    if event_key not in ALLOWED_EVENT_KEYS:
        return False

    session = open_session()
    try:
        if not tracking_allowed_for(session, principal_id, minor_flag):
            logger.debug("analytics event refused for event_key=%s", event_key)
            return False

        reference = principal_reference(principal_id) if principal_id else None
        today = now_utc().date()
        row = (
            session.query(AnalyticsRollup)
            .filter(
                AnalyticsRollup.day == today,
                AnalyticsRollup.event_key == event_key,
                AnalyticsRollup.principal_ref == reference,
            )
            .first()
        )
        if row is None:
            row = AnalyticsRollup(
                day=today,
                purpose="analytics",
                event_key=event_key,
                event_count=1,
                principal_ref=reference,
            )
            session.add(row)
        else:
            row.event_count = row.event_count + 1
        session.commit()
        return True
    finally:
        session.close()


def counters_for_day(on_day=None) -> list[dict]:
    """Aggregate counters, for the internal dashboard. No account level rows."""
    session = open_session()
    try:
        day = on_day or now_utc().date()
        rows = session.query(AnalyticsRollup).filter(AnalyticsRollup.day == day).all()
        totals: dict[str, int] = {}
        for row in rows:
            totals[row.event_key] = totals.get(row.event_key, 0) + row.event_count
        return [{"event_key": key, "seen": value} for key, value in sorted(totals.items())]
    finally:
        session.close()
