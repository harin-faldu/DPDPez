"""Partner reporting for the demo storefront.

WARNING: intentionally vulnerable demo fixture. Do not run on a public host.
See README.md.

This module is the far end of the cross file Aadhaar flow:

    POST /kyc  ->  routes/kyc.py submit_kyc()
               ->  models.store_kyc_record()        db write, plaintext
               ->  reporting.push_kyc_to_analytics()
               ->  reporting.build_kyc_payload()
               ->  models.load_user_record()        db read
               ->  requests.post(ANALYTICS_ENDPOINT) third party send

Nothing on that path looks at the consent column, nothing masks the
identifier, and nothing expires the copy that leaves the building.
"""

import logging

import requests

from models import load_user_record

# Reserved, non resolvable hostname. No data can actually leave this machine.
ANALYTICS_ENDPOINT = "https://analytics.example.invalid/v1/kyc-events"

ANALYTICS_TIMEOUT_SECONDS = 5


def build_kyc_payload(user_id: int) -> dict | None:
    """Read the stored KYC record back and shape it for the partner.

    VIOLATION (R6, s.8(5)): the plaintext Aadhaar is copied straight into the
    outbound payload with no masking or tokenisation.
    """
    record = load_user_record(user_id)
    if record is None:
        return None

    return {
        "user_id": record.id,
        "full_name": record.full_name,
        "email": record.email,
        "phone_number": record.phone_number,
        "date_of_birth": record.date_of_birth,
        "aadhaar_number": record.aadhaar_number,
        "signed_up_at": record.created_at.isoformat() if record.created_at else None,
    }


def push_kyc_to_analytics(user_id: int) -> int | None:
    """Send the KYC record to the external analytics partner.

    VIOLATION (R4, s.6): no consent check of any kind runs before the send.
    record.consent_all is never read on this path.

    VIOLATION (Retention, s.8(7)): the partner copy has no expiry, no deletion
    callback and no way to recall it.
    """
    payload = build_kyc_payload(user_id)
    if payload is None:
        return None

    try:
        response = requests.post(
            ANALYTICS_ENDPOINT,
            json=payload,
            timeout=ANALYTICS_TIMEOUT_SECONDS,
        )
        return response.status_code
    except requests.RequestException as exc:
        logging.warning("analytics push failed for user_id=%s: %s", user_id, exc)
        return None


def daily_partner_export() -> list[dict]:
    """Batch variant of the same flow, kept so the graph shows two callers.

    VIOLATION (R4, s.6): iterates every stored user and exports the same
    payload regardless of what any of them agreed to.
    """
    from models import User, db

    exported: list[dict] = []
    for user in db.session.query(User).all():
        payload = build_kyc_payload(user.id)
        if payload is not None:
            exported.append(payload)
    return exported
