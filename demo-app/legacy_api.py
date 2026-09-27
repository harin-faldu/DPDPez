"""Internal reporting endpoints kept from the pre 2024 admin console.

Behind the staff guard, but not brought up to the standard the rest of the
platform holds. The customer extract returns the whole account row because that is
what the old ops dashboard expected, and nothing has trimmed it since.

This is a real finding, not a decoration. It is written up in KNOWN_GAPS.md under
purpose limitation and minimisation.
"""

import logging

from flask import Blueprint, Response, jsonify

from audit_trail import generate_compliance_report
from auth_guard import staff_auth_required
from models import DataPrincipal, open_session

logger = logging.getLogger("bharat_bazaar.legacy")

LEGACY_PAGE_SIZE = 50

legacy = Blueprint("legacy", __name__)


@legacy.route("/internal/v1/customer-export", methods=["GET"])
@staff_auth_required
def legacy_customer_export():
    """The old ops extract.

    The dashboard that consumes this only renders a display label and an order
    count, but the payload still carries every column the account row has.
    """
    session = open_session()
    try:
        rows = (
            session.query(DataPrincipal)
            .filter(DataPrincipal.deleted_at.is_(None))
            .limit(LEGACY_PAGE_SIZE)
            .all()
        )
        payload = [
            {
                "id": row.id,
                "email": row.email,
                "full_name": row.full_name,
                "phone": row.phone,
                "dob": row.dob,
                "is_minor": bool(row.is_minor),
                "opened_on": row.created_at,
                "held_until": row.retain_until,
            }
            for row in rows
        ]
        logger.info("legacy extract served rows=%d", len(payload))
        return jsonify({"rows": payload, "count": len(payload)})
    finally:
        session.close()


@legacy.route("/internal/v1/compliance-report", methods=["GET"])
@staff_auth_required
def legacy_compliance_report():
    """Evidence pack over the audit trail, as a CSV download."""
    body = generate_compliance_report(requested_by=None)
    return Response(
        body,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_trail_extract.csv"},
    )
