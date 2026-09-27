"""KYC capture for the demo storefront.

WARNING: intentionally vulnerable demo fixture. Do not run on a public host.
See README.md.

This is the entry point of the cross file Aadhaar flow that the demo walks
through on the graph view.
"""

import logging

from flask import Blueprint, redirect, render_template, request, session, url_for

from models import store_kyc_record
from reporting import push_kyc_to_analytics

kyc_bp = Blueprint("kyc", __name__)


@kyc_bp.route("/kyc", methods=["GET"])
def kyc_form():
    """Render the KYC form."""
    return render_template("kyc.html", user_id=session.get("user_id", ""))


@kyc_bp.route("/kyc", methods=["POST"])
def submit_kyc():
    """Accept the KYC identifiers and fan them out.

    VIOLATION (R6, s.8(5)): the Aadhaar number is written to the application
    log in the clear on the line below, so every log shipper, log aggregator
    and on call engineer receives a critical identifier.

    VIOLATION (R4, s.6): no consent lookup runs before the write or before
    the third party send that follows it.

    VIOLATION (R12, s.8(1)): nothing records that this identifier was
    collected, by whom, or under which notice version.
    """
    user_id = int(request.form.get("user_id") or session.get("user_id") or 0)
    aadhaar_number = request.form.get("aadhaar_number", "")
    pan_number = request.form.get("pan_number", "")

    logging.info(
        "kyc submitted user_id=%s aadhaar_number=%s", user_id, aadhaar_number
    )

    store_kyc_record(user_id, aadhaar_number, pan_number)
    push_kyc_to_analytics(user_id)

    return redirect(url_for("account.dashboard", user_id=user_id))
