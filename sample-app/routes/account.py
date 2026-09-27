"""Account views for the demo storefront.

WARNING: intentionally vulnerable demo fixture. Do not run on a public host.
See README.md.
"""

from flask import Blueprint, abort, jsonify, render_template

from models import load_user_record
from routes import require_session

account_bp = Blueprint("account", __name__)


@account_bp.route("/", methods=["GET"])
def home():
    """Storefront landing page."""
    return render_template("index.html")


@account_bp.route("/dashboard/<int:user_id>", methods=["GET"])
@require_session
def dashboard(user_id: int):
    """Customer dashboard.

    NEGATIVE CONTROL: this route carries a session guard, so the scanner can
    report has_auth True here and has_auth False on the JSON endpoint below.
    """
    record = load_user_record(user_id)
    if record is None:
        abort(404)
    return render_template("dashboard.html", record=record)


@account_bp.route("/api/customer/<int:user_id>", methods=["GET"])
def customer_profile(user_id: int):
    """Return the full customer record as JSON.

    VIOLATION (R6, s.8(5)): no authentication, no authorisation and no rate
    limit on an endpoint that returns a plaintext Aadhaar number alongside
    name, email, phone, address and date of birth. Any caller who can guess a
    sequential user id gets the whole record.

    VIOLATION (R12, s.8(1)): the read is not written to any audit trail.
    """
    record = load_user_record(user_id)
    if record is None:
        abort(404)

    return jsonify(
        {
            "user_id": record.id,
            "full_name": record.full_name,
            "email": record.email,
            "phone_number": record.phone_number,
            "address_line": record.address_line,
            "date_of_birth": record.date_of_birth,
            "aadhaar_number": record.aadhaar_number,
            "consent_all": record.consent_all,
        }
    )
