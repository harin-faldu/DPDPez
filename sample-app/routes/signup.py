"""Signup flow for the demo storefront.

WARNING: intentionally vulnerable demo fixture. Do not run on a public host.
See README.md.
"""

from flask import Blueprint, redirect, render_template, request, session, url_for

from crypto_utils import legacy_password_digest, pbkdf2_pin_digest
from models import create_user

signup_bp = Blueprint("signup", __name__)


@signup_bp.route("/signup", methods=["GET"])
def signup_form():
    """Render the signup form.

    VIOLATION (R3, s.5): the template shows no privacy notice, no purpose
    list, no retention statement and no link to any notice page. There is no
    notice page in this application to link to.
    """
    return render_template("signup.html")


@signup_bp.route("/signup", methods=["POST"])
def create_account():
    """Create the account.

    VIOLATION (R4, s.6): consent_all is pulled out of the form and passed
    along as a value, but no branch in this function or anywhere downstream
    depends on it. The row is written either way.

    VIOLATION (R5, s.9): date_of_birth is read and stored and never evaluated.
    No age is computed, no under-18 branch exists, no parental consent is
    requested.
    """
    full_name = request.form.get("full_name", "")
    email = request.form.get("email", "")
    phone_number = request.form.get("phone_number", "")
    address_line = request.form.get("address_line", "")
    date_of_birth = request.form.get("date_of_birth", "")
    password = request.form.get("password", "")
    support_pin = request.form.get("support_pin", "")
    consent_all = request.form.get("consent_all")

    user = create_user(
        full_name=full_name,
        email=email,
        phone_number=phone_number,
        address_line=address_line,
        date_of_birth=date_of_birth,
        password_md5=legacy_password_digest(password),
        support_pin_pbkdf2=pbkdf2_pin_digest(support_pin),
        consent_all=bool(consent_all),
    )

    session["user_id"] = user.id
    return redirect(url_for("kyc.kyc_form"))


# VIOLATION (R4, s.6): there is no /consent/withdraw route, no consent
# management screen and no way for a customer to change consent_all after
# signup.
#
# VIOLATION (R10, s.11-14): there is no /account/export, /account/correct,
# /account/delete or /account/nominee route anywhere in this application.
#
# VIOLATION (R11, s.13, s.27): there is no /grievance route, no complaint
# form and no published escalation path to the Data Protection Board.
