"""Authenticated routes: the rights pages, KYC, grievances and preferences.

Every route in this module is behind login_required. Each of the statutory rights
gets its own page rather than a single support mailbox, because section 12 and
section 14 are separate rights and a mailbox cannot be shown to work.

Two paths are registered for several of these. The short one is what a person
types, the long one is what the footer links to and what a scanner will recognise
as the named request path.
"""

import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask import session as browser_session

from audit_trail import READ, audit_entries_for, record_access_now
from auth_guard import current_minor_flag, current_principal_id, login_required
from children import guardian_consent_verified
from consent_service import (
    POLICY_VERSION,
    apply_preference_form,
    consent_state,
    withdraw_consent,
)
from intake import store_kyc_record
from marketing import suppress_marketing
from models import open_session
from purposes import notified_purposes, optional_purposes
from rights_service import (
    GRIEVANCE_RESPONSE_DAYS,
    apply_correction,
    assemble_data_export,
    erase_account,
    open_grievances,
    raise_grievance,
    record_nomination,
)

logger = logging.getLogger("bharat_bazaar.account")

account = Blueprint("account", __name__)


@account.route("/account", methods=["GET"])
@login_required
def account_home():
    session = open_session()
    try:
        return render_template(
            "account.html",
            choices=consent_state(session, current_principal_id()),
            optional=optional_purposes(),
            guardian_ok=guardian_consent_verified(current_principal_id()),
            minor=current_minor_flag(),
            policy_version=POLICY_VERSION,
        )
    finally:
        session.close()


@account.route("/account/data", methods=["GET"])
@account.route("/account/my-data", methods=["GET"])
@login_required
def download_my_data():
    """Section 11 access. The page and the machine readable copy are one handler."""
    export = assemble_data_export(current_principal_id())
    if export is None:
        return redirect(url_for("login"))
    if request.args.get("as") == "json":
        return jsonify(export)
    return render_template("account_data.html", export=export)


@account.route("/account/correct", methods=["GET", "POST"])
@account.route("/account/correction", methods=["GET", "POST"])
@login_required
def update_my_data():
    """Section 12 correction."""
    if request.method == "POST":
        outcome = apply_correction(current_principal_id(), request.form)
        flash(outcome.get("reason") or "Your details have been corrected.")
        if outcome.get("ok"):
            return redirect(url_for("account.download_my_data"))
    return render_template("account_correct.html")


@account.route("/account/delete", methods=["GET", "POST"])
@account.route("/account/delete-my-data", methods=["GET", "POST"])
@login_required
def delete_my_data():
    """Section 12(3) erasure. Confirmed on a GET, carried out on a POST."""
    if request.method == "POST":
        outcome = erase_account(current_principal_id())
        browser_session.clear()
        flash(
            "Your account and the records linked to it have been erased."
            if outcome.get("ok")
            else (outcome.get("reason") or "Erasure could not be completed.")
        )
        return redirect(url_for("home"))
    return render_template("account_delete.html")


@account.route("/account/nominee", methods=["GET", "POST"])
@login_required
def nominee():
    """Section 14 nomination."""
    if request.method == "POST":
        outcome = record_nomination(current_principal_id(), request.form)
        flash(outcome.get("reason") or "Your nominee has been recorded.")
        if outcome.get("ok"):
            return redirect(url_for("account.account_home"))
    return render_template("account_nominee.html")


@account.route("/account/audit-trail", methods=["GET"])
@login_required
def my_audit_trail():
    """Section 8(1) evidence, from the account holder's side."""
    session = open_session()
    try:
        record_access_now(
            current_principal_id(), READ, "audit_log:self", "customer_support"
        )
        return render_template(
            "account_audit.html",
            entries=audit_entries_for(session, current_principal_id()),
        )
    finally:
        session.close()


@account.route("/kyc", methods=["GET", "POST"])
@login_required
def kyc_page():
    """Seller verification. Legal obligation basis, not consent."""
    if request.method == "POST":
        outcome = store_kyc_record(current_principal_id(), request.form)
        flash(outcome.get("reason") or "Verification documents received.")
        if outcome.get("ok"):
            return redirect(url_for("account.account_home"))
    return render_template("kyc.html", policy_version=POLICY_VERSION)


@account.route("/grievance", methods=["GET", "POST"])
@account.route("/grievance-redressal", methods=["GET"])
def grievance_page():
    """Section 13 grievance redressal.

    The procedure, the officer and the response window are public, because a person
    deciding whether to complain has to be able to read them first. Filing a
    grievance and reading the tickets on an account both need a sign in, which is
    enforced below rather than by a blanket guard on the page.
    """
    principal_id = current_principal_id()
    if request.method == "POST":
        if not principal_id:
            return redirect(url_for("login", next_path="/grievance"))
        outcome = raise_grievance(principal_id, request.form)
        flash(outcome.get("reason") or "Your grievance has been registered.")
    return render_template(
        "grievance.html",
        tickets=open_grievances(principal_id) if principal_id else [],
        signed_in=bool(principal_id),
        response_days=GRIEVANCE_RESPONSE_DAYS,
    )


@account.route("/consent/preferences", methods=["GET", "POST"])
@login_required
def consent_preferences():
    """The preference centre. Giving and withdrawing are the same form."""
    session = open_session()
    try:
        if request.method == "POST":
            outcome = apply_preference_form(
                session, current_principal_id(), request.form
            )
            if not outcome.get("marketing"):
                suppress_marketing(current_principal_id())
            flash("Your choices have been saved.")
        return render_template(
            "consent_preferences.html",
            choices=consent_state(session, current_principal_id()),
            optional=optional_purposes(),
            notified=notified_purposes(),
            policy_version=POLICY_VERSION,
        )
    finally:
        session.close()


@account.route("/consent/withdraw", methods=["POST"])
@login_required
def withdraw_purpose():
    """One click withdrawal of a single purpose, section 6(4)."""
    purpose_key = request.form.get("purpose") or ""
    session = open_session()
    try:
        withdraw_consent(session, current_principal_id(), purpose_key)
        session.commit()
    finally:
        session.close()
    if purpose_key == "marketing":
        suppress_marketing(current_principal_id())
    flash(f"Consent withdrawn for {purpose_key}.")
    return redirect(url_for("account.consent_preferences"))
