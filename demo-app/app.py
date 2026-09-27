"""Bharat Bazaar, a demonstration retail and seller verification site.

A local fixture used to exercise a DPDP Act 2023 compliance scanner against a
realistic, mostly compliant application. It binds to the loopback interface only,
runs with the debugger off, and every value in it is synthetic.

Route layout:
  public          home, privacy notice, cookie notice, catalogue, signup, sign in
  authenticated   account_routes.py, the five rights plus KYC and preferences
  internal        legacy_api.py, behind a second staff guard

Nothing in this process opens an outbound connection. The analytics counters are
local rows and the browser side script is served from this origin.
"""

import logging

from flask import Flask, flash, redirect, render_template, request, url_for
from flask import session as browser_session

from account_routes import account
from analytics_local import record_event
from auth_guard import current_minor_flag, current_principal_id
from consent_service import BANNER_COOKIE, POLICY_VERSION, record_banner_choice
from contacts import escalation_note, published_contacts
from crypto_box import session_signing_key
from intake import register_data_principal, sign_in_principal
from legacy_api import legacy
from models import Product, create_schema, open_session
from processing_register import (
    REGISTER_OWNER,
    REGISTER_REVIEWED_ON,
    high_risk_processing_activities,
    records_of_processing_activities,
)
from purposes import OPTIONAL_PURPOSE_KEYS, notified_purposes, optional_purposes
from retention_policy import start_retention_scheduler
from seed_fixture import ensure_seed_rows

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("bharat_bazaar")

BIND_HOST = "127.0.0.1"
BIND_PORT = 5001
BANNER_COOKIE_LIFETIME_SECONDS = 15_552_000

# Sent on every response. The policy is strict because this origin serves no
# third party script, so there is nothing legitimate to allow beyond self.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "connect-src 'self'; object-src 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), interest-cohort=()",
    "Cache-Control": "no-store",
}

CONTACT_POINTS = published_contacts()


def banner_state(raw_cookie: str | None) -> dict:
    """Decode the banner cookie into a per purpose answer.

    No cookie means no choice has been made, which is not the same as consent, so
    every optional purpose comes back false. The value is a dot separated list of
    the purposes that were granted, which keeps the cookie free of the quoting a
    JSON payload would need.
    """
    granted = {part for part in str(raw_cookie or "").split(".") if part}
    return {
        purpose_key: purpose_key in granted for purpose_key in OPTIONAL_PURPOSE_KEYS
    }


def banner_cookie_value(chosen: dict) -> str:
    """Encode the answer for the cookie. "none" records a refusal explicitly."""
    granted = [key for key in OPTIONAL_PURPOSE_KEYS if chosen.get(key)]
    return ".".join(granted) if granted else "none"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = session_signing_key()
    app.config["SESSION_COOKIE_NAME"] = "bb_session"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = 1800
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000

    app.register_blueprint(account)
    app.register_blueprint(legacy)

    @app.after_request
    def apply_security_headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.context_processor
    def inject_site_context():
        """Every page gets the contacts, the notice version and the banner state.

        The banner is driven from here rather than from each handler, so a page
        cannot be added that quietly skips the choice.
        """
        return {
            "default_contacts": CONTACT_POINTS,
            "policy_version": POLICY_VERSION,
            "optional": optional_purposes(),
            "chosen": banner_state(request.cookies.get(BANNER_COOKIE)),
            "banner_pending": not request.cookies.get(BANNER_COOKIE),
        }

    @app.route("/", methods=["GET"])
    def home():
        chosen = banner_state(request.cookies.get(BANNER_COOKIE))
        if chosen.get("analytics"):
            record_event(current_principal_id(), current_minor_flag(), "page_view")
        return render_template("home.html", contacts=CONTACT_POINTS)

    @app.route("/privacy", methods=["GET"])
    @app.route("/privacy-policy", methods=["GET"])
    def privacy_notice():
        return render_template(
            "privacy.html",
            contacts=CONTACT_POINTS,
            notified=notified_purposes(),
            register=records_of_processing_activities(),
            high_risk=high_risk_processing_activities(),
            register_owner=REGISTER_OWNER,
            reviewed_on=REGISTER_REVIEWED_ON,
            escalation=escalation_note(),
        )

    @app.route("/cookies", methods=["GET"])
    @app.route("/cookie-policy", methods=["GET"])
    def cookie_policy():
        return render_template("cookies.html", notified=notified_purposes())

    @app.route("/terms", methods=["GET"])
    def terms_of_use():
        return render_template("terms.html")

    @app.route("/children", methods=["GET"])
    def children_notice():
        return render_template("children.html", contacts=CONTACT_POINTS)

    @app.route("/security", methods=["GET"])
    def security_notice():
        return render_template("security.html")

    @app.route("/refund", methods=["GET"])
    def refund_policy():
        return render_template("refund.html")

    @app.route("/products", methods=["GET"])
    def catalogue():
        session = open_session()
        try:
            chosen = banner_state(request.cookies.get(BANNER_COOKIE))
            if chosen.get("analytics"):
                record_event(current_principal_id(), current_minor_flag(), "product_view")
            return render_template(
                "products.html", items=session.query(Product).all(), chosen=chosen
            )
        finally:
            session.close()

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            outcome = register_data_principal(request.form)
            if outcome.get("ok"):
                browser_session["principal_id"] = outcome.get("principal_id")
                browser_session["minor_flag"] = outcome.get("minor")
                browser_session["role"] = "account_holder"
                if outcome.get("needs_guardian"):
                    flash(
                        "This account is held by a minor, so a parent or guardian has to "
                        "confirm it before anything beyond sign in is available."
                    )
                return redirect(url_for("account.account_home"))
            flash(outcome.get("reason") or "Please check the form and try again.")
        return render_template(
            "signup.html",
            optional=optional_purposes(),
            notified=notified_purposes(),
            contacts=CONTACT_POINTS,
            policy_version=POLICY_VERSION,
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            outcome = sign_in_principal(request.form)
            if outcome.get("ok"):
                browser_session["principal_id"] = outcome.get("principal_id")
                browser_session["minor_flag"] = outcome.get("minor")
                browser_session["role"] = outcome.get("role")
                return redirect(
                    request.form.get("next_path") or url_for("account.account_home")
                )
            flash(outcome.get("reason") or "Those details do not match an account.")
        return render_template("login.html", next_path=request.args.get("next_path", ""))

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        browser_session.clear()
        return redirect(url_for("home"))

    @app.route("/consent/banner", methods=["POST"])
    def consent_banner_choice():
        chosen = record_banner_choice(request.form, current_principal_id())
        target = redirect(request.form.get("return_to") or url_for("home"))
        target.set_cookie(
            BANNER_COOKIE,
            banner_cookie_value(chosen),
            max_age=BANNER_COOKIE_LIFETIME_SECONDS,
            secure=True,
            httponly=True,
            samesite="Lax",
            path="/",
        )
        return target

    @app.route("/livez", methods=["GET"])
    def service_status():
        """Liveness probe. Carries no personal data and needs no session."""
        return {"ok": True, "fixture": "bharat-bazaar", "notice_version": POLICY_VERSION}

    return app


app = create_app()


def main() -> None:
    create_schema()
    ensure_seed_rows()
    start_retention_scheduler()
    logger.info(
        "demonstration fixture listening on http://%s:%d, notice version %s",
        BIND_HOST,
        BIND_PORT,
        POLICY_VERSION,
    )
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
