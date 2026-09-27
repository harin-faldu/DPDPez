# =====================================================================
# INTENTIONALLY VULNERABLE DEMO FIXTURE. DO NOT DEPLOY.
#
# This Flask app is the scan target for the DPDP Act 2023 compliance
# reviewer. Every privacy failure in it was planted on purpose so the
# scanner has something known to find during the demo. It must never be
# run on a public host, behind a tunnel, or on any machine that holds
# real data. It binds to 127.0.0.1 only and every value it stores is a
# synthetic placeholder.
#
# Do not fix the violations. They are the fixture.
# =====================================================================

"""Bharat Bazaar demo storefront: signup, KYC and account views."""

import os

from flask import Flask

from models import User, db
from routes.account import account_bp
from routes.kyc import kyc_bp
from routes.signup import signup_bp

DATABASE_URI = "sqlite:///demo_storefront.db"


def create_app() -> Flask:
    """Build the Flask application.

    VIOLATION (R8, s.8(4)): there is no data protection impact assessment in
    this project, no threat model and no processing inventory.

    VIOLATION (R9, s.10): no Data Protection Officer is named anywhere in the
    code, the config or the templates, and no independent audit hook exists.

    VIOLATION (R7, s.8(6)): there is no Incident or Breach model, no
    notification queue and no code path that would tell the Board or an
    affected customer that anything had gone wrong.

    VIOLATION (Retention, s.8(7)): no scheduler, no cleanup task, no purge
    command and no configured retention period. Nothing in this application
    ever deletes a row.
    """
    app = Flask(__name__)

    # No secret is pinned in the source tree. A throwaway key is generated per
    # process when the environment does not supply one.
    app.config["SECRET_KEY"] = os.environ.get(
        "DEMO_SECRET_KEY", os.urandom(24).hex()
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    app.register_blueprint(account_bp)
    app.register_blueprint(signup_bp)
    app.register_blueprint(kyc_bp)

    with app.app_context():
        db.create_all()
        seed_demo_data()

    return app


def seed_demo_data() -> None:
    """Insert two placeholder rows so the demo has something to show.

    All values below are obviously fake. The Aadhaar placeholders are strings
    of zeros, which fail the checksum used by every real verifier, and the PAN
    placeholder is a repeated letter pattern. The addresses, names, phone
    numbers and mail domains are reserved test values that resolve nowhere.
    """
    if db.session.query(User).count() > 0:
        return

    placeholders = [
        {
            "full_name": "Demo Customer One",
            "email": "demo.customer.one@example.invalid",
            "phone_number": "+91-00000-00001",
            "address_line": "1 Example Street, Test Nagar, Sample City 000001",
            "date_of_birth": "2000-01-01",
            "aadhaar_number": "000000000000",
            "password_md5": "0" * 32,
            "support_pin_pbkdf2": "pbkdf2_sha256$240000$00$00",
            "consent_all": True,
        },
        {
            "full_name": "Demo Customer Two",
            "email": "demo.customer.two@example.invalid",
            "phone_number": "+91-00000-00002",
            "address_line": "2 Example Street, Test Nagar, Sample City 000002",
            "date_of_birth": "2012-01-01",
            "aadhaar_number": "000000000001",
            "password_md5": "0" * 32,
            "support_pin_pbkdf2": "pbkdf2_sha256$240000$00$00",
            "consent_all": False,
        },
    ]

    for values in placeholders:
        db.session.add(User(**values))
    db.session.commit()


if __name__ == "__main__":
    # Loopback only, debugger off. This app is a scan target, not a service.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
