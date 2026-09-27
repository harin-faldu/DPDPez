"""Collection points: signup, sign in and KYC.

Everything that turns a form submission into a stored row lives here rather than
in the route module, so the collection logic can be read in one place and the
route layer stays thin. Each function states the basis it is processing under
before it touches a value, and nothing is stored that the stated purpose does not
need.

Only synthetic values are ever entered into this fixture. The seed account uses
.invalid addresses, which can never resolve.
"""

import logging

from auth_guard import role_for_digest
from children import is_minor, record_parental_consent
from consent_service import POLICY_VERSION, assert_lawful_basis, record_consent
from crypto_box import hash_password, lookup_digest, verify_password
from models import DataPrincipal, KycVerification, now_utc, open_session
from purposes import OPTIONAL_PURPOSE_KEYS
from retention_policy import retain_until_for

logger = logging.getLogger("bharat_bazaar.intake")

MINIMUM_SECRET_LENGTH = 10


def find_principal_by_login(session, submitted_email: str):
    """Locate an account from a submitted address using the keyed digest."""
    assert_lawful_basis("account_management")
    if not submitted_email:
        return None
    return (
        session.query(DataPrincipal)
        .filter(
            DataPrincipal.email_digest == lookup_digest(submitted_email),
            DataPrincipal.deleted_at.is_(None),
        )
        .first()
    )


def register_data_principal(submitted) -> dict:
    """Create an account from the signup form.

    Order matters here. The basis is stated, the age is evaluated before anything
    is written, and the optional purposes are recorded as their own consent events
    rather than being folded into account creation.
    """
    assert_lawful_basis("account_management")

    email = (submitted.get("email") or "").strip()
    full_name = (submitted.get("full_name") or "").strip()
    phone = (submitted.get("phone") or "").strip()
    dob = (submitted.get("dob") or "").strip()
    raw_secret = submitted.get("password") or ""

    if not email or "@" not in email:
        return {"ok": False, "reason": "A contact address is required."}
    if not full_name:
        return {"ok": False, "reason": "A name is required."}
    if len(raw_secret) < MINIMUM_SECRET_LENGTH:
        return {
            "ok": False,
            "reason": f"The passphrase must be at least {MINIMUM_SECRET_LENGTH} characters.",
        }
    if not submitted.get("notice_acknowledged"):
        return {
            "ok": False,
            "reason": "The privacy notice has to be acknowledged before an account is created.",
        }
    if not dob:
        return {"ok": False, "reason": "A date of birth is required to establish age."}

    minor_flag = is_minor(dob)

    session = open_session()
    try:
        if find_principal_by_login(session, email) is not None:
            return {"ok": False, "reason": "An account already exists for that address."}

        principal = DataPrincipal(
            email=email,
            email_digest=lookup_digest(email),
            full_name=full_name,
            phone=phone,
            dob=dob,
            password_hash=hash_password(raw_secret),
            is_minor=minor_flag,
            marketing_suppressed=False,
            created_at=now_utc(),
            retain_until=retain_until_for("account_management"),
        )
        session.add(principal)
        session.commit()
        new_id = principal.id

        for purpose_key in OPTIONAL_PURPOSE_KEYS:
            record_consent(
                session,
                new_id,
                purpose_key,
                submitted.get(purpose_key) is not None,
                channel="signup",
            )
        session.commit()
    finally:
        session.close()

    guardian_contact = (submitted.get("guardian_contact") or "").strip()
    if minor_flag and guardian_contact:
        record_parental_consent(
            new_id, guardian_contact, (submitted.get("guardian_label") or "").strip()
        )

    logger.info(
        "account created id=%s minor=%s notice_version=%s",
        new_id,
        minor_flag,
        POLICY_VERSION,
    )
    return {
        "ok": True,
        "principal_id": new_id,
        "minor": minor_flag,
        "needs_guardian": bool(minor_flag and not guardian_contact),
    }


def sign_in_principal(submitted) -> dict:
    """Check a submitted credential against the stored derivation."""
    assert_lawful_basis("account_management")
    submitted_email = (submitted.get("email") or "").strip()
    raw_secret = submitted.get("password") or ""

    session = open_session()
    try:
        principal = find_principal_by_login(session, submitted_email)
        if principal is None or not verify_password(raw_secret, principal.password_hash):
            logger.info("sign in refused: no matching account or credential")
            return {"ok": False, "reason": "Those details do not match an account."}
        return {
            "ok": True,
            "principal_id": principal.id,
            "minor": bool(principal.is_minor),
            "role": role_for_digest(principal.email_digest),
        }
    finally:
        session.close()


def store_kyc_record(principal_id: int, submitted) -> dict:
    """Store seller verification documents under the legal obligation basis.

    Only the last four digits of the Aadhaar number are kept. The full number is
    never written to a column, which is the minimisation the Act asks for on an
    identifier that cannot be reissued.
    """
    assert_lawful_basis("kyc_verification")

    pan_number = (submitted.get("pan_number") or "").strip().upper()
    aadhaar_last_four = (submitted.get("aadhaar_last_four") or "").strip()[-4:]
    address_line = (submitted.get("address_line") or "").strip()
    pincode = (submitted.get("pincode") or "").strip()

    if len(pan_number) != 10:
        return {"ok": False, "reason": "A permanent account number is ten characters."}
    if len(aadhaar_last_four) != 4 or not aadhaar_last_four.isdigit():
        return {"ok": False, "reason": "Enter the last four digits only."}

    session = open_session()
    try:
        row = KycVerification(
            principal_id=principal_id,
            pan_number=pan_number,
            aadhaar_last_four=aadhaar_last_four,
            address_line=address_line,
            pincode=pincode,
            verification_status="submitted",
            retain_until=retain_until_for("kyc_verification"),
        )
        session.add(row)
        session.commit()
        new_id = row.id
    finally:
        session.close()

    logger.info("kyc record stored id=%s status=%s", new_id, "submitted")
    return {"ok": True, "record_id": new_id}
