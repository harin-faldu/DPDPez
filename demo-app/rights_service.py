"""The five Data Principal rights, implemented rather than described.

  section 11     access, assemble_data_export
  section 12     correction, apply_correction
  section 12(3)  erasure, erase_account
  section 14     nomination, record_nomination
  section 13     grievance redressal, raise_grievance

Every one of these is an authenticated path, every one writes to the audit trail,
and erasure states in code exactly which stores it reaches. What it does not reach
is written up in KNOWN_GAPS.md.
"""

import logging
from datetime import timedelta

from audit_trail import ERASE, READ, WRITE, record_data_access
from consent_service import assert_lawful_basis, consent_state
from models import (
    ConsentRecord,
    DataPrincipal,
    GrievanceTicket,
    GuardianVerification,
    KycVerification,
    MailOutbox,
    Nomination,
    Order,
    now_utc,
    open_session,
)
from retention_policy import retain_until_for

logger = logging.getLogger("bharat_bazaar.rights")

GRIEVANCE_RESPONSE_DAYS = 30

# Stores erase_account walks. Anything holding a principal_id belongs in here.
LINKED_STORES: tuple[type, ...] = (
    KycVerification,
    Order,
    GrievanceTicket,
    GuardianVerification,
    Nomination,
    ConsentRecord,
)


def assemble_data_export(principal_id: int) -> dict | None:
    """Everything held about one account, in a form the account holder can read.

    Section 11 is a right to a summary of the personal data being processed and of
    the processing activities, so the export carries both the values and the
    purposes they are held under.
    """
    assert_lawful_basis("account_management")
    session = open_session()
    try:
        principal = session.get(DataPrincipal, principal_id)
        if principal is None or principal.deleted_at is not None:
            return None

        record_data_access(
            session, principal_id, READ, f"data_principals:{principal_id}", "account_management"
        )

        kyc_rows = (
            session.query(KycVerification)
            .filter(KycVerification.principal_id == principal_id)
            .all()
        )
        order_rows = session.query(Order).filter(Order.principal_id == principal_id).all()
        ticket_rows = (
            session.query(GrievanceTicket)
            .filter(GrievanceTicket.principal_id == principal_id)
            .all()
        )
        nomination_rows = (
            session.query(Nomination).filter(Nomination.principal_id == principal_id).all()
        )
        consent_rows = (
            session.query(ConsentRecord)
            .filter(ConsentRecord.principal_id == principal_id)
            .order_by(ConsentRecord.consented_at.desc())
            .all()
        )

        export = {
            "account": {
                "contact_address": principal.email,
                "known_as": principal.full_name,
                "telephone": principal.phone,
                "born_on_record": principal.dob,
                "flagged_as_child": bool(principal.is_minor),
                "opened_on": principal.created_at,
                "held_until": principal.retain_until,
            },
            "verification": [
                {
                    "permanent_account_number": row.pan_number,
                    "aadhaar_last_four": row.aadhaar_last_four,
                    "postal_address": row.address_line,
                    "pincode": row.pincode,
                    "outcome": row.verification_status,
                    "held_until": row.retain_until,
                }
                for row in kyc_rows
            ],
            "orders": [
                {
                    "sku": row.sku,
                    "deliver_to": row.delivery_address,
                    "paise": row.total_paise,
                    "held_until": row.retain_until,
                }
                for row in order_rows
            ],
            "grievances": [
                {"summary": row.summary, "status": row.status, "respond_by": row.respond_by}
                for row in ticket_rows
            ],
            "nominations": [
                {"nominated": row.nominee_name, "reach_at": row.nominee_email}
                for row in nomination_rows
            ],
            "consent_history": [
                {
                    "purpose": row.purpose,
                    "granted": bool(row.granted),
                    "at": row.consented_at,
                    "withdrawn_at": row.withdrawn_at,
                    "against_version": row.policy_version,
                }
                for row in consent_rows
            ],
            "current_choices": consent_state(session, principal_id),
        }
        session.commit()
        return export
    finally:
        session.close()


def apply_correction(principal_id: int, submitted) -> dict:
    """Section 12 correction. Only the fields the account holder may set."""
    assert_lawful_basis("account_management")
    session = open_session()
    try:
        principal = session.get(DataPrincipal, principal_id)
        if principal is None:
            return {"ok": False, "reason": "No such account."}

        changed: list[str] = []
        if submitted.get("full_name"):
            principal.full_name = submitted.get("full_name").strip()
            changed.append("full_name")
        if submitted.get("phone"):
            principal.phone = submitted.get("phone").strip()
            changed.append("phone")
        if not changed:
            return {"ok": False, "reason": "Nothing was submitted to correct."}

        record_data_access(
            session,
            principal_id,
            WRITE,
            f"data_principals:{principal_id}",
            "account_management",
        )
        session.commit()
        logger.info("correction applied to account id=%s fields=%s", principal_id, changed)
        return {"ok": True, "changed": changed}
    finally:
        session.close()


def erase_account(principal_id: int) -> dict:
    """Section 12(3) erasure.

    Walks LINKED_STORES and removes every row that carries this principal_id, then
    removes the account row itself. The analytics counters are keyed by a
    pseudonymous reference and are not reached from here, which is recorded as a
    known gap rather than claimed as compliance.
    """
    assert_lawful_basis("account_management")
    session = open_session()
    removed: dict[str, int] = {}
    try:
        principal = session.get(DataPrincipal, principal_id)
        if principal is None:
            return {"ok": False, "reason": "No such account."}

        for store in LINKED_STORES:
            rows = session.query(store).filter(store.principal_id == principal_id).all()
            for row in rows:
                session.delete(row)
            if rows:
                removed[store.__tablename__] = len(rows)

        queued = (
            session.query(MailOutbox).filter(MailOutbox.sent_at.is_(None)).all()
        )
        for row in queued:
            session.delete(row)

        record_data_access(
            session, principal_id, ERASE, f"data_principals:{principal_id}", "account_management"
        )
        session.delete(principal)
        session.commit()
        logger.info("account erased id=%s stores=%s", principal_id, sorted(removed))
        return {"ok": True, "removed": removed}
    finally:
        session.close()


def record_nomination(principal_id: int, submitted) -> dict:
    """Section 14 nomination of another individual to act on the account."""
    assert_lawful_basis("account_management")
    nominated_as = (submitted.get("nominee_label") or "").strip()
    reach_at = (submitted.get("nominee_contact") or "").strip()
    if not nominated_as:
        return {"ok": False, "reason": "A nominee has to be named."}

    session = open_session()
    try:
        row = Nomination(
            principal_id=principal_id,
            nominee_name=nominated_as,
            nominee_email=reach_at,
            relationship=(submitted.get("relationship") or "").strip(),
            retain_until=retain_until_for("account_management"),
        )
        session.add(row)
        record_data_access(
            session, principal_id, WRITE, f"nominations:{principal_id}", "account_management"
        )
        session.commit()
        return {"ok": True, "record_id": row.id}
    finally:
        session.close()


def raise_grievance(principal_id: int, submitted) -> dict:
    """Section 13 grievance intake, with the response clock set on the row."""
    assert_lawful_basis("customer_support")
    summary = (submitted.get("summary") or "").strip()
    if not summary:
        return {"ok": False, "reason": "A one line summary is required."}

    session = open_session()
    try:
        row = GrievanceTicket(
            principal_id=principal_id,
            summary=summary[:200],
            detail=(submitted.get("detail") or "").strip(),
            status="open",
            respond_by=now_utc() + timedelta(days=GRIEVANCE_RESPONSE_DAYS),
            retain_until=retain_until_for("customer_support"),
        )
        session.add(row)
        record_data_access(
            session, principal_id, WRITE, "grievance_tickets:new", "customer_support"
        )
        session.commit()
        logger.info(
            "grievance registered id=%s respond_by_days=%d",
            row.id,
            GRIEVANCE_RESPONSE_DAYS,
        )
        return {"ok": True, "record_id": row.id}
    finally:
        session.close()


def open_grievances(principal_id: int):
    session = open_session()
    try:
        return (
            session.query(GrievanceTicket)
            .filter(GrievanceTicket.principal_id == principal_id)
            .order_by(GrievanceTicket.created_at.desc())
            .all()
        )
    finally:
        session.close()
