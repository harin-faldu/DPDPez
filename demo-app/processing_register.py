"""The register of processing activities, kept in code next to the schema.

Written here rather than in a spreadsheet for one reason: a spreadsheet drifts
from the schema within a sprint. This module imports the same purpose register
the notice renders and the same tables the sweep covers, so an activity cannot be
added to the product without turning up in the register.

Two functions are the entry points:
  records_of_processing_activities   the full register, one row per activity
  high_risk_processing_activities    the subset a reviewer has to look at first
"""

from purposes import PURPOSE_REGISTER, purpose_label
from retention_policy import COVERED_TABLES, retention_period_days

REGISTER_OWNER = "Privacy Engineering, Bharat Bazaar Retail Private Limited"
REGISTER_REVIEWED_ON = "2026-09-01"

# Activity key, the kinds of personal data it touches, where those rows live, who
# outside the platform sees them.
ACTIVITY_DATA_KINDS: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "account_management": (
        ("contact address", "telephone number", "date of birth", "credential digest"),
        ("data_principals",),
        (),
    ),
    "order_fulfilment": (
        ("delivery address", "order history"),
        ("orders",),
        ("courier partner, address only, contract in place",),
    ),
    "kyc_verification": (
        ("permanent account number", "last four digits of the Aadhaar number", "postal address"),
        ("kyc_verifications",),
        ("payout bank, verification outcome only",),
    ),
    "customer_support": (
        ("contact address", "grievance correspondence"),
        ("grievance_tickets", "consent_records", "guardian_verifications"),
        (),
    ),
    "analytics": (
        ("page views", "pseudonymous account reference"),
        ("analytics_rollup",),
        (),
    ),
    "marketing": (
        ("contact address",),
        ("mail_outbox",),
        (),
    ),
}

# Activities that are large scale, involve a national identifier, or involve a
# category the Act treats as needing extra care. Recorded so a reviewer can see
# what the platform itself believes its exposure is.
HIGH_RISK_ACTIVITY_KEYS: tuple[str, ...] = (
    "kyc_verification",
    "account_management",
)

HIGH_RISK_REASONS: dict[str, str] = {
    "kyc_verification": (
        "Holds a permanent account number and part of an Aadhaar number for every "
        "verified seller, at a volume that grows with the seller base."
    ),
    "account_management": (
        "Holds a date of birth for every account, which is what determines whether "
        "a record falls inside the children regime."
    ),
}


def records_of_processing_activities() -> list[dict]:
    """The register. One row per purpose, matched to the tables that hold it.

    This is the record of processing activities for the platform: what is
    processed, why, on what basis, for how long, who receives it and how it is
    protected.
    """
    covered = {table.__tablename__ for table, _purpose in COVERED_TABLES}
    register: list[dict] = []
    for key, _label, basis, days, text in PURPOSE_REGISTER:
        kinds, tables, recipients = ACTIVITY_DATA_KINDS.get(key, ((), (), ()))
        register.append(
            {
                "activity": key,
                "shown_as": purpose_label(key),
                "why": text,
                "basis": basis,
                "data_kinds": list(kinds),
                "stored_in": list(tables),
                "recipients": list(recipients),
                "keep_for_days": days,
                "retention_enforced": all(table in covered for table in tables) if tables else False,
                "safeguards": [
                    "personal data columns encrypted at rest with a per column cipher",
                    "credentials derived with a slow key derivation function",
                    "authenticated access only, with every read written to the audit trail",
                ],
            }
        )
    return register


def high_risk_processing_activities() -> list[dict]:
    """The activities the platform itself rates as high risk, with the reason."""
    return [
        {
            "activity": key,
            "shown_as": purpose_label(key),
            "why_high_risk": HIGH_RISK_REASONS.get(key, "not stated"),
            "keep_for_days": retention_period_days(key),
        }
        for key in HIGH_RISK_ACTIVITY_KEYS
    ]


def register_coverage_gaps() -> list[str]:
    """Activities whose tables are not all inside the retention sweep.

    Reported rather than suppressed. The sweep covers the operational tables and
    not the two stores listed in KNOWN_GAPS.md, and this is where that shows up.
    """
    covered = {table.__tablename__ for table, _purpose in COVERED_TABLES}
    gaps: list[str] = []
    for row in records_of_processing_activities():
        for table in row["stored_in"]:
            if table not in covered:
                gaps.append(f"{row['activity']}: {table} has no retention sweep")
    if "exported_reports" not in covered:
        gaps.append("compliance_evidence: exported_reports has no retention clock")
    if "audit_log" not in covered:
        gaps.append("audit_trail: audit_log is kept beyond the purpose periods")
    return gaps
