"""The audit trail over personal data, and the export that proves compliance.

Section 8(1) puts the burden of demonstrating compliance on the Data Fiduciary,
so reads are recorded as well as writes. Every entry carries the purpose the
access was made under, because "who looked at this" is only half of an answer
that has to satisfy the Board.

Entries never contain the personal data itself, only a reference to the row, so
the trail is not a second copy of the thing it is protecting.
"""

import csv
import io
import logging

from models import AuditLogEntry, ExportedReport, now_utc, open_session

logger = logging.getLogger("bharat_bazaar.audit")

READ = "read"
WRITE = "write"
ERASE = "erase"
EXPORT = "export"


def record_data_access(
    session,
    actor_id: int | None,
    action: str,
    object_ref: str,
    purpose_key: str,
) -> AuditLogEntry:
    """Append one entry. Callers pass a row reference, never a stored value."""
    entry = AuditLogEntry(
        actor_principal_id=actor_id,
        action=action,
        object_ref=object_ref,
        purpose=purpose_key,
        occurred_at=now_utc(),
    )
    session.add(entry)
    return entry


def record_access_now(
    actor_id: int | None, action: str, object_ref: str, purpose_key: str
) -> None:
    """Same as record_data_access, on its own short lived session."""
    session = open_session()
    try:
        record_data_access(session, actor_id, action, object_ref, purpose_key)
        session.commit()
    finally:
        session.close()


def audit_entries_for(session, actor_id: int, limit_rows: int = 200):
    """The trail for one account, newest first."""
    return (
        session.query(AuditLogEntry)
        .filter(AuditLogEntry.actor_principal_id == actor_id)
        .order_by(AuditLogEntry.occurred_at.desc())
        .limit(limit_rows)
        .all()
    )


def generate_compliance_report(requested_by: str | None = None) -> str:
    """Produce the evidence pack a reviewer or the Board would ask for.

    Counts and timestamps only. The report says how many rows were read under
    which purpose, never what any of them said.
    """
    session = open_session()
    try:
        rows = (
            session.query(AuditLogEntry)
            .order_by(AuditLogEntry.occurred_at.desc())
            .limit(5000)
            .all()
        )
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["occurred_at", "action", "object_ref", "purpose"])
        for row in rows:
            writer.writerow(
                [row.occurred_at, row.action, row.object_ref, row.purpose]
            )
        report = ExportedReport(
            report_key="audit_trail_extract",
            purpose="compliance_evidence",
            requested_by_email=requested_by,
            row_count=len(rows),
            storage_path="in_memory_only",
        )
        session.add(report)
        session.commit()
        logger.info("compliance evidence produced over %d trail row(s)", len(rows))
        return buffer.getvalue()
    finally:
        session.close()
