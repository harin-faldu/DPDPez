"""Findings and data-flow endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Finding, PIIField, PIIFlowPath, Scan

router = APIRouter(prefix="/scans", tags=["findings"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def _require_scan(db: AsyncSession, scan_id: uuid.UUID) -> Scan:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings")
async def list_findings(
    scan_id: uuid.UUID,
    severity: str | None = None,
    rule_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    await _require_scan(db, scan_id)

    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)

    findings = (await db.execute(stmt)).scalars().all()
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    return [
        {
            "id": str(f.id),
            "rule_id": f.rule_id,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "code_snippet": f.code_snippet,
            "title": f.title,
            "description": f.description,
            "citation": f.citation,
            "citation_text": f.citation_text,
            "cited_section_ids": f.cited_section_ids,
            "data_flow_context": f.data_flow_context,
            "suggested_fix": f.suggested_fix,
            "ai_generated": f.ai_generated,
            "ai_confidence": f.ai_confidence,
            # The UI marks unverified findings. Omitting this would present an
            # ungrounded citation as settled law.
            "guardrail_passed": f.guardrail_passed,
            "guardrail_notes": f.guardrail_notes,
        }
        for f in findings
    ]


@router.get("/{scan_id}/data-flows")
async def list_data_flows(
    scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> list[dict]:
    await _require_scan(db, scan_id)
    stmt = select(PIIFlowPath).where(PIIFlowPath.scan_id == scan_id)
    paths = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(p.id),
            "pii_category": p.pii_category,
            "source_description": p.source_description,
            "transforms": p.transforms or [],
            "sink_description": p.sink_description,
            "has_consent_check": p.has_consent_check,
            "has_encryption": p.has_encryption,
            "has_retention_policy": p.has_retention_policy,
            "crosses_third_party": p.crosses_third_party,
        }
        for p in paths
    ]


@router.get("/{scan_id}/pii-fields")
async def list_pii_fields(
    scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> list[dict]:
    await _require_scan(db, scan_id)
    stmt = select(PIIField).where(PIIField.scan_id == scan_id)
    fields = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(f.id),
            "field_name": f.field_name,
            "pii_category": f.pii_category,
            "sensitivity": f.sensitivity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "location_kind": f.location_kind,
            "context": f.context,
        }
        for f in fields
    ]
