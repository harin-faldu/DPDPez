"""Scorecard and report endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import (
    Finding,
    PIIField,
    PIIFlowPath,
    PolicyCheck,
    PolicyClaimRecord,
    RuleResult,
    Scan,
)
from app.models.enums import RuleStatus
from app.scorecard import aggregate, report, scorer

router = APIRouter(prefix="/scans", tags=["scorecard"])

# A failed PolicyCheck carries no rule weight of its own to derive a severity
# from, the way a RuleVerdict does. These are the requirements a missing notice
# clause bears most directly on a bright-line prohibition or a principal's
# ability to act on a right at all, so a gap here is rated high rather than the
# medium default every other notice gap gets.
_HIGH_SEVERITY_POLICY_REQUIREMENTS = frozenset(
    {
        "notice.children",
        "notice.breach_intimation",
        "notice.security_measures",
        "notice.cross_border",
        "notice.withdraw_consent",
    }
)


def _policy_gap_severity(requirement_id: str) -> str:
    return "high" if requirement_id in _HIGH_SEVERITY_POLICY_REQUIREMENTS else "medium"

# The full set. Whether a rule lands in "rules" or in "not_assessed" depends on
# what the scan could actually reach.
ALL_RULES = (
    ("R3", "Notice"),
    ("R4", "Consent"),
    ("R5", "Children's Data"),
    ("R6", "Security Safeguards"),
    ("R7", "Breach Notification"),
    ("R8", "Data Protection Impact Assessment"),
    ("R9", "Significant Data Fiduciary Obligations"),
    ("R10", "Data Principal Rights"),
    ("R11", "Data Protection Board Readiness"),
    ("R12", "Compliance Verification"),
    ("RET", "Retention and Erasure"),
    ("CERTIN", "CERT-In Directions"),
    ("XBORDER", "Cross-Border Transfer"),
)


@router.get("/{scan_id}/scorecard")
async def get_scorecard(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> dict:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    results = (
        (await db.execute(select(RuleResult).where(RuleResult.scan_id == scan_id)))
        .scalars()
        .all()
    )
    by_id = {r.rule_id: r for r in results}

    # Rules the scan could not reach are reported separately rather than listed
    # alongside the graded ones. They already carry no weight in the score, and
    # showing them in the same list invited them to be read as failures: a web
    # crawl cannot see a breach register, and an axis pinned at zero for that
    # reason looks identical to one pinned at zero for non-compliance.
    rules = []
    not_assessed = []
    for rule_id, default_name in ALL_RULES:
        r = by_id.get(rule_id)
        if r is None:
            not_assessed.append(
                {
                    "rule_id": rule_id,
                    "rule_name": default_name,
                    "reason": "Not evaluated for this scan type.",
                    "dpdp_section": None,
                    "dpdp_rule": None,
                }
            )
            continue
        if r.status == RuleStatus.NOT_APPLICABLE:
            not_assessed.append(
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "reason": r.evidence or "Not assessable from this scan.",
                    "dpdp_section": r.dpdp_section,
                    "dpdp_rule": r.dpdp_rule,
                }
            )
            continue
        rules.append(
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "status": r.status,
                "score": r.score,
                "weight": r.weight,
                "evidence": r.evidence,
                "dpdp_section": r.dpdp_section,
                "dpdp_rule": r.dpdp_rule,
                "checks_passed": r.checks_passed,
                "checks_total": r.checks_total,
            }
        )

    severity_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        )
    ).all()
    counts = {sev: n for sev, n in severity_rows}

    pii_count = (
        await db.execute(
            select(func.count(PIIField.id)).where(PIIField.scan_id == scan_id)
        )
    ).scalar_one()
    flow_count = (
        await db.execute(
            select(func.count(PIIFlowPath.id)).where(PIIFlowPath.scan_id == scan_id)
        )
    ).scalar_one()
    unverified = (
        await db.execute(
            select(func.count(Finding.id)).where(
                Finding.scan_id == scan_id, Finding.guardrail_passed.is_(False)
            )
        )
    ).scalar_one()

    return {
        "scan_id": str(scan.id),
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "overall_score": scan.overall_score,
        "overall_grade": scan.overall_grade,
        # A withheld grade must stay withheld all the way to the client.
        # Defaulting a null score to 0 here would publish "Non-Compliant" for a
        # target nobody was able to inspect.
        "grade_label": (
            scorer.grade_for(scan.overall_score)[1]
            if scan.overall_grade is not None
            else scorer.NOT_ASSESSED_LABEL
        ),
        "assessed": scan.overall_grade is not None,
        "rules": rules,
        "not_assessed": not_assessed,
        "summary": {
            "total_findings": sum(counts.values()),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "pii_fields_detected": pii_count,
            "data_flow_paths_traced": flow_count,
            "unverified_citations": unverified,
        },
    }


@router.get("/aggregate")
async def get_aggregate_report(
    policy_scan_id: uuid.UUID | None = None,
    web_scan_id: uuid.UUID | None = None,
    code_scan_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Stage 4: one report from whichever of stages 1-3 already ran.

    Every id is optional and independent: a caller can ask for just a code
    scan's aggregate view, or all three. Nothing is re-scanned or re-graded
    here, only combined. See app.scorecard.aggregate for how a rule assessed
    by both the web and code scan is resolved.
    """
    if policy_scan_id is None and web_scan_id is None and code_scan_id is None:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one of policy_scan_id, web_scan_id, code_scan_id",
        )

    sources: dict[str, dict] = {}
    web_rules = None
    code_rules = None

    for label, scan_id in (("policy", policy_scan_id), ("web", web_scan_id), ("code", code_scan_id)):
        if scan_id is None:
            continue
        scan = await db.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail=f"{label} scan not found")
        sources[label] = {
            "scan_id": str(scan.id),
            "target": scan.target,
            "status": scan.status,
            "overall_score": scan.overall_score,
            "overall_grade": scan.overall_grade,
        }

    if web_scan_id is not None:
        web_rules = (
            (await db.execute(select(RuleResult).where(RuleResult.scan_id == web_scan_id)))
            .scalars()
            .all()
        )
    if code_scan_id is not None:
        code_rules = (
            (await db.execute(select(RuleResult).where(RuleResult.scan_id == code_scan_id)))
            .scalars()
            .all()
        )

    aggregated = aggregate.build_aggregate(web_rules=web_rules, code_rules=code_rules)

    policy_section = None
    if policy_scan_id is not None:
        checks = (
            (await db.execute(select(PolicyCheck).where(PolicyCheck.scan_id == policy_scan_id)))
            .scalars()
            .all()
        )
        claims = (
            (
                await db.execute(
                    select(PolicyClaimRecord).where(PolicyClaimRecord.scan_id == policy_scan_id)
                )
            )
            .scalars()
            .all()
        )
        policy_section = {
            "satisfied_checks": sum(1 for c in checks if c.satisfied and not c.unassessed),
            "failed_checks": sum(1 for c in checks if not c.satisfied and not c.unassessed),
            "unassessed_checks": sum(1 for c in checks if c.unassessed),
            # A failed check is a gap the notice itself admits to, not just a
            # count: the same requirement text, evidence and citation a rule
            # checker's finding would carry, so a reader sees why it failed
            # without cross-referencing the checklist against a rulebook.
            "gap_findings": [
                {
                    "requirement_id": c.requirement_id,
                    "title": c.title,
                    "severity": _policy_gap_severity(c.requirement_id),
                    "dpdp_section": c.dpdp_section,
                    "dpdp_rule": c.dpdp_rule,
                    "evidence": c.evidence,
                    "quote": c.quote,
                    "source_url": c.source_url,
                    "requires_human_validation": c.requires_human_validation,
                }
                for c in checks
                if not c.satisfied and not c.unassessed
            ],
            "claims": [
                {
                    "claim_type": c.claim_type,
                    "subject": c.subject,
                    "value": c.value,
                    "quote": c.quote,
                    "source_url": c.source_url,
                    "verified_by": c.verified_by,
                    "verification": c.verification,
                    "verification_detail": c.verification_detail,
                }
                for c in claims
            ],
            "contradicted_claims": sum(1 for c in claims if c.verification == "contradicted"),
        }

    return {
        "sources": sources,
        "stages_included": aggregated.stages_included + (["policy"] if policy_scan_id else []),
        "overall_score": aggregated.overall_score,
        "overall_grade": aggregated.overall_grade,
        "grade_label": aggregated.grade_label,
        "assessed": aggregated.overall_grade is not None,
        "rules": [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "score": r.score,
                "status": r.status,
                "dpdp_section": r.dpdp_section,
                "dpdp_rule": r.dpdp_rule,
                "web_score": r.web_score,
                "code_score": r.code_score,
                "sources": r.sources,
                "evidence": r.evidence,
            }
            for r in aggregated.rules
        ],
        "not_assessed": [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "reason": r.reason,
                "dpdp_section": r.dpdp_section,
                "dpdp_rule": r.dpdp_rule,
            }
            for r in aggregated.not_assessed
        ],
        "policy": policy_section,
    }


@router.get("/{scan_id}/report/pdf")
async def get_pdf_report(
    scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        pdf = await report.render_pdf(db, scan_id)
    except report.PDFUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    filename = f"dpdp-compliance-{scan_id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
