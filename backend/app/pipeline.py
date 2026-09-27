"""Scan pipeline.

Wires the four modules together in the order that keeps verdicts auditable:

    scanner  ->  context engine  ->  rules engine  ->  grounded RAG  ->  scorecard
    evidence     data flow map      deterministic     explanation       grade
                                    verdict           and citation

The AI step sits after the verdict is already decided and never feeds back into
it. Everything before the AI step runs without an API key.
"""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import grounded_analysis
from app.context import assembler, pii_flow
from app.context.code_graph import CodeGraph
from app.contracts import (
    AnalysisContext,
    CertInEvidence,
    PolicyClaim,
    CodeScanResult,
    PIIFlowPathInfo,
    PolicyScanResult,
    RuleVerdict,
    WebScanResult,
)
from app.models import (
    DataFlowEdge,
    Finding,
    PIIField,
    PIIFlowPath,
    PolicyCheck,
    PolicyClaimRecord,
    RuleResult,
    Scan,
    ScanStatus,
)
from app.models.enums import RuleStatus
from app.policy import analyzer as policy_analyzer
from app.policy import code_verification as policy_code_verification
from app.policy import verification as policy_verification
from app.policy import scanner as policy_scanner
from app.rules import engine as rules_engine
from app.scanner import certin_scanner, code_scanner, web_scanner
from app.scorecard import scorer

logger = logging.getLogger(__name__)


async def run_policy_scan(
    db: AsyncSession,
    scan_id: uuid.UUID,
    url: str,
    policy_urls: list[str] | None = None,
) -> None:
    """Stage 1: read what the organisation publishes and record it.

    No rule verdicts and no grade. Grading the policy stage on its own would
    mean deciding how a satisfied notice offsets an unassessed one before the
    aggregation that combines all three stages exists, and a number published
    now is a number the aggregate would have to contradict later.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None:
        logger.error("Scan %s disappeared before it could run", scan_id)
        return

    try:
        await _set_status(db, scan, ScanStatus.SCANNING)
        result = await policy_scanner.scan_policies(url, policy_urls=policy_urls)
        scan.pages_crawled = len(result.documents)

        await _persist_policy_evidence(db, scan, result)

        scan.status = ScanStatus.COMPLETE
        scan.completed_at = datetime.now(UTC)
        if result.crawl_note:
            scan.error_message = result.crawl_note[:2000]
        await db.commit()

    except Exception as exc:  # noqa: BLE001 - the scan row must record the failure
        logger.exception("Policy scan %s failed", scan_id)
        await _fail(db, scan, str(exc))


async def _persist_policy_evidence(
    db: AsyncSession, scan: Scan, result: PolicyScanResult
) -> None:
    for check in result.checks:
        db.add(
            PolicyCheck(
                scan_id=scan.id,
                requirement_id=check.requirement_id,
                title=check.title,
                dpdp_section=check.dpdp_section,
                dpdp_rule=check.dpdp_rule,
                satisfied=check.satisfied,
                unassessed=policy_analyzer.is_unassessed(check),
                evidence=check.evidence,
                quote=check.quote,
                source_url=check.source_url,
                requires_human_validation=check.requires_human_validation,
                confidence=check.confidence,
            )
        )

    for claim in result.claims:
        db.add(
            PolicyClaimRecord(
                scan_id=scan.id,
                claim_type=claim.claim_type,
                subject=claim.subject[:200],
                value=claim.value[:300] if claim.value else None,
                quote=claim.quote,
                source_url=claim.source_url,
                confidence=claim.confidence,
                # Left null on purpose. A later stage fills these in, and null
                # says nobody has looked rather than looked and found nothing.
                verified_by=claim.verified_by,
                verification=claim.verification,
                verification_detail=claim.verification_detail,
            )
        )

    await db.commit()


async def run_web_scan(
    db: AsyncSession,
    scan_id: uuid.UUID,
    url: str,
    policy_scan_id: uuid.UUID | None = None,
) -> None:
    """Stage 2. Observe the site, and test what stage 1 read against it.

    policy_scan_id points at a completed policy scan of the same target. Given
    one, every claim it recorded is tested against what the page actually did,
    and the verdict is written back onto that scan's claims. A notice promising
    no third party sharing, on a page that loaded trackers before anyone
    consented, becomes a contradiction that neither stage could reach alone.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None:
        logger.error("Scan %s disappeared before it could run", scan_id)
        return

    try:
        await _set_status(db, scan, ScanStatus.SCANNING)
        web_result = await web_scanner.scan_url(url)
        scan.pages_crawled = len(web_result.pages)

        verdicts = rules_engine.run_all(web_result=web_result)
        await _persist_web_evidence(db, scan, web_result)
        if policy_scan_id is not None:
            await _verify_policy_claims(db, policy_scan_id, web_result)
        await _finish(db, scan, verdicts, web_result=web_result)

    except Exception as exc:  # noqa: BLE001 - the scan row must record the failure
        logger.exception("Web scan %s failed", scan_id)
        await _fail(db, scan, str(exc))


async def _verify_policy_claims(
    db: AsyncSession, policy_scan_id: uuid.UUID, web_result: WebScanResult
) -> None:
    """Write this stage's verdict onto the claims stage 1 recorded.

    Written back onto the policy scan rather than copied onto this one, so there
    is a single record of what the organisation asserted and what each stage
    found, rather than a fork that has to be reconciled later.
    """
    rows = (
        await db.execute(
            select(PolicyClaimRecord).where(
                PolicyClaimRecord.scan_id == policy_scan_id
            )
        )
    ).scalars().all()
    if not rows:
        logger.info("Policy scan %s recorded no claims to verify", policy_scan_id)
        return

    claims = [
        PolicyClaim(
            claim_type=row.claim_type,
            subject=row.subject,
            value=row.value,
            quote=row.quote,
            source_url=row.source_url,
            confidence=row.confidence,
        )
        for row in rows
    ]
    for row, verified in zip(
        rows, policy_verification.verify_against_web(claims, web_result), strict=True
    ):
        row.verified_by = verified.verified_by
        row.verification = verified.verification
        row.verification_detail = verified.verification_detail

    await db.commit()
    contradicted = sum(
        1 for row in rows if row.verification == policy_verification.CONTRADICTED
    )
    logger.info(
        "Verified %d policy claim(s) against the web scan, %d contradicted",
        len(rows),
        contradicted,
    )


async def _verify_policy_claims_against_code(
    db: AsyncSession,
    policy_scan_id: uuid.UUID,
    code_result: CodeScanResult,
    certin_evidence: CertInEvidence,
) -> None:
    """Stage 3's pass over the same claim rows stage 2 already touched.

    Reads each claim's current verdict so a claim stage 2 already resolved is
    left untouched, and writes back only the ones code evidence could add to.
    """
    rows = (
        await db.execute(
            select(PolicyClaimRecord).where(
                PolicyClaimRecord.scan_id == policy_scan_id
            )
        )
    ).scalars().all()
    if not rows:
        logger.info("Policy scan %s recorded no claims to verify", policy_scan_id)
        return

    claims = [
        PolicyClaim(
            claim_type=row.claim_type,
            subject=row.subject,
            value=row.value,
            quote=row.quote,
            source_url=row.source_url,
            confidence=row.confidence,
            verified_by=row.verified_by,
            verification=row.verification,
            verification_detail=row.verification_detail,
        )
        for row in rows
    ]
    resolved = policy_code_verification.verify_against_code(
        claims, code_result, certin=certin_evidence
    )
    for row, verified in zip(rows, resolved, strict=True):
        row.verified_by = verified.verified_by
        row.verification = verified.verification
        row.verification_detail = verified.verification_detail

    await db.commit()
    from_code = sum(
        1 for row in rows if row.verified_by == policy_code_verification.CODE
    )
    logger.info(
        "Verified %d policy claim(s) against the code scan, %d resolved from code evidence",
        len(rows),
        from_code,
    )


async def run_code_scan(
    db: AsyncSession,
    scan_id: uuid.UUID,
    root_path: str,
    policy_scan_id: uuid.UUID | None = None,
) -> None:
    """Stage 3. Read the implementation, and resolve what stage 2 could not see.

    policy_scan_id points at a completed policy scan of the same target. Given
    one, every claim still not_observable after stage 2 (or never tested at
    all) is tried again against the code: retention against schema expiry,
    breach reporting against alert wiring, cross-border transfer against
    configured storage regions, a named recipient reached only server side, a
    rights route behind a sign in, and encryption of data at rest. A claim
    stage 2 already settled is left exactly as stage 2 left it.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None:
        logger.error("Scan %s disappeared before it could run", scan_id)
        return

    try:
        await _set_status(db, scan, ScanStatus.SCANNING)
        code_result = await code_scanner.scan_directory(root_path)
        scan.files_scanned = len(code_result.files)

        graph = CodeGraph(code_result)
        flows = pii_flow.trace_flows(code_result, graph)
        certin_evidence = certin_scanner.scan_directory(root_path)

        verdicts = rules_engine.run_all(
            code_result=code_result, flows=flows, certin_evidence=certin_evidence
        )
        await _persist_code_evidence(db, scan, code_result, flows)
        if policy_scan_id is not None:
            await _verify_policy_claims_against_code(
                db, policy_scan_id, code_result, certin_evidence
            )
        await _finish(
            db, scan, verdicts, code_result=code_result, graph=graph, flows=flows
        )

    except Exception as exc:  # noqa: BLE001 - the scan row must record the failure
        logger.exception("Code scan %s failed", scan_id)
        await _fail(db, scan, str(exc))


async def _finish(
    db: AsyncSession,
    scan: Scan,
    verdicts: list[RuleVerdict],
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    graph: CodeGraph | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> None:
    for verdict in verdicts:
        db.add(
            RuleResult(
                scan_id=scan.id,
                rule_id=verdict.rule_id,
                rule_name=verdict.rule_name,
                status=verdict.status,
                score=verdict.score,
                weight=scorer.RULE_WEIGHTS.get(verdict.rule_id, 0.0),
                evidence=verdict.evidence,
                checks_passed=verdict.checks_passed,
                checks_total=len(verdict.checks),
                dpdp_section=verdict.dpdp_section,
                dpdp_rule=verdict.dpdp_rule,
            )
        )
    await db.commit()

    await _set_status(db, scan, ScanStatus.ANALYZING)

    for verdict in verdicts:
        if verdict.status in (RuleStatus.COMPLIANT, RuleStatus.NOT_APPLICABLE):
            continue
        context = assembler.assemble_for_verdict(
            verdict,
            scan_result=code_result,
            graph=graph,
            flows=flows,
            web_result=web_result,
        )
        await _create_finding(db, scan, verdict, context)

    await db.commit()

    card = scorer.compute(verdicts)
    scan.overall_score = card.overall_score
    scan.overall_grade = card.overall_grade
    scan.status = ScanStatus.COMPLETE
    scan.completed_at = datetime.now(UTC)
    await db.commit()


async def _create_finding(
    db: AsyncSession, scan: Scan, verdict: RuleVerdict, context: AnalysisContext
) -> None:
    restrict = _retrieval_ids_for(verdict.rule_id)
    explanation = await grounded_analysis.explain_verdict(
        db, verdict, context, restrict_section_ids=restrict
    )

    failed = verdict.failed_checks
    first = failed[0] if failed else None

    db.add(
        Finding(
            scan_id=scan.id,
            rule_id=verdict.rule_id,
            severity=scorer.severity_for(verdict),
            file_path=first.file_path if first else None,
            line_number=first.line_number if first else None,
            code_snippet=context.code_snippet,
            title=explanation.title,
            description=explanation.description,
            citation=explanation.citation,
            citation_text=explanation.citation_text,
            cited_section_ids=", ".join(explanation.cited_section_ids) or None,
            data_flow_context=explanation.data_flow_summary or None,
            suggested_fix=explanation.suggested_fix or None,
            ai_generated=explanation.confidence > 0.0,
            ai_confidence=explanation.confidence,
            guardrail_passed=explanation.guardrail_passed,
            guardrail_notes=explanation.guardrail_notes,
        )
    )


def _retrieval_ids_for(rule_id: str) -> list[str] | None:
    """Pin RAG retrieval to the sections a rule is about.

    Each checker declares RETRIEVAL_SECTION_IDS. Reading it here rather than in
    the AI layer keeps the legal mapping in one place, next to the rule.
    """
    for checker in rules_engine.RULE_CHECKERS:
        if getattr(checker, "RULE_ID", None) == rule_id:
            ids = getattr(checker, "RETRIEVAL_SECTION_IDS", None)
            return list(ids) if ids else None
    return None


async def _persist_web_evidence(
    db: AsyncSession, scan: Scan, result: WebScanResult
) -> None:
    for form in result.forms:
        for f in form.fields:
            from app.pii import field_classifier

            ref = field_classifier.build_field_ref(
                f.name, location_kind="form_input", context=form.action
            )
            if ref is None:
                continue
            db.add(
                PIIField(
                    scan_id=scan.id,
                    field_name=ref.field_name,
                    pii_category=ref.pii_category,
                    sensitivity=ref.sensitivity,
                    location_kind="form_input",
                    context=f"form action {form.action}",
                )
            )
    await db.commit()


async def _persist_code_evidence(
    db: AsyncSession,
    scan: Scan,
    result: CodeScanResult,
    flows: list[PIIFlowPathInfo],
) -> None:
    for ref in result.pii_fields:
        db.add(
            PIIField(
                scan_id=scan.id,
                file_path=ref.file_path,
                line_number=ref.line_number,
                field_name=ref.field_name,
                pii_category=ref.pii_category,
                sensitivity=ref.sensitivity,
                location_kind=ref.location_kind,
                context=ref.context,
            )
        )

    for edge in result.data_flow_edges:
        db.add(
            DataFlowEdge(
                scan_id=scan.id,
                source_file=edge.source_file,
                source_line=edge.source_line,
                source_symbol=edge.source_symbol,
                sink_file=edge.sink_file,
                sink_line=edge.sink_line,
                sink_symbol=edge.sink_symbol,
                edge_type=edge.edge_type,
                pii_categories=edge.pii_categories or None,
            )
        )

    for flow in flows:
        db.add(
            PIIFlowPath(
                scan_id=scan.id,
                pii_category=flow.pii_category,
                source_description=flow.source_description,
                transforms=flow.transforms or None,
                sink_description=flow.sink_description,
                has_consent_check=flow.has_consent_check,
                has_encryption=flow.has_encryption,
                has_retention_policy=flow.has_retention_policy,
                crosses_third_party=flow.crosses_third_party,
            )
        )

    await db.commit()


async def _set_status(db: AsyncSession, scan: Scan, status: str) -> None:
    scan.status = status
    await db.commit()


async def _fail(db: AsyncSession, scan: Scan, message: str) -> None:
    scan.status = ScanStatus.FAILED
    scan.error_message = message[:2000]
    scan.completed_at = datetime.now(UTC)
    await db.commit()
