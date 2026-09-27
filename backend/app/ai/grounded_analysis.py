"""Grounded RAG pipeline.

Takes a verdict the rules engine already decided, retrieves the statutory
provisions behind it, and asks Gemini to explain and cite. The model is never
asked whether something is compliant. That question is already answered before
this module runs, which is what makes the output auditable.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import gateway, guardrail, retrieval
from app.contracts import (
    AnalysisContext,
    GroundedExplanation,
    RetrievedProvision,
    RuleVerdict,
)

logger = logging.getLogger(__name__)

SYSTEM_INSTRUCTION = """You are a DPDP Act 2023 compliance analyst.

A deterministic rules engine has already decided the compliance verdict. Your job
is to explain that verdict in plain English, cite the statutory provision behind
it, and suggest a fix. You do not decide compliance.

Hard constraints:
- Cite ONLY provisions that appear in the PROVISIONS block you are given.
- citation_text must be a SINGLE CONTIGUOUS SPAN copied character for character
  out of ONE provision's text field, no longer than 40 words. Do not join
  fragments from two places, do not stitch around an ellipsis, do not tidy the
  wording. An automated check compares your quote against the provision and
  flags the finding when it does not match.
- cited_section_ids must repeat the section_id values exactly as they appear in
  the PROVISIONS block, for example "s.8(5)" or "rule_6".
- Never invent a section number, a rule number, or a quotation.
- If the provisions given do not support a claim, say so in the description
  rather than reaching for a provision you were not shown.
- Write for a developer who has to fix the code, not for a lawyer.
- Do not use em dashes.

Return a single JSON object with exactly these keys:
  title              short finding title, under 80 characters
  description        2 to 4 sentences: what is wrong, why it matters under DPDP
  citation           for example "DPDP Act 2023, Section 8(5); DPDP Rules 2025, Rule 6"
  citation_text      verbatim quote from the cited provision
  cited_section_ids  array of the section_id values you used, e.g. ["s.8(5)","rule_6"]
  suggested_fix      concrete code-level change, a snippet where possible
  data_flow_summary  one sentence tracing the personal data involved
  confidence         float 0.0 to 1.0 in how well the provisions support this
"""


# A checker that enumerates every offending flow can produce a detail string
# thousands of characters long. Sending all of it crowds out the provisions and
# drives the model's reasoning past the output cap without adding signal.
MAX_DETAIL_CHARS = 600
MAX_EVIDENCE_CHARS = 1200


def _clip(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()} ... (truncated)"


def _build_prompt(
    verdict: RuleVerdict,
    context: AnalysisContext,
    provisions: list[RetrievedProvision],
) -> str:
    failed = verdict.failed_checks
    checks_block = (
        "\n".join(
            f"  - FAILED: {c.name}: {_clip(c.detail, MAX_DETAIL_CHARS)}"
            + (f" ({c.file_path}:{c.line_number})" if c.file_path else "")
            for c in failed
        )
        or "  (no individual check details recorded)"
    )

    provisions_block = (
        "\n\n".join(
            f"[section_id: {p.section_id}]\n"
            f"citation_label: {p.citation_label}\n"
            f"title: {p.section_title}\n"
            f"text: {p.text}"
            for p in provisions
        )
        or "(none retrieved)"
    )

    return f"""VERDICT ALREADY DECIDED BY THE RULES ENGINE, do not change it:
  rule: {verdict.rule_id} {verdict.rule_name}
  status: {verdict.status}
  evidence: {_clip(verdict.evidence, MAX_EVIDENCE_CHARS)}
  statutory basis recorded by the engine: {verdict.dpdp_section}; {verdict.dpdp_rule}

FAILED CHECKS:
{checks_block}

CONTEXT FROM THE CODEBASE OR PAGE:
{context.render()}

PROVISIONS (the only text you may cite or quote):
{provisions_block}

Explain this verdict as JSON."""


def _retrieval_query(verdict: RuleVerdict, context: AnalysisContext) -> str:
    failed_names = ", ".join(c.name for c in verdict.failed_checks[:5])
    pii = ", ".join(sorted({f.pii_category for f in context.pii_flows}))
    parts = [verdict.rule_name, verdict.evidence]
    if failed_names:
        parts.append(failed_names)
    if pii:
        parts.append(f"personal data categories: {pii}")
    return " | ".join(p for p in parts if p)


def _fallback(verdict: RuleVerdict, reason: str) -> GroundedExplanation:
    """Deterministic explanation used when AI is off or unusable.

    The tool stays useful without Gemini: the verdict and evidence are already
    deterministic, so only the prose is degraded.
    """
    return GroundedExplanation(
        title=f"{verdict.rule_name}: {verdict.status}",
        description=verdict.evidence,
        citation=f"{verdict.dpdp_section}; {verdict.dpdp_rule}",
        citation_text="",
        cited_section_ids=[],
        suggested_fix="",
        data_flow_summary="",
        confidence=0.0,
        guardrail_passed=False,
        guardrail_notes=reason,
    )


async def explain_verdict(
    db: AsyncSession,
    verdict: RuleVerdict,
    context: AnalysisContext,
    *,
    restrict_section_ids: list[str] | None = None,
) -> GroundedExplanation:
    query = _retrieval_query(verdict, context)
    provisions = await retrieval.retrieve_provisions(
        db, query, restrict_section_ids=restrict_section_ids
    )

    if not provisions:
        return _fallback(
            verdict, "No statutory provisions retrieved; corpus may not be indexed."
        )

    try:
        raw = await gateway.generate_text(
            _build_prompt(verdict, context, provisions),
            system_instruction=SYSTEM_INSTRUCTION,
        )
    except gateway.AIUnavailableError as exc:
        return _fallback(verdict, str(exc))
    except gateway.AIResponseTruncatedError as exc:
        logger.warning("Gemini response truncated for %s: %s", verdict.rule_id, exc)
        return _fallback(verdict, f"Explanation was cut short: {exc}")
    except Exception as exc:  # noqa: BLE001 - a failed AI call must not fail the scan
        logger.exception("Gemini generation failed for %s", verdict.rule_id)
        return _fallback(verdict, f"AI call failed: {exc}")

    payload = gateway.parse_json_response(raw)
    if not isinstance(payload, dict):
        # Record what came back. "not valid JSON" on its own sends whoever
        # debugs this looking at the parser rather than at the response.
        snippet = (raw or "").strip()[:200] or "(empty response)"
        logger.warning(
            "Unparseable response for %s (%d chars): %r", verdict.rule_id, len(raw or ""), snippet
        )
        return _fallback(
            verdict, f"AI response was not valid JSON. Response began: {snippet}"
        )

    cited_ids = payload.get("cited_section_ids") or []
    if isinstance(cited_ids, str):
        cited_ids = [cited_ids]

    try:
        confidence = float(payload.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5

    explanation = GroundedExplanation(
        title=str(payload.get("title") or f"{verdict.rule_name}: {verdict.status}"),
        description=str(payload.get("description") or verdict.evidence),
        citation=str(payload.get("citation") or ""),
        citation_text=str(payload.get("citation_text") or ""),
        cited_section_ids=[str(s) for s in cited_ids],
        suggested_fix=str(payload.get("suggested_fix") or ""),
        data_flow_summary=str(payload.get("data_flow_summary") or ""),
        confidence=max(0.0, min(1.0, confidence)),
    )

    return guardrail.apply(explanation, provisions)
