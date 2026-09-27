"""PDF report generation.

Compliance officers want something they can file and forward, not a URL. The
report renders the same data the dashboard shows, including the guardrail state
per finding: presenting an unverified citation as settled law would be worse
than shipping no report at all.
"""

import uuid
from datetime import UTC, datetime

from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, PIIFlowPath, RuleResult, Scan

_TEMPLATE = Template(
    """<!doctype html>
<html><head><meta charset="utf-8"><style>
  @page { size: A4; margin: 18mm 15mm; }
  body { font-family: "DejaVu Sans", Helvetica, Arial, sans-serif; font-size: 10pt;
         color: #1a1a1a; }
  h1 { font-size: 20pt; margin: 0 0 2mm; }
  h2 { font-size: 13pt; margin: 8mm 0 3mm; border-bottom: 1px solid #ccc;
       padding-bottom: 1mm; }
  .meta { color: #555; font-size: 9pt; margin-bottom: 6mm; }
  .grade { font-size: 40pt; font-weight: bold; line-height: 1; }
  .grade-A, .grade-B { color: #157f3d; }
  .grade-C { color: #a86b00; }
  .grade-D, .grade-F { color: #b3261e; }
  .grade-NA { color: #777; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 4mm; }
  th, td { text-align: left; padding: 2mm; border-bottom: 1px solid #e5e5e5;
           vertical-align: top; }
  th { background: #f5f5f5; font-size: 9pt; }
  .status-compliant { color: #157f3d; font-weight: 600; }
  .status-gap { color: #a86b00; font-weight: 600; }
  .status-violation { color: #b3261e; font-weight: 600; }
  .status-not_applicable { color: #777; }
  .finding { border-left: 3px solid #ddd; padding: 2mm 0 2mm 3mm; margin-bottom: 4mm;
             page-break-inside: avoid; }
  .sev-critical { border-left-color: #b3261e; }
  .sev-high { border-left-color: #d9730d; }
  .sev-medium { border-left-color: #a86b00; }
  .sev-low { border-left-color: #888; }
  .cite { background: #f7f7f7; padding: 2mm; font-size: 9pt; margin: 2mm 0; }
  .unverified { background: #fff4e5; border: 1px solid #d9730d; color: #8a4b00;
                padding: 1.5mm; font-size: 8.5pt; margin: 2mm 0; }
  code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt; }
  .loc { color: #555; font-size: 9pt; }
</style></head><body>

<h1>DPDP Compliance Report</h1>
<div class="meta">
  Target: {{ scan.target }}<br>
  Scan type: {{ scan.scan_type }}<br>
  Generated: {{ generated_at }}
</div>

{% if scan.overall_grade %}
<div class="grade grade-{{ scan.overall_grade }}">{{ scan.overall_grade }}</div>
<div class="meta">{{ scan.overall_score }} / 100</div>
{% else %}
<div class="grade grade-NA">&mdash;</div>
<div class="unverified">
  No grade was issued. Nothing in this target could be assessed, so reporting a
  score would state a conclusion about a system that was never inspected.
  {% if scan.error_message %}<br>Reason: {{ scan.error_message }}{% endif %}
</div>
{% endif %}

<h2>Rule Breakdown</h2>
<table>
  <tr><th>Rule</th><th>Status</th><th>Checks</th><th>Provision</th><th>Evidence</th></tr>
  {% for r in rules %}
  <tr>
    <td>{{ r.rule_id }} {{ r.rule_name }}</td>
    <td class="status-{{ r.status }}">{{ r.status }}</td>
    <td>{{ r.checks_passed }}/{{ r.checks_total }}</td>
    <td>{{ r.dpdp_section or '' }}{% if r.dpdp_rule %}; {{ r.dpdp_rule }}{% endif %}</td>
    <td>{{ r.evidence or '' }}</td>
  </tr>
  {% endfor %}
</table>

<h2>Findings ({{ findings|length }})</h2>
{% for f in findings %}
<div class="finding sev-{{ f.severity }}">
  <strong>[{{ f.severity|upper }}] {{ f.title }}</strong>
  {% if f.file_path %}
  <div class="loc">{{ f.file_path }}{% if f.line_number %}:{{ f.line_number }}{% endif %}</div>
  {% endif %}
  <p>{{ f.description or '' }}</p>
  {% if not f.guardrail_passed %}
  <div class="unverified">
    Unverified citation. This explanation did not pass the faithfulness check and
    requires manual review before it is relied upon.
    {% if f.guardrail_notes %}<br>Reason: {{ f.guardrail_notes }}{% endif %}
  </div>
  {% endif %}
  {% if f.citation %}
  <div class="cite">
    <strong>{{ f.citation }}</strong>
    {% if f.citation_text %}<br>"{{ f.citation_text }}"{% endif %}
  </div>
  {% endif %}
  {% if f.data_flow_context %}<div class="loc">Data flow: {{ f.data_flow_context }}</div>{% endif %}
  {% if f.suggested_fix %}<p><code>{{ f.suggested_fix }}</code></p>{% endif %}
</div>
{% else %}
<p>No findings recorded.</p>
{% endfor %}

{% if flows %}
<h2>Personal Data Flows</h2>
<table>
  <tr><th>Category</th><th>Source</th><th>Sink</th><th>Consent</th><th>Encrypted</th><th>Retention</th></tr>
  {% for p in flows %}
  <tr>
    <td>{{ p.pii_category }}</td>
    <td>{{ p.source_description }}</td>
    <td>{{ p.sink_description }}</td>
    <td>{{ 'yes' if p.has_consent_check else 'no' }}</td>
    <td>{{ 'yes' if p.has_encryption else 'no' }}</td>
    <td>{{ 'yes' if p.has_retention_policy else 'no' }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<h2>How to read this report</h2>
<p>
  Compliance verdicts are produced by a deterministic rules engine from concrete
  checks against the scanned target. Explanations and statutory citations are
  generated separately and verified against the text of the DPDP Act 2023 and the
  DPDP Rules 2025 before inclusion. Any explanation that failed that verification
  is marked above as an unverified citation.
</p>
<p>
  This report is an automated self-check. It is not legal advice and does not by
  itself establish compliance or non-compliance.
</p>

</body></html>"""
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class PDFUnavailableError(RuntimeError):
    pass


async def render_pdf(db: AsyncSession, scan_id: uuid.UUID) -> bytes:
    # WeasyPrint needs cairo and pango at runtime. They ship in the backend
    # image but are not present on a bare Windows host, so the import is kept
    # local and the failure is reported rather than crashing the process.
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:
        raise PDFUnavailableError(
            "PDF rendering needs the cairo and pango libraries. They are "
            "installed in the backend container; run the API under Docker to "
            "export a report."
        ) from exc

    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")

    rules = (
        (await db.execute(select(RuleResult).where(RuleResult.scan_id == scan_id)))
        .scalars()
        .all()
    )
    findings = (
        (await db.execute(select(Finding).where(Finding.scan_id == scan_id)))
        .scalars()
        .all()
    )
    flows = (
        (await db.execute(select(PIIFlowPath).where(PIIFlowPath.scan_id == scan_id)))
        .scalars()
        .all()
    )

    html = _TEMPLATE.render(
        scan=scan,
        rules=sorted(rules, key=lambda r: r.rule_id),
        findings=sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)),
        flows=flows,
        generated_at=datetime.now(UTC).strftime("%d %B %Y, %H:%M UTC"),
    )
    return HTML(string=html).write_pdf()
