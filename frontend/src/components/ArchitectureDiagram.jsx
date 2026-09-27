// ArchitectureDiagram. A static SVG of the pipeline, for the landing page.
// Deliberately plain shapes and text rather than a diagramming library: this
// is read once by a person, not re-laid-out at runtime, and a library would be
// one more third-party request the rest of this project goes out of its way
// to avoid.
const TONE = {
  slate: { box: 'fill-white dark:fill-slate-900 stroke-slate-300 dark:stroke-slate-700', text: 'fill-slate-800 dark:fill-slate-200', sub: 'fill-slate-500 dark:fill-slate-400' },
  indigo: { box: 'fill-indigo-50 dark:fill-indigo-950/40 stroke-indigo-300 dark:stroke-indigo-800', text: 'fill-indigo-900 dark:fill-indigo-200', sub: 'fill-indigo-600 dark:fill-indigo-400' },
  amber: { box: 'fill-amber-50 dark:fill-amber-950/30 stroke-amber-300 dark:stroke-amber-800', text: 'fill-amber-900 dark:fill-amber-200', sub: 'fill-amber-700 dark:fill-amber-400' },
  emerald: { box: 'fill-emerald-50 dark:fill-emerald-950/30 stroke-emerald-300 dark:stroke-emerald-800', text: 'fill-emerald-900 dark:fill-emerald-200', sub: 'fill-emerald-600 dark:fill-emerald-400' },
  violet: { box: 'fill-violet-50 dark:fill-violet-950/30 stroke-violet-300 dark:stroke-violet-800', text: 'fill-violet-900 dark:fill-violet-200', sub: 'fill-violet-600 dark:fill-violet-400' },
}

function Box({ x, y, w, h, title, sub, tone = 'slate', mono = false }) {
  const t = TONE[tone]
  const lines = Array.isArray(sub) ? sub : sub ? [sub] : []
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={10} className={t.box} strokeWidth={1.5} />
      <text
        x={x + w / 2}
        y={y + (lines.length ? 24 : h / 2 + 5)}
        textAnchor="middle"
        className={t.text}
        style={{ fontSize: 13, fontWeight: 700, fontFamily: mono ? 'ui-monospace, monospace' : undefined }}
      >
        {title}
      </text>
      {lines.map((line, i) => (
        <text
          key={i}
          x={x + w / 2}
          y={y + 42 + i * 15}
          textAnchor="middle"
          className={t.sub}
          style={{ fontSize: 10.5 }}
        >
          {line}
        </text>
      ))}
    </g>
  )
}

function Arrow({ x1, y1, x2, y2, dashed = false, label, labelAt = 0.5 }) {
  const mx = x1 + (x2 - x1) * labelAt
  const my = y1 + (y2 - y1) * labelAt
  return (
    <g>
      <line
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        className="stroke-slate-400 dark:stroke-slate-600"
        strokeWidth={1.5}
        strokeDasharray={dashed ? '4 3' : undefined}
        markerEnd="url(#arrowhead)"
      />
      {label ? (
        <text
          x={mx}
          y={my - 6}
          textAnchor="middle"
          className="fill-slate-500 dark:fill-slate-400"
          style={{ fontSize: 10 }}
        >
          {label}
        </text>
      ) : null}
    </g>
  )
}

function Cylinder({ x, y, w, h, label }) {
  const ry = 8
  return (
    <g>
      <path
        d={`M ${x} ${y + ry} a ${w / 2} ${ry} 0 1 0 ${w} 0 a ${w / 2} ${ry} 0 1 0 ${-w} 0 v ${h} a ${w / 2} ${ry} 0 1 0 ${w} 0 v ${-h}`}
        className="fill-slate-50 dark:fill-slate-800/60 stroke-slate-300 dark:stroke-slate-600"
        strokeWidth={1.5}
      />
      <text
        x={x + w / 2}
        y={y + h + ry + 5}
        textAnchor="middle"
        className="fill-slate-500 dark:fill-slate-400"
        style={{ fontSize: 10, fontWeight: 600 }}
      >
        {label}
      </text>
    </g>
  )
}

export default function ArchitectureDiagram() {
  const col1 = 40, col2 = 400, col3 = 760
  const boxW = 300

  return (
    <svg
      viewBox="0 0 1120 900"
      role="img"
      aria-label="Pipeline architecture: three scanners feed a deterministic rules engine, an aggregator, and a grounded explanation layer that produces the scorecard."
      className="w-full"
    >
      <defs>
        <marker id="arrowhead" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
          <path d="M0,0 L8,4 L0,8 z" className="fill-slate-400 dark:fill-slate-600" />
        </marker>
      </defs>

      {/* Row 1: inputs */}
      <Box x={col1} y={10} w={boxW} h={50} title="Privacy notice URL" tone="slate" />
      <Box x={col2} y={10} w={boxW} h={50} title="Live website URL" tone="slate" />
      <Box x={col3} y={10} w={boxW} h={50} title="Source archive (.zip)" tone="slate" />

      <Arrow x1={col1 + boxW / 2} y1={60} x2={col1 + boxW / 2} y2={90} />
      <Arrow x1={col2 + boxW / 2} y1={60} x2={col2 + boxW / 2} y2={90} />
      <Arrow x1={col3 + boxW / 2} y1={60} x2={col3 + boxW / 2} y2={90} />

      {/* Row 2: scanners (stage 1/2/3) */}
      <Box
        x={col1} y={90} w={boxW} h={92}
        title="Stage 1 · Policy scanner"
        sub={['Reads the published notice', '15-requirement checklist + claims']}
        tone="indigo"
      />
      <Box
        x={col2} y={90} w={boxW} h={92}
        title="Stage 2 · Web scanner (Playwright)"
        sub={['Crawl, forms, cookies, headers,', 'consent banner, network requests']}
        tone="indigo"
      />
      <Box
        x={col3} y={90} w={boxW} h={92}
        title="Stage 3 · Code + CERT-In scanners"
        sub={['AST: models, routes, PII, data flow', 'Infra: NTP, log regions, secrets, TLS']}
        tone="indigo"
      />

      {/* Claim verification chain, drawn under the scanners */}
      <Arrow x1={col1 + boxW - 10} y1={210} x2={col2 + 10} y2={210} label="claims tested against the live site" />
      <Arrow x1={col2 + boxW - 10} y1={225} x2={col3 + 10} y2={225} label="what's left is tested against the code" />

      {/* down to rules engine, from web + code only */}
      <Arrow x1={col2 + boxW / 2} y1={182} x2={col2 + boxW / 2} y2={260} />
      <Arrow x1={col3 + boxW / 2} y1={182} x2={col3 + boxW / 2} y2={260} />
      {/* policy's own checklist bypasses the rules engine */}
      <Arrow x1={col1 + boxW / 2} y1={182} x2={col1 + boxW / 2} y2={520} dashed label="checklist + claims, ungraded" />

      {/* Row 3: rules engine */}
      <Box
        x={col2 - 20} y={260} w={col3 + boxW - col2 + 40} h={80}
        title="Rules engine — 13 deterministic checkers"
        sub={['Pure functions: evidence in, verdict out. No AI, no randomness.', 'A rule assessed by both scanners keeps its weaker score.']}
        tone="violet"
      />

      <Arrow x1={col2 + 150} y1={340} x2={col2 + 150} y2={390} />
      <Arrow x1={col3 + 150} y1={340} x2={col3 + 150} y2={390} />

      {/* Row 4: grounded RAG */}
      <Box
        x={col2 - 20} y={390} w={col3 + boxW - col2 + 40} h={92}
        title="Grounded explanation (AI, explanation only)"
        sub={['Retrieval over the indexed DPDP Act + Rules 2025 corpus', 'DeepSeek / Gemini writes the explanation and cites a provision', 'Guardrail verifies every quote against the corpus before it ships']}
        tone="amber"
      />

      <Arrow x1={col2 + 150} y1={482} x2={col2 + 150} y2={520} />
      <Arrow x1={col3 + 150} y1={482} x2={col3 + 150} y2={520} />

      {/* Row 5: aggregation */}
      <Box
        x={col1} y={520} w={col3 + boxW - col1} h={80}
        title="Stage 4 · Aggregation"
        sub={['Combines whichever stages ran. Not_applicable is excluded from the grade, never scored zero.', 'Web + code rules take the lower score; the policy checklist contributes its own gap findings.']}
        tone="violet"
      />

      <Arrow x1={col1 + (col3 + boxW - col1) / 2} y1={600} x2={col1 + (col3 + boxW - col1) / 2} y2={640} />

      {/* Row 6: output */}
      <Box
        x={col2 - 60} y={640} w={480} h={70}
        title="Scorecard, findings and citations"
        sub="One graded report per stage, and one combined view across all three"
        tone="emerald"
      />

      {/* Database, set apart rather than wired through the flow so its line
          does not have to cross boxes it has nothing to do with. */}
      <Cylinder x={920} y={740} w={140} h={60} label="Postgres + pgvector" />
      <text x={990} y={825} textAnchor="middle" className="fill-slate-400 dark:fill-slate-500" style={{ fontSize: 10 }}>
        every scan's evidence, and the
      </text>
      <text x={990} y={838} textAnchor="middle" className="fill-slate-400 dark:fill-slate-500" style={{ fontSize: 10 }}>
        embedded statutory corpus
      </text>
    </svg>
  )
}
