// FindingsList. OWNER: Manan
// Sortable, filterable table of findings with citations.
// Sorted by severity by default. Every row shows the guardrail state: a finding
// whose citation failed verification carries a visible unverified marker rather
// than being quietly dropped, because catching an unsupported citation is the
// point of the check.
import { useMemo, useState } from 'react'
import {
  ArrowUpDown,
  ChevronDown,
  ChevronRight,
  FileWarning,
  Quote,
  Route,
  Search,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  X,
} from 'lucide-react'
import Card, { CardHeader, CardTitle } from './ui/Card.jsx'
import Badge, { MonoBadge } from './ui/Badge.jsx'
import { EmptyState } from './ui/Feedback.jsx'
import CodeViewer from './CodeViewer.jsx'
import { severityMeta, SEVERITY_ORDER } from '../lib/compliance.js'
import { cx, fileLabel } from '../lib/format.js'

const SORTS = [
  { key: 'severity', label: 'Severity' },
  { key: 'rule', label: 'Rule' },
  { key: 'file', label: 'File path' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'verification', label: 'Unverified first' },
]

const VERIFICATION_FILTERS = [
  { key: 'all', label: 'All citations' },
  { key: 'unverified', label: 'Unverified only' },
  { key: 'verified', label: 'Verified only' },
]

function isUnverified(finding) {
  return finding?.guardrail_passed === false
}

function confidencePercent(value) {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return null
  return Math.round(numeric <= 1 ? numeric * 100 : numeric)
}

/** Amber marker that must stay visible wherever an unverified finding appears. */
export function UnverifiedBadge({ size = 'sm' }) {
  return (
    <Badge
      tone="warning"
      size={size}
      icon={ShieldAlert}
      title="The quoted statutory text could not be matched back to the DPDP corpus"
    >
      Unverified citation
    </Badge>
  )
}

export default function FindingsList({ findings = [] }) {
  const [query, setQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState([])
  const [ruleFilter, setRuleFilter] = useState('all')
  const [verification, setVerification] = useState('all')
  const [sortKey, setSortKey] = useState('severity')
  const [expandedIds, setExpandedIds] = useState(() => new Set())

  const ruleOptions = useMemo(() => {
    const seen = new Map()
    findings.forEach((finding) => {
      if (finding?.rule_id && !seen.has(finding.rule_id)) seen.set(finding.rule_id, finding.rule_id)
    })
    return Array.from(seen.keys()).sort()
  }, [findings])

  const severityCounts = useMemo(() => {
    const counts = {}
    findings.forEach((finding) => {
      const key = finding?.severity || 'unknown'
      counts[key] = (counts[key] || 0) + 1
    })
    return counts
  }, [findings])

  const unverifiedCount = useMemo(() => findings.filter(isUnverified).length, [findings])

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const filtered = findings.filter((finding) => {
      if (severityFilter.length && !severityFilter.includes(finding?.severity)) return false
      if (ruleFilter !== 'all' && finding?.rule_id !== ruleFilter) return false
      if (verification === 'unverified' && !isUnverified(finding)) return false
      if (verification === 'verified' && isUnverified(finding)) return false
      if (!needle) return true
      const haystack = [
        finding?.title,
        finding?.description,
        finding?.file_path,
        finding?.citation,
        finding?.rule_id,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return haystack.includes(needle)
    })

    const sorted = [...filtered]
    sorted.sort((a, b) => {
      switch (sortKey) {
        case 'rule':
          return String(a?.rule_id || '').localeCompare(String(b?.rule_id || ''), undefined, {
            numeric: true,
          })
        case 'file':
          return String(a?.file_path || '').localeCompare(String(b?.file_path || ''))
        case 'confidence':
          return (confidencePercent(b?.ai_confidence) ?? -1) - (confidencePercent(a?.ai_confidence) ?? -1)
        case 'verification':
          return Number(isUnverified(b)) - Number(isUnverified(a))
        case 'severity':
        default:
          return severityMeta(a?.severity).order - severityMeta(b?.severity).order
      }
    })
    return sorted
  }, [findings, query, severityFilter, ruleFilter, verification, sortKey])

  function toggleSeverity(key) {
    setSeverityFilter((current) =>
      current.includes(key) ? current.filter((item) => item !== key) : [...current, key],
    )
  }

  function toggleRow(id) {
    setExpandedIds((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const filtersActive =
    query.trim() !== '' || severityFilter.length > 0 || ruleFilter !== 'all' || verification !== 'all'

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={FileWarning} hint={`${findings.length} recorded across all rules`}>
          Findings
        </CardTitle>
        {unverifiedCount > 0 ? (
          <button
            type="button"
            onClick={() => setVerification(verification === 'unverified' ? 'all' : 'unverified')}
            className="inline-flex items-center gap-1.5 rounded-md border border-amber-300 bg-amber-50 px-2.5 py-1 text-xs font-medium text-amber-800 hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-300 dark:hover:bg-amber-950"
          >
            <ShieldAlert size={13} aria-hidden="true" />
            {unverifiedCount} unverified citation{unverifiedCount === 1 ? '' : 's'}
          </button>
        ) : (
          <Badge tone="success" size="sm" icon={ShieldCheck}>
            All citations verified
          </Badge>
        )}
      </CardHeader>

      <div className="flex flex-col gap-3 border-b border-slate-200 px-4 py-3 sm:px-5 dark:border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[200px] flex-1">
            <Search
              size={14}
              className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-slate-400"
              aria-hidden="true"
            />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search title, description, file or citation"
              aria-label="Search findings"
              className="w-full rounded-md border border-slate-300 bg-white py-1.5 pr-3 pl-8 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-2 focus:outline-indigo-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>

          <select
            value={ruleFilter}
            onChange={(event) => setRuleFilter(event.target.value)}
            aria-label="Filter by rule"
            className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-700 focus:outline-2 focus:outline-indigo-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200"
          >
            <option value="all">All rules</option>
            {ruleOptions.map((ruleId) => (
              <option key={ruleId} value={ruleId}>
                {ruleId}
              </option>
            ))}
          </select>

          <select
            value={verification}
            onChange={(event) => setVerification(event.target.value)}
            aria-label="Filter by citation verification"
            className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-700 focus:outline-2 focus:outline-indigo-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200"
          >
            {VERIFICATION_FILTERS.map((option) => (
              <option key={option.key} value={option.key}>
                {option.label}
              </option>
            ))}
          </select>

          <label className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200">
            <ArrowUpDown size={13} className="text-slate-400" aria-hidden="true" />
            <span className="sr-only">Sort findings by</span>
            <select
              value={sortKey}
              onChange={(event) => setSortKey(event.target.value)}
              className="bg-transparent focus:outline-none"
            >
              {SORTS.map((option) => (
                <option key={option.key} value={option.key}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {SEVERITY_ORDER.filter((key) => severityCounts[key]).map((key) => {
            const meta = severityMeta(key)
            const active = severityFilter.includes(key)
            return (
              <button
                key={key}
                type="button"
                onClick={() => toggleSeverity(key)}
                aria-pressed={active}
                className={cx(
                  'inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium transition-colors',
                  active
                    ? 'border-slate-400 bg-slate-100 text-slate-900 dark:border-slate-500 dark:bg-slate-800 dark:text-slate-100'
                    : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-400 dark:hover:bg-slate-800/60',
                )}
              >
                <span className={cx('size-2 rounded-full', meta.dot)} aria-hidden="true" />
                {meta.label}
                <span className="tabular-nums opacity-70">{severityCounts[key]}</span>
              </button>
            )
          })}

          <span className="ml-auto text-xs text-slate-500 tabular-nums dark:text-slate-400">
            Showing {visible.length} of {findings.length}
          </span>
          {filtersActive ? (
            <button
              type="button"
              onClick={() => {
                setQuery('')
                setSeverityFilter([])
                setRuleFilter('all')
                setVerification('all')
              }}
              className="inline-flex items-center gap-1 text-xs font-medium text-indigo-600 hover:text-indigo-700 dark:text-indigo-400"
            >
              <X size={12} aria-hidden="true" />
              Clear
            </button>
          ) : null}
        </div>
      </div>

      {visible.length === 0 ? (
        <EmptyState
          title={findings.length === 0 ? 'No findings recorded' : 'No findings match these filters'}
          description={
            findings.length === 0
              ? 'The rule checks did not raise anything for this target.'
              : 'Widen the severity, rule or verification filter to see more.'
          }
        />
      ) : (
        <ul className="divide-y divide-slate-200 dark:divide-slate-800">
          {visible.map((finding, index) => (
            <FindingRow
              key={finding?.id ?? `${finding?.rule_id}-${index}`}
              finding={finding}
              expanded={expandedIds.has(finding?.id ?? `${finding?.rule_id}-${index}`)}
              onToggle={() => toggleRow(finding?.id ?? `${finding?.rule_id}-${index}`)}
            />
          ))}
        </ul>
      )}
    </Card>
  )
}

function FindingRow({ finding, expanded, onToggle }) {
  const meta = severityMeta(finding?.severity)
  const unverified = isUnverified(finding)
  const confidence = confidencePercent(finding?.ai_confidence)
  const location = fileLabel(finding?.file_path, finding?.line_number)

  return (
    <li className={cx('border-l-4', meta.edge)}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50 sm:px-5 dark:hover:bg-slate-800/50"
      >
        <span className="mt-0.5 shrink-0 text-slate-400">
          {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </span>

        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone={meta.tone} size="xs" uppercase>
              {meta.label}
            </Badge>
            {finding?.rule_id ? <MonoBadge>{finding.rule_id}</MonoBadge> : null}
            {unverified ? <UnverifiedBadge size="xs" /> : null}
          </span>

          <span className="mt-1.5 block text-sm font-medium text-slate-900 dark:text-slate-100">
            {finding?.title || 'Untitled finding'}
          </span>

          <span className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
            {location ? (
              <span className="font-mono break-all">{location}</span>
            ) : (
              <span className="italic">No file location</span>
            )}
            {finding?.citation ? <span>{finding.citation}</span> : null}
            {confidence !== null ? (
              <span className="tabular-nums">Confidence {confidence}%</span>
            ) : null}
          </span>
        </span>
      </button>

      {expanded ? <FindingDetail finding={finding} unverified={unverified} /> : null}
    </li>
  )
}

function FindingDetail({ finding, unverified }) {
  return (
    <div className="space-y-4 border-t border-slate-200 bg-slate-50/70 px-4 py-4 sm:px-5 dark:border-slate-800 dark:bg-slate-950/50">
      {unverified ? (
        <div className="flex items-start gap-2.5 rounded-md border border-amber-300 bg-amber-50 px-3 py-2.5 dark:border-amber-800 dark:bg-amber-950/40">
          <ShieldAlert
            size={16}
            className="mt-0.5 shrink-0 text-amber-700 dark:text-amber-400"
            aria-hidden="true"
          />
          <div className="text-xs text-amber-900 dark:text-amber-200">
            <p className="font-semibold">Unverified citation</p>
            <p className="mt-0.5 leading-relaxed">
              The quoted statutory text below could not be matched back to the indexed DPDP
              corpus, so it may not be an accurate quotation. Confirm the provision against the
              Act before relying on this finding.
            </p>
          </div>
        </div>
      ) : null}

      {finding?.description ? (
        <Section title="What was detected">
          <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-300">
            {finding.description}
          </p>
        </Section>
      ) : null}

      {finding?.code_snippet ? (
        <Section title="Evidence">
          <CodeViewer
            code={finding.code_snippet}
            filePath={finding.file_path}
            startLine={finding.line_number ? Math.max(1, Number(finding.line_number)) : 1}
            highlightLine={finding.line_number ? Number(finding.line_number) : null}
          />
          <p className="mt-1.5 text-[11px] text-slate-500 dark:text-slate-400">
            The flagged line is marked in the gutter.
          </p>
        </Section>
      ) : null}

      {finding?.citation || finding?.citation_text ? (
        <Section title="Statutory basis" icon={Quote}>
          {finding?.citation ? (
            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
              {finding.citation}
            </p>
          ) : null}
          {finding?.citation_text ? (
            <blockquote
              className={cx(
                'mt-1.5 border-l-2 pl-3 text-sm leading-relaxed text-slate-700 italic dark:text-slate-300',
                unverified
                  ? 'border-amber-400 dark:border-amber-600'
                  : 'border-slate-300 dark:border-slate-700',
              )}
            >
              {`"${finding.citation_text}"`}
            </blockquote>
          ) : null}
        </Section>
      ) : null}

      {finding?.data_flow_context ? (
        <Section title="Data flow" icon={Route}>
          <p className="rounded-md border border-slate-200 bg-white px-3 py-2 font-mono text-xs leading-relaxed break-words text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300">
            {finding.data_flow_context}
          </p>
        </Section>
      ) : null}

      {finding?.suggested_fix ? (
        <Section title="Suggested fix" icon={Wrench}>
          <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm leading-relaxed text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200">
            {finding.suggested_fix}
          </p>
        </Section>
      ) : null}
    </div>
  )
}

function Section({ title, icon: Icon, children }) {
  return (
    <div>
      <h4 className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {Icon ? <Icon size={12} aria-hidden="true" /> : null}
        {title}
      </h4>
      {children}
    </div>
  )
}
