// RuleStatus. OWNER: Manan
// One card per rule: name, section, status badge, score bar.
// Colour comes from the status, never from the score. A rule that is genuinely
// not applicable scores nothing and must not read as a failure. The DPDP
// section sits on the card because that is what makes a verdict checkable.
import { useState } from 'react'
import { BookMarked, ChevronDown, ChevronUp } from 'lucide-react'
import Badge, { MonoBadge } from './ui/Badge.jsx'
import { ScoreBar, Skeleton } from './ui/Feedback.jsx'
import { ruleStatusMeta } from '../lib/compliance.js'
import { cx, toPercent } from '../lib/format.js'

export default function RuleStatus({ rule }) {
  const [expanded, setExpanded] = useState(false)
  const meta = ruleStatusMeta(rule?.status)
  const applicable = rule?.status !== 'not_applicable'
  const percent = applicable ? toPercent(rule?.score) : null
  const evidence = rule?.evidence || ''
  const isLongEvidence = evidence.length > 160
  const weight = Number(rule?.weight)

  return (
    <div
      className={cx(
        'flex min-w-0 flex-col rounded-lg border border-l-4 border-slate-200 bg-white shadow-sm',
        'dark:border-slate-800 dark:bg-slate-900',
        meta.edge,
        !applicable && 'opacity-80',
      )}
    >
      <div className="flex items-start justify-between gap-3 p-4">
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {rule?.rule_id ? <MonoBadge>{rule.rule_id}</MonoBadge> : null}
            <h3 className="min-w-0 truncate text-sm font-semibold text-slate-900 dark:text-slate-100">
              {rule?.rule_name || 'Unnamed rule'}
            </h3>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
            {rule?.dpdp_section ? (
              <span className="inline-flex items-center gap-1">
                <BookMarked size={11} aria-hidden="true" />
                {rule.dpdp_section}
              </span>
            ) : null}
            {rule?.dpdp_rule ? <span>{rule.dpdp_rule}</span> : null}
            {Number.isFinite(weight) && weight > 0 ? (
              <span className="tabular-nums">
                Weight {weight <= 1 ? Math.round(weight * 100) : Math.round(weight)}%
              </span>
            ) : null}
          </div>
        </div>
        <Badge tone={meta.tone} icon={meta.icon} size="sm" className="shrink-0">
          {meta.label}
        </Badge>
      </div>

      <div className="mt-auto px-4 pb-4">
        <div className="mb-1.5 flex items-baseline justify-between gap-2 text-xs">
          <span className="text-slate-500 dark:text-slate-400">
            {applicable ? 'Rule score' : 'Not assessable from this scan'}
          </span>
          <span className="font-semibold text-slate-700 tabular-nums dark:text-slate-200">
            {percent === null ? 'n/a' : `${percent} / 100`}
          </span>
        </div>
        <ScoreBar
          percent={percent ?? 0}
          barClass={meta.bar}
          label={`${rule?.rule_name || 'Rule'} score ${percent === null ? 'not applicable' : percent}`}
        />

        <div className="mt-2.5 flex items-center justify-between gap-2 text-xs">
          <span className="text-slate-500 tabular-nums dark:text-slate-400">
            {Number.isFinite(Number(rule?.checks_total)) && Number(rule?.checks_total) > 0
              ? `${rule.checks_passed ?? 0} of ${rule.checks_total} checks passed`
              : 'No checks recorded'}
          </span>
          {isLongEvidence ? (
            <button
              type="button"
              onClick={() => setExpanded((value) => !value)}
              className="inline-flex items-center gap-1 font-medium text-indigo-600 hover:text-indigo-700 dark:text-indigo-400"
              aria-expanded={expanded}
            >
              {expanded ? 'Less' : 'Evidence'}
              {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>
          ) : null}
        </div>

        {evidence ? (
          <p
            className={cx(
              'mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-300',
              isLongEvidence && !expanded && 'line-clamp-2',
            )}
          >
            {evidence}
          </p>
        ) : null}
      </div>
    </div>
  )
}

/** Placeholder card shown while a scan is still running. */
export function RuleStatusSkeleton() {
  return (
    <div className="rounded-lg border border-l-4 border-slate-200 border-l-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:border-l-slate-800 dark:bg-slate-900">
      <div className="flex items-start justify-between gap-3">
        <div className="w-full">
          <Skeleton className="h-4 w-2/5" />
          <Skeleton className="mt-2 h-3 w-3/5" />
        </div>
        <Skeleton className="h-5 w-20 shrink-0" />
      </div>
      <Skeleton className="mt-5 h-1.5 w-full" />
      <Skeleton className="mt-3 h-3 w-1/3" />
    </div>
  )
}
