// DataFlowGraph. OWNER: Manan
// Visual chain: source through transforms to sink.
// A horizontal chain of nodes reads better than a force-directed graph at demo
// size. The PII category badges the chain, and the hops that lack a consent
// check or encryption are flagged on the node they belong to.
import {
  ArrowDown,
  ArrowRight,
  Building2,
  Database,
  KeyRound,
  Lock,
  LockOpen,
  ShieldAlert,
  Timer,
  Wand2,
} from 'lucide-react'
import Badge from './ui/Badge.jsx'
import { cx } from '../lib/format.js'

function Node({ icon: Icon, kind, label, warnings = [], tone = 'default' }) {
  const toneClass =
    tone === 'danger'
      ? 'border-red-300 bg-red-50 dark:border-red-900 dark:bg-red-950/40'
      : tone === 'warning'
        ? 'border-amber-300 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/40'
        : 'border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900'

  return (
    <div
      className={cx(
        'flex w-full min-w-[170px] flex-col gap-1.5 rounded-lg border px-3 py-2.5 shadow-sm md:w-[190px]',
        toneClass,
      )}
    >
      <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        <Icon size={12} aria-hidden="true" />
        {kind}
      </span>
      <span className="text-xs leading-snug font-medium break-words text-slate-800 dark:text-slate-100">
        {label || 'Not recorded'}
      </span>
      {warnings.length ? (
        <span className="flex flex-wrap gap-1 pt-0.5">
          {warnings.map((warning) => (
            <Badge key={warning.label} tone={warning.tone} size="xs" icon={warning.icon}>
              {warning.label}
            </Badge>
          ))}
        </span>
      ) : null}
    </div>
  )
}

function Connector() {
  return (
    <div
      className="flex shrink-0 items-center justify-center py-1 text-slate-300 md:py-0 dark:text-slate-600"
      aria-hidden="true"
    >
      <ArrowDown size={18} className="md:hidden" />
      <ArrowRight size={18} className="hidden md:block" />
    </div>
  )
}

export default function DataFlowGraph({ flow }) {
  if (!flow) return null

  const transforms = Array.isArray(flow.transforms) ? flow.transforms.filter(Boolean) : []

  const sourceWarnings = []
  if (!flow.has_consent_check) {
    sourceWarnings.push({ label: 'No consent check', tone: 'danger', icon: ShieldAlert })
  }

  const sinkWarnings = []
  if (!flow.has_encryption) {
    sinkWarnings.push({ label: 'Not encrypted', tone: 'danger', icon: LockOpen })
  }
  if (!flow.has_retention_policy) {
    sinkWarnings.push({ label: 'No retention limit', tone: 'warning', icon: Timer })
  }
  if (flow.crosses_third_party) {
    sinkWarnings.push({ label: 'Third party', tone: 'warning', icon: Building2 })
  }

  const riskCount = sourceWarnings.length + sinkWarnings.length
  const headerTone = !flow.has_consent_check || !flow.has_encryption ? 'danger' : riskCount ? 'warning' : 'success'

  return (
    <div className="rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-2.5 dark:border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="accent" size="sm" icon={KeyRound}>
            {flow.pii_category || 'Unclassified personal data'}
          </Badge>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {transforms.length} transform{transforms.length === 1 ? '' : 's'} between collection and storage
          </span>
        </div>
        <Badge tone={headerTone} size="sm" icon={headerTone === 'success' ? Lock : ShieldAlert}>
          {riskCount === 0
            ? 'All safeguards present'
            : `${riskCount} safeguard${riskCount === 1 ? '' : 's'} missing`}
        </Badge>
      </div>

      <div className="overflow-x-auto px-4 py-4">
        <div className="flex flex-col items-stretch md:w-max md:flex-row md:items-center md:gap-2">
          <Node
            icon={Wand2}
            kind="Source"
            label={flow.source_description}
            warnings={sourceWarnings}
            tone={sourceWarnings.length ? 'danger' : 'default'}
          />

          {transforms.length === 0 ? (
            <>
              <Connector />
              <Node icon={Wand2} kind="Transform" label="Passed through unchanged" />
            </>
          ) : (
            transforms.map((transform, index) => (
              <div
                key={`${transform}-${index}`}
                className="flex flex-col items-stretch md:flex-row md:items-center md:gap-2"
              >
                <Connector />
                <Node icon={Wand2} kind={`Transform ${index + 1}`} label={transform} />
              </div>
            ))
          )}

          <Connector />
          <Node
            icon={Database}
            kind="Sink"
            label={flow.sink_description}
            warnings={sinkWarnings}
            tone={sinkWarnings.some((warning) => warning.tone === 'danger') ? 'danger' : sinkWarnings.length ? 'warning' : 'default'}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-2 border-t border-slate-200 px-4 py-2.5 text-xs dark:border-slate-800">
        <Flag label="Consent check" present={Boolean(flow.has_consent_check)} />
        <Flag label="Encryption at rest" present={Boolean(flow.has_encryption)} />
        <Flag label="Retention policy" present={Boolean(flow.has_retention_policy)} />
        <Flag label="Stays in house" present={!flow.crosses_third_party} />
      </div>
    </div>
  )
}

function Flag({ label, present }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={cx('size-2 rounded-full', present ? 'bg-emerald-500' : 'bg-red-500')}
        aria-hidden="true"
      />
      <span className={present ? 'text-slate-600 dark:text-slate-300' : 'font-medium text-red-600 dark:text-red-400'}>
        {label}: {present ? 'yes' : 'no'}
      </span>
    </span>
  )
}
