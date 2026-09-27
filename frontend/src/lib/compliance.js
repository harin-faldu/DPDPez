// Shared vocabulary for DPDP verdicts: rule status, severity, grades and the
// short axis labels used by the radar chart. Colour is driven by status, never
// by score, so a low scoring rule that is genuinely not applicable never reads
// as a failure.
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Info,
  MinusCircle,
  XCircle,
} from 'lucide-react'

export const RULE_STATUS_META = {
  compliant: {
    key: 'compliant',
    label: 'Compliant',
    tone: 'success',
    icon: CheckCircle2,
    bar: 'bg-emerald-500',
    edge: 'border-l-emerald-500',
    chart: { light: '#059669', dark: '#34d399' },
  },
  gap: {
    key: 'gap',
    label: 'Gap',
    tone: 'warning',
    icon: AlertTriangle,
    bar: 'bg-amber-500',
    edge: 'border-l-amber-500',
    chart: { light: '#d97706', dark: '#fbbf24' },
  },
  violation: {
    key: 'violation',
    label: 'Violation',
    tone: 'danger',
    icon: XCircle,
    bar: 'bg-red-500',
    edge: 'border-l-red-500',
    chart: { light: '#dc2626', dark: '#f87171' },
  },
  not_applicable: {
    key: 'not_applicable',
    label: 'Not applicable',
    tone: 'neutral',
    icon: MinusCircle,
    bar: 'bg-slate-400 dark:bg-slate-600',
    edge: 'border-l-slate-300 dark:border-l-slate-700',
    chart: { light: '#94a3b8', dark: '#64748b' },
  },
}

const UNKNOWN_RULE_STATUS = {
  key: 'unknown',
  label: 'Unknown',
  tone: 'neutral',
  icon: CircleDashed,
  bar: 'bg-slate-400 dark:bg-slate-600',
  edge: 'border-l-slate-300 dark:border-l-slate-700',
  chart: { light: '#94a3b8', dark: '#64748b' },
}

export function ruleStatusMeta(status) {
  return RULE_STATUS_META[status] || UNKNOWN_RULE_STATUS
}

export const SEVERITY_META = {
  critical: {
    key: 'critical',
    label: 'Critical',
    order: 0,
    tone: 'danger',
    icon: AlertOctagon,
    dot: 'bg-red-600',
    edge: 'border-l-red-600',
  },
  high: {
    key: 'high',
    label: 'High',
    order: 1,
    tone: 'orange',
    icon: AlertTriangle,
    dot: 'bg-orange-500',
    edge: 'border-l-orange-500',
  },
  medium: {
    key: 'medium',
    label: 'Medium',
    order: 2,
    tone: 'warning',
    icon: AlertTriangle,
    dot: 'bg-amber-500',
    edge: 'border-l-amber-500',
  },
  low: {
    key: 'low',
    label: 'Low',
    order: 3,
    tone: 'info',
    icon: Info,
    dot: 'bg-sky-500',
    edge: 'border-l-sky-500',
  },
  info: {
    key: 'info',
    label: 'Info',
    order: 4,
    tone: 'neutral',
    icon: Info,
    dot: 'bg-slate-400',
    edge: 'border-l-slate-400',
  },
}

const UNKNOWN_SEVERITY = {
  key: 'unknown',
  label: 'Unrated',
  order: 5,
  tone: 'neutral',
  icon: CircleDashed,
  dot: 'bg-slate-400',
  edge: 'border-l-slate-400',
}

export function severityMeta(severity) {
  return SEVERITY_META[severity] || UNKNOWN_SEVERITY
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export function gradeMeta(grade) {
  const letter = String(grade || '').trim().toUpperCase().charAt(0)
  switch (letter) {
    case 'A':
      return {
        letter,
        text: 'text-emerald-600 dark:text-emerald-400',
        ring: 'border-emerald-300 dark:border-emerald-800',
        wash: 'bg-emerald-50 dark:bg-emerald-950/40',
        tone: 'success',
      }
    case 'B':
      return {
        letter,
        text: 'text-teal-600 dark:text-teal-400',
        ring: 'border-teal-300 dark:border-teal-800',
        wash: 'bg-teal-50 dark:bg-teal-950/40',
        tone: 'success',
      }
    case 'C':
      return {
        letter,
        text: 'text-amber-600 dark:text-amber-400',
        ring: 'border-amber-300 dark:border-amber-800',
        wash: 'bg-amber-50 dark:bg-amber-950/40',
        tone: 'warning',
      }
    case 'D':
      return {
        letter,
        text: 'text-orange-600 dark:text-orange-400',
        ring: 'border-orange-300 dark:border-orange-800',
        wash: 'bg-orange-50 dark:bg-orange-950/40',
        tone: 'orange',
      }
    case 'E':
    case 'F':
      return {
        letter,
        text: 'text-red-600 dark:text-red-400',
        ring: 'border-red-300 dark:border-red-800',
        wash: 'bg-red-50 dark:bg-red-950/40',
        tone: 'danger',
      }
    default:
      // No grade. The backend withholds one when nothing could be assessed,
      // for example a crawl that was turned away. Render it as absent rather
      // than as a bad grade, because "we could not look" and "this failed" are
      // different claims and only one of them is true.
      return {
        letter: letter || 'n/a',
        notAssessed: !letter,
        text: 'text-slate-600 dark:text-slate-300',
        ring: 'border-slate-300 dark:border-slate-700',
        wash: 'bg-slate-50 dark:bg-slate-900',
        tone: 'neutral',
      }
  }
}

// Short axis labels for the radar chart. Only rule ids the rules engine
// actually emits are mapped here; anything else falls back to its own id so the
// chart never shows an invented rule name.
const RULE_AXIS_LABELS = {
  R3: 'Notice',
  R4: 'Consent',
  R5: 'Children',
  R6: 'Security',
  R7: 'Breach',
  R8: 'DPIA',
  R9: 'SDF',
  R10: 'Rights',
  R11: 'Board',
  R12: 'Verification',
  RET: 'Retention',
  CERTIN: 'CERT-In',
  XBORDER: 'Cross-border',
}

export function ruleAxisLabel(rule) {
  if (!rule) return ''
  const mapped = RULE_AXIS_LABELS[rule.rule_id]
  if (mapped) return mapped
  if (rule.rule_name && rule.rule_name.length <= 14) return rule.rule_name
  return rule.rule_id || rule.rule_name || ''
}

// Scan progress stages in the order the backend moves through them.
export const SCAN_STAGES = [
  { key: 'pending', label: 'Queued', blurb: 'Scan accepted and waiting for a worker' },
  { key: 'scanning', label: 'Collecting evidence', blurb: 'Crawling pages or parsing the archive' },
  { key: 'analyzing', label: 'Evaluating rules', blurb: 'Running rule checks and grounding citations' },
  { key: 'complete', label: 'Scorecard ready', blurb: 'Grade, rules and findings available' },
]

export function stageIndex(status) {
  const index = SCAN_STAGES.findIndex((stage) => stage.key === status)
  return index === -1 ? 0 : index
}

export const TERMINAL_STATUSES = ['complete', 'failed']

// A claim's verdict, once a later stage has tested it against what the site or
// the code actually does. Colour follows the same rule as everywhere else:
// "could not tell" is a distinct, neutral state, never a soft failure.
export const CLAIM_VERIFICATION_META = {
  supported: {
    key: 'supported',
    label: 'Supported',
    tone: 'success',
    icon: CheckCircle2,
  },
  contradicted: {
    key: 'contradicted',
    label: 'Contradicted',
    tone: 'danger',
    icon: XCircle,
  },
  not_observable: {
    key: 'not_observable',
    label: 'Not observable',
    tone: 'neutral',
    icon: MinusCircle,
  },
}

const UNVERIFIED_CLAIM = {
  key: 'unverified',
  label: 'Not yet tested',
  tone: 'neutral',
  icon: CircleDashed,
}

export function claimVerificationMeta(verification) {
  return CLAIM_VERIFICATION_META[verification] || UNVERIFIED_CLAIM
}

// The four-stage pipeline, in the order it runs. A flow run steps through
// these in order; an independent run picks exactly one.
export const PIPELINE_STAGES = [
  {
    key: 'policy',
    label: 'Policy',
    blurb: 'Read what the organisation publishes about itself',
  },
  {
    key: 'web',
    label: 'Website',
    blurb: "Observe the live site and test the policy's claims against it",
  },
  {
    key: 'code',
    label: 'Code',
    blurb: 'Read the implementation and resolve what the web scan could not see',
  },
  {
    key: 'aggregate',
    label: 'Aggregate',
    blurb: 'Combine all three into one scorecard',
  },
]
