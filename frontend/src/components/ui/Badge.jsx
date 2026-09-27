// Badge primitive. One place that owns status colour, so every panel in the
// dashboard reads the same way.
import { cx } from '../../lib/format.js'

const TONES = {
  neutral:
    'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
  success:
    'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900',
  warning:
    'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
  orange:
    'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900',
  danger:
    'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900',
  info: 'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900',
  accent:
    'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900',
  outline:
    'bg-transparent text-slate-600 border-slate-300 dark:text-slate-400 dark:border-slate-700',
}

const SIZES = {
  xs: 'text-[11px] px-1.5 py-0.5 gap-1',
  sm: 'text-xs px-2 py-0.5 gap-1',
  md: 'text-sm px-2.5 py-1 gap-1.5',
}

const ICON_SIZES = { xs: 11, sm: 12, md: 14 }

export default function Badge({
  children,
  tone = 'neutral',
  size = 'sm',
  icon: Icon,
  uppercase = false,
  className = '',
  title,
}) {
  return (
    <span
      title={title}
      className={cx(
        'inline-flex items-center rounded-md border font-medium whitespace-nowrap',
        TONES[tone] || TONES.neutral,
        SIZES[size] || SIZES.sm,
        uppercase && 'uppercase tracking-wide',
        className,
      )}
    >
      {Icon ? <Icon size={ICON_SIZES[size] || 12} className="shrink-0" aria-hidden="true" /> : null}
      {children}
    </span>
  )
}

/** Monospace chip for rule ids, sections and file paths. */
export function MonoBadge({ children, className = '', title }) {
  return (
    <span
      title={title}
      className={cx(
        'inline-flex items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] text-slate-600',
        'dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-300',
        className,
      )}
    >
      {children}
    </span>
  )
}
