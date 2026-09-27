// Card primitive plus the section header used across the results pages.
import { cx } from '../../lib/format.js'

export default function Card({ children, className = '', padded = false, as: Tag = 'div' }) {
  return (
    <Tag
      className={cx(
        'rounded-lg border border-slate-200 bg-white shadow-sm',
        'dark:border-slate-800 dark:bg-slate-900',
        padded && 'p-4 sm:p-5',
        className,
      )}
    >
      {children}
    </Tag>
  )
}

export function CardHeader({ children, className = '' }) {
  return (
    <div
      className={cx(
        'flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-4 py-3 sm:px-5',
        'dark:border-slate-800',
        className,
      )}
    >
      {children}
    </div>
  )
}

export function CardTitle({ children, icon: Icon, hint, className = '' }) {
  return (
    <div className={cx('min-w-0', className)}>
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
        {Icon ? (
          <Icon size={16} className="shrink-0 text-slate-400 dark:text-slate-500" aria-hidden="true" />
        ) : null}
        {children}
      </h2>
      {hint ? (
        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{hint}</p>
      ) : null}
    </div>
  )
}

export function CardBody({ children, className = '' }) {
  return <div className={cx('p-4 sm:p-5', className)}>{children}</div>
}

/** Compact label plus value block used in the scan summary strips. */
export function Stat({ label, value, tone = 'default', icon: Icon }) {
  const toneClass =
    {
      default: 'text-slate-900 dark:text-slate-100',
      danger: 'text-red-600 dark:text-red-400',
      orange: 'text-orange-600 dark:text-orange-400',
      warning: 'text-amber-600 dark:text-amber-400',
      info: 'text-sky-600 dark:text-sky-400',
      success: 'text-emerald-600 dark:text-emerald-400',
      muted: 'text-slate-500 dark:text-slate-400',
    }[tone] || 'text-slate-900 dark:text-slate-100'

  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {Icon ? <Icon size={12} aria-hidden="true" /> : null}
        <span className="truncate">{label}</span>
      </div>
      <div className={cx('mt-1 text-xl font-semibold tabular-nums', toneClass)}>{value}</div>
    </div>
  )
}
