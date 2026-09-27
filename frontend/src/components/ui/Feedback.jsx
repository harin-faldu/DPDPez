// Shared loading, empty and error states plus the score bar.
import { AlertCircle, Inbox } from 'lucide-react'
import { cx } from '../../lib/format.js'
import Card from './Card.jsx'

export function Skeleton({ className = '' }) {
  return (
    <div
      className={cx('animate-pulse rounded bg-slate-200 dark:bg-slate-800', className)}
      aria-hidden="true"
    />
  )
}

/** Indeterminate bar for work whose remaining time the server does not report. */
export function IndeterminateBar({ className = '' }) {
  return (
    <div
      className={cx(
        'relative h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800',
        className,
      )}
      role="progressbar"
      aria-label="Scan in progress"
    >
      <div className="animate-indeterminate absolute inset-y-0 left-0 w-1/3 rounded-full bg-indigo-500" />
    </div>
  )
}

export function ScoreBar({ percent, barClass = 'bg-slate-400', label }) {
  const width = percent === null || percent === undefined ? 0 : percent
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800"
      role="img"
      aria-label={label || `Score ${width} of 100`}
    >
      <div
        className={cx('h-full rounded-full transition-[width] duration-500', barClass)}
        style={{ width: `${width}%` }}
      />
    </div>
  )
}

export function EmptyState({ title, description, icon: Icon = Inbox, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <Icon size={28} className="text-slate-300 dark:text-slate-600" aria-hidden="true" />
      <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{title}</p>
      {description ? (
        <p className="max-w-sm text-xs text-slate-500 dark:text-slate-400">{description}</p>
      ) : null}
      {action}
    </div>
  )
}

export function ErrorPanel({ title = 'Something went wrong', message, action }) {
  return (
    <Card className="border-red-200 dark:border-red-900/70">
      <div className="flex items-start gap-3 p-4 sm:p-5">
        <AlertCircle
          size={18}
          className="mt-0.5 shrink-0 text-red-600 dark:text-red-400"
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-red-700 dark:text-red-300">{title}</p>
          {message ? (
            <p className="mt-1 text-sm break-words text-slate-600 dark:text-slate-300">{message}</p>
          ) : null}
          {action ? <div className="mt-3">{action}</div> : null}
        </div>
      </div>
    </Card>
  )
}
