// Button primitive. Renders a button by default, or any element via `as` so a
// router Link can reuse the same styling.
import { Loader2 } from 'lucide-react'
import { cx } from '../../lib/format.js'

const VARIANTS = {
  primary:
    'bg-indigo-600 text-white border-indigo-600 hover:bg-indigo-700 hover:border-indigo-700 focus-visible:outline-indigo-600',
  secondary:
    'bg-white text-slate-700 border-slate-300 hover:bg-slate-50 focus-visible:outline-slate-500 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700 dark:hover:bg-slate-800',
  ghost:
    'bg-transparent text-slate-600 border-transparent hover:bg-slate-100 focus-visible:outline-slate-500 dark:text-slate-300 dark:hover:bg-slate-800',
  danger:
    'bg-red-600 text-white border-red-600 hover:bg-red-700 hover:border-red-700 focus-visible:outline-red-600',
}

const SIZES = {
  sm: 'text-xs px-2.5 py-1.5 gap-1.5',
  md: 'text-sm px-3.5 py-2 gap-2',
  lg: 'text-sm px-5 py-2.5 gap-2 font-semibold',
}

const ICON_SIZES = { sm: 14, md: 16, lg: 16 }

export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  icon: Icon,
  iconRight: IconRight,
  loading = false,
  disabled = false,
  className = '',
  as: Tag = 'button',
  type = 'button',
  ...rest
}) {
  const isDisabled = disabled || loading
  const tagProps = Tag === 'button' ? { type, disabled: isDisabled } : {}
  const iconSize = ICON_SIZES[size] || 16

  return (
    <Tag
      {...tagProps}
      {...rest}
      aria-disabled={isDisabled || undefined}
      className={cx(
        'inline-flex items-center justify-center rounded-md border font-medium transition-colors',
        'focus-visible:outline-2 focus-visible:outline-offset-2',
        isDisabled && 'pointer-events-none opacity-50',
        VARIANTS[variant] || VARIANTS.primary,
        SIZES[size] || SIZES.md,
        className,
      )}
    >
      {loading ? (
        <Loader2 size={iconSize} className="animate-spin shrink-0" aria-hidden="true" />
      ) : Icon ? (
        <Icon size={iconSize} className="shrink-0" aria-hidden="true" />
      ) : null}
      {children}
      {IconRight && !loading ? (
        <IconRight size={iconSize} className="shrink-0" aria-hidden="true" />
      ) : null}
    </Tag>
  )
}

/** Square icon-only button, used for the theme toggle and row controls. */
export function IconButton({ icon: Icon, label, className = '', size = 16, ...rest }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      {...rest}
      className={cx(
        'inline-flex items-center justify-center rounded-md border border-slate-300 bg-white p-2 text-slate-600 transition-colors',
        'hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-500',
        'dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800',
        className,
      )}
    >
      <Icon size={size} aria-hidden="true" />
    </button>
  )
}
