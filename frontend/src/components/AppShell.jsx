// Application shell: masthead, theme toggle and page container.
import { Link } from 'react-router-dom'
import { Moon, Scale, Sun } from 'lucide-react'
import { IconButton } from './ui/Button.jsx'
import { useTheme } from '../lib/theme.jsx'
import { cx } from '../lib/format.js'

export default function AppShell({ children, actions, width = 'wide' }) {
  const { isDark, toggleTheme } = useTheme()

  return (
    <div className="flex min-h-screen flex-col bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
        <div
          className={cx(
            'mx-auto flex items-center justify-between gap-3 px-4 py-3 sm:px-6',
            width === 'wide' ? 'max-w-7xl' : 'max-w-5xl',
          )}
        >
          <Link to="/" className="flex min-w-0 items-center gap-2.5">
            <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-blue-600 text-white">
              <Scale size={17} aria-hidden="true" />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-sm font-semibold tracking-tight">
                DPDP Compliance Self-Check
              </span>
              <span className="hidden truncate text-[11px] text-slate-500 sm:block dark:text-slate-400">
                Digital Personal Data Protection Act, 2023
              </span>
            </span>
          </Link>

          <div className="flex shrink-0 items-center gap-2">
            {actions}
            <IconButton
              icon={isDark ? Sun : Moon}
              label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
              onClick={toggleTheme}
            />
          </div>
        </div>
      </header>

      <main className="flex-1">
        <div
          className={cx(
            'mx-auto w-full px-4 py-6 sm:px-6 sm:py-8',
            width === 'wide' ? 'max-w-7xl' : 'max-w-5xl',
          )}
        >
          {children}
        </div>
      </main>

      <footer className="border-t border-slate-200 py-5 dark:border-slate-800">
        <div
          className={cx(
            'mx-auto px-4 text-xs text-slate-500 sm:px-6 dark:text-slate-400',
            width === 'wide' ? 'max-w-7xl' : 'max-w-5xl',
          )}
        >
          Automated self-assessment against the DPDP Act, 2023 and the DPDP Rules, 2025.
          Findings are an engineering aid and are not a substitute for legal advice.
        </div>
      </footer>
    </div>
  )
}
