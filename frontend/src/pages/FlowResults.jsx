// FlowResults. OWNER: Manan
// Orchestrates the four-stage cycle from the browser: start the policy scan,
// wait for it, start the website scan against it, wait for it, start the code
// scan against it if an archive was given, wait for it, then read the
// aggregate. Each stage still writes to its own scan row exactly as an
// independent run would, so nothing here is special-cased on the backend; this
// page is just a client that calls the same four endpoints in order.
//
// A stage that fails does not stop the cycle. The policy stage failing (a bot
// wall, most often) still lets the website and code stages run on their own
// evidence; the aggregate is built from whichever of the three came back.
import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ExternalLink,
  Loader2,
  Plus,
  XCircle,
} from 'lucide-react'
import AppShell from '../components/AppShell.jsx'
import ScoreCard from '../components/ScoreCard.jsx'
import AggregateRuleTable from '../components/AggregateRuleTable.jsx'
import PolicyReport from '../components/PolicyReport.jsx'
import Card, { CardHeader, CardTitle } from '../components/ui/Card.jsx'
import Badge from '../components/ui/Badge.jsx'
import Button from '../components/ui/Button.jsx'
import { ErrorPanel, IndeterminateBar } from '../components/ui/Feedback.jsx'
import {
  getAggregate,
  getScan,
  startCodeScan,
  startPolicyScan,
  startWebScan,
} from '../api/client.js'
import { PIPELINE_STAGES, TERMINAL_STATUSES } from '../lib/compliance.js'
import { cx } from '../lib/format.js'

const POLL_INTERVAL_MS = 1500

/** Polls GET /scan/:id until it reaches a terminal status, or the cycle is cancelled. */
function pollScan(scanId, isCancelled) {
  return new Promise((resolve, reject) => {
    async function tick() {
      if (isCancelled()) return
      try {
        const data = await getScan(scanId)
        if (isCancelled()) return
        if (TERMINAL_STATUSES.includes(data?.status)) {
          resolve(data)
          return
        }
      } catch (caught) {
        if (isCancelled()) return
        reject(caught)
        return
      }
      setTimeout(tick, POLL_INTERVAL_MS)
    }
    tick()
  })
}

const INITIAL_STAGES = () =>
  Object.fromEntries(PIPELINE_STAGES.map((stage) => [stage.key, { status: 'pending' }]))

export default function FlowResults() {
  const location = useLocation()
  const navigate = useNavigate()
  const { url, file } = location.state || {}

  const [stages, setStages] = useState(INITIAL_STAGES)
  const [aggregate, setAggregate] = useState(null)
  const [fatalError, setFatalError] = useState(null)

  useEffect(() => {
    if (!url) return undefined
    // A plain closure variable, not a ref: React 18 StrictMode mounts this
    // effect, cleans it up, then mounts it again, all synchronously, before
    // either run() has done any real work. A ref shared across both
    // invocations would have its cleanup-set true clobbered back to false by
    // the second mount, so the first invocation's abandoned run() would never
    // see itself as cancelled and would carry on submitting scans nobody
    // asked for anymore. A variable captured fresh per effect invocation has
    // no such second owner to reset it.
    let cancelled = false
    const isCancelled = () => cancelled

    function patch(key, value) {
      if (isCancelled()) return
      setStages((prev) => ({ ...prev, [key]: { ...prev[key], ...value } }))
    }

    async function run() {
      let policyScanId = null
      let webScanId = null
      let codeScanId = null

      // Stage 1: policy. A bot wall or a missing notice does not stop the
      // cycle, it just means stages 2 and 3 run without a claim to test.
      try {
        patch('policy', { status: 'active' })
        const started = await startPolicyScan(url)
        policyScanId = started?.scan_id || null
        patch('policy', { scanId: policyScanId })
        const finished = await pollScan(policyScanId, isCancelled)
        if (finished.status === 'failed') {
          patch('policy', { status: 'failed', error: finished.error_message })
          policyScanId = null
        } else {
          patch('policy', { status: 'done' })
        }
      } catch (caught) {
        patch('policy', { status: 'failed', error: caught?.message })
        policyScanId = null
      }
      if (isCancelled()) return

      // Stage 2: website, verified against stage 1's claims when it succeeded.
      try {
        patch('web', { status: 'active' })
        const started = await startWebScan(url, policyScanId)
        webScanId = started?.scan_id || null
        patch('web', { scanId: webScanId })
        const finished = await pollScan(webScanId, isCancelled)
        if (finished.status === 'failed') {
          patch('web', { status: 'failed', error: finished.error_message })
          webScanId = null
        } else {
          patch('web', { status: 'done' })
        }
      } catch (caught) {
        patch('web', { status: 'failed', error: caught?.message })
        webScanId = null
      }
      if (isCancelled()) return

      // Stage 3: code, only if an archive was supplied.
      if (file) {
        try {
          patch('code', { status: 'active' })
          const started = await startCodeScan(file, policyScanId)
          codeScanId = started?.scan_id || null
          patch('code', { scanId: codeScanId })
          const finished = await pollScan(codeScanId, isCancelled)
          if (finished.status === 'failed') {
            patch('code', { status: 'failed', error: finished.error_message })
            codeScanId = null
          } else {
            patch('code', { status: 'done' })
          }
        } catch (caught) {
          patch('code', { status: 'failed', error: caught?.message })
          codeScanId = null
        }
      } else {
        patch('code', { status: 'skipped' })
      }
      if (isCancelled()) return

      // Stage 4: combine whichever of the three actually produced evidence.
      if (!policyScanId && !webScanId && !codeScanId) {
        patch('aggregate', { status: 'skipped' })
        setFatalError('Every stage failed, so there is nothing to combine into a scorecard.')
        return
      }
      try {
        patch('aggregate', { status: 'active' })
        const result = await getAggregate({ policyScanId, webScanId, codeScanId })
        if (isCancelled()) return
        setAggregate(result)
        patch('aggregate', { status: 'done' })
      } catch (caught) {
        patch('aggregate', { status: 'failed', error: caught?.message })
      }
    }

    run()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, file])

  const actions = (
    <Button as={Link} to="/" variant="secondary" size="sm" icon={Plus}>
      <span className="hidden sm:inline">New scan</span>
    </Button>
  )

  if (!url) {
    return (
      <AppShell actions={actions}>
        <ErrorPanel
          title="Nothing to run"
          message="This page needs a target from the home page's form. Start a new cycle from there."
          action={
            <Button as={Link} to="/" size="sm" icon={Plus}>
              Start a cycle
            </Button>
          }
        />
      </AppShell>
    )
  }

  const done = stages.aggregate.status === 'done'
  const running = !done && stages.aggregate.status !== 'skipped'

  return (
    <AppShell actions={actions} width="wide">
      <button
        type="button"
        onClick={() => navigate('/')}
        className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
      >
        <ArrowLeft size={13} aria-hidden="true" />
        Start another scan
      </button>

      <Card className="mt-3">
        <div className="p-4 sm:p-5">
          <p className="text-xs font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">
            Full compliance cycle
          </p>
          <p className="mt-1 flex items-center gap-1.5 text-sm font-medium break-all text-slate-900 dark:text-slate-100">
            {url}
          </p>
          {file ? (
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              with codebase archive &ldquo;{file.name}&rdquo;
            </p>
          ) : (
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              No archive supplied, so the code stage is skipped.
            </p>
          )}
        </div>
      </Card>

      <div className="mt-5">
        <StagesPanel stages={stages} running={running} />
      </div>

      {fatalError ? (
        <div className="mt-5">
          <ErrorPanel title="Cycle could not complete" message={fatalError} />
        </div>
      ) : null}

      {done && aggregate ? (
        <div className="mt-5 space-y-5">
          <ScoreCard scorecard={aggregate} />
          <AggregateRuleTable rules={aggregate.rules} />
          {aggregate.policy ? <PolicyReport policy={aggregate.policy} /> : null}
          <StageLinks stages={stages} />
        </div>
      ) : null}
    </AppShell>
  )
}

const STAGE_ICON = {
  pending: null,
  active: Loader2,
  done: CheckCircle2,
  failed: XCircle,
  skipped: null,
}

function StagesPanel({ stages, running }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle
          icon={Loader2}
          hint="Each stage still writes its own scan row; this is just the order they run in"
        >
          {running ? 'Cycle in progress' : 'Cycle finished'}
        </CardTitle>
      </CardHeader>
      <div className="p-4 sm:p-5">
        {running ? <IndeterminateBar /> : null}
        <ol className={cx('grid gap-3 sm:grid-cols-4', running && 'mt-5')}>
          {PIPELINE_STAGES.map((stage) => {
            const state = stages[stage.key] || { status: 'pending' }
            const Icon = STAGE_ICON[state.status]
            return (
              <li
                key={stage.key}
                className={cx(
                  'rounded-md border px-3 py-2.5',
                  state.status === 'active'
                    ? 'border-indigo-300 bg-indigo-50 dark:border-indigo-800 dark:bg-indigo-950/40'
                    : state.status === 'done'
                      ? 'border-emerald-200 bg-emerald-50/60 dark:border-emerald-900 dark:bg-emerald-950/30'
                      : state.status === 'failed'
                        ? 'border-red-200 bg-red-50/60 dark:border-red-900 dark:bg-red-950/20'
                        : 'border-slate-200 dark:border-slate-800',
                )}
              >
                <div className="flex items-center gap-1.5">
                  {Icon ? (
                    <Icon
                      size={13}
                      className={cx(
                        state.status === 'active' && 'animate-spin text-indigo-600 dark:text-indigo-400',
                        state.status === 'done' && 'text-emerald-600 dark:text-emerald-400',
                        state.status === 'failed' && 'text-red-600 dark:text-red-400',
                      )}
                      aria-hidden="true"
                    />
                  ) : (
                    <span
                      className="size-[13px] rounded-full border border-slate-300 dark:border-slate-700"
                      aria-hidden="true"
                    />
                  )}
                  <span
                    className={cx(
                      'text-xs font-semibold',
                      state.status === 'active'
                        ? 'text-indigo-800 dark:text-indigo-200'
                        : state.status === 'done'
                          ? 'text-emerald-800 dark:text-emerald-300'
                          : state.status === 'failed'
                            ? 'text-red-700 dark:text-red-300'
                            : 'text-slate-500 dark:text-slate-400',
                    )}
                  >
                    {stage.label}
                  </span>
                  {state.status === 'skipped' ? (
                    <Badge tone="outline" size="sm">
                      skipped
                    </Badge>
                  ) : null}
                </div>
                <p className="mt-1 text-[11px] leading-snug text-slate-500 dark:text-slate-400">
                  {state.status === 'failed' && state.error ? (
                    <span className="flex items-start gap-1 text-red-600 dark:text-red-400">
                      <AlertTriangle size={11} className="mt-0.5 shrink-0" aria-hidden="true" />
                      {state.error}
                    </span>
                  ) : (
                    stage.blurb
                  )}
                </p>
              </li>
            )
          })}
        </ol>
      </div>
    </Card>
  )
}

function StageLinks({ stages }) {
  const links = PIPELINE_STAGES.filter(
    (stage) => stage.key !== 'aggregate' && stages[stage.key]?.scanId,
  )
  if (links.length === 0) return null

  return (
    <Card padded>
      <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
        Each stage's own page has its full detail: findings, evidence, data flow.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {links.map((stage) => (
          <Button
            key={stage.key}
            as={Link}
            to={`/scans/${stages[stage.key].scanId}`}
            variant="secondary"
            size="sm"
            icon={ExternalLink}
          >
            {stage.label} scan
          </Button>
        ))}
      </div>
    </Card>
  )
}
