// ScanResults. OWNER: Manan
// Scorecard and findings for one scan.
// Polls GET /scan/:id until the status is terminal, then loads the scorecard
// and findings. The stage tracker and the rule placeholders render from the
// first response, so the page never sits blank while a scan is running.
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  CheckCircle2,
  ClipboardList,
  FileArchive,
  Files,
  Globe,
  Layers,
  Loader2,
  Network,
  Plus,
  Target,
} from 'lucide-react'
import AppShell from '../components/AppShell.jsx'
import ScoreCard from '../components/ScoreCard.jsx'
import RuleStatus, { RuleStatusSkeleton } from '../components/RuleStatus.jsx'
import FindingsList from '../components/FindingsList.jsx'
import PolicyReport from '../components/PolicyReport.jsx'
import Card, { CardHeader, CardTitle } from '../components/ui/Card.jsx'
import Badge, { MonoBadge } from '../components/ui/Badge.jsx'
import Button from '../components/ui/Button.jsx'
import { ErrorPanel, IndeterminateBar } from '../components/ui/Feedback.jsx'
import { getAggregate, getFindings, getScan, getScorecard } from '../api/client.js'
import { SCAN_STAGES, stageIndex, TERMINAL_STATUSES } from '../lib/compliance.js'
import { cx, formatElapsed } from '../lib/format.js'

const POLL_INTERVAL_MS = 1500
const MAX_CONSECUTIVE_FAILURES = 4
const SLOW_SCAN_SECONDS = 120

export default function ScanResults() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [pollError, setPollError] = useState(null)
  const [elapsed, setElapsed] = useState(0)

  const [scorecard, setScorecard] = useState(null)
  const [findings, setFindings] = useState([])
  const [policyReport, setPolicyReport] = useState(null)
  const [resultsLoading, setResultsLoading] = useState(false)
  const [scorecardError, setScorecardError] = useState(null)
  const [findingsError, setFindingsError] = useState(null)

  const status = scan?.status
  const isTerminal = TERMINAL_STATUSES.includes(status)
  const isPolicy = scan?.scan_type === 'policy'

  useEffect(() => {
    if (!scanId) return undefined
    let cancelled = false
    let timer = null
    let failures = 0

    async function tick() {
      try {
        const data = await getScan(scanId)
        if (cancelled) return
        failures = 0
        setScan(data)
        setPollError(null)
        if (TERMINAL_STATUSES.includes(data?.status)) return
      } catch (caught) {
        if (cancelled) return
        failures += 1
        // A single dropped request during a long scan is not fatal; only give
        // up once the API has been unreachable several times in a row.
        if (failures >= MAX_CONSECUTIVE_FAILURES) {
          setPollError(caught?.message || 'Lost contact with the scanner API.')
          return
        }
      }
      timer = setTimeout(tick, POLL_INTERVAL_MS)
    }

    tick()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [scanId])

  useEffect(() => {
    if (isTerminal) return undefined
    const id = setInterval(() => setElapsed((value) => value + 1), 1000)
    return () => clearInterval(id)
  }, [isTerminal])

  useEffect(() => {
    if (status !== 'complete' || !scanId) return undefined
    let cancelled = false
    setResultsLoading(true)

    // A policy scan issues no grade and no rule verdicts on its own (see
    // app/pipeline.py's run_policy_scan), so its own page reads the checklist
    // and claims through the same aggregate endpoint a flow run's final report
    // uses, passed only this scan's id.
    if (isPolicy) {
      getAggregate({ policyScanId: scanId }).then(
        (result) => {
          if (cancelled) return
          setPolicyReport(result?.policy || null)
          setScorecardError(null)
          setResultsLoading(false)
        },
        (caught) => {
          if (cancelled) return
          setScorecardError(caught?.message || 'Could not load the policy report.')
          setResultsLoading(false)
        },
      )
      return () => {
        cancelled = true
      }
    }

    Promise.allSettled([getScorecard(scanId), getFindings(scanId)]).then(
      ([scorecardResult, findingsResult]) => {
        if (cancelled) return
        if (scorecardResult.status === 'fulfilled') {
          setScorecard(scorecardResult.value)
          setScorecardError(null)
        } else {
          setScorecardError(scorecardResult.reason?.message || 'Could not load the scorecard.')
        }
        if (findingsResult.status === 'fulfilled') {
          setFindings(Array.isArray(findingsResult.value) ? findingsResult.value : [])
          setFindingsError(null)
        } else {
          setFindingsError(findingsResult.reason?.message || 'Could not load the findings.')
        }
        setResultsLoading(false)
      },
    )

    return () => {
      cancelled = true
    }
  }, [status, scanId, isPolicy])

  const rules = useMemo(() => scorecard?.rules || [], [scorecard])

  const actions = (
    <div className="flex items-center gap-2">
      {status === 'complete' && scan?.scan_type === 'code' ? (
        <Button
          as={Link}
          to={`/scans/${scanId}/data-flow`}
          variant="secondary"
          size="sm"
          icon={Network}
        >
          <span className="hidden sm:inline">Data flow</span>
        </Button>
      ) : null}
      <Button as={Link} to="/" variant="secondary" size="sm" icon={Plus}>
        <span className="hidden sm:inline">New scan</span>
      </Button>
    </div>
  )

  return (
    <AppShell actions={actions}>
      <Link
        to="/"
        className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
      >
        <ArrowLeft size={13} aria-hidden="true" />
        Start another scan
      </Link>

      <ScanHeader scan={scan} scanId={scanId} elapsed={elapsed} />

      {pollError ? (
        <div className="mt-5">
          <ErrorPanel
            title="Cannot reach the scanner"
            message={pollError}
            action={
              <Button size="sm" variant="secondary" onClick={() => window.location.reload()}>
                Retry
              </Button>
            }
          />
        </div>
      ) : null}

      {status === 'failed' ? (
        <div className="mt-5">
          <ErrorPanel
            title="Scan failed"
            message={
              scan?.error_message ||
              'The scanner stopped before it could produce a scorecard, and reported no reason.'
            }
            action={
              <Button as={Link} to="/" size="sm" icon={Plus}>
                Run a new scan
              </Button>
            }
          />
        </div>
      ) : null}

      {!isTerminal && !pollError ? (
        <div className="mt-5 space-y-5">
          <ProgressPanel status={status} elapsed={elapsed} />
          <PendingRules />
        </div>
      ) : null}

      {status === 'complete' && isPolicy ? (
        <div className="mt-5 space-y-5">
          {resultsLoading ? (
            <Card padded>
              <p className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <Loader2 size={15} className="animate-spin" aria-hidden="true" />
                Loading the policy report
              </p>
            </Card>
          ) : null}
          {scorecardError ? <ErrorPanel title="Policy report unavailable" message={scorecardError} /> : null}
          {policyReport ? (
            <PolicyReport policy={policyReport} />
          ) : !resultsLoading && !scorecardError ? (
            <Card padded>
              <p className="text-sm text-slate-600 dark:text-slate-300">
                No policy documents were readable from this target.
              </p>
            </Card>
          ) : null}
          <Card padded className="border-indigo-200 bg-indigo-50/50 dark:border-indigo-900 dark:bg-indigo-950/20">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              A policy scan issues no grade on its own. Run the website and code stages against
              this scan (its id is <code className="rounded bg-white px-1 py-0.5 font-mono dark:bg-slate-900">{scanId}</code>),
              or start a full cycle from the home page to see a combined scorecard.
            </p>
          </Card>
        </div>
      ) : null}

      {status === 'complete' && !isPolicy ? (
        <div className="mt-5 space-y-5">
          {resultsLoading ? (
            <Card padded>
              <p className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <Loader2 size={15} className="animate-spin" aria-hidden="true" />
                Loading the scorecard and findings
              </p>
            </Card>
          ) : null}

          {scorecardError ? <ErrorPanel title="Scorecard unavailable" message={scorecardError} /> : null}
          {scorecard ? <ScoreCard scorecard={scorecard} /> : null}

          {rules.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle icon={Layers} hint="Status is set by the rule checkers, not by the score alone">
                  Rule by rule
                </CardTitle>
                <span className="text-xs text-slate-500 tabular-nums dark:text-slate-400">
                  {rules.length} rules evaluated
                </span>
              </CardHeader>
              <div className="grid gap-3 p-4 sm:p-5 md:grid-cols-2 xl:grid-cols-3">
                {rules.map((rule, index) => (
                  <RuleStatus key={rule.rule_id || index} rule={rule} />
                ))}
              </div>
            </Card>
          ) : null}

          {findingsError ? <ErrorPanel title="Findings unavailable" message={findingsError} /> : null}
          {!findingsError && !resultsLoading ? <FindingsList findings={findings} /> : null}
        </div>
      ) : null}
    </AppShell>
  )
}

const SCAN_TYPE_META = {
  policy: { label: 'Policy scan', icon: ClipboardList },
  web: { label: 'Website scan', icon: Globe },
  code: { label: 'Code scan', icon: FileArchive },
}

function ScanHeader({ scan, scanId, elapsed }) {
  const typeMeta = SCAN_TYPE_META[scan?.scan_type] || { label: 'Scan', icon: FileArchive }
  const isTerminal = TERMINAL_STATUSES.includes(scan?.status)

  return (
    <Card className="mt-3">
      <div className="flex flex-wrap items-start justify-between gap-4 p-4 sm:p-5">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="accent" size="sm" icon={typeMeta.icon}>
              {typeMeta.label}
            </Badge>
            <MonoBadge title="Scan identifier">{scanId}</MonoBadge>
          </div>
          <p className="mt-2 flex items-start gap-1.5 text-sm font-medium break-all text-slate-900 dark:text-slate-100">
            <Target size={14} className="mt-0.5 shrink-0 text-slate-400" aria-hidden="true" />
            {scan?.target || 'Resolving target'}
          </p>
        </div>

        <dl className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
          {Number.isFinite(Number(scan?.pages_crawled)) && scan?.pages_crawled !== null ? (
            <MetaItem icon={Files} label="Pages crawled" value={scan.pages_crawled} />
          ) : null}
          {Number.isFinite(Number(scan?.files_scanned)) && scan?.files_scanned !== null ? (
            <MetaItem icon={Files} label="Files scanned" value={scan.files_scanned} />
          ) : null}
          <MetaItem
            icon={isTerminal ? CheckCircle2 : Loader2}
            label={isTerminal ? 'Duration' : 'Elapsed'}
            value={formatElapsed(elapsed)}
            spin={!isTerminal}
          />
        </dl>
      </div>
    </Card>
  )
}

function MetaItem({ icon: Icon, label, value, spin = false }) {
  return (
    <div>
      <dt className="flex items-center gap-1 text-[11px] font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">
        <Icon size={11} className={spin ? 'animate-spin' : undefined} aria-hidden="true" />
        {label}
      </dt>
      <dd className="mt-0.5 text-sm font-semibold text-slate-800 tabular-nums dark:text-slate-100">
        {value}
      </dd>
    </div>
  )
}

function ProgressPanel({ status, elapsed }) {
  const current = stageIndex(status)

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={Loader2} hint="The scorecard appears here as soon as the rules finish">
          Scan in progress
        </CardTitle>
        {elapsed >= SLOW_SCAN_SECONDS ? (
          <Badge tone="warning" size="sm">
            Taking longer than usual
          </Badge>
        ) : null}
      </CardHeader>

      <div className="p-4 sm:p-5">
        <IndeterminateBar />
        <ol className="mt-5 grid gap-3 sm:grid-cols-4">
          {SCAN_STAGES.map((stage, index) => {
            const done = index < current
            const active = index === current
            return (
              <li
                key={stage.key}
                className={cx(
                  'rounded-md border px-3 py-2.5',
                  active
                    ? 'border-indigo-300 bg-indigo-50 dark:border-indigo-800 dark:bg-indigo-950/40'
                    : done
                      ? 'border-emerald-200 bg-emerald-50/60 dark:border-emerald-900 dark:bg-emerald-950/30'
                      : 'border-slate-200 dark:border-slate-800',
                )}
              >
                <div className="flex items-center gap-1.5">
                  {done ? (
                    <CheckCircle2
                      size={13}
                      className="text-emerald-600 dark:text-emerald-400"
                      aria-hidden="true"
                    />
                  ) : active ? (
                    <Loader2
                      size={13}
                      className="animate-spin text-indigo-600 dark:text-indigo-400"
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
                      active
                        ? 'text-indigo-800 dark:text-indigo-200'
                        : done
                          ? 'text-emerald-800 dark:text-emerald-300'
                          : 'text-slate-500 dark:text-slate-400',
                    )}
                  >
                    {stage.label}
                  </span>
                </div>
                <p className="mt-1 text-[11px] leading-snug text-slate-500 dark:text-slate-400">
                  {stage.blurb}
                </p>
              </li>
            )
          })}
        </ol>
      </div>
    </Card>
  )
}

function PendingRules() {
  return (
    <Card>
      <CardHeader>
        <CardTitle icon={Layers} hint="Placeholders fill in as each rule checker reports">
          Rule by rule
        </CardTitle>
      </CardHeader>
      <div className="grid gap-3 p-4 sm:p-5 md:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }).map((_, index) => (
          <RuleStatusSkeleton key={index} />
        ))}
      </div>
    </Card>
  )
}
