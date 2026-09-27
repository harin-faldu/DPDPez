// DataFlow. OWNER: Manan
// PII flow visualisation for one scan.
// Loads GET /scans/:id/data-flows and renders each path as source, transforms
// and sink with the four compliance flags marked on the hops they belong to.
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  Building2,
  GitBranch,
  Loader2,
  LockOpen,
  ShieldAlert,
  Timer,
} from 'lucide-react'
import AppShell from '../components/AppShell.jsx'
import DataFlowGraph from '../components/DataFlowGraph.jsx'
import Card, { CardHeader, CardTitle, Stat } from '../components/ui/Card.jsx'
import Button from '../components/ui/Button.jsx'
import Badge from '../components/ui/Badge.jsx'
import { EmptyState, ErrorPanel, Skeleton } from '../components/ui/Feedback.jsx'
import { getDataFlows, getScan } from '../api/client.js'
import { cx } from '../lib/format.js'

const FILTERS = [
  { key: 'all', label: 'All flows' },
  { key: 'no_consent', label: 'No consent check', icon: ShieldAlert },
  { key: 'no_encryption', label: 'Not encrypted', icon: LockOpen },
  { key: 'no_retention', label: 'No retention limit', icon: Timer },
  { key: 'third_party', label: 'Reaches third party', icon: Building2 },
]

export default function DataFlow() {
  const { scanId } = useParams()
  const [flows, setFlows] = useState([])
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    if (!scanId) return undefined
    let cancelled = false
    setLoading(true)

    Promise.allSettled([getDataFlows(scanId), getScan(scanId)]).then(([flowResult, scanResult]) => {
      if (cancelled) return
      if (flowResult.status === 'fulfilled') {
        setFlows(Array.isArray(flowResult.value) ? flowResult.value : [])
        setError(null)
      } else {
        setError(flowResult.reason?.message || 'Could not load the data flows.')
      }
      if (scanResult.status === 'fulfilled') setScan(scanResult.value)
      setLoading(false)
    })

    return () => {
      cancelled = true
    }
  }, [scanId])

  const counts = useMemo(
    () => ({
      total: flows.length,
      no_consent: flows.filter((flow) => !flow?.has_consent_check).length,
      no_encryption: flows.filter((flow) => !flow?.has_encryption).length,
      no_retention: flows.filter((flow) => !flow?.has_retention_policy).length,
      third_party: flows.filter((flow) => flow?.crosses_third_party).length,
    }),
    [flows],
  )

  const visible = useMemo(() => {
    switch (filter) {
      case 'no_consent':
        return flows.filter((flow) => !flow?.has_consent_check)
      case 'no_encryption':
        return flows.filter((flow) => !flow?.has_encryption)
      case 'no_retention':
        return flows.filter((flow) => !flow?.has_retention_policy)
      case 'third_party':
        return flows.filter((flow) => flow?.crosses_third_party)
      default:
        return flows
    }
  }, [flows, filter])

  const categories = useMemo(() => {
    const set = new Set()
    flows.forEach((flow) => {
      if (flow?.pii_category) set.add(flow.pii_category)
    })
    return Array.from(set)
  }, [flows])

  return (
    <AppShell
      actions={
        <Button as={Link} to={`/scans/${scanId}`} variant="secondary" size="sm" icon={ArrowLeft}>
          <span className="hidden sm:inline">Scorecard</span>
        </Button>
      }
    >
      <Link
        to={`/scans/${scanId}`}
        className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
      >
        <ArrowLeft size={13} aria-hidden="true" />
        Back to the scorecard
      </Link>

      <div className="mt-3">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          Personal data flows
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-600 dark:text-slate-300">
          Each chain traces one category of personal data from the point it is collected, through
          every transform applied to it, to where it comes to rest.
          {scan?.target ? (
            <span className="break-all"> Target: {scan.target}.</span>
          ) : null}
        </p>
      </div>

      {loading ? (
        <div className="mt-5 space-y-3">
          <Card padded>
            <p className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
              <Loader2 size={15} className="animate-spin" aria-hidden="true" />
              Loading data flows
            </p>
          </Card>
          <Skeleton className="h-36 w-full" />
          <Skeleton className="h-36 w-full" />
        </div>
      ) : error ? (
        <div className="mt-5">
          <ErrorPanel title="Data flows unavailable" message={error} />
        </div>
      ) : flows.length === 0 ? (
        <Card className="mt-5">
          <EmptyState
            icon={GitBranch}
            title="No personal data flows recorded"
            description="The scanner did not trace any personal data from a source to a sink for this target. A website scan records flows only where the page evidence supports them."
          />
        </Card>
      ) : (
        <div className="mt-5 space-y-5">
          <Card>
            <CardHeader>
              <CardTitle icon={GitBranch} hint="Counted across every traced flow">
                Safeguard summary
              </CardTitle>
              {categories.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {categories.slice(0, 5).map((category) => (
                    <Badge key={category} tone="outline" size="xs">
                      {category}
                    </Badge>
                  ))}
                  {categories.length > 5 ? (
                    <Badge tone="outline" size="xs">
                      +{categories.length - 5} more
                    </Badge>
                  ) : null}
                </div>
              ) : null}
            </CardHeader>
            <div className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-5 sm:p-5">
              <Stat label="Flows traced" value={counts.total} />
              <Stat label="No consent" value={counts.no_consent} tone="danger" />
              <Stat label="Not encrypted" value={counts.no_encryption} tone="danger" />
              <Stat label="No retention" value={counts.no_retention} tone="warning" />
              <Stat label="Third party" value={counts.third_party} tone="orange" />
            </div>
          </Card>

          <div className="flex flex-wrap items-center gap-1.5">
            {FILTERS.map((option) => {
              const count = option.key === 'all' ? counts.total : counts[option.key]
              const active = filter === option.key
              return (
                <button
                  key={option.key}
                  type="button"
                  onClick={() => setFilter(option.key)}
                  aria-pressed={active}
                  className={cx(
                    'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors',
                    active
                      ? 'border-indigo-300 bg-indigo-50 text-indigo-800 dark:border-indigo-700 dark:bg-indigo-950/50 dark:text-indigo-200'
                      : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400 dark:hover:bg-slate-800',
                  )}
                >
                  {option.icon ? <option.icon size={13} aria-hidden="true" /> : null}
                  {option.label}
                  <span className="tabular-nums opacity-70">{count}</span>
                </button>
              )
            })}
          </div>

          {visible.length === 0 ? (
            <Card>
              <EmptyState
                icon={GitBranch}
                title="No flows match this filter"
                description="Every traced flow has this safeguard in place."
              />
            </Card>
          ) : (
            <div className="space-y-4">
              {visible.map((flow, index) => (
                <DataFlowGraph
                  key={`${flow?.pii_category || 'flow'}-${index}`}
                  flow={flow}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </AppShell>
  )
}
