// AggregateRuleTable. The one thing the radar chart cannot show: which stage
// produced which score for a rule assessed by more than one, and which of the
// two the aggregate actually used. A rule scored 0.8 by the web scan and 0.3
// by the code scan is not averaged; the lower one is the rule's real risk.
import { Scale } from 'lucide-react'
import Card, { CardHeader, CardTitle } from './ui/Card.jsx'
import Badge, { MonoBadge } from './ui/Badge.jsx'
import { ruleStatusMeta } from '../lib/compliance.js'
import { toPercent } from '../lib/format.js'

function cell(score) {
  const pct = toPercent(score)
  return pct === null ? <span className="text-slate-300 dark:text-slate-700">&mdash;</span> : `${pct}`
}

export default function AggregateRuleTable({ rules = [] }) {
  const multiSource = rules.filter((r) => (r.sources || []).length > 1)

  if (rules.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle
          icon={Scale}
          hint={
            multiSource.length > 0
              ? `${multiSource.length} rule${multiSource.length === 1 ? '' : 's'} assessed by more than one stage; the lower score won`
              : 'Each rule assessed by exactly one stage so far'
          }
        >
          Rule by rule, across stages
        </CardTitle>
      </CardHeader>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-200 text-[11px] tracking-wide text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
              <th className="px-4 py-2 sm:px-5">Rule</th>
              <th className="px-3 py-2 text-right">Web</th>
              <th className="px-3 py-2 text-right">Code</th>
              <th className="px-3 py-2 text-right">Used</th>
              <th className="px-4 py-2 sm:px-5">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
            {rules.map((rule) => {
              const meta = ruleStatusMeta(rule.status)
              const usedFromBoth = (rule.sources || []).length > 1
              return (
                <tr key={rule.rule_id}>
                  <td className="px-4 py-2.5 sm:px-5">
                    <div className="flex items-center gap-2">
                      <MonoBadge>{rule.rule_id}</MonoBadge>
                      <span className="text-slate-700 dark:text-slate-300">{rule.rule_name}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-right tabular-nums text-slate-600 dark:text-slate-400">
                    {cell(rule.web_score)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular-nums text-slate-600 dark:text-slate-400">
                    {cell(rule.code_score)}
                  </td>
                  <td className="px-3 py-2.5 text-right font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                    {cell(rule.score)}
                    {usedFromBoth ? (
                      <span className="ml-1 text-[10px] font-normal text-slate-400">min</span>
                    ) : null}
                  </td>
                  <td className="px-4 py-2.5 sm:px-5">
                    <Badge tone={meta.tone} size="sm" icon={meta.icon}>
                      {meta.label}
                    </Badge>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
