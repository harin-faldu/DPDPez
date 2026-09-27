// ScoreCard. OWNER: Manan
// Radar chart across the rules the scan could assess, plus the grade badge.
// Rules the scan could not reach are listed separately rather than plotted.
// They used to sit on the chart at zero, which read as a failing score: an axis
// pinned at zero because a crawl cannot see a breach register looked identical
// to one pinned at zero for non-compliance.
import { useMemo } from 'react'
import {
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import { ShieldCheck } from 'lucide-react'
import Card, { CardHeader, CardTitle, Stat } from './ui/Card.jsx'
import Badge from './ui/Badge.jsx'
import { gradeMeta, ruleAxisLabel, ruleStatusMeta } from '../lib/compliance.js'
import { toPercent } from '../lib/format.js'
import { useTheme } from '../lib/theme.jsx'

export default function ScoreCard({ scorecard }) {
  const { isDark } = useTheme()
  const rules = useMemo(() => scorecard?.rules || [], [scorecard])

  // The API now sends only assessed rules in `rules`. The filter stays as a
  // guard so an older payload cannot put a zero-scored axis back on the chart.
  const chartData = useMemo(
    () =>
      rules
        .filter((rule) => rule.status !== 'not_applicable')
        .map((rule) => ({
          axis: ruleAxisLabel(rule),
          ruleId: rule.rule_id,
          ruleName: rule.rule_name,
          status: rule.status,
          applicable: true,
          score: toPercent(rule.score) ?? 0,
        })),
    [rules],
  )

  const notAssessed = scorecard?.not_assessed || []
  const excludedCount = notAssessed.length
  const grade = gradeMeta(scorecard?.overall_grade)
  const overall = toPercent(scorecard?.overall_score)
  const summary = scorecard?.summary || {}

  const axisTickFill = isDark ? '#cbd5e1' : '#334155'
  const mutedFill = isDark ? '#64748b' : '#94a3b8'
  const gridStroke = isDark ? '#1e293b' : '#e2e8f0'
  const radarStroke = isDark ? '#818cf8' : '#4f46e5'

  function renderAxisTick(props) {
    const { payload, x, y, textAnchor } = props
    const datum = chartData[payload?.index ?? -1]
    const excluded = datum && !datum.applicable
    return (
      <text
        x={x}
        y={y}
        textAnchor={textAnchor}
        fill={excluded ? mutedFill : axisTickFill}
        fontSize={11}
        fontWeight={excluded ? 400 : 500}
        fontStyle={excluded ? 'italic' : 'normal'}
      >
        <tspan>{payload?.value}</tspan>
        {excluded ? (
          <tspan fontSize={9} dx={3}>
            (n/a)
          </tspan>
        ) : null}
      </text>
    )
  }

  function renderDot(props) {
    const { cx: dotX, cy: dotY, index } = props
    const datum = chartData[index]
    if (!datum) return null
    const meta = ruleStatusMeta(datum.status)
    const colour = isDark ? meta.chart.dark : meta.chart.light
    return (
      <circle
        key={`radar-dot-${datum.ruleId || index}`}
        cx={dotX}
        cy={dotY}
        r={datum.applicable ? 4 : 3}
        fill={datum.applicable ? colour : 'none'}
        stroke={colour}
        strokeWidth={datum.applicable ? 1.5 : 1.5}
        strokeDasharray={datum.applicable ? undefined : '2 2'}
      />
    )
  }

  function renderTooltip({ active, payload }) {
    if (!active || !payload || !payload.length) return null
    const datum = payload[0].payload
    const meta = ruleStatusMeta(datum.status)
    return (
      <div className="rounded-md border border-slate-200 bg-white px-3 py-2 text-xs shadow-md dark:border-slate-700 dark:bg-slate-900">
        <p className="font-semibold text-slate-900 dark:text-slate-100">
          {datum.ruleId ? `${datum.ruleId} ` : ''}
          {datum.ruleName || datum.axis}
        </p>
        <p className="mt-1 text-slate-600 dark:text-slate-300">
          {meta.label}
          {datum.applicable ? ` at ${datum.score} of 100` : ' and excluded from the grade'}
        </p>
      </div>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={ShieldCheck} hint="Weighted across every DPDP rule the scan could assess">
          Compliance scorecard
        </CardTitle>
        {excludedCount > 0 ? (
          <Badge tone="outline" size="sm">
            {excludedCount} rule{excludedCount === 1 ? '' : 's'} not assessable
          </Badge>
        ) : null}
      </CardHeader>

      <div className="grid gap-6 p-4 sm:p-5 lg:grid-cols-[minmax(0,260px)_minmax(0,1fr)]">
        <div className="flex flex-col gap-5">
          <div className="flex items-center gap-4">
            <div
              className={`flex size-24 shrink-0 items-center justify-center rounded-xl border-2 ${grade.ring} ${grade.wash}`}
            >
              <span
                className={`leading-none font-bold ${grade.text} ${
                  grade.notAssessed ? 'text-2xl' : 'text-5xl'
                }`}
              >
                {grade.letter}
              </span>
            </div>
            <div className="min-w-0">
              <div className="text-3xl font-semibold text-slate-900 tabular-nums dark:text-slate-100">
                {overall === null ? '--' : overall}
                <span className="ml-1 text-base font-normal text-slate-400">/ 100</span>
              </div>
              {scorecard?.grade_label ? (
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                  {scorecard.grade_label}
                </p>
              ) : null}
              {grade.notAssessed ? (
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Nothing in this target could be assessed, so no grade was
                  issued. A score here would describe a system that was never
                  inspected.
                </p>
              ) : null}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 border-t border-slate-200 pt-4 dark:border-slate-800">
            <Stat label="Findings" value={summary.total_findings ?? 0} />
            <Stat label="Critical" value={summary.critical ?? 0} tone="danger" />
            <Stat label="High" value={summary.high ?? 0} tone="orange" />
            <Stat label="Medium" value={summary.medium ?? 0} tone="warning" />
            <Stat label="Low" value={summary.low ?? 0} tone="info" />
            <Stat label="Rules scored" value={chartData.length} tone="muted" />
          </div>
        </div>

        <div className="min-w-0">
          {chartData.length > 0 ? (
            <>
              {/* Axis labels are allowed to spill into the card padding so a long
                  rule name is not clipped on a narrow viewport. */}
              <div className="h-[340px] w-full [&_.recharts-surface]:overflow-visible">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={chartData} outerRadius="68%" margin={{ top: 20, right: 40, bottom: 20, left: 40 }}>
                    <PolarGrid stroke={gridStroke} />
                    <PolarAngleAxis dataKey="axis" tick={renderAxisTick} tickLine={false} />
                    <PolarRadiusAxis
                      angle={90}
                      domain={[0, 100]}
                      tickCount={3}
                      axisLine={false}
                      tick={{ fontSize: 9, fill: mutedFill }}
                    />
                    <Radar
                      name="Rule score"
                      dataKey="score"
                      stroke={radarStroke}
                      strokeWidth={2}
                      fill={radarStroke}
                      fillOpacity={0.18}
                      dot={renderDot}
                      isAnimationActive={false}
                    />
                    <Tooltip content={renderTooltip} cursor={false} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                Vertices are coloured by rule status. Only rules this scan could assess are
                plotted, and the grade is weighted across those alone.
              </p>
            </>
          ) : (
            // Recharts cannot draw a polygon over zero points, so this is not
            // just a style choice: a chart handed an empty axis list renders a
            // degenerate SVG path and logs a console error rather than an
            // empty radar.
            <div className="flex h-[340px] w-full items-center justify-center rounded-md border border-dashed border-slate-200 dark:border-slate-800">
              <p className="max-w-xs px-4 text-center text-xs text-slate-500 dark:text-slate-400">
                No rule could be assessed, so there is nothing to plot. See "Not assessable from
                this scan" below for why.
              </p>
            </div>
          )}
        </div>
      </div>

      {notAssessed.length > 0 ? (
        <div className="border-t border-slate-200 px-4 py-4 sm:px-5 dark:border-slate-800">
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">
            Not assessable from this scan
          </h3>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            These carry no weight in the grade. They are listed because silently
            dropping them would imply the scan covered ground it never reached.
          </p>
          <ul className="mt-3 space-y-2">
            {notAssessed.map((rule) => (
              <li key={rule.rule_id} className="flex gap-3 text-xs">
                <Badge tone="outline" size="sm">
                  {rule.rule_id}
                </Badge>
                <div className="min-w-0">
                  <span className="font-medium text-slate-700 dark:text-slate-300">
                    {rule.rule_name}
                  </span>
                  {rule.dpdp_section ? (
                    <span className="ml-2 text-slate-400">{rule.dpdp_section}</span>
                  ) : null}
                  <p className="mt-0.5 text-slate-500 dark:text-slate-400">{rule.reason}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  )
}
