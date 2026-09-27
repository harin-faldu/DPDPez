// PolicyReport. Renders stage 1's statutory checklist and stage 1's claims,
// with whatever verdict stage 2 or stage 3 has since written onto each claim.
// No score is shown here on purpose: the policy stage alone issues no grade,
// and a lone claim list is not a scorecard.
import { useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ClipboardList,
  FileWarning,
  MinusCircle,
  Quote,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader, CardTitle } from './ui/Card.jsx'
import Badge, { MonoBadge } from './ui/Badge.jsx'
import { cx } from '../lib/format.js'
import { claimVerificationMeta, severityMeta } from '../lib/compliance.js'

export default function PolicyReport({ policy }) {
  if (!policy) return null

  const { satisfied_checks, failed_checks, unassessed_checks, claims = [], gap_findings = [] } = policy
  const contradicted = claims.filter((c) => c.verification === 'contradicted')
  const other = claims.filter((c) => c.verification !== 'contradicted')

  return (
    <Card>
      <CardHeader>
        <CardTitle
          icon={ClipboardList}
          hint="What the organisation's own published notice says, and whether it holds up"
        >
          Policy notice
        </CardTitle>
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="success" size="sm" icon={CheckCircle2}>
            {satisfied_checks ?? 0} satisfied
          </Badge>
          <Badge tone="danger" size="sm" icon={XCircle}>
            {failed_checks ?? 0} failed
          </Badge>
          <Badge tone="outline" size="sm" icon={MinusCircle}>
            {unassessed_checks ?? 0} unassessed
          </Badge>
        </div>
      </CardHeader>

      {gap_findings.length > 0 ? (
        <div className="border-b border-slate-200 p-4 sm:p-5 dark:border-slate-800">
          <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-800 dark:text-slate-200">
            <FileWarning size={15} className="text-slate-400" aria-hidden="true" />
            Findings from the notice itself
          </h3>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Each failed check below is a requirement the Act or the Rules place on the notice,
            with the evidence the analyser found absent. No AI writes these: they follow directly
            from the statutory checklist stage 1 reads the notice against.
          </p>
          <ul className="mt-3 space-y-2">
            {gap_findings.map((gap) => (
              <GapFindingRow key={gap.requirement_id} gap={gap} />
            ))}
          </ul>
        </div>
      ) : null}

      {claims.length > 0 ? (
        <div className="p-4 sm:p-5">
          {contradicted.length > 0 ? (
            <p className="mb-3 flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-400">
              <AlertTriangle size={13} aria-hidden="true" />
              {contradicted.length} claim{contradicted.length === 1 ? '' : 's'} contradicted by
              what the site or the code actually does
            </p>
          ) : null}
          <ul className="space-y-2">
            {[...contradicted, ...other].map((claim, index) => (
              <ClaimRow key={`${claim.claim_type}-${claim.subject}-${index}`} claim={claim} />
            ))}
          </ul>
        </div>
      ) : (
        <p className="p-4 text-xs text-slate-500 sm:p-5 dark:text-slate-400">
          No testable claims were recorded from this notice.
        </p>
      )}
    </Card>
  )
}

function GapFindingRow({ gap }) {
  const [open, setOpen] = useState(false)
  const meta = severityMeta(gap.severity)

  return (
    <li className={cx('rounded-md border-l-4 bg-white dark:bg-slate-900', meta.edge, 'border-y border-r border-slate-200 dark:border-slate-800')}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start justify-between gap-3 px-3.5 py-2.5 text-left"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={meta.tone} size="xs" uppercase icon={meta.icon}>
              {meta.label}
            </Badge>
            {gap.dpdp_section ? <MonoBadge>{gap.dpdp_section}</MonoBadge> : null}
            {gap.requires_human_validation ? (
              <Badge tone="outline" size="xs">
                Needs human check
              </Badge>
            ) : null}
          </div>
          <p className="mt-1.5 text-sm font-medium text-slate-800 dark:text-slate-200">
            {gap.title}
          </p>
        </div>
        <ChevronDown
          size={15}
          className={cx('mt-0.5 shrink-0 text-slate-400 transition-transform', open && 'rotate-180')}
          aria-hidden="true"
        />
      </button>
      {open ? (
        <div className="space-y-1.5 border-t border-slate-200 px-3.5 py-2.5 text-xs dark:border-slate-800">
          {gap.evidence ? (
            <p className="text-slate-700 dark:text-slate-300">{gap.evidence}</p>
          ) : null}
          {gap.quote ? (
            <p className="flex gap-1.5 text-slate-500 italic dark:text-slate-400">
              <Quote size={11} className="mt-0.5 shrink-0" aria-hidden="true" />
              {gap.quote}
            </p>
          ) : null}
          <p className="text-slate-400">
            {gap.dpdp_section}
            {gap.dpdp_rule ? ` · ${gap.dpdp_rule}` : ''}
          </p>
          {gap.source_url ? (
            <a
              href={gap.source_url}
              target="_blank"
              rel="noreferrer"
              className="inline-block break-all text-indigo-600 hover:underline dark:text-indigo-400"
            >
              {gap.source_url}
            </a>
          ) : null}
        </div>
      ) : null}
    </li>
  )
}

function ClaimRow({ claim }) {
  const [open, setOpen] = useState(claim.verification === 'contradicted')
  const meta = claimVerificationMeta(claim.verification)

  return (
    <li
      className={cx(
        'rounded-md border px-3 py-2.5',
        claim.verification === 'contradicted'
          ? 'border-red-200 bg-red-50/60 dark:border-red-900 dark:bg-red-950/20'
          : 'border-slate-200 dark:border-slate-800',
      )}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start justify-between gap-3 text-left"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <MonoBadge>{claim.claim_type}</MonoBadge>
            <span className="text-sm font-medium text-slate-800 dark:text-slate-200">
              {claim.subject}
            </span>
            {claim.value ? (
              <span className="text-xs text-slate-500 dark:text-slate-400">
                &ldquo;{claim.value}&rdquo;
              </span>
            ) : null}
          </div>
          <Badge tone={meta.tone} size="sm" icon={meta.icon} className="mt-1.5">
            {meta.label}
            {claim.verified_by ? ` · ${claim.verified_by} scan` : ''}
          </Badge>
        </div>
        <ChevronDown
          size={15}
          className={cx('mt-0.5 shrink-0 text-slate-400 transition-transform', open && 'rotate-180')}
          aria-hidden="true"
        />
      </button>

      {open ? (
        <div className="mt-2.5 space-y-2 border-t border-slate-200 pt-2.5 text-xs dark:border-slate-800">
          <p className="flex gap-1.5 text-slate-600 italic dark:text-slate-400">
            <Quote size={12} className="mt-0.5 shrink-0" aria-hidden="true" />
            {claim.quote}
          </p>
          {claim.verification_detail ? (
            <p className="text-slate-700 dark:text-slate-300">{claim.verification_detail}</p>
          ) : null}
          {claim.source_url ? (
            <a
              href={claim.source_url}
              target="_blank"
              rel="noreferrer"
              className="inline-block break-all text-indigo-600 hover:underline dark:text-indigo-400"
            >
              {claim.source_url}
            </a>
          ) : null}
        </div>
      ) : null}
    </li>
  )
}
