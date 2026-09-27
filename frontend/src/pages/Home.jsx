// Home. OWNER: Manan
// Landing page: the scan form, and the case for why the tool looks the way it
// does. Written for a hackathon reader as much as a first-time user, since the
// two questions they ask are the same one: why four stages instead of one
// scorecard.
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Ban,
  BookMarked,
  CheckCircle2,
  ClipboardList,
  Database,
  FileWarning,
  GitBranch,
  Globe,
  Quote,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Workflow,
} from 'lucide-react'
import AppShell from '../components/AppShell.jsx'
import ScanForm from '../components/ScanForm.jsx'
import Card, { CardHeader, CardTitle } from '../components/ui/Card.jsx'
import Badge, { MonoBadge } from '../components/ui/Badge.jsx'
import { startCodeScan, startPolicyScan, startWebScan } from '../api/client.js'

const CAPABILITIES = [
  {
    icon: ClipboardList,
    title: 'Thirteen compliance dimensions',
    body: 'Notice through cross-border transfer, plus the CERT-In Directions a body corporate in India carries independently of the DPDP Act. Each is a deterministic checker: run the same scan twice and the verdict does not move.',
  },
  {
    icon: BookMarked,
    title: 'Every finding cites the Act',
    body: 'Findings carry the section they rest on and the statutory text itself, so a reviewer can check the verdict against the source rather than taking it on trust.',
  },
  {
    icon: ShieldAlert,
    title: 'Citations are verified',
    body: 'A guardrail matches each quoted provision back to the indexed corpus. Anything it cannot confirm is labelled unverified in the report instead of being hidden.',
  },
  {
    icon: Workflow,
    title: 'Four stages, one aggregate',
    body: 'Policy, website, code and a combined scorecard. A rule assessed by more than one stage takes its weakest score; a rule no stage reached is excluded from the grade, never scored zero.',
  },
  {
    icon: FileWarning,
    title: 'Gaps read as findings',
    body: "A failed statutory check on the notice itself is not just a count. It shows up as a finding, with the evidence, the section it rests on and a severity, the same as a web or code finding does.",
  },
  {
    icon: Ban,
    title: 'No AI decides compliance',
    body: 'A deterministic rules engine reaches every verdict from evidence alone. The model is only ever asked to explain and cite a verdict already reached, never to reach one.',
  },
]

const STEPS = [
  {
    icon: ClipboardList,
    title: 'Read the notice',
    body: 'The published privacy notice is read for what it promises: 15 statutory requirements it must cover, and testable claims a later stage can check.',
  },
  {
    icon: Globe,
    title: 'Watch the site',
    body: 'A live crawl tests those claims against what the site actually does, and evaluates everything a page load can answer on its own.',
  },
  {
    icon: GitBranch,
    title: 'Read the code',
    body: 'An uploaded archive resolves what the crawl could not see: retention, breach reporting, storage region, CERT-In infrastructure facts, and more.',
  },
  {
    icon: Workflow,
    title: 'Combine the three',
    body: 'One scorecard from whichever stages ran. A rule assessed by more than one takes its weakest score; a rule no stage reached is excluded, not penalised.',
  },
]

// The rule set the scorecard is actually weighted on. Grounded in
// backend/app/rules/*.py: RULE_ID, DPDP_SECTION, DPDP_RULE and RETRIEVAL_SECTION_IDS
// are read straight from those files, and "assessed by" is empirical, confirmed by
// running both a web-only and a code-only scan and reading which rules came back
// not_applicable on each side.
const RULES = [
  {
    id: 'R3',
    name: 'Notice',
    act: 's.5',
    rules: 'Rule 3',
    stage: 'web',
    checks:
      'The notice is reachable before anything is collected, names a specified purpose, a retention period, a route to the Board and a contact point.',
  },
  {
    id: 'R4',
    name: 'Consent',
    act: 's.6, s.7',
    rules: 'Rule 4',
    stage: 'both',
    checks:
      'Consent is a real, itemised, pre-unchecked choice; refusing takes the same one click as accepting; nothing tracks before that choice; withdrawal is as easy as giving, and the server actually holds a consent record.',
  },
  {
    id: 'R5',
    name: "Children's data",
    act: 's.9',
    rules: 'Rule 5, 10, 12',
    stage: 'both',
    checks:
      "Only engages when the site genuinely targets children, then checks for an age gate, verifiable parental consent, and that a child's tracking is not silently exempted.",
  },
  {
    id: 'R6',
    name: 'Security safeguards',
    act: 's.8(4), s.8(5)',
    rules: 'Rule 6',
    stage: 'both',
    checks:
      'Encryption of personal data, password hashing, HTTPS and security headers, cookie Secure/HttpOnly/SameSite flags, and whether sensitive fields are exposed in the clear.',
  },
  {
    id: 'R7',
    name: 'Breach notification',
    act: 's.8(6)',
    rules: 'Rule 7',
    stage: 'code',
    checks:
      'A breach record model exists, a notification path reaches someone, and the code respects the intimation timeline.',
  },
  {
    id: 'R8',
    name: 'Impact assessment',
    act: 's.10(2)',
    rules: 'Rule 13*',
    stage: 'code',
    checks:
      'A DPIA document exists, a risk register is maintained, and it actually covers the high-risk processing the code scan found.',
  },
  {
    id: 'R9',
    name: 'Significant fiduciary duties',
    act: 's.10(1), s.10(2)',
    rules: 'Rule 13*',
    stage: 'both',
    checks:
      'Scale indicators that would trigger Significant Data Fiduciary duties, a published Data Protection Officer, an independent audit, and algorithmic fairness.',
  },
  {
    id: 'R10',
    name: 'Data principal rights',
    act: 's.11-14',
    rules: 'Rule 14*',
    stage: 'both',
    checks:
      'Working paths for access, correction, erasure and nominating someone to act for you, plus a grievance channel, checked both for existing and for being reachable.',
  },
  {
    id: 'R11',
    name: 'Board readiness',
    act: 's.13, s.27',
    rules: 'Rule 9, 14*',
    stage: 'both',
    checks:
      'A grievance intake that gets tracked to resolution, and an inbound path for a Data Protection Board direction under s.27.',
  },
  {
    id: 'R12',
    name: 'Compliance verification',
    act: 's.8(1)',
    rules: 'Rule 6*',
    stage: 'code',
    checks:
      'An audit trail of who accessed personal data, a record of processing activities, and whether either is actually retrievable, not just present.',
  },
  {
    id: 'RET',
    name: 'Retention & erasure',
    act: 's.8(7)',
    rules: 'Rule 8',
    stage: 'code',
    checks:
      'A configured retention period, an expiry mechanism, a cleanup job that runs it, and erasure that propagates to every linked store, not only the primary one.',
  },
  {
    id: 'CERTIN',
    name: 'CERT-In Directions',
    act: 's.70B(6) IT Act',
    rules: 'Rule 6, 7*',
    stage: 'code',
    checks:
      'NTP sync to samay1/2.nic.in or NPL, 180-day log retention inside Indian jurisdiction, an incident path reachable inside six hours, no hardcoded secrets or credentials logged in the clear, no deprecated TLS.',
    highlight: true,
  },
  {
    id: 'XBORDER',
    name: 'Cross-border transfer',
    act: 's.16',
    rules: 'Rule 15',
    stage: 'code',
    checks:
      'Whether any configured storage region sits outside India, read from the same infrastructure facts the CERT-In check reads, for a different obligation.',
  },
]

const STAGE_META = {
  web: { label: 'Web', tone: 'info' },
  code: { label: 'Code', tone: 'accent' },
  both: { label: 'Web + Code', tone: 'success' },
}

const NOTICE_REQUIREMENTS = [
  'Itemised personal data collected', 'The specified purpose, tied to the goods or service',
  'That consent can be withdrawn as easily as given', 'How to exercise a data principal right',
  'How to complain to the Data Protection Board', 'A contact point for processing questions',
  'The retention period, or the criteria for it', 'Third party sharing, named where it happens',
  'Cross-border transfer, where it happens', 'Security measures in place',
  'Breach intimation commitments', "Provisions specific to a child's data",
  'A grievance redressal mechanism', 'Whether a Consent Manager is used',
  'Plain, clear language rather than legalese',
]

export default function Home() {
  const navigate = useNavigate()
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  async function handleSubmit(payload) {
    setSubmitting(true)
    setError(null)
    try {
      if (payload.mode === 'flow') {
        // The flow page does its own orchestration (policy, then web, then
        // code if a file was given, then the aggregate). It needs the raw
        // inputs, which cannot travel through a URL, so they go through
        // router state instead of a query string.
        navigate('/flow', { state: { url: payload.url, file: payload.file || null } })
        return
      }

      let response
      if (payload.mode === 'policy') {
        response = await startPolicyScan(payload.url)
      } else if (payload.mode === 'web') {
        response = await startWebScan(payload.url)
      } else {
        response = await startCodeScan(payload.file)
      }
      const scanId = response?.scan_id
      if (!scanId) {
        throw new Error('The scanner accepted the job but did not return a scan id.')
      }
      navigate(`/scans/${scanId}`)
    } catch (caught) {
      setError(caught?.message || 'Could not start the scan.')
      setSubmitting(false)
    }
  }

  return (
    <AppShell width="wide">
      <section className="mx-auto max-w-3xl text-center">
        <span className="inline-flex items-center gap-1.5 rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 text-xs font-medium text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950/50 dark:text-indigo-300">
          Digital Personal Data Protection Act, 2023
        </span>
        <h1 className="mt-4 text-3xl font-bold tracking-tight text-balance text-slate-900 sm:text-4xl dark:text-slate-50">
          Check a product against the DPDP Act before a regulator does
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-base leading-relaxed text-pretty text-slate-600 dark:text-slate-300">
          Point it at a privacy notice, a live website, a codebase, or all three as one cycle. It
          gathers the evidence, evaluates it across thirteen compliance dimensions drawn from the
          Act, the notified Rules 2025, and the CERT-In Directions, and returns a graded scorecard
          where every finding names the provision it rests on.
        </p>
      </section>

      <section className="mx-auto mt-8 max-w-2xl">
        <ScanForm onSubmit={handleSubmit} submitting={submitting} error={error} />
      </section>

      <section className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {CAPABILITIES.map((item) => (
          <Card key={item.title} padded>
            <item.icon
              size={20}
              className="text-indigo-600 dark:text-indigo-400"
              aria-hidden="true"
            />
            <h2 className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
              {item.title}
            </h2>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              {item.body}
            </p>
          </Card>
        ))}
      </section>

      {/* ---------------------------------------------------------- the brief */}
      <section className="mx-auto mt-16 max-w-3xl">
        <SectionLabel icon={Quote}>Where this started</SectionLabel>
        <Card className="mt-3 border-indigo-200 dark:border-indigo-900">
          <div className="p-5 sm:p-6">
            <p className="text-xs font-semibold tracking-wide text-indigo-700 uppercase dark:text-indigo-300">
              The original problem statement
            </p>
            <blockquote className="mt-2 border-l-2 border-indigo-300 pl-4 text-sm leading-relaxed text-slate-700 italic dark:border-indigo-700 dark:text-slate-300">
              "DPDP compliance self-check. A tool that scans a sample web form or app and produces
              a compliance scorecard against DPDP basics: consent, purpose limitation, and
              retention." Build target: a scorecard generator for a sample form or app.
            </blockquote>
          </div>
        </Card>

        <div className="mt-4 space-y-3 text-sm leading-relaxed text-slate-600 dark:text-slate-300">
          <p>
            A scorecard generator for one form does not survive contact with a real product. A
            page can promise it never shares data while a tracker fires before anyone clicks
            anything; a login form can look clean while the encryption it claims lives only in the
            notice. Reading one surface and grading it would have produced a confident number
            about the wrong thing.
          </p>
          <p>
            So the build target became a pipeline instead of a page: read what a business{' '}
            <strong>says</strong> about itself, watch what its site <strong>does</strong>, read
            what its code <strong>actually implements</strong>, and only then combine the three.
            Consent, purpose limitation and retention are still in there, at R4 and RET, alongside
            ten more dimensions the same self-check needed once it had to survive a real target
            instead of a sample form.
          </p>
        </div>
      </section>

      {/* -------------------------------------------------------------- steps */}
      <section className="mt-14">
        <SectionLabel icon={Workflow}>How the full cycle runs</SectionLabel>
        <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
          Each of these also runs on its own from the tabs above, without the others.
        </p>
        <ol className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((step, index) => (
            <li
              key={step.title}
              className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
            >
              <div className="flex items-center gap-2">
                <span className="flex size-6 items-center justify-center rounded-full bg-slate-100 text-xs font-semibold text-slate-600 tabular-nums dark:bg-slate-800 dark:text-slate-300">
                  {index + 1}
                </span>
                <step.icon size={15} className="text-slate-400" aria-hidden="true" />
                <h3 className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {step.title}
                </h3>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                {step.body}
              </p>
            </li>
          ))}
        </ol>
      </section>

      {/* --------------------------------------------------------- notice list */}
      <section className="mt-14">
        <SectionLabel icon={ClipboardList}>Stage 1 reads the notice against 15 requirements</SectionLabel>
        <p className="mt-1.5 max-w-3xl text-xs text-slate-500 dark:text-slate-400">
          These come from the notice content the Act and Rule 3 require, not from the 13 scored
          rules below. A missing one is reported as a gap finding with its own evidence and
          severity; it never carries a score on its own, because the policy stage issues no grade
          by itself.
        </p>
        <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {NOTICE_REQUIREMENTS.map((item) => (
            <div
              key={item}
              className="flex items-start gap-2 rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
            >
              <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-slate-300 dark:text-slate-600" aria-hidden="true" />
              {item}
            </div>
          ))}
        </div>
      </section>

      {/* ---------------------------------------------------------- rules table */}
      <section className="mt-14">
        <SectionLabel icon={ScrollText}>The thirteen scored rules</SectionLabel>
        <p className="mt-1.5 max-w-3xl text-xs text-slate-500 dark:text-slate-400">
          "Assessed by" is not a design claim, it is measured: a rule marked Web only came back
          not-applicable on a code-only scan, and the reverse. A rule assessed by both stages is
          scored on the weaker of the two, not their average. Rules marked * cite the notified
          Rules 2025 number that actually governs the topic, which is not always the same digit as
          the rule's own name.
        </p>
        <Card className="mt-4 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-[11px] tracking-wide text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
                  <th className="px-4 py-2.5 sm:px-5">Rule</th>
                  <th className="px-3 py-2.5">DPDP Act</th>
                  <th className="px-3 py-2.5">Rules 2025</th>
                  <th className="px-3 py-2.5">Assessed by</th>
                  <th className="px-4 py-2.5 sm:px-5">What it checks</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {RULES.map((rule) => {
                  const stage = STAGE_META[rule.stage]
                  return (
                    <tr key={rule.id} className={rule.highlight ? 'bg-amber-50/50 dark:bg-amber-950/10' : undefined}>
                      <td className="px-4 py-3 align-top sm:px-5">
                        <div className="flex items-center gap-2">
                          <MonoBadge>{rule.id}</MonoBadge>
                        </div>
                        <p className="mt-1 font-medium text-slate-800 dark:text-slate-200">{rule.name}</p>
                      </td>
                      <td className="px-3 py-3 align-top whitespace-nowrap text-slate-600 dark:text-slate-400">
                        {rule.act}
                      </td>
                      <td className="px-3 py-3 align-top whitespace-nowrap text-slate-600 dark:text-slate-400">
                        {rule.rules}
                      </td>
                      <td className="px-3 py-3 align-top">
                        <Badge tone={stage.tone} size="sm">
                          {stage.label}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 align-top leading-relaxed text-slate-600 sm:px-5 dark:text-slate-400">
                        {rule.checks}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      </section>

      {/* -------------------------------------------------------------- CERT-In */}
      <section className="mt-14">
        <Card className="border-amber-300 bg-amber-50/40 dark:border-amber-800 dark:bg-amber-950/20">
          <div className="p-5 sm:p-6">
            <SectionLabel icon={ShieldAlert} tone="amber">
              CERT-In Directions, checked independently of the DPDP Act
            </SectionLabel>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-slate-700 dark:text-slate-300">
              The Directions of 28 April 2022, issued under section 70B(6) of the Information
              Technology Act 2000, bind every body corporate in India regardless of whether the
              DPDP Act applies to a given system. They sit in the scorecard as their own rule,{' '}
              <MonoBadge>CERTIN</MonoBadge>, rather than as a footnote next to the DPDP rules that
              happen to share evidence with it.
            </p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[
                { title: 'Clock synchronisation', body: 'NTP pointed at samay1.nic.in, samay2.nic.in or time.nplindia.org, without which a breach timeline cannot be reconstructed across systems.' },
                { title: 'Log retention & sovereignty', body: '180 days minimum, held inside Indian jurisdiction; DPDP pushes access logs to a full year on top of that floor.' },
                { title: 'Incident reporting', body: 'An alerting path that can reach a responder inside the six-hour reporting window, not an error swallowed and written to local disk.' },
                { title: 'Cryptographic posture', body: 'No hardcoded secrets, no credentials logged in clear text, no deprecated TLS still accepted at the edge.' },
              ].map((item) => (
                <div key={item.title} className="rounded-md border border-amber-200 bg-white p-3 dark:border-amber-900 dark:bg-slate-900">
                  <p className="text-xs font-semibold text-amber-900 dark:text-amber-200">{item.title}</p>
                  <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-400">{item.body}</p>
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
              Read only from a code scan: a crawl cannot see a Dockerfile or a Terraform region, so
              a web-only run correctly reports CERTIN as not assessed rather than guessing.
              <MonoBadge className="ml-1.5">XBORDER</MonoBadge> reads the same declared storage
              regions for a related but distinct question: not whether logs stay in India, but
              whether personal data itself is sent outside it under s.16.
            </p>
          </div>
        </Card>
      </section>

      {/* ---------------------------------------------------- our own compliance */}
      <section className="mt-14 mb-4">
        <SectionLabel icon={ShieldCheck}>How the tool holds itself to the same standard</SectionLabel>
        <p className="mt-1.5 max-w-3xl text-xs text-slate-500 dark:text-slate-400">
          A compliance scanner that mishandled what it found would be its own worst finding. Two
          honest answers: what already holds, and what a production deployment would still need to
          add.
        </p>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <Card padded className="border-emerald-200 dark:border-emerald-900">
            <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-400">
              <Database size={17} aria-hidden="true" />
              <h3 className="text-sm font-semibold">Already true: no raw data is stored</h3>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              A secret the code scanner finds is recorded as "credential literal, redacted, 30
              characters", never the value. A personal-data field is recorded by category, file and
              line, never its content. This is not a policy layered on afterward, it is the shape
              of the data classes themselves: <MonoBadge>PayloadPII</MonoBadge> and{' '}
              <MonoBadge>PIIFieldRef</MonoBadge> have no field a raw value could go in. What the
              database does keep is the scan's own evidence trail, which rule passed and why, which
              host was contacted, which section it cites, because that is the report, and none of
              it is a data principal's actual information.
            </p>
          </Card>
          <Card padded className="border-amber-200 dark:border-amber-900">
            <div className="flex items-center gap-2 text-amber-700 dark:text-amber-400">
              <Sparkles size={17} aria-hidden="true" />
              <h3 className="text-sm font-semibold">Open item: a DPA with the AI vendor</h3>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              The only data leaving this deployment goes to the generation and embedding
              providers, and only a rule's already-decided evidence text plus public statutory
              text, never a raw secret or personal-data value. That should still rest on a signed
              data processing agreement with the provider before a production deployment, not on
              the shape of the prompt alone. The provider is already swappable by config (
              <MonoBadge>AI_PROVIDER</MonoBadge>), which is also the path to a self-hosted model
              and zero external calls, for a deployment that wants that instead of a DPA.
            </p>
          </Card>
        </div>
      </section>
    </AppShell>
  )
}

function SectionLabel({ icon: Icon, children, tone = 'default' }) {
  return (
    <h2
      className={
        tone === 'amber'
          ? 'flex items-center gap-2 text-sm font-semibold tracking-wide text-amber-800 uppercase dark:text-amber-300'
          : 'flex items-center gap-2 text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400'
      }
    >
      <Icon size={15} aria-hidden="true" />
      {children}
    </h2>
  )
}
