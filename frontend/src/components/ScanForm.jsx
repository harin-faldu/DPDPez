// ScanForm. OWNER: Manan
// Four modes in one component, toggled by a tab. "Full cycle" is the
// recommended path and runs stages 1-4 in order; the other three run exactly
// one stage, for a caller who already has a scan id to build on or who only
// wants one dimension. The URL shape is validated client-side only to catch
// typos early; the server still makes the real safety call about whether a
// host may be scanned.
import { useCallback, useMemo, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import {
  ClipboardList,
  FileArchive,
  Globe,
  Link2,
  Play,
  Upload,
  Workflow,
  X,
} from 'lucide-react'
import Button from './ui/Button.jsx'
import Card from './ui/Card.jsx'
import { cx, formatBytes } from '../lib/format.js'

const ARCHIVE_EXTENSIONS = ['.zip', '.tar', '.tar.gz', '.tgz']
const MAX_ARCHIVE_BYTES = 200 * 1024 * 1024

const DROPZONE_ACCEPT = {
  'application/zip': ['.zip'],
  'application/x-zip-compressed': ['.zip'],
  'application/x-tar': ['.tar'],
  'application/gzip': ['.gz', '.tgz'],
  'application/x-gzip': ['.gz', '.tgz'],
}

/** Returns an error string, or null when the URL looks usable. */
export function validateUrl(raw) {
  const value = String(raw || '').trim()
  if (!value) return 'Enter the URL of the site you want to check.'

  let parsed
  try {
    parsed = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`)
  } catch {
    return 'That does not look like a valid URL.'
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return 'Only http and https addresses can be scanned.'
  }
  const host = parsed.hostname
  if (!host) return 'The URL is missing a hostname.'
  const isLocal = looksLocal(host)
  if (!isLocal && !host.includes('.')) {
    return 'Include a full domain, for example example.co.in.'
  }
  if (!isLocal && host.startsWith('.')) return 'The hostname is malformed.'
  return null
}

/** True for a hostname that is only ever reachable on this machine or network. */
function looksLocal(hostname) {
  return hostname === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
}

/**
 * Adds the scheme the user left off, so the backend always sees an absolute URL.
 *
 * Defaults to https, except for a local host, which defaults to http. A dev
 * server on 127.0.0.1 or localhost almost never has a TLS certificate, so
 * guessing https there does not time out gracefully, it fails the handshake
 * outright, and the plain http address the person actually meant was one
 * character away the whole time.
 */
export function normaliseUrl(raw) {
  const value = String(raw || '').trim()
  if (/^https?:\/\//i.test(value)) return value
  const hostname = value.split(/[/:?#]/)[0]
  return `${looksLocal(hostname) ? 'http' : 'https'}://${value}`
}

const TABS = [
  {
    key: 'flow',
    label: 'Full cycle',
    icon: Workflow,
    hint: 'Runs policy, website and (with an archive) code in order, then combines all three into one scorecard.',
  },
  {
    key: 'policy',
    label: 'Policy notice',
    icon: ClipboardList,
    hint: 'Reads only the published privacy notice and records what it claims. No grade on its own.',
  },
  { key: 'web', label: 'Website', icon: Globe, hint: 'Crawls pages, forms, cookies and headers on their own.' },
  { key: 'code', label: 'Code archive', icon: FileArchive, hint: 'Parses an uploaded source archive on its own.' },
]

const NEEDS_URL = new Set(['flow', 'policy', 'web'])
const NEEDS_FILE = new Set(['code'])
const OPTIONAL_FILE = new Set(['flow'])

export default function ScanForm({ onSubmit, submitting = false, error = null }) {
  const [mode, setMode] = useState('flow')
  const [url, setUrl] = useState('')
  const [urlError, setUrlError] = useState(null)
  const [file, setFile] = useState(null)
  const [fileError, setFileError] = useState(null)

  const onDrop = useCallback((accepted, rejected) => {
    if (rejected && rejected.length) {
      const reason = rejected[0]?.errors?.[0]?.code
      if (reason === 'file-too-large') {
        setFileError(`That archive is larger than ${formatBytes(MAX_ARCHIVE_BYTES)}.`)
      } else if (reason === 'too-many-files') {
        setFileError('Upload one archive at a time.')
      } else {
        setFileError(`Unsupported file. Use ${ARCHIVE_EXTENSIONS.join(', ')}.`)
      }
      return
    }
    if (accepted && accepted.length) {
      setFile(accepted[0])
      setFileError(null)
    }
  }, [])

  const { getRootProps, getInputProps, isDragActive, isDragReject, open } = useDropzone({
    onDrop,
    accept: DROPZONE_ACCEPT,
    maxFiles: 1,
    multiple: false,
    maxSize: MAX_ARCHIVE_BYTES,
    noClick: true,
    noKeyboard: true,
  })

  const needsUrl = NEEDS_URL.has(mode)
  const needsFile = NEEDS_FILE.has(mode)
  const offersFile = needsFile || OPTIONAL_FILE.has(mode)

  const canSubmit = useMemo(() => {
    if (submitting) return false
    if (needsUrl && url.trim().length === 0) return false
    if (needsFile && !file) return false
    return true
  }, [submitting, needsUrl, needsFile, url, file])

  function handleSubmit(event) {
    event.preventDefault()
    if (submitting) return

    if (needsUrl) {
      const problem = validateUrl(url)
      setUrlError(problem)
      if (problem) return
    }
    if (needsFile && !file) {
      setFileError('Add a ZIP or TAR archive of the codebase.')
      return
    }

    onSubmit({
      mode,
      url: needsUrl ? normaliseUrl(url) : undefined,
      file: offersFile ? file || null : undefined,
    })
  }

  const activeTab = TABS.find((tab) => tab.key === mode) || TABS[0]

  return (
    <Card className="overflow-hidden">
      <div
        className="flex flex-wrap border-b border-slate-200 dark:border-slate-800"
        role="tablist"
        aria-label="Scan input type"
      >
        {TABS.map((tab) => {
          const active = mode === tab.key
          return (
            <button
              key={tab.key}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setMode(tab.key)}
              className={cx(
                'flex flex-1 items-center justify-center gap-2 border-b-2 px-3 py-3 text-sm font-medium whitespace-nowrap transition-colors',
                active
                  ? 'border-blue-600 text-blue-700 dark:border-blue-400 dark:text-blue-300'
                  : 'border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200',
              )}
            >
              <tab.icon size={15} aria-hidden="true" />
              {tab.label}
            </button>
          )
        })}
      </div>

      <form onSubmit={handleSubmit} className="p-4 sm:p-6">
        <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">{activeTab.hint}</p>

        {needsUrl ? (
          <div>
            <label
              htmlFor="scan-url"
              className="block text-sm font-medium text-slate-700 dark:text-slate-200"
            >
              Site to assess
            </label>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              A bare host like <code className="rounded bg-slate-100 px-1 py-0.5 font-mono dark:bg-slate-800">localhost:5001</code> is
              read as plain http, since a local dev server almost never has a TLS certificate.
            </p>
            <div className="relative mt-3">
              <Link2
                size={16}
                className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-slate-400"
                aria-hidden="true"
              />
              <input
                id="scan-url"
                type="text"
                inputMode="url"
                autoComplete="off"
                spellCheck="false"
                placeholder="https://example.co.in"
                value={url}
                onChange={(event) => {
                  setUrl(event.target.value)
                  if (urlError) setUrlError(null)
                }}
                aria-invalid={Boolean(urlError)}
                aria-describedby={urlError ? 'scan-url-error' : undefined}
                className={cx(
                  'w-full rounded-md border bg-white py-2.5 pr-3 pl-9 text-sm text-slate-900 shadow-sm',
                  'placeholder:text-slate-400 focus:outline-2 focus:outline-offset-0',
                  'dark:bg-slate-950 dark:text-slate-100',
                  urlError
                    ? 'border-red-400 focus:outline-red-500 dark:border-red-700'
                    : 'border-slate-300 focus:outline-blue-500 dark:border-slate-700',
                )}
              />
            </div>
            {urlError ? (
              <p id="scan-url-error" className="mt-2 text-xs text-red-600 dark:text-red-400">
                {urlError}
              </p>
            ) : null}
          </div>
        ) : null}

        {offersFile ? (
          <div className={needsUrl ? 'mt-5' : undefined}>
            <span className="block text-sm font-medium text-slate-700 dark:text-slate-200">
              Codebase archive
              {mode === 'flow' ? (
                <span className="ml-1.5 font-normal text-slate-400">(optional)</span>
              ) : null}
            </span>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              {mode === 'flow'
                ? 'Add one to run the code stage too. Without it the cycle stops after the website stage.'
                : 'Source is parsed locally by the scanner. Models, routes and PII fields are extracted to build the data flow map.'}
            </p>

            <div
              {...getRootProps()}
              className={cx(
                'mt-3 rounded-lg border-2 border-dashed px-4 py-8 text-center transition-colors',
                isDragReject
                  ? 'border-blue-400 bg-blue-50 dark:border-blue-700 dark:bg-blue-950/30'
                  : isDragActive
                    ? 'border-blue-500 bg-blue-50 dark:border-blue-500 dark:bg-blue-950/30'
                    : 'border-slate-300 bg-slate-50 dark:border-slate-700 dark:bg-slate-950/40',
              )}
            >
              <input {...getInputProps()} />
              {file ? (
                <div className="flex flex-wrap items-center justify-center gap-3">
                  <FileArchive size={20} className="text-blue-600 dark:text-blue-400" aria-hidden="true" />
                  <span className="min-w-0 text-sm font-medium break-all text-slate-800 dark:text-slate-100">
                    {file.name}
                  </span>
                  <span className="text-xs text-slate-500 tabular-nums dark:text-slate-400">
                    {formatBytes(file.size)}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setFile(null)
                      setFileError(null)
                    }}
                    className="inline-flex items-center gap-1 rounded border border-slate-300 px-2 py-1 text-xs text-slate-600 hover:bg-white dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                  >
                    <X size={12} aria-hidden="true" />
                    Remove
                  </button>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-2">
                  <Upload size={22} className="text-slate-400" aria-hidden="true" />
                  <p className="text-sm text-slate-600 dark:text-slate-300">
                    Drag an archive here, or{' '}
                    <button
                      type="button"
                      onClick={open}
                      className="font-medium text-blue-600 underline underline-offset-2 hover:text-blue-700 dark:text-blue-400"
                    >
                      browse
                    </button>
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {ARCHIVE_EXTENSIONS.join(', ')} up to {formatBytes(MAX_ARCHIVE_BYTES)}
                  </p>
                </div>
              )}
            </div>
            {fileError ? (
              <p className="mt-2 text-xs text-red-600 dark:text-red-400">{fileError}</p>
            ) : null}
          </div>
        ) : null}

        {error ? (
          <p className="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
            {error}
          </p>
        ) : null}

        <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Scans run in the background. You are taken to the live scorecard.
          </p>
          <Button type="submit" size="lg" icon={Play} loading={submitting} disabled={!canSubmit}>
            {submitting ? 'Starting scan' : mode === 'flow' ? 'Run the full cycle' : 'Run this stage'}
          </Button>
        </div>
      </form>
    </Card>
  )
}
