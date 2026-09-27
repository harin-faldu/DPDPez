// Small formatting helpers shared across the dashboard.

/**
 * Normalise a score to a 0 to 100 integer.
 * Rule scores arrive as 0 to 1 fractions from the rules engine, while the
 * overall score may already be on a 0 to 100 scale. Any value at or below 1 is
 * read as a fraction.
 */
export function toPercent(value) {
  if (value === null || value === undefined) return null
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return null
  const percent = numeric <= 1 ? numeric * 100 : numeric
  return Math.max(0, Math.min(100, Math.round(percent)))
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / 1024 ** exponent
  return `${value >= 10 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`
}

export function formatElapsed(seconds) {
  const total = Math.max(0, Math.floor(seconds))
  if (total < 60) return `${total}s`
  const minutes = Math.floor(total / 60)
  const remainder = total % 60
  return `${minutes}m ${String(remainder).padStart(2, '0')}s`
}

/** Keep the tail of a long path, which is the part that identifies the file. */
export function shortenPath(path, maxLength = 54) {
  if (!path) return ''
  if (path.length <= maxLength) return path
  return `...${path.slice(path.length - maxLength + 3)}`
}

export function fileLabel(filePath, lineNumber) {
  if (!filePath) return null
  return lineNumber ? `${filePath}:${lineNumber}` : filePath
}

/** Map a file extension onto a Prism language id registered in CodeViewer. */
export function languageFromPath(filePath) {
  const extension = String(filePath || '').split('.').pop().toLowerCase()
  const map = {
    js: 'javascript',
    mjs: 'javascript',
    cjs: 'javascript',
    jsx: 'jsx',
    ts: 'typescript',
    tsx: 'tsx',
    py: 'python',
    rb: 'ruby',
    go: 'go',
    java: 'java',
    php: 'php',
    sql: 'sql',
    json: 'json',
    yml: 'yaml',
    yaml: 'yaml',
    sh: 'bash',
    bash: 'bash',
    env: 'bash',
    html: 'markup',
    htm: 'markup',
    xml: 'markup',
    vue: 'markup',
    css: 'css',
    scss: 'css',
  }
  return map[extension] || 'javascript'
}

export function pluralise(count, singular, plural) {
  return count === 1 ? singular : plural || `${singular}s`
}

/** Join conditional class names without pulling in another dependency. */
export function cx(...parts) {
  return parts.filter(Boolean).join(' ')
}
