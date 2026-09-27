// CodeViewer. OWNER: Manan
// Syntax-highlighted snippet with the flagged line marked.
// PrismLight with explicit language registration keeps the bundle to the
// grammars this scanner actually reports on.
import { PrismLight as SyntaxHighlighter } from 'react-syntax-highlighter'
import bash from 'react-syntax-highlighter/dist/esm/languages/prism/bash'
import css from 'react-syntax-highlighter/dist/esm/languages/prism/css'
import go from 'react-syntax-highlighter/dist/esm/languages/prism/go'
import java from 'react-syntax-highlighter/dist/esm/languages/prism/java'
import javascript from 'react-syntax-highlighter/dist/esm/languages/prism/javascript'
import jsx from 'react-syntax-highlighter/dist/esm/languages/prism/jsx'
import json from 'react-syntax-highlighter/dist/esm/languages/prism/json'
import markup from 'react-syntax-highlighter/dist/esm/languages/prism/markup'
import php from 'react-syntax-highlighter/dist/esm/languages/prism/php'
import python from 'react-syntax-highlighter/dist/esm/languages/prism/python'
import ruby from 'react-syntax-highlighter/dist/esm/languages/prism/ruby'
import sql from 'react-syntax-highlighter/dist/esm/languages/prism/sql'
import tsx from 'react-syntax-highlighter/dist/esm/languages/prism/tsx'
import typescript from 'react-syntax-highlighter/dist/esm/languages/prism/typescript'
import yaml from 'react-syntax-highlighter/dist/esm/languages/prism/yaml'
import { oneDark, oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { FileCode2 } from 'lucide-react'
import { languageFromPath } from '../lib/format.js'
import { useTheme } from '../lib/theme.jsx'

const LANGUAGES = {
  bash,
  css,
  go,
  java,
  javascript,
  jsx,
  json,
  markup,
  php,
  python,
  ruby,
  sql,
  tsx,
  typescript,
  yaml,
}

Object.entries(LANGUAGES).forEach(([name, definition]) => {
  SyntaxHighlighter.registerLanguage(name, definition)
})

/**
 * Snippets rarely start at line one, so startLine offsets the gutter. The
 * highlighter reports absolute numbers to lineProps once showLineNumbers is on,
 * which is what highlightLine is compared against.
 */
export default function CodeViewer({
  code,
  filePath,
  language,
  startLine = 1,
  highlightLine = null,
  maxHeight = 320,
}) {
  const { isDark } = useTheme()
  if (!code) return null

  const resolvedLanguage = language || languageFromPath(filePath)
  const safeLanguage = LANGUAGES[resolvedLanguage] ? resolvedLanguage : 'javascript'
  const firstLine = Number.isFinite(Number(startLine)) && Number(startLine) > 0 ? Number(startLine) : 1

  const highlightBackground = isDark ? 'rgba(248, 113, 113, 0.16)' : 'rgba(254, 202, 202, 0.55)'
  const highlightBorder = isDark ? '#f87171' : '#dc2626'

  return (
    <div className="overflow-hidden rounded-md border border-slate-200 dark:border-slate-700">
      {filePath ? (
        <div className="flex items-center justify-between gap-2 border-b border-slate-200 bg-slate-50 px-3 py-1.5 dark:border-slate-700 dark:bg-slate-800/70">
          <span className="flex min-w-0 items-center gap-1.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
            <FileCode2 size={12} className="shrink-0" aria-hidden="true" />
            <span className="truncate">{filePath}</span>
          </span>
          {highlightLine ? (
            <span className="shrink-0 font-mono text-[11px] text-red-600 tabular-nums dark:text-red-400">
              line {highlightLine}
            </span>
          ) : null}
        </div>
      ) : null}

      <SyntaxHighlighter
        language={safeLanguage}
        style={isDark ? oneDark : oneLight}
        showLineNumbers
        wrapLines
        startingLineNumber={firstLine}
        lineNumberStyle={{
          minWidth: '2.6em',
          paddingRight: '1em',
          opacity: 0.45,
          userSelect: 'none',
        }}
        lineProps={(lineNumber) =>
          lineNumber === Number(highlightLine)
            ? {
                style: {
                  display: 'block',
                  backgroundColor: highlightBackground,
                  boxShadow: `inset 3px 0 0 0 ${highlightBorder}`,
                },
              }
            : { style: { display: 'block' } }
        }
        customStyle={{
          margin: 0,
          fontSize: '12px',
          lineHeight: 1.6,
          maxHeight: `${maxHeight}px`,
          background: isDark ? '#0f172a' : '#f8fafc',
        }}
        codeTagProps={{ style: { fontFamily: 'inherit' } }}
      >
        {String(code).replace(/\n$/, '')}
      </SyntaxHighlighter>
    </div>
  )
}
