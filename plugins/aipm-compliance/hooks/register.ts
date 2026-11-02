import type { Register } from 'claude-code'

// Must match skills/confidential-legend/SKILL.md + scripts/check_legend.py
// and skills/no-egress/SKILL.md + scripts/check_egress.py.
const LEGEND = /CONFIDENTIAL\s*[–—-]\s*FOR INTERNAL USE ONLY|AIPM-CONFIDENTIAL-INTERNAL|aipm-audience:\s*external/i
const HTML = /\.html?$/i
const DELIVERABLE = /\.(html?|docx|pptx|xlsx|pdf)$/i
// Everything check_egress.py has a verdict for, including the formats it refuses outright (svg, mhtml, macro-enabled, xlsb).
const EGRESS_FILES = /\.(html?|svg|xhtml?|xht|mhtml?|docx|dotx|docm|dotm|xlsx|xltx|xlsm|xltm|xlam|xlsb|pptx|potx|ppsx|pptm|potm|ppsm|ppam|pdf)$/i
// App development account: the no-egress check is skipped (the legend check still runs). Not mentioned in the distributed skill.
const EXEMPT_ACCOUNT = 'wscott@advancedipm.com'
const TIMEOUT_MS = 120_000 // a 20 MB page or a qpdf expansion can take seconds; the default 30 s would fail the guard

const legendWhy = (paths: string[]) =>
  `aipm-compliance: ${paths.join(', ')} lacks the Advanced IPM confidentiality legend. ` +
  `Add it per the confidential-legend skill (or mark it external if customer-facing), then retry.`
const egressWhy = (detail: string) =>
  `aipm-compliance: the file can send data out or its no-egress guard cannot be proven:\n${detail}\n` +
  `Fix the generator per the no-egress skill (generated head block, pinned providers, no network/navigation/storage APIs), then retry.`
const brokenWhy = (what: string, err: unknown) =>
  `aipm-compliance: the ${what} check could not run (${String(err).slice(0, 200)}); refusing rather than skipping the guard.`

const strings = (v: unknown): string[] =>
  typeof v === 'string' ? [v] : Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string')
  : v && typeof v === 'object' ? Object.entries(v as Record<string, unknown>).flatMap(([k, x]) => [k, ...strings(x)]) : []

// Runs check_egress.py on files already on disk, or on `content` (a Write that hasn't landed yet). Throws if it cannot run.
async function egress($: any, paths: string[], content?: string): Promise<string | null> {
  const files = paths.filter(p => EGRESS_FILES.test(p))
  if (!files.length) return null
  const argv = ['python3', `${$.plugin.root}/skills/no-egress/scripts/check_egress.py`, '--exempt-account', EXEMPT_ACCOUNT]
  const r = content === undefined
    ? await $.process.run([...argv, ...files], { timeoutMs: TIMEOUT_MS })
    : await $.process.run([...argv, '--stdin', files[0]], { stdin: content, timeoutMs: TIMEOUT_MS })
  if (r.exitCode === 0) return null
  const lines = r.stdout.split('\n').filter((l: string) => l.startsWith('EGRESS:'))
  return lines.length ? lines.join('\n') : `${files.join(', ')}: check_egress.py failed (exit ${r.exitCode}) ${r.stderr?.slice(0, 200) ?? ''}`
}

// Hand-off chokepoints: a file shown to the user or published must pass both checkers. Any failure to check is a deny.
async function gate($: any, paths: string[], e: any, next: any) {
  try {
    const files = paths.filter(p => DELIVERABLE.test(p))
    if (files.length) {
      const r = await $.process.run(['python3', `${$.plugin.root}/skills/confidential-legend/scripts/check_legend.py`, ...files], { timeoutMs: TIMEOUT_MS })
      if (r.exitCode !== 0) {
        const missing = r.stdout.split('\n').filter(Boolean).map((l: string) => l.replace('MISSING LEGEND: ', ''))
        return { deny: legendWhy(missing.length ? missing : files) }
      }
    }
    const bad = await egress($, paths)
    return bad ? { deny: egressWhy(bad) } : next(e)
  } catch (err) {
    return { deny: brokenWhy('hand-off', err) }
  }
}

export const register: Register = on => {
  // HTML isn't on disk yet at Write time; check the content itself (over stdin, so size is not an argv problem).
  on('tool.call', { tool: 'Write' }, async ($, e, next) => {
    if (!HTML.test(e.file_path)) return next(e)
    if (!LEGEND.test(e.content)) return { deny: legendWhy([e.file_path]) }
    try {
      const bad = await egress($, [e.file_path], e.content)
      return bad ? { deny: egressWhy(bad) } : next(e)
    } catch (err) {
      return { deny: brokenWhy('Write', err) }
    }
  })

  on('tool.call', { tool: 'SendUserFile' }, ($, e, next) => gate($, strings((e as any).files), e, next))
  // Every path an Artifact call can carry, whether published as the page or uploaded as an asset.
  on('tool.call', { tool: 'Artifact' }, ($, e, next) => {
    const a = e as any
    return gate($, [...strings(a.file_path), ...strings(a.file_paths), ...strings(a.files)], e, next)
  })
}
