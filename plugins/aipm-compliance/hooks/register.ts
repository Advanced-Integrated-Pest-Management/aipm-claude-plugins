import type { Register } from 'claude-code'

// Must match skills/confidential-legend/SKILL.md + scripts/check_legend.py
// and skills/no-egress/SKILL.md + scripts/check_egress.py.
const LEGEND = /CONFIDENTIAL\s*[–—-]\s*FOR INTERNAL USE ONLY|AIPM-CONFIDENTIAL-INTERNAL|aipm-audience:\s*external/i
const HTML = /\.html?$/i
const DELIVERABLE = /\.(html?|docx|pptx|xlsx|pdf)$/i
const EGRESS_FILES = /\.(html?|docx|pptx|xlsx|pdf|docm|xlsm|pptm|dotx|potx)$/i
// App development account: the no-egress check is skipped (the legend check still runs). See no-egress/SKILL.md.
const EXEMPT_ACCOUNT = 'wscott@advancedipm.com'

const legendWhy = (paths: string[]) =>
  `aipm-compliance: ${paths.join(', ')} lacks the Advanced IPM confidentiality legend. ` +
  `Add it per the confidential-legend skill (or mark it external if customer-facing), then retry.`
const egressWhy = (detail: string) =>
  `aipm-compliance: the file can send data out or loads from an unapproved host:\n${detail}\n` +
  `Fix the generator per the no-egress skill (CSP head block, pinned providers, no network or storage APIs), then retry.`

// Runs check_egress.py on files already on disk, or on `content` (a Write that hasn't landed yet).
async function egress($: any, paths: string[], content?: string): Promise<string | null> {
  const files = paths.filter(p => EGRESS_FILES.test(p))
  if (!files.length) return null
  const argv = ['python3', `${$.plugin.root}/skills/no-egress/scripts/check_egress.py`, '--exempt-account', EXEMPT_ACCOUNT]
  const r = content === undefined
    ? await $.process.run([...argv, ...files])
    : await $.process.run([...argv, '--stdin', files[0]], { stdin: content })
  if (r.exitCode === 0) return null
  const lines = r.stdout.split('\n').filter((l: string) => l.startsWith('EGRESS:'))
  return lines.length ? lines.join('\n') : `${files.join(', ')}: check_egress.py failed (exit ${r.exitCode})`
}

// Hand-off chokepoints: a file shown to the user or published must pass both checkers.
async function gate($: any, paths: string[], e: any, next: any) {
  const files = paths.filter(p => DELIVERABLE.test(p))
  if (files.length) {
    const r = await $.process.run(['python3', `${$.plugin.root}/skills/confidential-legend/scripts/check_legend.py`, ...files])
    if (r.exitCode !== 0) {
      const missing = r.stdout.split('\n').filter(Boolean).map((l: string) => l.replace('MISSING LEGEND: ', ''))
      return { deny: legendWhy(missing.length ? missing : files) }
    }
  }
  const bad = await egress($, paths)
  return bad ? { deny: egressWhy(bad) } : next(e)
}

export const register: Register = on => {
  // HTML isn't on disk yet at Write time; check the content itself.
  on('tool.call', { tool: 'Write' }, async ($, e, next) => {
    if (!HTML.test(e.file_path)) return next(e)
    if (!LEGEND.test(e.content)) return { deny: legendWhy([e.file_path]) }
    const bad = await egress($, [e.file_path], e.content)
    return bad ? { deny: egressWhy(bad) } : next(e)
  })

  on('tool.call', { tool: 'SendUserFile' }, ($, e, next) => gate($, (e as any).files ?? [], e, next))
  on('tool.call', { tool: 'Artifact' }, ($, e, next) => {
    const a = e as any
    return a.asset || !a.file_path ? next(e) : gate($, [a.file_path], e, next)
  })
}
