import type { Register } from 'claude-code'

// Must match skills/confidential-legend/SKILL.md and bin/check_legend.py.
const LEGEND = /CONFIDENTIAL\s*[–—-]\s*FOR INTERNAL USE ONLY|AIPM-CONFIDENTIAL-INTERNAL|aipm-audience:\s*external/i
const HTML = /\.html?$/i
const DELIVERABLE = /\.(html?|docx|pptx|xlsx|pdf)$/i

const why = (paths: string[]) =>
  `aipm-compliance: ${paths.join(', ')} lacks the Advanced IPM confidentiality legend. ` +
  `Add it per the confidential-legend skill (or mark it external if customer-facing), then retry.`

// Hand-off chokepoints: a file shown to the user or published must pass the checker.
async function gate($: any, paths: string[], e: any, next: any) {
  const files = paths.filter(p => DELIVERABLE.test(p))
  if (!files.length) return next(e)
  const r = await $.process.run(['python3', `${$.plugin.root}/bin/check_legend.py`, ...files])
  if (r.exitCode === 0) return next(e)
  const missing = r.stdout.split('\n').filter(Boolean).map((l: string) => l.replace('MISSING LEGEND: ', ''))
  return { deny: why(missing.length ? missing : files) }
}

export const register: Register = on => {
  // HTML isn't on disk yet at Write time; check the content itself.
  on('tool.call', { tool: 'Write' }, ($, e, next) =>
    HTML.test(e.file_path) && !LEGEND.test(e.content) ? { deny: why([e.file_path]) } : next(e),
  )

  on('tool.call', { tool: 'SendUserFile' }, ($, e, next) => gate($, (e as any).files ?? [], e, next))
  on('tool.call', { tool: 'Artifact' }, ($, e, next) => {
    const a = e as any
    return a.asset || !a.file_path ? next(e) : gate($, [a.file_path], e, next)
  })
}
