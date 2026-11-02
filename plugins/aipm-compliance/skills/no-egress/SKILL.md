---
name: no-egress
description: No-egress rule for every Advanced IPM / AIPM document the AI creates that a browser or Office app could make talk to a network - HTML pages, Artifacts, DOCX, PPTX, XLSX and PDF. Use alongside the confidential-legend skill whenever creating or editing such a deliverable. Nothing the reader has may leave the file; assets load only from pinned, hash-verified providers.
---

# Advanced IPM no-egress rule

A document you build for Advanced IPM must not send anything out and must not stash data on the reader's machine. It may load code, styles and fonts from a short list of providers, each pinned by an integrity hash, and the browser is told to enforce that with a Content-Security-Policy. Build the file this way from the start; do not patch a finished file by hand.

Applies with the confidential-legend skill. Exempt: nothing by file. In Claude Code the guard skips the signed-in account `wscott@advancedipm.com` (app development); every other account is checked.

## HTML and Artifacts

### Head block (required, verbatim)

```html
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; style-src 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; font-src data: https://fonts.gstatic.com; img-src data: blob:; media-src data: blob:; connect-src 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'">
<meta name="referrer" content="no-referrer">
```

The CSP is the runtime guard: even if a stray reference slips through, the reader's browser refuses it. Do not widen it.

### Allowed providers

| Provider | Hosts | Rule |
|---|---|---|
| cdnjs | `cdnjs.cloudflare.com` | `integrity` + `crossorigin="anonymous"` required; hash verified against cdnjs's published sha512 |
| jsDelivr (npm only) | `cdn.jsdelivr.net/npm/…` | same; verified against jsDelivr's published sha256 |
| unpkg | `unpkg.com` | same; verified byte-for-byte against jsDelivr's copy |
| Google Fonts | `fonts.googleapis.com`, `fonts.gstatic.com` | stylesheet link only; no hash possible (CSS varies by browser), CSP locks the origin |

Any other host is a violation. Version must be pinned in the URL (`xlsx@0.18.5`, never `@latest`).

### Pinning a library (required for every CDN script or stylesheet)

```bash
python3 <this skill's folder>/scripts/pin_sri.py https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js
```

It downloads the file, checks it against the hash the provider itself publishes, and prints the finished tag. Paste that tag; never type a hash from memory. If it prints `FAIL`, pick another provider or version. Prefer cdnjs: it publishes a hash for every file.

### Inside the page

- **No network calls.** No `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, service workers, dynamic `import()` of URLs, or remote workers. Forms have no `action`; the CSP blocks submits anyway.
- **No browser storage.** No `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie` or the Cache API. State lives in memory for the page's lifetime.
- **Data leaves only by the reader's own click:** a `Blob` + `URL.createObjectURL` + `<a download>` download, or the browser's print/save. Those are allowed.
- **Images, logos and media are inline** `data:` URIs (the AIPM logo lives at `~/.claude/assets/AIPM_Logo_Transparent.png`; base64 it). No `<img src="https://…">`, no CSS `url(https://…)` except Google Fonts.
- **No iframes, objects, embeds, `<base>`, or meta refresh.**
- **Self-contained:** no relative file references (`src="lib.js"`). The file is forwarded on its own.
- **Outbound links** `<a href="https://…">` are fine (a click is the reader's choice) but must carry `rel="noopener noreferrer"`.
- **Fonts:** Google Fonts via `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?…">` with a system fallback in the stack, or a system stack alone. Never a font from any other host.

## DOCX, PPTX, XLSX

- Insert pictures as embedded media, never linked (`TargetMode="External"` on anything but a hyperlink fails).
- No external data connections, query tables, external workbook links or web extensions (`xl/connections.xml`, `xl/externalLinks/`, `xl/queryTables/`).
- No macros (`.docm`, `.xlsm`, `.pptm`, `vbaProject.bin`).
- No `INCLUDEPICTURE`, `INCLUDETEXT`, `IMPORT`, `LINK` or `DDE` field codes in Word.
- Hyperlinks are allowed.

## PDF

- No JavaScript, `Launch`, `SubmitForm`, `ImportData`, `GoToR` or rich-media actions. Plain `URI` links are allowed.
- Generate with reportlab or HTML→PDF from a page that already passes the HTML rule.

## Verify before hand-off (required)

```bash
python3 <this skill's folder>/scripts/check_egress.py <output files...>
```

Each `EGRESS:` line names the file, line and rule. Fix the generator and regenerate; do not hand-edit the output. In Claude Code the aipm-compliance guard runs the same check when the file is written (HTML), sent or published, and blocks it if the check fails.
