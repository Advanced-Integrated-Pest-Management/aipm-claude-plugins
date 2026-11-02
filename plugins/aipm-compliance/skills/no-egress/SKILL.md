---
name: no-egress
description: No-egress rule for every Advanced IPM / AIPM document the AI creates that a browser or Office app could make talk to a network - HTML pages, Artifacts, DOCX, PPTX, XLSX and PDF. Use alongside the confidential-legend skill whenever creating or editing such a deliverable. Nothing the reader has may leave the file; code, styles and fonts load only from pinned, hash-verified providers under a generated Content-Security-Policy.
---

# Advanced IPM no-egress rule

A document you build for Advanced IPM must not send anything out and must not stash data on the reader's machine. Build the file this way from the start; do not patch a finished file by hand.

Two layers do the work, and they are not the same:

- **The browser enforces the CSP.** Scripts, styles, fonts, images, media, fetch/XHR, frames, forms and workers can only come from the exact pinned URLs the page's Content-Security-Policy names. `check_egress.py` proves that policy is really in force (one well-formed UTF-8 document, no duplicate attributes, the generated head block first).
- **The checker enforces the rest by inspection.** Navigation (`location`, `window.open`, programmatic clicks, meta refresh), WebRTC and browser storage have no CSP control. For those the checker scans script text for the APIs. That catches mistakes; it is not a guarantee against a deliberately disguised script, so do not describe it as one.

## HTML and Artifacts

### Build order

1. **Pin every library** you need:
   ```bash
   python3 <this skill's folder>/scripts/pin_sri.py https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js
   ```
   It validates the URL, downloads the file, checks it against the hash the provider itself publishes, and prints the finished `<script>` or `<link>` tag. Paste that tag; never type a hash from memory. `FAIL` means pick another provider or version. Prefer cdnjs.
2. **Generate the head block** for exactly those URLs (add `--google-fonts` if the page uses Google Fonts):
   ```bash
   python3 <this skill's folder>/scripts/check_egress.py --head <every pinned URL> --google-fonts
   ```
   Paste the three lines it prints as the first three elements of `<head>`, before `<title>`. Regenerate whenever the set of pinned URLs changes; the checker compares the CSP against the tags.
3. Write the page under the rules below.
4. Run the checker (last section).

A generated head block looks like this (one pinned script, Google Fonts on):

```html
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js; style-src 'unsafe-inline' https://fonts.googleapis.com/css2; font-src data: https://fonts.gstatic.com; img-src data: blob:; media-src data: blob:; connect-src 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'">
<meta name="referrer" content="no-referrer">
```

### Allowed providers

| Provider | URL shape | Verification |
|---|---|---|
| cdnjs | `https://cdnjs.cloudflare.com/ajax/libs/<lib>/<version>/<file>` | provider's published sha512 |
| jsDelivr, npm only | `https://cdn.jsdelivr.net/npm/<pkg>@<version>/<file>` | provider's published sha256 |
| unpkg | `https://unpkg.com/<pkg>@<version>/<file>` | byte-identical to jsDelivr's copy |
| Google Fonts | `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=…">` | none possible (CSS varies by browser); origin-locked by the CSP |

The version is pinned in the URL: never `@latest`, never a GitHub mirror, never a query string. Every CDN tag carries `integrity="sha384-…"` and `crossorigin="anonymous"`. The CSP names each pinned file by full URL, so even script that tries to load something else from those hosts is refused by the browser.

### Inside the page

- **No network calls.** No `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, service workers, workers, `RTCPeerConnection`, dynamic `import()`, `type="module"` scripts, or anything on `navigator`.
- **No navigation.** No `location` assignments or reads, `window.open`, `.click()`, `.submit()`, `dispatchEvent`, `document.write`, and no `<meta http-equiv="refresh">`. Do not name a variable `location`.
- **No browser storage.** No `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`, Cache API. State lives in memory for the page's lifetime. (Every `file://` page shares one storage origin in Chrome, so stored data would be readable by any other local file.)
- **No disguised names.** No `eval`, `Function(…)`, `with`, `Reflect`, `fromCharCode`, bracket access on `window`/`self`/`document`/`globalThis`, or splicing string literals (`'fe'+'tch'`). Write `"Total: " + n`, not `"Total: " + " units"`.
- **Data leaves only by the reader's own click.** Offer a visible `<a download="report.csv">` whose `href` you set to `URL.createObjectURL(blob)`; the reader clicks it. The browser's own print and save also work. Never click or submit anything from script.
- **Images, logos and media are inline** `data:` URIs (the AIPM logo lives at `~/.claude/assets/AIPM_Logo_Transparent.png`; base64 it). No remote `<img>`, `srcset`, `poster`, `background`, CSS `url()` or `image-set()`. Inline `<svg>` is fine; `<script>` inside it is not.
- **Not allowed at all:** `<iframe>`, `<frame>`, `<object>`, `<embed>`, `<base>`, `<form>`, `<noscript>`, `<template>`, `<math>`, `<foreignObject>`, `javascript:` URLs, processing instructions, CDATA sections, comments containing `--`, self-closing syntax on non-void elements (`<title/>`, `<script/>`), duplicate attributes on an element, any `charset` other than `utf-8`, any `http-equiv` other than the CSP.
- **Self-contained:** no relative file references (`src="lib.js"`). The file is forwarded on its own.
- **Outbound links** `<a href="https://…">` are fine (a click is the reader's choice) but must carry `rel="noopener noreferrer"`; no `ping`.
- **Fonts:** Google Fonts via the `<link>` above with a system fallback in the stack, or a system stack alone. Never a font from any other host.

## DOCX, PPTX, XLSX

- Save as `.docx` / `.xlsx` / `.pptx` (or the `x` template variants). Macro-enabled formats (`.docm`, `.xlsm`, `.pptm`, …) and `.xlsb` are refused outright.
- Pictures are embedded media, never linked. Any external relationship other than a hyperlink fails, as do OLE objects, ActiveX controls, web extensions (add-ins), attached templates, subdocuments and mail-merge sources.
- No data connections, query tables, external workbook links (`xl/connections.xml`, `xl/queryTables/`, `xl/externalLinks/`).
- Word: no `INCLUDEPICTURE`, `INCLUDETEXT`, `IMPORT`, `LINK`, `DDE`, `RD` field codes (in runs or `fldSimple`), no `altChunk`. `HYPERLINK` fields are fine.
- Excel: no `WEBSERVICE`, `IMAGE`, `RTD` or `FILTERXML` formulas.

## PDF

- No JavaScript, `Launch`, `SubmitForm`, `ImportData`, `GoToR`/`GoToE`, XFA forms, rich media, renditions, movies, sounds, URL file specifications, additional actions (`/AA`), or an `OpenAction` other than a plain page destination. Plain `URI` link annotations are fine.
- Generate with reportlab or HTML→PDF from a page that already passes the HTML rule.

## Verify before hand-off (required)

```bash
python3 <this skill's folder>/scripts/check_egress.py <output files...>
```

Each `EGRESS:` line names the file, line and rule. Fix the generator and regenerate; do not hand-edit the output. The checker refuses constructs that different HTML parsers read differently, so a file it passes means the same thing to the browser as it did to the check. If it says a PDF "cannot be verified", the PDF uses object streams or encryption: install `qpdf` (`brew install qpdf`) and rerun, or regenerate without them. In Claude Code the aipm-compliance guard runs the same check when the file is written (HTML), sent or published, and blocks it if the check fails or cannot run.
