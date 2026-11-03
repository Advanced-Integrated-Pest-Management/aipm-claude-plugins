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
   It validates the URL, downloads the file, checks it against the hash the provider itself publishes, and prints the finished `<script>` or `<link>` tag. Paste that tag; never type a hash from memory. `FAIL` means pick another provider or version. Prefer cdnjs. On jsDelivr, pin the file the package actually ships: a `.min.js` it does not ship is minified on the fly and has no published hash (Chart.js 4 ships `dist/chart.umd.js`).
2. **Generate the head block** for exactly those URLs (add `--google-fonts` if the page uses Google Fonts):
   ```bash
   python3 <this skill's folder>/scripts/check_egress.py --head <every pinned URL> --google-fonts
   ```
   The file must begin `<!DOCTYPE html><html lang="en"><head>` followed by the lines it prints, verbatim and in order. Only whitespace and plain comments (such as `<!-- AIPM-CONFIDENTIAL-INTERNAL -->`) may sit before or between them; `<title>`, Google Fonts and pinned tags follow the head block. Regenerate whenever the set of pinned URLs changes; the checker compares the CSP against the tags and refuses any other head shape.
3. Write the page under the rules below.
4. Run the checker (last section).

A generated head block looks like this (one pinned script, Google Fonts on):

```html
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js; style-src 'unsafe-inline' https://fonts.googleapis.com/css2; font-src data: https://fonts.gstatic.com/s/; img-src data: blob:; media-src data: blob:; connect-src 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'">
<meta name="referrer" content="no-referrer">
```

### Allowed providers

| Provider | URL shape | Verification |
|---|---|---|
| cdnjs | `https://cdnjs.cloudflare.com/ajax/libs/<lib>/<version>/<file>` | provider's published sha512 |
| jsDelivr, npm only | `https://cdn.jsdelivr.net/npm/<pkg>@<version>/<file>` | provider's published sha256 |
| unpkg | `https://unpkg.com/<pkg>@<version>/<file>` | byte-identical to jsDelivr's copy |
| Google Fonts | `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=…&display=swap">` | none possible (CSS varies by browser); the CSP allows only Google's `/s/` font-file path, and the query may carry only `family=` and `display=` |

The version is pinned in the URL: never `@latest`, never a GitHub mirror, never a query string. Every CDN tag carries `integrity="sha384-…"` and `crossorigin="anonymous"`. The CSP names each pinned file by full URL, so even script that tries to load something else from those hosts is refused by the browser.

### Inside the page

- **No network calls.** No `fetch(…)`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, service workers, workers, `RTCPeerConnection`, `import(…)`, `type="module"` scripts, the Artifact runtime (`window.claude.*`), or anything on `navigator` beyond `language`, `userAgent`, `platform`, `onLine` and `clipboard.writeText` (a Copy button is fine). Words like "worker" or "fetch" in data, labels and comments are fine.
- **No navigation.** No `location` reads or writes on anything (`x.location = …` is refused even on a data object; call the field `site`), no `open`, `window.open`, `.click()` (except the download pattern below), `.submit()`, `dispatchEvent`, `document.write`, `navigation.*`, `defaultView`, and no `<meta http-equiv="refresh">`, static or inserted. Do not name a variable `location` or a function `open`.
- **No browser storage.** No `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`, Cache API. State lives in memory for the page's lifetime. (Every `file://` page shares one storage origin in Chrome, so stored data would be readable by any other local file.)
- **No disguised names.** No `eval`, `Function(…)`, `with`, `Reflect`, `prototype`, `String.raw`, `fromCharCode`, bracket access on `window`/`self`/`document`/`globalThis`/`this`, splicing string literals (`'fe'+'tch'`) or interpolating them (`${'tch'}`). Write `"Total: " + n`, not `"Total: " + " units"`.
- **No element creation that the CSP cannot police.** No `createElement` of `script`, `link`, `meta`, `base`, `iframe`, `form`, `object` or `embed`; no `.src = …` assignments; no `setAttribute` of `src`, `href`, `srcset`, `action`, `formaction`, `ping`, `poster`, `data` or `content`. Put images in the markup as `data:` URIs rather than setting them from script.
- **Data leaves only by the reader's own click.** For an Export button, use the standard pattern: `const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "report.csv"; a.click();` (a `const url = URL.createObjectURL(…)` variable or a `"data:text/csv,…"` string also works). That `.click()` is allowed only on a script-created `<a>` with `download` set, assigned once, whose `href` is an object or `data:` URL. A visible `<a download>` works too, as do the browser's own print and save. Never click any other element or submit anything from script.
- **Images, logos and media are inline** `data:` URIs (the AIPM logo lives at `~/.claude/assets/AIPM_Logo_Transparent.png`; base64 it). No remote `<img>`, `srcset`, `poster`, `background`, CSS `url()` or `image-set()`. Page CSS may reference only `data:` URIs; a backslash anywhere in CSS is refused.
- **Inline `<svg>`** is fine for charts. Inside it, `<style>` and `<title>` may hold plain text only (no `<` or `&`); `<script>`, `<textarea>` and the other raw-text elements are refused there, as are SMIL animations of `href`. Only known SVG leaf elements may use `<x/>` self-closing syntax.
- **Not allowed at all:** `<iframe>`, `<frame>`, `<object>`, `<embed>`, `<base>`, `<form>`, `<noscript>`, `<template>`, `<math>`, `<foreignObject>`, `<link>` rels other than `stylesheet`/`preconnect`/`dns-prefetch`/`icon`, `javascript:` URLs, processing instructions, CDATA sections, abrupt comments (`<!-->`), comments closed with `-- >` or `--!>`, `<!--` or `<script` inside script text, `</script x>`-style end tags, `</ ` with a space, self-closing syntax on non-void elements (`<title/>`, `<script/>`), duplicate attributes on an element, a second `charset` declaration, any `charset` other than `utf-8`, any `http-equiv` other than the CSP (including `content-type`), a doctype other than `<!DOCTYPE html>`, backslashes or `@` in URLs, and non-ASCII space characters (U+00A0 and friends) inside a tag outside its quoted attribute values. They are fine in text, data and attribute values.
- **Self-contained:** no relative file references (`src="lib.js"`). The file is forwarded on its own.
- **Outbound links** `<a href="https://…">` are fine (a click is the reader's choice) but must carry `rel="noopener noreferrer"`; no `ping`.
- **Fonts:** Google Fonts via the `<link>` above, or the same URL as `@import url("https://fonts.googleapis.com/css2?…")` in a `<style>` block (with `--google-fonts` on the head block either way), with a system fallback in the stack; or a system stack alone. Never `@font-face` to any host, Google's included; the only web-font path is Google's own stylesheet.
- **File name:** `.html` or `.htm`. `.shtml`, `.xhtml`, `.svg`, `.mhtml` and `.hta` cannot carry this policy and are refused by extension; the checker fails closed on any extension it does not know.

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

Each `EGRESS:` line names the file, line and rule. Fix the generator and regenerate; do not hand-edit the output. The checker refuses constructs that different HTML parsers read differently, so a file it passes means the same thing to the browser as it did to the check. If it says a PDF "cannot be verified", the PDF uses object streams or encryption: install `qpdf` (`brew install qpdf`) and rerun, or regenerate without them. In Claude Code the aipm-compliance guard runs the same check when the file is written (any egress-relevant extension), sent or published, and blocks it if the check fails or cannot run.
