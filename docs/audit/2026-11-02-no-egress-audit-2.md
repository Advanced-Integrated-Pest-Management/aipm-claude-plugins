<!-- AIPM-CONFIDENTIAL-INTERNAL -->

> **CONFIDENTIAL – FOR INTERNAL USE ONLY**
> This document contains confidential and proprietary information of Advanced Integrated Pest Management, Inc., and may contain trade secrets protected under the California Uniform Trade Secrets Act (Cal. Civ. Code § 3426 et seq.). It is intended solely for authorized Advanced Integrated Pest Management, Inc. personnel, who must handle it in accordance with the confidentiality provisions of the Employee Handbook. Any review, use, disclosure, copying or distribution by anyone other than the intended recipients is prohibited. If you received this in error, notify the sender and delete all copies.

# Security audit 2: `no-egress` skill after the first remediation (aipm-compliance 1.1.0 → 1.2.0, PR 1)

- **Date:** 2026-11-02 (audit run), 2026-11-03 (remediation)
- **Revision audited:** `c0134c0` (branch `feat/no-egress-skill`), the rework that answered audit 1 (`docs/audit/2026-11-02-no-egress-audit.md`)
- **Auditor:** an independent Claude Opus session (high effort, fresh context, its own worktree), briefed to re-test every audit-1 item, look for new bypasses, and write a report without the implementer's input
- **Environment:** macOS 25.6, Python 3.9.6 (`/usr/bin/python3`) and 3.14.4; headless Chrome through puppeteer 25.8.0; qpdf 12.4.2
- **How this report came to be:** the audit session built its corpus, ran the checker over it on both Python versions, confirmed every verdict in headless Chrome and ran `pin_sri.py` live, but was stopped by a content safeguard before it wrote its report. Its generators, corpus and Chrome logs survived on disk. This report is the implementer's reconstruction from that evidence: each finding below is a fixture the auditor wrote, a checker verdict and a Chrome observation, not an opinion. Attack strings are described by class, not reproduced.

## Summary

Audit 1's three Critical CSP-disabling tricks (invalid UTF-8, duplicate attributes, legacy charset) stayed fixed. Audit 2 found **a second family of the same disease**: markup that Python's `html.parser` (3.9 or 3.14, each differently) reads one way and Chrome reads another, so the checker sees a valid CSP in `<head>` while Chrome either never installs it or runs a script the checker never scanned. It also found that most of the navigation, storage and dynamic-loading bans could be stepped around with aliases, computed property access and template-literal interpolation, that four extensions Chrome renders as HTML were not checked at all, and that two allowed hosts (Google Fonts, the pinned CDN file) could carry data out in a query string or an unpinned path.

Of the auditor's 110 HTML fixtures, **35 expected-violation files passed the checker at `c0134c0`** on at least one Python version. After remediation, every expected-violation file fails on both versions, every expected-clean file passes except the eight listed under "accepted false positives", and Chrome confirms the new policy still loads pinned scripts and Google fonts while refusing off-path fonts, unpinned scripts and remote images.

## Findings and remediation

Severity follows audit 1's scale. "Bypassed" means Chrome did the forbidden thing (or would, for navigation and storage cases proven by title or `localStorage` probes) while the checker returned exit 0.

### G1. Critical: parser differentials that hide or disable the CSP (8 fixtures)

Non-ASCII whitespace (NBSP, NEL) used as an attribute separator or inside `http-equiv`; `content==` double equals; a leading space in `http-equiv`; a comment closed with `-- >`; an abrupt `<!-->` comment; a form feed inside the CSP; a second `content-type` meta with a legacy charset after a decoy UTF-8 declaration. In each case Python 3.9 (and for some, 3.14) delivered a CSP meta to the scanner while Chrome put the meta in `<body>`, ignored the attribute, or switched the document encoding.

**Fix.** The document must now begin with the generated head block **verbatim**: a byte-level regular expression accepts only `<!DOCTYPE html>`, an optional `<html>` with `lang`/`dir`/`class`/`id`, `<head>`, `<meta charset="utf-8">` and the CSP meta with printable-ASCII content, with nothing else, not even a comment, before the CSP. The CSP the scanner extracted must equal the one the regex extracted. Non-ASCII space characters are refused anywhere in the file; NEL joins the control-character refusal; comments are extracted with the browser's rule and refused if a 3.9-style early close sits inside; `content-type` and every other `http-equiv` are refused outright; a second `charset` declaration is refused. The `charset` and `http-equiv` values are compared without trimming, as browsers do.

### G2. Critical: raw-text element boundaries (7 fixtures)

Double-escaped script (`<!--<script>` inside script text), `</ script>` with a space, `</style x>` with junk after the name, `<style>` or `<title>` inside inline `<svg>` carrying a `<script>`, `<img onerror>` or `<meta refresh>`. The scanner treated the content as raw text; Chrome parsed it as live markup, or the reverse. Three of these were Python-3.9-only, one was 3.14-only.

**Fix.** `<!--` or `<script` inside script text is refused. End tags of any raw-text element (`script`, `style`, `textarea`, `title`, `xmp`, `iframe`, `noembed`, `noframes`, `noscript`, `plaintext`) must be exactly `</name>`; `</` followed by whitespace is refused. Inside `<svg>`/`<math>`, `<style>` and `<title>` may hold plain text only (no `<`, no `&`), and every other raw-text element is refused there. The scanner forces the same raw-text element list on every Python version.

### G3. High: extensions Chrome renders as HTML were not checked (4 fixtures)

`.shtml`, `.shtm`, `.xhtm`, `.svgz` passed with exit 0 because the checker returned "nothing to check" for unknown extensions and the hook regex did not list them. Chrome ran the script in the `.shtml` and `.shtm` files.

**Fix.** The checker fails closed on every extension it does not recognise; `.shtml`, `.shtm`, `.xhtm`, `.svgz`, `.hta`, `.htc` join the refused-by-extension list; the hook regex covers them and the Write gate now runs the checker for every egress-relevant extension, not only `.html`.

### G4. High: navigation and storage bans bypassed by aliasing (14 fixtures)

`this.location`, an alias of `this` or of `document.defaultView`, `Object.assign(window, {location})`, `open.call`, `HTMLElement.prototype.click.call`, `navigation.navigate`, a meta refresh built from template literals and inserted with `insertAdjacentHTML`, `this[...]` with template-literal or `atob` spelling of `localStorage` and `RTCPeerConnection`, a `javascript:` URL with an embedded tab, a SMIL `<set attributeName="href">`, and the claude.ai Artifact runtime API. Every one navigated, wrote storage, opened a UDP socket or would have called the network in Chrome.

**Fix.** The script scan now also refuses: `.location` writes and `.location.href|assign|replace|…` on any object; `this.location`; `defaultView`; `navigation.`; `assign(` with a global as first argument; bare `open` followed by `(`/`.`/`[` and dotted `open` on globals; `.click` in any form; `prototype`; `String.raw`; `this[...]`; `${'…'}` string-literal interpolation; `equiv` in any case; `claude.`/`claude[`; `createElement` of script/link/meta/base/iframe/frame/object/embed/form; `.src =`; `setAttribute` of URL-bearing or `http-equiv`/`content` attributes; SMIL animation of `href`. Tab/newline are stripped from URLs before scheme detection, as the URL parser does. This layer remains inspection, not proof; SKILL.md says so.

### G5. High: allowed hosts as exfiltration channels (5 fixtures)

A query string on the pinned library URL (CSP path matching ignores the query, so the request went out), a trailing slash or `..` in a "pinned" path (the CSP source became a prefix and an unpinned file loaded), any path on `fonts.gstatic.com` via page `@font-face` (the font-src allowed the whole host), and `text=`/arbitrary `family=` on the Google Fonts stylesheet URL.

**Fix.** Pinned URLs must end in a file name with no `.`/`..` segments (checker and `pin_sri.py` agree). The CSP `font-src` is now `https://fonts.gstatic.com/s/`, a path prefix covering only Google's font files; page CSS may reference `data:` URIs only, and a backslash anywhere in CSS is refused. The Google Fonts query may carry only `family=` (font-name-shaped values, both API shapes) and `display=`. Dynamic script creation and `.src =` are refused (G4), which closes the query-string case at the inspection layer. **Residual, accepted:** a font-name-shaped `family=` value of up to 40 characters still reaches Google per request; this follows from the decision to allow Google Fonts, which cannot be hash-pinned.

### G6. Medium: URL and attribute tokenising (6 fixtures)

Backslash-userinfo host confusion in a script `src`; a CSS escape spelling `url(`; `<link rel=preload imagesrcset>` (no `href`, so never checked); NBSP inside `rel`; a `srcset` whose `data:` candidate ended in a comma, hiding the next candidate; `<svg><script>` with a character-reference-spelled API name (already refused; kept as regression).

**Fix.** URLs containing a backslash, whitespace or userinfo are refused for every URL-bearing attribute; `<link>` must carry an allowed `rel` and an `href`, and `imagesrcset` is scanned like `srcset`; `srcset` is split with the HTML specification's algorithm; `rel` tokens are split on ASCII whitespace only (NBSP is refused globally).

### G7. Low: false positives the auditor reported

Fixed: `navigator.language` and the other read-only `navigator` properties; a function named `open` being defined; `details.open = …`; `el.open(1)`; `i-- > 0` in script; a comment containing `--` (only the differential forms are refused now); `<textarea>` content mentioning `fetch` on Python 3.9; `<svg><style>` chart CSS; `srcset` with `data:` candidates and descriptors.

Accepted (by design, documented in SKILL.md): `a.click()` to trigger a download (use a visible `<a download>`); `'Site: '+'HQ'` literal splicing; `function open()` *called* as `open(…)`; `x.location = …` on a data object; `<!DOCTYPE html SYSTEM "about:legacy-compat">`; omitted `<head>`; `<foo/>` on an unknown element; uploading SheetJS by `createElement('script')` (pin it in the head block instead).

### G8. Info: things that held

Audit 1 items F1–F3 (encoding, duplicate attributes, charset) stayed closed on both Python versions. The exact-URL CSP blocked a dynamically injected unpinned cdnjs script, a remote image, fetch/XHR/WebSocket, a form post, an iframe and a blob worker in Chrome. `pin_sri.py` verified lodash on cdnjs and jsDelivr against the providers' published hashes and emitted correct tags. The hook changes from audit 1 (deny on checker failure, Artifact and SendUserFile coverage) were present; live hook execution in Claude Code is still unverified pending merge and `claude plugin update`.

## Verification after remediation

| Set | Files | Result on 3.9.6 and 3.14.4 |
|---|---|---|
| Auditor corpus, round 1 (`html/`) | 63 | every expected-violation file fails; expected-clean files pass except the accepted false positives above and one fixture whose uppercase `HTTPS://` CSP the font-src rewrite did not touch |
| Auditor corpus, round 2 (`html3/`) | 46 | same |
| Audit-1 corpus, HTML (`corpus/html`) | 45 | every expected-violation file fails; six expected-clean fixtures from before the exact-URL decision still carry a whole-host CSP and fail on the CSP comparison, as intended |
| Audit-1 corpus, Office | 15 | unchanged, all correct |
| Audit-1 corpus, PDF | 9 | unchanged, all correct (with and without qpdf in audit 1) |
| `check_egress.py --selftest` | 150+ documents | passes on both versions |
| `pin_sri.py --selftest` | | passes on both versions |
| Headless Chrome, page built from the new head block | | pinned lodash runs, Montserrat loads from `fonts.gstatic.com/s/`, download link works; an off-path gstatic font, an unpinned cdnjs script and a remote image are each refused by the CSP |

Not verified: the hooks running live inside Claude Code; the Python version in the claude.ai sandbox; Office and Acrobat viewer behaviour (checker-level only, as in audit 1).

## Design observation

Every Critical in both audits was the same shape: the scanner and the browser disagreeing about where `<head>` ends or where raw text ends. The verbatim head-block prefix removes the first class structurally; the raw-text rules remove the known members of the second. A third audit should start from the HTML parsing specification's list of parse errors rather than from known tricks, and should drive the file through a second browser engine.

---

CONFIDENTIAL – FOR INTERNAL USE ONLY · Advanced Integrated Pest Management, Inc.
