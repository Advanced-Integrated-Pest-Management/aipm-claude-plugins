---
name: confidential-legend
description: Required confidentiality legend for every Advanced IPM document, PDF, slide deck, spreadsheet, HTML page or Artifact the AI creates. Use whenever creating or exporting any Advanced IPM / AIPM business deliverable (docx, pptx, pdf, xlsx, html, Artifact), alongside the docx/pptx/pdf/xlsx skills. Internal by default; customer-facing material opts out.
---

# Advanced IPM confidentiality legend

<!-- TODO(remediate): wording revised 2026-10-02 (entity name, "may contain", Employee Handbook); pending final counsel sign-off. Privilege markings are out of scope — Compliance owns those. -->

Every Advanced IPM deliverable you create is **internal by default** and must carry the legend. Build it in while generating the file — do not add it afterwards by hand.

## Out of scope
Attorney-client privilege markings are handled by Compliance, not this legend. Don't add privilege language.

## Audience first
- **Internal (default):** apply the legend.
- **Customer-facing / external** (quotes, proposals, customer letters, public web): do **not** apply it. Set the opt-out token `AIPM-EXTERNAL` instead (locations below). If you can't tell which, ask the user.

## Legend text

**Short** (footer, every page/slide):
`CONFIDENTIAL – FOR INTERNAL USE ONLY · Advanced Integrated Pest Management, Inc.`

**Full** (first page / title slide / top of page):
> CONFIDENTIAL – FOR INTERNAL USE ONLY
> This document contains confidential and proprietary information of Advanced Integrated Pest Management, Inc., and may contain trade secrets protected under the California Uniform Trade Secrets Act (Cal. Civ. Code § 3426 et seq.). It is intended solely for authorized Advanced Integrated Pest Management, Inc. personnel, who must handle it in accordance with the confidentiality provisions of the Employee Handbook. Any review, use, disclosure, copying or distribution by anyone other than the intended recipients is prohibited. If you received this in error, notify the sender and delete all copies.

## How to apply it, per format

| Format | Typical tool | Full legend | Short legend | Metadata token |
|---|---|---|---|---|
| DOCX | python-docx / docx (JS) | paragraph under the title on page 1 | `section.footer` on every section | core props `keywords = "AIPM-CONFIDENTIAL-INTERNAL"` |
| PPTX | python-pptx / pptxgenjs | small text box at bottom of title slide | footer text box on every slide (or the master) | core props `keywords` |
| PDF | reportlab / HTML→PDF | page 1 block | `onPage` footer callback on every page | `setKeywords("AIPM-CONFIDENTIAL-INTERNAL")` |
| XLSX | openpyxl | rows 1–2 of the first sheet | `ws.oddFooter.center.text` on each sheet | `wb.properties.keywords` |
| HTML / Artifact | — | visible banner at top | page footer | `<!-- AIPM-CONFIDENTIAL-INTERNAL -->` |

External documents put `AIPM-EXTERNAL` in that same metadata slot instead of the legend.

Use the exact heading string `CONFIDENTIAL – FOR INTERNAL USE ONLY`. The footer goes in the real header/footer layer (section footer, slide master, PDF page callback), so it repeats on every page and can't be scrolled away.

## Verify before hand-off (required)
Before telling the user the file is done, run:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/bin/check_legend.py" <output files...>
```

If it prints `MISSING LEGEND`, fix the generator and regenerate. The aipm-compliance guard runs the same check when you send or publish a file and blocks it if the check fails.
