---
name: confidential-legend
description: Required confidentiality legend for every Advanced IPM document, PDF, slide deck, spreadsheet, HTML page or Artifact the AI creates. Use whenever creating or exporting any Advanced IPM / AIPM business deliverable (docx, pptx, pdf, xlsx, html, Artifact), alongside the docx/pptx/pdf/xlsx skills. Internal by default; customer-facing material carries a customer legend instead, public material none.
---

# Advanced IPM confidentiality legend

<!-- Internal wording approved by Compliance 2026-10-02; customer wording and audience rule approved 2026-11-18. Privilege markings are out of scope; Compliance owns those. -->

Every Advanced IPM deliverable you create is **internal by default** and must carry the internal legend. Build it in while generating the file — do not add it afterwards by hand.

## Out of scope
Attorney-client privilege markings are handled by Compliance, not this legend. Don't add privilege language.

## Audience first
Decide by **who will read the file**, not by what kind of file it is. A proposal to management is internal; a proposal to a customer is not.

| Audience | Examples | Marking | Metadata token |
|---|---|---|---|
| **Internal** (default) | procedures, staff reports, internal analysis | internal legend | `AIPM-CONFIDENTIAL-INTERNAL` |
| **Customer** | quotes, proposals, customer letters, service reports, for any customer, **including public agencies** (school districts, cities) | customer legend | `AIPM-CONFIDENTIAL-CUSTOMER` |
| **Public** | website copy, marketing material, published notices | none | `AIPM-PUBLIC` |

- The requester says who it is for: use that.
- Not stated, but the request clearly addresses someone outside the company (a quote for a named customer, a letter to a customer): treat it as **customer**, and tell the requester so in your reply ("Marked as customer-facing for <customer>; say if it's internal").
- Anything else is **internal**. If it could reasonably be either ("proposal", "report", "letter" with no recipient), ask.
- The customer legend names the customer. If you don't know the customer's name, ask; never guess or leave the placeholder in.

## Internal legend text

**Short** (footer, every page/slide):
`CONFIDENTIAL – FOR INTERNAL USE ONLY · Advanced Integrated Pest Management, Inc.`

**Full** (first page / title slide / top of page):
> CONFIDENTIAL – FOR INTERNAL USE ONLY
> This document contains confidential and proprietary information of Advanced Integrated Pest Management, Inc., and may contain trade secrets protected under the California Uniform Trade Secrets Act (Cal. Civ. Code § 3426 et seq.). It is intended solely for authorized Advanced Integrated Pest Management, Inc. personnel, who must handle it in accordance with the confidentiality provisions of the Employee Handbook. Any review, use, disclosure, copying or distribution by anyone other than the intended recipients is prohibited. If you received this in error, notify the sender and delete all copies.

## Customer legend text

**Short** (footer, every page/slide):
`Confidential – Prepared for [Customer Name] · Advanced Integrated Pest Management, Inc.`

**Full** (first page / title slide / top of page):
> CONFIDENTIAL – PREPARED FOR [CUSTOMER NAME]
> This document contains proprietary pricing and service information of Advanced Integrated Pest Management, Inc., provided solely for the recipient's evaluation. Please do not distribute it outside your organization without our written consent.

## How to apply it, per format

Same placement for both legends; the token comes from the audience table.

| Format | Typical tool | Full legend | Short legend | Metadata token |
|---|---|---|---|---|
| DOCX | python-docx / docx (JS) | paragraph under the title on page 1 | `section.footer` on every section | core props `keywords` |
| PPTX | python-pptx / pptxgenjs | small text box at bottom of title slide | footer text box on every slide (or the master) | core props `keywords` |
| PDF | reportlab / HTML→PDF | page 1 block | `onPage` footer callback on every page | `setKeywords(<token>)` |
| XLSX | openpyxl | rows 1–2 of the first sheet | `ws.oddFooter.center.text` on each sheet | `wb.properties.keywords` |
| HTML / Artifact | — | visible banner at top | page footer | `<!-- <token> -->` |

Public files carry no legend, only `AIPM-PUBLIC` in the metadata slot.

Use the exact heading strings `CONFIDENTIAL – FOR INTERNAL USE ONLY` and `CONFIDENTIAL – PREPARED FOR <CUSTOMER NAME>`. The footer goes in the real header/footer layer (section footer, slide master, PDF page callback), so it repeats on every page and can't be scrolled away.

## Verify before hand-off (required)
Before telling the user the file is done, run:

```bash
python3 <this skill's folder>/scripts/check_legend.py <output files...>
```

If it prints `MISSING LEGEND`, fix the generator and regenerate. In Claude Code, the aipm-compliance guard runs the same check when you send or publish a file and blocks it if the check fails.
