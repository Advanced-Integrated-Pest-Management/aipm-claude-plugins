#!/usr/bin/env python3
"""Exit 0 if each file carries an AIPM confidentiality legend (internal or customer) or the public token, else 1.

Stdlib only. docx/pptx/xlsx: text from the OOXML parts. pdf: pdftotext when present,
plus raw bytes (catches the metadata Keywords token). html/md/txt: the text itself.
"""
import re, shutil, subprocess, sys, zipfile
from pathlib import Path

# Keep in sync with LEGEND in hooks/register.ts.
LEGEND = re.compile(r"CONFIDENTIAL\s*[–—-]\s*(FOR INTERNAL USE ONLY|PREPARED FOR\b)", re.I)
# Metadata tokens. A token alone passes: without pdftotext a PDF's text is compressed and only Keywords is readable.
# AIPM-EXTERNAL / aipm-audience: external are pre-1.3.0 spellings of AIPM-PUBLIC.
TOKENS = re.compile(r"AIPM-CONFIDENTIAL-(INTERNAL|CUSTOMER)|AIPM-PUBLIC|AIPM-EXTERNAL|aipm-audience:\s*external", re.I)
OOXML = re.compile(r"^(word/(document|header\d*|footer\d*)|ppt/(slides|slideMasters|slideLayouts|notesSlides)/.*|xl/(sharedStrings|worksheets/.*)|docProps/(core|custom))\.xml$")


def text_of(p: Path) -> str:
    ext = p.suffix.lower()
    if ext in {".docx", ".pptx", ".xlsx", ".dotx", ".potx"}:
        with zipfile.ZipFile(p) as z:
            xml = " ".join(z.read(n).decode("utf-8", "ignore") for n in z.namelist() if OOXML.match(n))
        # Word/PowerPoint split runs across tags; join the text nodes before matching.
        return re.sub(r"<[^>]+>", "", xml)
    if ext == ".pdf":
        raw = p.read_bytes().decode("latin-1", "ignore")
        if shutil.which("pdftotext"):
            raw += subprocess.run(["pdftotext", str(p), "-"], capture_output=True, text=True).stdout
        return raw
    return p.read_text("utf-8", "ignore")


def ok(text: str) -> bool:
    return bool(LEGEND.search(text) or TOKENS.search(text))


def main(paths: list[str]) -> int:
    bad = [p for p in paths if not Path(p).is_file() or not ok(text_of(Path(p)))]
    for p in bad:
        print(f"MISSING LEGEND: {p}")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        assert ok("x CONFIDENTIAL – FOR INTERNAL USE ONLY y") and ok("confidential - for internal use only")
        assert ok("<!-- aipm-audience: external -->") and ok("/Keywords (AIPM-CONFIDENTIAL-INTERNAL)")
        assert not ok("Confidential draft")
        assert ok("CONFIDENTIAL – PREPARED FOR ACME SCHOOL DISTRICT") and ok("/Keywords (AIPM-CONFIDENTIAL-CUSTOMER)")
        assert ok("<!-- AIPM-PUBLIC -->") and ok("<!-- AIPM-EXTERNAL -->")
        assert not ok("Prepared for Acme")
        print("selftest ok"); sys.exit(0)
    sys.exit(main(sys.argv[1:]))
