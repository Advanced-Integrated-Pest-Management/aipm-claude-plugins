#!/usr/bin/env python3
"""Exit 0 if each file carries the AIPM confidentiality legend (or the external opt-out), else 1.

Stdlib only. docx/pptx/xlsx: text from the OOXML parts. pdf: pdftotext when present,
plus raw bytes (catches the metadata Keywords token). html/md/txt: the text itself.
"""
import re, shutil, subprocess, sys, zipfile
from pathlib import Path

LEGEND = re.compile(r"CONFIDENTIAL\s*[–—-]\s*FOR INTERNAL USE ONLY", re.I)
TOKENS = re.compile(r"AIPM-CONFIDENTIAL-INTERNAL|aipm-audience:\s*external|AIPM-EXTERNAL", re.I)
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
        print("selftest ok"); sys.exit(0)
    sys.exit(main(sys.argv[1:]))
