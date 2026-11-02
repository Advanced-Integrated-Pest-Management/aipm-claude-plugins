#!/usr/bin/env python3
"""Exit 0 if each file can send no data out (AIPM no-egress rule), else print each violation and exit 1.

html: only allowlisted asset origins, SRI on CDN scripts/styles, a locked CSP meta, no-referrer,
no network or storage APIs, self-contained. docx/pptx/xlsx: no external non-hyperlink
relationships, no data connections, no macros. pdf: no JavaScript, Launch, SubmitForm,
ImportData or GoToR actions. Stdlib only, so it runs in claude.ai's sandbox too.

Usage: check_egress.py [--exempt-account EMAIL] [--stdin NAME] FILE...
"""
import json, os, re, shutil, subprocess, sys, zipfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

# Must match SKILL.md and hooks/register.ts.
CDN_HOSTS = {"cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com"}
FONT_HOSTS = {"fonts.googleapis.com", "fonts.gstatic.com"}
ALLOWED_HOSTS = CDN_HOSTS | FONT_HOSTS
SRI = re.compile(r"^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$")
REQUIRED_CSP = {"default-src": "'none'", "connect-src": "'none'", "form-action": "'none'"}
# Every CSP source token must be one of these or exactly https://<allowed host>; nothing else is accepted.
CSP_KEYWORDS = {"'none'", "'unsafe-inline'", "data:", "blob:"}
HYPERLINK_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
BANNED_JS = re.compile(
    r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|serviceWorker|"
    r"localStorage|sessionStorage|indexedDB|document\.cookie|\bcaches\.|"
    r"import\s*\(\s*['\"]https?:|new\s+Worker\s*\("
)
CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+)|@import\s+(?:url\()?['\"]?([^'\")\s;]+)", re.I)
# Element attributes that make the browser fetch something.
FETCH_ATTRS = {("script", "src"), ("link", "href"), ("img", "src"), ("img", "srcset"), ("source", "src"),
               ("source", "srcset"), ("video", "src"), ("video", "poster"), ("audio", "src"), ("track", "src"),
               ("iframe", "src"), ("frame", "src"), ("object", "data"), ("embed", "src"), ("form", "action"),
               ("base", "href"), ("use", "href"), ("image", "href")}


def host_of(url: str):
    """Hostname for http(s) URLs; None for data:, blob:, mailto:, tel:, # and javascript: (checked elsewhere)."""
    u = url.strip()
    if not u or u.startswith(("data:", "blob:", "#", "mailto:", "tel:")):
        return None
    if u.startswith("//"):
        u = "https:" + u
    p = urlsplit(u)
    if p.scheme in ("http", "https"):
        return p.hostname or ""
    if p.scheme == "javascript":
        return None
    return "RELATIVE"


class Scan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.bad, self.csp, self.referrer, self.in_script, self.in_style = [], None, None, False, False
        self.csp_count, self.fetched, self.head_closed = 0, False, False

    def fail(self, msg):
        self.bad.append(f"line {self.getpos()[0]}: {msg}")

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        rel = a.get("rel", "").lower().split()
        if tag == "meta":
            if a.get("http-equiv", "").lower() == "content-security-policy":
                self.csp_count += 1
                if self.csp_count > 1:
                    self.fail("more than one Content-Security-Policy meta tag")
                elif self.fetched or self.head_closed:
                    self.fail("Content-Security-Policy meta must be in <head> before any script, link, style or media element")
                self.csp = a.get("content", "")
            if a.get("name", "").lower() == "referrer":
                self.referrer = a.get("content", "").strip().lower()
            if a.get("http-equiv", "").lower() == "refresh" and "url=" in a.get("content", "").lower():
                self.fail("meta refresh to a URL")
        if tag == "script":
            self.in_script = True
        if tag == "style":
            self.in_style = True
        if tag in ("script", "style", "body") or tag in {t for t, _ in FETCH_ATTRS}:
            self.fetched = True  # anything from here on is loaded before a later CSP meta could apply
        for k, v in a.items():
            if k.startswith("on") and BANNED_JS.search(v):
                self.fail(f"inline {k} handler uses a network or storage API")
            if k == "style":
                self.check_css(v)
        if tag == "a" and (h := host_of(a.get("href", ""))) not in (None, "RELATIVE"):
            if not {"noopener", "noreferrer"} <= set(rel):
                self.fail(f'<a href="{a["href"]}"> needs rel="noopener noreferrer"')
        for (t, attr) in FETCH_ATTRS:
            if tag != t or attr not in a:
                continue
            url = a[attr].split(",")[0].split()[0] if attr == "srcset" and a[attr].strip() else a[attr]
            h = host_of(url)
            if h is None:
                continue
            if h == "RELATIVE":
                self.fail(f"<{tag} {attr}=\"{url}\"> is a relative file reference; the document must be self-contained")
            elif tag == "script" or (tag == "link" and {"stylesheet", "preload", "modulepreload"} & set(rel)):
                if h not in ALLOWED_HOSTS:
                    self.fail(f"<{tag}> loads from {h}, not an allowed provider")
                elif h in CDN_HOSTS and (not SRI.match(a.get("integrity", "")) or "crossorigin" not in a):
                    self.fail(f"<{tag}> from {h} needs integrity=\"sha384-…\" and crossorigin")
            elif tag == "link" and {"preconnect", "dns-prefetch"} & set(rel):
                if h not in ALLOWED_HOSTS:
                    self.fail(f"<link rel=preconnect> to {h}, not an allowed provider")
            else:
                self.fail(f"<{tag} {attr}> points at {h}; images and media must be inline data: URIs")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
        if tag == "style":
            self.in_style = False
        if tag == "head":
            self.head_closed = True

    def handle_data(self, data):
        if self.in_script and (m := BANNED_JS.search(data)):
            self.fail(f"script uses {m.group(0).strip()} (network or storage API)")
        if self.in_style:
            self.check_css(data)

    def check_css(self, css):
        for m in CSS_URL.finditer(css):
            h = host_of(m.group(1) or m.group(2) or "")
            if h == "RELATIVE":
                self.fail("CSS references a relative file; the document must be self-contained")
            elif h and h not in FONT_HOSTS:
                self.fail(f"CSS loads from {h}; only inline data or Google Fonts are allowed")


def check_csp(csp):
    if csp is None:
        return ["no <meta http-equiv=\"Content-Security-Policy\"> tag"]
    bad, d = [], {}
    for part in csp.split(";"):
        toks = part.split()
        if not toks:
            continue
        name = toks[0].lower()
        if name in d:  # browsers keep the first occurrence; a repeat is either a mistake or an attempt to confuse
            bad.append(f"CSP repeats {name}")
        d.setdefault(name, toks[1:])
        for s in toks[1:]:
            if s in CSP_KEYWORDS or (s.startswith("https://") and s[8:] in ALLOWED_HOSTS):
                continue
            bad.append(f"CSP {name} allows {s}; only 'none', 'unsafe-inline', data:, blob: and https://<allowed provider> are accepted")
    for k, v in REQUIRED_CSP.items():
        if d.get(k) != [v]:
            bad.append(f"CSP must set {k} {v}")
    return bad


def check_html(text):
    s = Scan()
    s.feed(text)
    bad = s.bad + check_csp(s.csp)
    if s.referrer != "no-referrer":
        bad.append('no <meta name="referrer" content="no-referrer">')
    return bad


OOXML_BAD_PARTS = re.compile(r"^(xl/(connections\.xml|queryTables/|externalLinks/|webextensions/)|.*vbaProject\.bin|.*vbaData\.xml)")
FIELD = re.compile(r"INCLUDEPICTURE|INCLUDETEXT|IMPORT\b|\bLINK\b|\bDDE(AUTO)?\b", re.I)


def check_rels(n: str, data: bytes):
    """External relationships other than plain hyperlinks (linked images, OLE, external workbooks, templates)."""
    if re.search(rb"<!(DOCTYPE|ENTITY)", data, re.I):  # a .rels part never needs a DTD; refuse entity tricks before parsing
        return [f"{n}: relationships part declares a DTD or entities"]
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        return [f"{n}: unparseable relationships ({e})"]
    bad = []
    for rel in root.iter():
        if rel.tag.rsplit("}", 1)[-1] != "Relationship":
            continue
        if rel.get("TargetMode") == "External" and rel.get("Type") != HYPERLINK_REL:
            bad.append(f"{n}: external {rel.get('Type', '?').rsplit('/', 1)[-1]} -> {rel.get('Target', '?')}")
    return bad


def check_ooxml(p: Path):
    bad = []
    with zipfile.ZipFile(p) as z:
        for n in z.namelist():
            if OOXML_BAD_PARTS.match(n):
                bad.append(f"{n}: external data connection or macro part")
            if n.endswith(".rels"):
                bad += check_rels(n, z.read(n))
            if n.startswith("word/") and n.endswith(".xml"):
                xml = z.read(n).decode("utf-8", "ignore")
                for m in re.finditer(r"<w:instrText[^>]*>([^<]*)</w:instrText>", xml):
                    if FIELD.search(m.group(1)):
                        bad.append(f"{n}: field code {m.group(1).strip()[:60]}")
    return bad


PDF_ACTION = re.compile(rb"/(JavaScript|JS|Launch|SubmitForm|ImportData|GoToR|RichMedia)\b")


def pdf_names_decoded(raw: bytes) -> bytes:
    """PDF names may hex-escape characters (/J#61vaScript); normalise so the pattern can't be dodged."""
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)


def check_pdf(p: Path):
    raw = pdf_names_decoded(p.read_bytes())
    # Object streams hide dictionaries from a raw scan; expand them with qpdf, or fail closed without it.
    if shutil.which("qpdf"):
        r = subprocess.run(["qpdf", "--qdf", "--object-streams=disable", "--decrypt", str(p), "-"], capture_output=True)
        if r.returncode != 0:
            return [f"qpdf could not expand the PDF (exit {r.returncode}); cannot verify it"]
        raw = pdf_names_decoded(r.stdout)
    elif b"/ObjStm" in raw or b"/Encrypt" in raw:
        return ["PDF uses object streams or encryption and qpdf is not installed; cannot verify it"]
    return sorted({f"PDF action /{m.group(1).decode()}" for m in PDF_ACTION.finditer(raw)})


def check(p: Path, text=None):
    ext = p.suffix.lower()
    if ext in {".html", ".htm"}:
        return check_html(text if text is not None else p.read_text("utf-8", "ignore"))
    if ext in {".docx", ".pptx", ".xlsx", ".dotx", ".potx", ".xlsm", ".docm", ".pptm"}:
        return check_ooxml(p)
    if ext == ".pdf":
        return check_pdf(p)
    return []


def exempt(email: str) -> bool:
    try:
        acct = json.loads(Path(os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude") + ".json").expanduser().read_text())
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


def selftest():
    good = """<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src data: https://fonts.gstatic.com; img-src data: blob:; connect-src 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat">
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js" integrity="sha384-vtjasyidUo0kW94K5MXDXntzOJpQgBKXmE7e2Ga4LG0skTTLeBi97eFAXsqewJjw" crossorigin="anonymous"></script>
<img src="data:image/png;base64,iVBORw0KGgo="><a href="https://clypboard.com" rel="noopener noreferrer">x</a>
<script>const a=new Blob(["x"]);const u=URL.createObjectURL(a);</script>"""
    assert check_html(good) == [], check_html(good)
    bad = check_html(open(sys.argv[2]).read()) if len(sys.argv) > 2 else []
    cases = {
        '<script src="https://cdnjs.cloudflare.com/x.js"></script>': "needs integrity",
        '<script src="https://evil.example/x.js" integrity="sha384-AAA" crossorigin></script>': "not an allowed provider",
        '<img src="https://advancedipm.com/logo.png">': "inline data: URIs",
        '<script>fetch("/x")</script>': "fetch(",
        '<script>localStorage.setItem("a",1)</script>': "localStorage",
        '<style>.x{background:url(https://x.example/a.png)}</style>': "CSS loads from x.example",
        '<a href="https://x.example">x</a>': 'rel="noopener noreferrer"',
        '<script src="lib.js"></script>': "self-contained",
        '<meta http-equiv="Content-Security-Policy" content="default-src *">': "CSP",
        '<div onclick="fetch(1)"></div>': "inline onclick",
    }
    for html, needle in cases.items():
        out = "\n".join(check_html(html))
        assert needle in out, (html, out)
    base = "default-src 'none'; connect-src 'none'; form-action 'none'; "
    assert check_csp(base + "script-src 'unsafe-inline' https://unpkg.com; img-src data: blob:") == []
    assert any("allows https://x.example" in b for b in check_csp(base + "img-src https://x.example"))
    assert any("allows cdnjs.cloudflare.com" in b for b in check_csp(base + "img-src cdnjs.cloudflare.com"))  # scheme-less
    assert any("allows https://cdnjs.cloudflare.com.evil.example" in b for b in check_csp(base + "script-src https://cdnjs.cloudflare.com.evil.example"))
    assert any("allows 'self'" in b for b in check_csp(base + "script-src 'self'"))
    dup = check_csp(base + "script-src https://unpkg.com; script-src https://evil.example")
    assert any("repeats script-src" in b for b in dup) and any("allows https://evil.example" in b for b in dup), dup
    two = check_html(good + '\n<meta http-equiv="Content-Security-Policy" content="default-src *">')
    assert any("more than one" in b for b in two), two
    late = check_html('<script>1</script>' + good)
    assert any("before any script" in b for b in late), late
    assert pdf_names_decoded(b"/J#61vaScript /Launc#68") == b"/JavaScript /Launch"
    assert PDF_ACTION.search(pdf_names_decoded(b"<< /S /J#61vaScript >>"))
    rels = b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">%s</Relationships>'
    assert check_rels("r", rels % f'<Relationship Id="a" Type="{HYPERLINK_REL}" Target="https://x" TargetMode="External"/>'.encode()) == []
    assert check_rels("r", rels % f'<Relationship Id="a" Type="{HYPERLINK_REL}X" Target="https://x" TargetMode="External"/>'.encode())
    assert check_rels("r", rels % b'<Relationship Id="a" Type="http://s/image" Target="https://x" TargetMode="External"/>')
    assert check_rels("r", rels % b'<Relationship Id="a" Type="http://s/image" Target="https://x" targetmode="External"/>') == []  # attribute names are case-sensitive in OOXML
    assert check_rels("r", b'<!DOCTYPE x [<!ENTITY a "b">]>' + rels % b"")
    print("selftest ok")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--selftest"]:
        selftest(); sys.exit(0)
    sys.exit(main(sys.argv[1:]))
