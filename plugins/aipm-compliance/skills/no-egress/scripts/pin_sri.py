#!/usr/bin/env python3
"""Pin a CDN asset: download it, verify it against the provider's own published hash, print the tag to paste.

Usage: pin_sri.py URL [URL...]        (stdlib only; needs network for the download and the publisher check)

Accepted URLs (https, version pinned, no query string; validated BEFORE anything is downloaded):
  https://cdnjs.cloudflare.com/ajax/libs/<lib>/<ver>/<file>   checked against api.cdnjs.com's published sha512
  https://cdn.jsdelivr.net/npm/<pkg>@<ver>/<file>             checked against data.jsdelivr.com's published sha256
  https://unpkg.com/<pkg>@<ver>/<file>                        checked byte-for-byte against jsDelivr's copy of the same npm file
The cdnjs and jsDelivr checks prove the bytes match what that provider publishes (transport integrity); only the unpkg
check crosses two operators. Exit 1 and print nothing to paste if any check fails or the network is unavailable.
After pinning, regenerate the head block: check_egress.py --head <every pinned URL> [--google-fonts]
"""
import base64, hashlib, json, re, sys
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

VERSION = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?"
SEG = r"[A-Za-z0-9._~+-]+"  # one path segment; must match check_egress.py
CDNJS = re.compile(rf"^/ajax/libs/({SEG})/({VERSION})/((?:{SEG}/)*{SEG})$")
NPM = re.compile(rf"^/((?:@{SEG}/)?{SEG})@({VERSION})/((?:{SEG}/)*{SEG})$")
PLAIN_PATH = re.compile(r"^[A-Za-z0-9._~/@+-]+$")


def get(url, binary=False):
    with urlopen(Request(url, headers={"User-Agent": "aipm-pin-sri"}), timeout=30) as r:
        data = r.read()
    return data if binary else json.loads(data)


def b64(h):
    return base64.b64encode(h).decode()


def parse(url):
    """Validate shape without touching the network. Returns (host, lib_or_pkg, version, file) or raises ValueError."""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if u.scheme.lower() != "https":
        raise ValueError("must be https://")
    if u.query or u.fragment or not PLAIN_PATH.match(u.path):
        raise ValueError("no query string, fragment or escaped characters in a pinned URL")
    if host == "cdnjs.cloudflare.com":
        m = CDNJS.match(u.path)
        if not m:
            raise ValueError("cdnjs URL must be /ajax/libs/<lib>/<version>/<file>")
    elif host == "cdn.jsdelivr.net":
        m = NPM.match(u.path[4:]) if u.path.startswith("/npm/") else None
        if not m:
            raise ValueError("jsDelivr URL must be /npm/<pkg>@<version>/<file> (GitHub mirrors are not accepted)")
    elif host == "unpkg.com":
        m = NPM.match(u.path)
        if not m:
            raise ValueError("unpkg URL must be /<pkg>@<version>/<file>")
    else:
        raise ValueError(f"{host or url} is not an allowed provider (cdnjs, jsDelivr npm, unpkg)")
    file = m.group(3)
    if any(x in (".", "..") for x in file.split("/")) or "." not in file.rsplit("/", 1)[-1].strip("."):
        raise ValueError("a pinned URL must end in a file name (a trailing slash or '..' would make the CSP source a prefix)")
    return host, m.group(1), m.group(2), file


def publisher_check(url):
    """Return (bytes, ok, note). Compares our download with the hash the provider itself serves."""
    host, name, ver, file = parse(url)
    body = get(url, binary=True)
    if host == "cdnjs.cloudflare.com":
        sri = get(f"https://api.cdnjs.com/libraries/{name}/{ver}?fields=sri").get("sri", {}).get(file)
        ours = "sha512-" + b64(hashlib.sha512(body).digest())
        return body, sri == ours, f"cdnjs publishes {sri}" if sri else "cdnjs has no hash for that file"
    if host == "cdn.jsdelivr.net":
        files = get(f"https://data.jsdelivr.com/v1/package/npm/{name}@{ver}/flat").get("files", [])
        pub = next((f["hash"] for f in files if f["name"] == "/" + file), None)
        ours = b64(hashlib.sha256(body).digest())
        if not pub and re.search(r"\.min\.(js|css)$", file):
            return body, False, ("jsDelivr has no hash for that file: the package does not ship it, so jsDelivr minifies it on the fly. "
                                 "Pin the file the package ships (drop .min), or use cdnjs")
        return body, pub == ours, f"jsDelivr publishes sha256 {pub}" if pub else "jsDelivr has no hash for that file"
    mirror = get(f"https://cdn.jsdelivr.net/npm/{name}@{ver}/{file}", binary=True)
    return body, mirror == body, "unpkg and jsDelivr serve identical bytes" if mirror == body else "unpkg and jsDelivr differ"


def tag(url, body):
    sri = "sha384-" + b64(hashlib.sha384(body).digest())
    if urlsplit(url).path.lower().endswith(".css"):
        return f'<link rel="stylesheet" href="{url}" integrity="{sri}" crossorigin="anonymous" referrerpolicy="no-referrer">'
    return f'<script src="{url}" integrity="{sri}" crossorigin="anonymous" referrerpolicy="no-referrer"></script>'


def main(urls):
    rc, pinned = 0, []
    for url in urls:
        try:
            parse(url)
        except ValueError as e:
            print(f"FAIL {url}: {e}"); rc = 1; continue
        try:
            body, ok, note = publisher_check(url)
        except Exception as e:  # network or JSON failure: never guess a hash
            print(f"FAIL {url}: {e}"); rc = 1; continue
        if not ok:
            print(f"FAIL {url}: {note}"); rc = 1; continue
        print(f"OK   {url}: {note}, {len(body):,} bytes")
        print(tag(url, body))
        pinned.append(url)
    if pinned:
        print("Now regenerate the head block:  check_egress.py --head " + " ".join(pinned) + " [--google-fonts]")
    return rc


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        assert parse("https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js")[1:] == ("xlsx", "0.18.5", "xlsx.full.min.js")
        assert parse("https://cdn.jsdelivr.net/npm/@scope/pkg@1.2.3/dist/a.js")[1:] == ("@scope/pkg", "1.2.3", "dist/a.js")
        assert parse("https://unpkg.com/chart.js@4.4.1/dist/chart.umd.js")[1:] == ("chart.js", "4.4.1", "dist/chart.umd.js")
        for u in ("https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/", "https://cdn.jsdelivr.net/npm/a@1.0.0/../../x.js",
                  "https://unpkg.com/a@1.0.0/x", "https://cdnjs.cloudflare.com/ajax/libs/x/1.0.0/a.js?v=1"):
            try:
                parse(u)
                raise AssertionError(u)
            except ValueError:
                pass
        for bad in ("https://cdn.jsdelivr.net/npm/xlsx@latest/x.js", "https://cdnjs.cloudflare.com/ajax/libs/xlsx/latest/x.js",
                    "https://cdn.jsdelivr.net/gh/foo/bar@1.0.0/x.js", "http://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/x.js",
                    "https://unpkg.com/lodash@4.17.21/lodash.js?v=1", "https://evil.example/x.js", "file:///etc/passwd"):
            try:
                parse(bad); raise AssertionError(bad)
            except ValueError:
                pass
        assert tag("https://x/a.css", b"").startswith("<link") and tag("https://x/a.js?x.css", b"").startswith("<script")
        print("selftest ok"); sys.exit(0)
    if not sys.argv[1:]:
        print(__doc__); sys.exit(2)
    sys.exit(main(sys.argv[1:]))
