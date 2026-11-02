#!/usr/bin/env python3
"""Pin a CDN asset: download it, verify it against the publisher's own hash, print the tag to paste.

Usage: pin_sri.py URL [URL...]        (stdlib only; needs network for the download and the publisher check)

Accepted URLs (version must be pinned, no @latest):
  https://cdnjs.cloudflare.com/ajax/libs/<lib>/<ver>/<file>   checked against api.cdnjs.com's published sha512
  https://cdn.jsdelivr.net/npm/<pkg>@<ver>/<file>             checked against data.jsdelivr.com's published sha256
  https://unpkg.com/<pkg>@<ver>/<file>                        checked byte-for-byte against jsDelivr's copy of the same npm file
Exit 1 and print nothing to paste if any check fails.
"""
import base64, hashlib, json, re, sys
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

VERSION = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?"
CDNJS = re.compile(rf"^/ajax/libs/([^/]+)/({VERSION})/(.+)$")
NPM = re.compile(rf"^/(?:npm/)?((?:@[^/@]+/)?[^/@]+)@({VERSION})/(.+)$")


def get(url, binary=False):
    with urlopen(Request(url, headers={"User-Agent": "aipm-pin-sri"}), timeout=30) as r:
        data = r.read()
    return data if binary else json.loads(data)


def b64(h):
    return base64.b64encode(h).decode()


def publisher_check(url):
    """Return (ok, note). Compares our download with the hash the publisher itself serves."""
    u = urlsplit(url)
    body = get(url, binary=True)
    if u.hostname == "cdnjs.cloudflare.com":
        m = CDNJS.match(u.path)
        if not m:
            return body, False, "cdnjs URL must be /ajax/libs/<lib>/<version>/<file>"
        lib, ver, file = m.groups()
        sri = get(f"https://api.cdnjs.com/libraries/{lib}/{ver}?fields=sri").get("sri", {}).get(file)
        ours = "sha512-" + b64(hashlib.sha512(body).digest())
        return body, sri == ours, f"cdnjs publishes {sri}" if sri else "cdnjs has no hash for that file"
    if u.hostname == "cdn.jsdelivr.net":
        m = NPM.match(u.path)
        if not m or not u.path.startswith("/npm/"):
            return body, False, "jsDelivr URL must be /npm/<pkg>@<version>/<file> (GitHub mirrors are not accepted)"
        pkg, ver, file = m.groups()
        files = get(f"https://data.jsdelivr.com/v1/package/npm/{pkg}@{ver}/flat").get("files", [])
        pub = next((f["hash"] for f in files if f["name"] == "/" + file), None)
        ours = b64(hashlib.sha256(body).digest())
        return body, pub == ours, f"jsDelivr publishes sha256 {pub}" if pub else "jsDelivr has no hash for that file"
    if u.hostname == "unpkg.com":
        m = NPM.match(u.path)
        if not m:
            return body, False, "unpkg URL must be /<pkg>@<version>/<file>"
        pkg, ver, file = m.groups()
        mirror = get(f"https://cdn.jsdelivr.net/npm/{pkg}@{ver}/{file}", binary=True)
        return body, mirror == body, "unpkg and jsDelivr serve identical bytes" if mirror == body else "unpkg and jsDelivr differ"
    return body, False, f"{u.hostname} is not an allowed provider (cdnjs, jsDelivr npm, unpkg)"


def tag(url, body):
    sri = "sha384-" + b64(hashlib.sha384(body).digest())
    if url.lower().endswith(".css"):
        return f'<link rel="stylesheet" href="{url}" integrity="{sri}" crossorigin="anonymous" referrerpolicy="no-referrer">'
    return f'<script src="{url}" integrity="{sri}" crossorigin="anonymous" referrerpolicy="no-referrer"></script>'


def main(urls):
    rc = 0
    for url in urls:
        try:
            body, ok, note = publisher_check(url)
        except Exception as e:  # network or JSON failure: never guess a hash
            print(f"FAIL {url}: {e}"); rc = 1; continue
        if not ok:
            print(f"FAIL {url}: {note}"); rc = 1; continue
        print(f"OK   {url}: {note}, {len(body):,} bytes")
        print(tag(url, body))
    return rc


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        assert CDNJS.match("/ajax/libs/xlsx/0.18.5/xlsx.full.min.js").groups() == ("xlsx", "0.18.5", "xlsx.full.min.js")
        assert NPM.match("/npm/@scope/pkg@1.2.3/dist/a.js").groups() == ("@scope/pkg", "1.2.3", "dist/a.js")
        assert NPM.match("/chart.js@4.4.1/dist/chart.umd.js").groups() == ("chart.js", "4.4.1", "dist/chart.umd.js")
        assert not NPM.match("/npm/xlsx@latest/x.js") and not CDNJS.match("/ajax/libs/xlsx/latest/x.js")
        assert tag("https://x/a.css", b"").startswith("<link") and tag("https://x/a.js", b"").startswith("<script")
        print("selftest ok"); sys.exit(0)
    if not sys.argv[1:]:
        print(__doc__); sys.exit(2)
    sys.exit(main(sys.argv[1:]))
