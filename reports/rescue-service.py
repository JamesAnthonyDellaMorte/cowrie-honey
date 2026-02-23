#!/usr/bin/env python3
"""
Host-side service that watches for partial download signals from the container.
When capture.sh writes a filename to dl/.rescue, this service:
1. Searches cowrie logs for the source URL
2. Downloads the full binary directly from the C2
3. Saves to dl/ and clears the flag

Runs as a systemd service on the host.
"""

import glob
import hashlib
import json
import os
import re
import ssl
import time
import urllib.request

DL = "/root/cowrie/dl"
RESCUE_FLAG = os.path.join(DL, ".rescue")
LOG_DIR = "/root/cowrie/log"

URL_RE = re.compile(r'https?://[^\s\'\";<>|`\)]+')

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

BINARY_MAGICS = {
    b"\x7fELF",
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
}


def find_urls(name):
    """Search cowrie logs for URLs that delivered this filename."""
    urls = set()
    for logfile in sorted(glob.glob(os.path.join(LOG_DIR, "cowrie.json*"))):
        try:
            with open(logfile) as f:
                for line in f:
                    try:
                        e = json.loads(line.strip())
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if e.get("eventid") != "cowrie.command.input":
                        continue
                    cmd = str(e.get("input", ""))
                    if name not in cmd:
                        continue
                    for url in URL_RE.findall(cmd):
                        url = url.rstrip(".,;:)")
                        if name in url:
                            urls.add(url)
        except OSError:
            continue
    return urls


def download(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Wget/1.21.2"})
        with urllib.request.urlopen(req, timeout=60, context=ssl_ctx) as resp:
            return resp.read(100 * 1024 * 1024)
    except Exception:
        return None


def is_binary(data):
    if len(data) < 4:
        return False
    return data[:4] in BINARY_MAGICS or data[:2] == b"MZ"


def already_have(prefix):
    for f in os.listdir(DL):
        if f.startswith(prefix + "-"):
            return True
    return False


def rescue(name):
    """Try to download the full binary for a partial."""
    print(f"[rescue] Partial detected: {name}", flush=True)

    urls = find_urls(name)
    if not urls:
        print(f"[rescue] No source URL found for {name}", flush=True)
        return

    for url in urls:
        print(f"[rescue] Trying {url}", flush=True)
        data = download(url)

        if not data:
            print(f"[rescue] Download failed", flush=True)
            continue

        if not is_binary(data):
            print(f"[rescue] Not a binary, skipping", flush=True)
            continue

        sha = hashlib.sha256(data).hexdigest()
        prefix = sha[:9]

        if already_have(prefix):
            print(f"[rescue] Already have {prefix}", flush=True)
            return

        friendly = f"{prefix}-{name}"
        path = os.path.join(DL, friendly)
        with open(path, "wb") as f:
            f.write(data)
        print(f"[rescue] SAVED: {friendly} ({len(data):,} bytes)", flush=True)
        return

    print(f"[rescue] All URLs failed for {name}", flush=True)


def main():
    print("[rescue] Watching for partial signals...", flush=True)
    os.makedirs(DL, exist_ok=True)

    while True:
        if os.path.exists(RESCUE_FLAG):
            try:
                with open(RESCUE_FLAG) as f:
                    name = f.read().strip()
                # Clear the flag immediately
                os.remove(RESCUE_FLAG)
                if name:
                    rescue(name)
            except Exception as e:
                print(f"[rescue] Error: {e}", flush=True)
                try:
                    os.remove(RESCUE_FLAG)
                except OSError:
                    pass

        time.sleep(5)


if __name__ == "__main__":
    main()
