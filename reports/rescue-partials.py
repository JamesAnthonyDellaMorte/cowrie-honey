#!/usr/bin/env python3
"""
Rescue partial downloads by fetching directly from C2.
Runs on the HOST (outside the container) so OOM/kills don't affect it.

Checks docker logs for skipped partials, finds source URLs in cowrie.json,
and downloads the full binary directly from the C2.

Usage:
  python3 rescue-partials.py            # check and download
  python3 rescue-partials.py --dry-run  # show what would be downloaded
"""

import glob
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.request

DL = "/root/cowrie/dl"
LOG_DIR = "/root/cowrie/log"
RESCUED_FILE = "/root/cowrie/reports/.rescued_urls"

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


def get_skipped_partials():
    """Parse docker logs for skipped partial filenames."""
    try:
        output = subprocess.check_output(
            ["docker", "logs", "cowrie"], stderr=subprocess.STDOUT, text=True
        )
    except subprocess.CalledProcessError:
        return []

    partials = set()
    for line in output.splitlines():
        if "[capture] skipped partial:" in line:
            # Format: [capture] skipped partial: .b0s (2023424 / 6577376 bytes)
            match = re.search(r'skipped partial: (\S+)', line)
            if match:
                partials.add(match.group(1))
    return partials


def find_urls_for_filename(name):
    """Search all cowrie logs for URLs that delivered this filename."""
    urls = set()
    log_files = sorted(glob.glob(os.path.join(LOG_DIR, "cowrie.json*")))

    for logfile in log_files:
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


def load_rescued():
    """Load set of already-rescued URLs."""
    try:
        with open(RESCUED_FILE) as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()


def save_rescued(url):
    """Append a URL to the rescued tracking file."""
    with open(RESCUED_FILE, "a") as f:
        f.write(url + "\n")


def already_have(sha_prefix):
    """Check if we already have a file with this hash prefix in dl/."""
    for f in os.listdir(DL):
        if f.startswith(sha_prefix + "-"):
            return True
    return False


def download(url):
    """Download a URL and return the bytes, or None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Wget/1.21.2"})
        with urllib.request.urlopen(req, timeout=60, context=ssl_ctx) as resp:
            return resp.read(100 * 1024 * 1024)
    except Exception:
        return None


def is_binary(data):
    """Check if data starts with a known executable magic."""
    if len(data) < 4:
        return False
    magic4 = data[:4]
    magic2 = data[:2]
    return magic4 in BINARY_MAGICS or magic2 == b"MZ"


def main():
    dry_run = "--dry-run" in sys.argv

    print("[rescue] Checking for skipped partials...")
    partials = get_skipped_partials()

    if not partials:
        print("[rescue] No partials found.")
        return

    print(f"[rescue] Found {len(partials)} partial filenames:")
    for name in sorted(partials):
        print(f"  {name}")

    rescued_urls = load_rescued()
    rescued_count = 0

    for name in sorted(partials):
        urls = find_urls_for_filename(name)
        if not urls:
            print(f"\n  {name}: no source URL found in logs")
            continue

        for url in sorted(urls):
            if url in rescued_urls:
                continue

            print(f"\n  {name} -> {url}")

            if dry_run:
                continue

            data = download(url)
            if not data:
                print("    Download failed")
                save_rescued(url)
                continue

            if not is_binary(data):
                print(f"    Not a binary, skipping")
                save_rescued(url)
                continue

            sha = hashlib.sha256(data).hexdigest()
            prefix = sha[:9]

            if already_have(prefix):
                print("    Already have this hash")
                save_rescued(url)
                continue

            friendly = f"{prefix}-{name}"
            path = os.path.join(DL, friendly)
            with open(path, "wb") as f:
                f.write(data)

            print(f"    RESCUED: {friendly} ({len(data):,} bytes)")
            save_rescued(url)
            rescued_count += 1

    print(f"\n[rescue] Done. Rescued {rescued_count} files.")


if __name__ == "__main__":
    main()
