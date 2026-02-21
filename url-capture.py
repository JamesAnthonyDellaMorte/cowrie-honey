#!/usr/bin/env python3
"""
Watches Cowrie JSON log for download URLs in commands and captures them.
Fills the gap where proxy mode doesn't intercept wget/curl URLs like shell mode does.

On startup, replays the entire existing log to catch URLs from before a restart.
Then tails for new events. Handles log rotation (truncation or replacement).
"""
import json
import re
import os
import hashlib
import time
import ssl
import urllib.request

LOG = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
DL_DIR = "/mnt/captures"

# Match http/https URLs
URL_RE = re.compile(r'https?://[^\s\'\";<>|`\)]+')

# URLs that are just recon, not payload downloads
SKIP_DOMAINS = {'ipinfo.io', 'ifconfig.me', 'icanhazip.com', 'example.com',
                'checkip.amazonaws.com', 'api.ipify.org', 'wtfismyip.com'}

# Don't re-download URLs we've already seen
seen_urls = set()

# Loose SSL for sketchy C2 servers
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def already_have(sha_prefix):
    """Check if we already captured a file with this hash prefix."""
    try:
        for f in os.listdir(DL_DIR):
            if f.startswith(sha_prefix + "-"):
                return True
    except OSError:
        pass
    return False


def download_url(url):
    """Download a URL and save to DL_DIR with sha9-name format."""
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Wget/1.21.2'
        })
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            data = resp.read(100 * 1024 * 1024)  # 100MB limit
            if not data:
                return

            sha = hashlib.sha256(data).hexdigest()
            prefix = sha[:9]

            if already_have(prefix):
                return

            # Use the filename from the URL path
            name = url.rstrip('/').split('/')[-1].split('?')[0] or 'payload'
            # Sanitize filename
            name = re.sub(r'[^\w.\-]', '_', name)
            friendly = f"{prefix}-{name}"

            # Only keep executable binaries (ELF, PE, Mach-O)
            magic = data[:4]
            if magic[:4] not in (b'\x7fELF',                          # ELF
                                 b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',  # Mach-O
                                 b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',  # Mach-O reversed
                                 b'\xca\xfe\xba\xbe') \
               and magic[:2] != b'MZ':                                # PE/Windows
                return

            path = os.path.join(DL_DIR, friendly)
            with open(path, 'wb') as f:
                f.write(data)
            print(f"[url-capture] {friendly} ({len(data)} bytes) from {url}", flush=True)
    except Exception:
        # C2 servers go down all the time, don't spam logs
        pass


def is_recon_url(url):
    """Skip URLs that are connectivity checks, not payload downloads."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ''
        return any(skip in host for skip in SKIP_DOMAINS)
    except Exception:
        return False


def extract_urls(cmd):
    """Extract download URLs from a command string."""
    urls = URL_RE.findall(cmd)
    result = []
    for url in urls:
        # Clean trailing punctuation
        url = url.rstrip('.,;:)')
        if is_recon_url(url):
            continue
        if url not in seen_urls:
            seen_urls.add(url)
            result.append(url)
    return result


def process_line(line):
    """Process a single JSON log line, download any new URLs."""
    try:
        event = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return

    if event.get('eventid') != 'cowrie.command.input':
        return

    cmd = event.get('input', '')
    urls = extract_urls(cmd)
    for url in urls:
        download_url(url)


def tail_log():
    """Replay existing log then tail for new events. Handles log rotation."""
    # Wait for log file to exist
    while not os.path.exists(LOG):
        time.sleep(1)

    # Phase 1: Replay entire existing log to catch URLs from before restart
    print("[url-capture] Replaying existing log for missed URLs...", flush=True)
    replayed = 0
    with open(LOG) as f:
        for line in f:
            process_line(line)
            replayed += 1
    print(f"[url-capture] Replayed {replayed} events, {len(seen_urls)} unique URLs seen", flush=True)

    # Phase 2: Tail for new events
    print("[url-capture] Now tailing for new events", flush=True)
    with open(LOG) as f:
        f.seek(0, 2)
        inode = os.stat(LOG).st_ino

        while True:
            line = f.readline()
            if not line:
                # Check for log rotation: file truncated or replaced
                try:
                    stat = os.stat(LOG)
                    if stat.st_ino != inode:
                        # File replaced (new inode) — reopen
                        print("[url-capture] Log rotated (new file), reopening", flush=True)
                        f.close()
                        time.sleep(0.5)
                        f = open(LOG)
                        inode = stat.st_ino
                        continue
                    if stat.st_size < f.tell():
                        # File truncated — seek to beginning
                        print("[url-capture] Log truncated, seeking to start", flush=True)
                        f.seek(0)
                        continue
                except OSError:
                    pass
                time.sleep(0.5)
                continue

            process_line(line)


if __name__ == '__main__':
    print("[url-capture] Starting URL capture from Cowrie log", flush=True)
    os.makedirs(DL_DIR, exist_ok=True)
    tail_log()
