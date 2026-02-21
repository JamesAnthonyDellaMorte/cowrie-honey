#!/usr/bin/env python3
"""
Watches Cowrie JSON log for download URLs in commands and captures them.
Fills the gap where proxy mode doesn't intercept wget/curl URLs like shell mode does.

On startup, replays the entire existing log to catch URLs from before a restart.
Then tails for new events. Handles log rotation (truncation or replacement).
"""

import concurrent.futures
import hashlib
import json
import os
import re
import ssl
import threading
import time
import urllib.request
from urllib.parse import urlparse

LOG = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
DL_DIR = "/mnt/captures"
MAX_BYTES = 100 * 1024 * 1024
MAX_WORKERS = int(os.getenv("URL_CAPTURE_WORKERS", "8"))
MAX_ATTEMPTS = int(os.getenv("URL_CAPTURE_MAX_ATTEMPTS", "4"))
DOWNLOAD_TIMEOUT = int(os.getenv("URL_CAPTURE_TIMEOUT", "30"))

# Match http/https URLs found inside commands
URL_RE = re.compile(r'https?://[^\s\'\";<>|`\)]+')
ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

# URLs that are usually connectivity checks, not payload downloads
SKIP_DOMAINS = {
    "ipinfo.io",
    "ifconfig.me",
    "icanhazip.com",
    "example.com",
    "checkip.amazonaws.com",
    "api.ipify.org",
    "wtfismyip.com",
}

# URL state tracking
seen_urls = set()          # Successfully processed URLs (captured, duplicate, or non-binary)
attempt_counts = {}        # URL -> number of attempts
inflight_urls = set()      # URLs currently being downloaded
state_lock = threading.Lock()
executor = None

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


def normalize_url(url, src_ip):
    """Normalize attacker URL strings and resolve simple server-ip placeholders."""
    cleaned = url.rstrip(".,;:)")

    if src_ip:
        cleaned = cleaned.replace("${SERVER_IP}", src_ip)
        cleaned = cleaned.replace("$SERVER_IP", src_ip)
        cleaned = cleaned.replace("${server_ip}", src_ip)
        cleaned = cleaned.replace("$server_ip", src_ip)

    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    if "$" in parsed.netloc:
        # Unresolved variable in host part
        return None

    return cleaned


def download_url(url):
    """Download a URL and save to DL_DIR with sha9-name format.

    Returns True when URL is fully handled (captured/duplicate/non-binary).
    Returns False when request failed and should be retried.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Wget/1.21.2"})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT, context=ssl_ctx) as resp:
            data = resp.read(MAX_BYTES)

        if not data:
            return False

        sha = hashlib.sha256(data).hexdigest()
        prefix = sha[:9]

        if already_have(prefix):
            return True

        # Use the filename from the URL path
        name = url.rstrip("/").split("/")[-1].split("?")[0] or "payload"
        name = re.sub(r"[^\w.\-]", "_", name)
        friendly = f"{prefix}-{name}"

        # Keep executable binaries only (ELF, PE, Mach-O)
        magic = data[:4]
        if (
            magic[:4]
            not in (
                b"\x7fELF",  # ELF
                b"\xfe\xed\xfa\xce",
                b"\xfe\xed\xfa\xcf",  # Mach-O
                b"\xce\xfa\xed\xfe",
                b"\xcf\xfa\xed\xfe",  # Mach-O reversed
                b"\xca\xfe\xba\xbe",
            )
            and magic[:2] != b"MZ"  # PE/Windows
        ):
            return True

        path = os.path.join(DL_DIR, friendly)
        with open(path, "wb") as f:
            f.write(data)

        print(f"[url-capture] {friendly} ({len(data)} bytes) from {url}", flush=True)
        return True
    except Exception:
        # C2 servers go down all the time; keep retries bounded by MAX_ATTEMPTS.
        return False


def is_recon_url(url):
    """Skip URLs that are connectivity checks, not payload downloads."""
    try:
        host = urlparse(url).hostname or ""
        return any(skip in host for skip in SKIP_DOMAINS)
    except Exception:
        return False


def extract_urls(cmd, src_ip):
    """Extract download URLs from command text."""
    cmd = ANSI_ESCAPE_RE.sub("", cmd)
    urls = URL_RE.findall(cmd)

    result = []
    seen_local = set()
    for raw in urls:
        url = normalize_url(raw, src_ip)
        if not url:
            continue
        if is_recon_url(url):
            continue
        if url in seen_local:
            continue
        seen_local.add(url)
        result.append(url)

    return result


def claim_url(url):
    """Reserve a URL for a bounded number of download attempts."""
    with state_lock:
        if url in seen_urls or url in inflight_urls:
            return False

        attempts = attempt_counts.get(url, 0)
        if attempts >= MAX_ATTEMPTS:
            return False

        attempt_counts[url] = attempts + 1
        inflight_urls.add(url)
        return True


def finish_url(url, done):
    """Release URL in-flight state and mark completion if done."""
    with state_lock:
        inflight_urls.discard(url)
        if done:
            seen_urls.add(url)


def download_worker(url):
    done = download_url(url)
    finish_url(url, done)


def process_line(line):
    """Process a single JSON log line, queueing any new URLs."""
    try:
        event = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return

    if event.get("eventid") != "cowrie.command.input":
        return

    cmd = event.get("input", "")
    src_ip = event.get("src_ip", "")

    for url in extract_urls(cmd, src_ip):
        if claim_url(url):
            executor.submit(download_worker, url)


def tail_log():
    """Replay existing log then tail for new events. Handles log rotation."""
    while not os.path.exists(LOG):
        time.sleep(1)

    print(f"[url-capture] Starting with {MAX_WORKERS} workers", flush=True)
    print("[url-capture] Replaying existing log for missed URLs...", flush=True)

    replayed = 0
    with open(LOG) as f:
        for line in f:
            process_line(line)
            replayed += 1

    print(f"[url-capture] Replayed {replayed} events", flush=True)
    print("[url-capture] Now tailing for new events", flush=True)

    with open(LOG) as f:
        f.seek(0, 2)
        inode = os.stat(LOG).st_ino

        while True:
            line = f.readline()
            if not line:
                try:
                    stat = os.stat(LOG)
                    if stat.st_ino != inode:
                        print("[url-capture] Log rotated (new file), reopening", flush=True)
                        f.close()
                        time.sleep(0.5)
                        f = open(LOG)
                        inode = stat.st_ino
                        continue
                    if stat.st_size < f.tell():
                        print("[url-capture] Log truncated, seeking to start", flush=True)
                        f.seek(0)
                        continue
                except OSError:
                    pass
                time.sleep(0.5)
                continue

            process_line(line)


if __name__ == "__main__":
    print("[url-capture] Starting URL capture from Cowrie log", flush=True)
    os.makedirs(DL_DIR, exist_ok=True)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        tail_log()
    finally:
        executor.shutdown(wait=False)
