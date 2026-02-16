#!/usr/bin/env python3
"""
VirusTotal sample checker for Cowrie honeypot.

Three-pass design:
  Pass 1: Check local SQLite cache (instant)
  Pass 2: Lookup uncached hashes on VT (4 lookups/min rate limit)
  Pass 3: Upload unknowns to VT, then poll for results

Usage:
  python3 vt-check.py [--force] [--no-upload]
"""

import asyncio
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import vt

# --- Config ---
VT_KEY = Path("/root/.config/virustotal/api_key").read_text().strip()
DL = Path("/root/cowrie/dl")
DB_PATH = Path("/root/cowrie/reports/vt-cache.db")
UNANALYZED = Path("/root/cowrie/unanalyzed")
RATE_LIMIT = 4       # lookups per minute
RATE_WINDOW = 60     # seconds
POLL_INTERVAL = 30   # seconds between poll attempts
POLL_MAX = 10        # max poll rounds


# --- Database ---
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS samples (
        sha256 TEXT PRIMARY KEY,
        first_seen TEXT DEFAULT (datetime('now')),
        filename TEXT,
        filesize INTEGER,
        filetype TEXT,
        vt_known INTEGER DEFAULT 0,
        vt_detections INTEGER DEFAULT 0,
        vt_total INTEGER DEFAULT 0,
        vt_label TEXT DEFAULT '',
        vt_names TEXT DEFAULT '',
        vt_link TEXT DEFAULT '',
        checked_at TEXT DEFAULT (datetime('now'))
    )""")
    try:
        db.execute("ALTER TABLE samples ADD COLUMN vt_link TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    db.commit()
    return db


def db_get_cached(db, sha256):
    row = db.execute(
        "SELECT vt_known, vt_detections, vt_total, vt_label, vt_names FROM samples WHERE sha256=?",
        (sha256,)
    ).fetchone()
    return row


def db_save_known(db, sha256, fname, size, ftype, det, total, label, names, link):
    db.execute(
        """INSERT OR REPLACE INTO samples
           (sha256, filename, filesize, filetype, vt_known, vt_detections, vt_total, vt_label, vt_names, vt_link, checked_at)
           VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, datetime('now'))""",
        (sha256, fname, size, ftype, det, total, label, names, link)
    )
    db.commit()


def db_save_unknown(db, sha256, fname, size, ftype, link):
    db.execute(
        """INSERT OR REPLACE INTO samples
           (sha256, filename, filesize, filetype, vt_known, vt_link, checked_at)
           VALUES (?, ?, ?, ?, 0, ?, datetime('now'))""",
        (sha256, fname, size, ftype, link)
    )
    db.commit()


# --- Helpers ---
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def filetype(path):
    try:
        return subprocess.check_output(["file", "-b", str(path)], text=True).strip()[:80]
    except Exception:
        return "unknown"


def friendly_name(basename):
    """Strip sha9- prefix if present."""
    parts = basename.split("-", 1)
    if len(parts) == 2 and len(parts[0]) == 9:
        return parts[1]
    return basename


def parse_vt_object(obj):
    """Extract detection info from a VT file object."""
    stats = obj.last_analysis_stats
    det = stats.get("malicious", 0)
    total = det + stats.get("undetected", 0)
    try:
        label = obj.popular_threat_classification["suggested_threat_label"]
    except (AttributeError, KeyError, TypeError):
        label = "unknown"
    try:
        names = ", ".join(obj.names[:3])
    except (AttributeError, TypeError):
        names = "?"
    return det, total, label, names


def vt_link(sha256):
    return f"https://www.virustotal.com/gui/file/{sha256}"


class RateLimiter:
    """Rate limiter with live countdown display."""
    def __init__(self, max_calls, window):
        self.max_calls = max_calls
        self.window = window
        self.calls = []

    async def acquire(self):
        now = time.time()
        # Remove calls outside the window
        self.calls = [t for t in self.calls if now - t < self.window]
        if len(self.calls) >= self.max_calls:
            wait_until = self.calls[0] + self.window
            remaining = wait_until - now
            while remaining > 0:
                print(f"\r  [rate] Waiting... {int(remaining)}s  ", end="", flush=True)
                await asyncio.sleep(1)
                remaining -= 1
            print("\r  [rate] Resuming...            ", flush=True)
            self.calls = []
        self.calls.append(time.time())


# --- Scanning ---
def collect_files():
    """Build list of files to check."""
    files = []
    for f in sorted(DL.iterdir()):
        if f.is_symlink() or not f.is_file():
            continue
        size = f.stat().st_size
        if size == 0:
            continue
        bname = f.name
        fname = friendly_name(bname)
        sha = sha256_file(f)
        files.append({
            "path": f,
            "bname": bname,
            "fname": fname,
            "sha256": sha,
            "size": size,
        })
    return files


async def run(force=False, upload=True):
    UNANALYZED.mkdir(parents=True, exist_ok=True)
    db = init_db()
    files = collect_files()
    total = len(files)
    print(f"  Found {total} files in {DL}\n")

    # ==========================================================
    # PASS 1: Local cache
    # ==========================================================
    print("--- Pass 1: Local cache ---")
    uncached = []
    p1_known = 0
    p1_unknown = 0

    for entry in files:
        sha = entry["sha256"]
        if not force:
            row = db_get_cached(db, sha)
            if row:
                known, det, vtotal, label, names = row
                if known:
                    print(f"  [cache] {sha[:16]}... -> {det}/{vtotal} - {label}  [{names}]")
                    p1_known += 1
                else:
                    print(f"  [cache] ****** UNKNOWN: {sha[:16]}... ******")
                    shutil.copy2(entry["path"], UNANALYZED / entry["bname"])
                    p1_unknown += 1
                continue
        uncached.append(entry)

    print(f"  Known: {p1_known} | Unknown: {p1_unknown} | Need lookup: {len(uncached)}\n")

    # ==========================================================
    # PASS 2: VT lookups
    # ==========================================================
    unknowns = []
    p2_known = 0
    p2_unknown = 0
    p2_error = 0

    if uncached:
        print("--- Pass 2: VT lookups ---")
        rate = RateLimiter(RATE_LIMIT, RATE_WINDOW)

        async with vt.Client(VT_KEY) as client:
            for entry in uncached:
                sha = entry["sha256"]
                fname = entry["fname"]
                size = entry["size"]
                ftype = filetype(entry["path"])
                link = vt_link(sha)
                entry["filetype"] = ftype

                await rate.acquire()

                try:
                    obj = await client.get_object_async(f"/files/{sha}")
                    det, vtotal, label, names = parse_vt_object(obj)
                    print(f"  [new]   {sha[:16]}... -> {det}/{vtotal} - {label}  [{names}]")
                    db_save_known(db, sha, fname, size, ftype, det, vtotal, label, names, link)
                    p2_known += 1
                except vt.APIError as e:
                    if e.code == "NotFoundError":
                        print(f"  [new]   {sha[:16]}... -> NOT ON VT ({fname})")
                        db_save_unknown(db, sha, fname, size, ftype, link)
                        shutil.copy2(entry["path"], UNANALYZED / entry["bname"])
                        unknowns.append(entry)
                        p2_unknown += 1
                    else:
                        print(f"  [error] {sha[:16]}... -> {e.code}: {e.message}")
                        p2_error += 1

        print(f"  Known: {p2_known} | Unknown: {p2_unknown} | Errors: {p2_error}\n")

    # ==========================================================
    # PASS 3: Upload unknowns, then poll
    # ==========================================================
    p3_uploaded = 0
    p3_done = 0
    p3_pending = 0

    if upload and unknowns:
        print("--- Pass 3: Upload & analyze ---")

        uploaded = []
        async with vt.Client(VT_KEY) as client:
            # Upload all (no rate limit on uploads)
            for entry in unknowns:
                fname = entry["fname"]
                sha = entry["sha256"]
                link = vt_link(sha)

                print(f"  [upload] {fname} -> VT...")
                try:
                    with open(entry["path"], "rb") as f:
                        await client.scan_file_async(f)
                    print(f"  [upload] Submitted! {link}")
                    uploaded.append(entry)
                    p3_uploaded += 1
                except vt.APIError as e:
                    print(f"  [upload] Failed: {e.code}")

            # Poll for results
            if uploaded:
                print(f"\n  Waiting for VT to process {len(uploaded)} samples...")
                rate = RateLimiter(RATE_LIMIT, RATE_WINDOW)
                pending = list(uploaded)

                for attempt in range(1, POLL_MAX + 1):
                    if not pending:
                        break

                    # Countdown timer
                    for sec in range(POLL_INTERVAL, 0, -1):
                        print(f"\r  [poll] Next check in {sec}s ({len(pending)} pending)  ", end="", flush=True)
                        await asyncio.sleep(1)
                    print()

                    still_pending = []
                    for entry in pending:
                        sha = entry["sha256"]
                        fname = entry["fname"]
                        size = entry["size"]
                        ftype = entry.get("filetype", "unknown")
                        link = vt_link(sha)

                        await rate.acquire()

                        try:
                            obj = await client.get_object_async(f"/files/{sha}")
                            det, vtotal, label, names = parse_vt_object(obj)
                            if vtotal > 0:
                                print(f"  [done]  {sha[:16]}... -> {det}/{vtotal} - {label}  [{names}]")
                                db_save_known(db, sha, fname, size, ftype, det, vtotal, label, names, link)
                                # Remove from unanalyzed
                                ua = UNANALYZED / entry["bname"]
                                if ua.exists():
                                    ua.unlink()
                                p3_done += 1
                            else:
                                still_pending.append(entry)
                        except vt.APIError:
                            still_pending.append(entry)

                    pending = still_pending

                # Report still pending
                for entry in pending:
                    print(f"  [pending] {entry['fname']} — check later: {vt_link(entry['sha256'])}")
                    p3_pending += 1

        print(f"  Uploaded: {p3_uploaded} | Analyzed: {p3_done} | Pending: {p3_pending}\n")

    # ==========================================================
    # Summary
    # ==========================================================
    total_cached = db.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    total_known_db = db.execute("SELECT COUNT(*) FROM samples WHERE vt_known=1").fetchone()[0]
    total_unknown_db = db.execute("SELECT COUNT(*) FROM samples WHERE vt_known=0").fetchone()[0]

    print("--- Summary ---")
    print(f"  Total files:   {total}")
    print(f"  From cache:    {p1_known + p1_unknown}")
    print(f"  Looked up:     {p2_known + p2_unknown + p2_error}")
    print(f"  Uploaded:      {p3_uploaded}")
    print(f"\n  Database:      {total_cached} samples ({total_known_db} known, {total_unknown_db} unknown)")

    db.close()


def main():
    force = "--force" in sys.argv
    no_upload = "--no-upload" in sys.argv
    asyncio.run(run(force=force, upload=not no_upload))


if __name__ == "__main__":
    main()
