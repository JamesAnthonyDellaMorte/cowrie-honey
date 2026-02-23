#!/usr/bin/env python3
"""
Cowrie malware pipeline: VT check → VT refresh → Storj backup.

Replaces the old bash backup-samples.sh and the fragile cron chain.
Imports vt-check.py functions directly as a library.

Usage:
  python3 backup-samples.py                # full pipeline
  python3 backup-samples.py --backup-only  # skip VT, just backup
  python3 backup-samples.py --vt-only      # VT check+refresh, no backup
  python3 backup-samples.py --dry-run      # show what would happen
  python3 backup-samples.py --clean        # delete dl/ samples after backup
"""

import hashlib
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────
COWRIE = Path("/root/cowrie")
DL = COWRIE / "dl"
UNANALYZED = COWRIE / "unanalyzed"
DB_PATH = COWRIE / "reports" / "malware.db"
LOG_PATH = COWRIE / "log" / "backup.log"
UPLINK = "/usr/local/bin/uplink"
BUCKET_SAMPLES = "sj://cowrie/samples"
BUCKET_UNANALYZED = "sj://cowrie/unanalyzed-samples"
STORJ_ACCESS = "cowrie"
ZIP_PASSWORD = "infected"
VT_REFRESH_DELAY = 600  # seconds between vt-check and vt-refresh

# ── Logging ─────────────────────────────────────────────────────────
log = logging.getLogger("pipeline")

def setup_logging():
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log.setLevel(logging.DEBUG)

    # File handler — always append
    fh = logging.FileHandler(LOG_PATH)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    log.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    log.addHandler(ch)


# ── Import vt-check as library ──────────────────────────────────────
def import_vt_check():
    """Import vt-check.py from the reports directory."""
    reports_dir = str(COWRIE / "reports")
    if reports_dir not in sys.path:
        sys.path.insert(0, reports_dir)
    # The file is named vt-check.py so we need importlib
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "vt_check", COWRIE / "reports" / "vt-check.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Database helpers ────────────────────────────────────────────────
def ensure_backed_up_column(db):
    try:
        db.execute("ALTER TABLE samples ADD COLUMN backed_up INTEGER DEFAULT 0")
        db.commit()
    except sqlite3.OperationalError:
        pass  # column already exists


def get_backed_up_hashes(db):
    rows = db.execute(
        "SELECT sha256 FROM samples WHERE backed_up=1"
    ).fetchall()
    return {r[0] for r in rows}


def mark_backed_up(db, hashes):
    for h in hashes:
        db.execute(
            "INSERT OR IGNORE INTO samples (sha256, backed_up) VALUES (?, 1)",
            (h,),
        )
        db.execute("UPDATE samples SET backed_up=1 WHERE sha256=?", (h,))
    db.commit()


def get_backup_stats(db):
    total = db.execute("SELECT COUNT(*) FROM samples WHERE backed_up=1").fetchone()[0]
    pending = db.execute("SELECT COUNT(*) FROM samples WHERE backed_up=0").fetchone()[0]
    return total, pending


# ── File helpers ────────────────────────────────────────────────────
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_partial_elf(path):
    try:
        with open(path, "rb") as f:
            header = f.read(64)
        size = path.stat().st_size
        if header[:4] != b"\x7fELF":
            return False
        ei_class = header[4]
        if ei_class == 2:  # ELF64
            shoff = int.from_bytes(header[40:48], "little")
        else:  # ELF32
            shoff = int.from_bytes(header[32:36], "little")
        return shoff > 0 and size < shoff
    except Exception:
        return False


# ── VT pipeline step ────────────────────────────────────────────────
def run_vt_check(dry_run=False):
    """Run VT check and refresh using vt-check.py as a library."""
    import asyncio

    log.info("=== VT Check: starting ===")
    if dry_run:
        log.info("VT Check: dry-run, skipping")
        return True

    try:
        vt_mod = import_vt_check()
    except Exception as e:
        log.error("VT Check: failed to import vt-check.py: %s", e)
        return False

    # Pass 1-3: main VT check
    try:
        log.info("VT Check: running main scan (check + upload unknowns)")
        asyncio.run(vt_mod.run(force=False, upload=True))
        log.info("VT Check: main scan complete")
    except Exception as e:
        log.error("VT Check: main scan failed: %s", e)
        return False

    # Wait before refresh so VT has time to process uploads
    log.info("VT Check: waiting %ds before refresh...", VT_REFRESH_DELAY)
    time.sleep(VT_REFRESH_DELAY)

    # Refresh yara-tagged entries
    try:
        log.info("VT Refresh: checking yara-tagged entries against VT")
        asyncio.run(vt_mod.refresh_yara_tags())
        log.info("VT Refresh: complete")
    except Exception as e:
        log.error("VT Refresh: failed: %s", e)
        # Non-fatal — backup can still proceed

    return True


# ── Backup step ─────────────────────────────────────────────────────
def check_uplink():
    """Verify uplink binary exists and Storj access is configured."""
    if not os.path.isfile(UPLINK):
        log.error("Backup: uplink not found at %s", UPLINK)
        return False
    try:
        result = subprocess.run(
            [UPLINK, "access", "list"],
            capture_output=True, text=True, timeout=30,
        )
        if STORJ_ACCESS not in result.stdout:
            log.error("Backup: Storj access '%s' not found. Available:\n%s",
                      STORJ_ACCESS, result.stdout.strip())
            return False
    except Exception as e:
        log.error("Backup: uplink access check failed: %s", e)
        return False
    return True


def scan_dir(dirpath, label, already_backed):
    """Scan a directory, return list of (path, sha256) for new files."""
    if not dirpath.is_dir():
        log.warning("Backup [%s]: directory not found: %s", label, dirpath)
        return []

    new_files = []
    skipped = 0
    partials = 0

    for f in sorted(dirpath.iterdir()):
        if not f.is_file() or f.is_symlink() or f.stat().st_size == 0:
            continue

        if is_partial_elf(f):
            log.info("Backup [%s]: removing partial: %s", label, f.name)
            f.unlink()
            partials += 1
            continue

        sha = sha256_file(f)
        if sha in already_backed:
            skipped += 1
            continue

        new_files.append((f, sha))

    total_scanned = len(new_files) + skipped + partials
    log.info(
        "Backup [%s]: scanned %d files — %d new, %d already backed up, %d partials removed",
        label, total_scanned, len(new_files), skipped, partials,
    )
    return new_files


def upload_to_storj(files, label):
    """Zip files and upload to Storj. Returns True on success."""
    if not files:
        return True

    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    archive_name = f"{label}-{stamp}.zip"
    bucket = BUCKET_UNANALYZED if "unanalyzed" in label else BUCKET_SAMPLES
    remote = f"{bucket}/{archive_name}"

    # Create password-protected zip
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        archive_path = tmp.name

    try:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.setpassword(ZIP_PASSWORD.encode())
            for fpath, _ in files:
                zf.write(fpath, fpath.name)

        size_mb = os.path.getsize(archive_path) / (1024 * 1024)
        log.info(
            "Backup [%s]: uploading %.1fMB (%d samples) to %s",
            label, size_mb, len(files), remote,
        )

        result = subprocess.run(
            [UPLINK, "cp", archive_path, remote, "--access", STORJ_ACCESS],
            capture_output=True, text=True, timeout=300,
        )

        if result.returncode != 0:
            log.error("Backup [%s]: uplink upload failed (rc=%d): %s",
                      label, result.returncode, result.stderr.strip())
            return False

        log.info("Backup [%s]: upload successful", label)
        return True

    except subprocess.TimeoutExpired:
        log.error("Backup [%s]: uplink upload timed out (300s)", label)
        return False
    except Exception as e:
        log.error("Backup [%s]: upload error: %s", label, e)
        return False
    finally:
        if os.path.exists(archive_path):
            os.unlink(archive_path)


def run_backup(dry_run=False, clean=False):
    """Scan dl/ and unanalyzed/, zip new samples, upload to Storj."""
    log.info("=== Backup: starting ===")

    # Pre-flight: check uplink
    if not dry_run and not check_uplink():
        return False

    db = sqlite3.connect(DB_PATH)
    ensure_backed_up_column(db)
    already_backed = get_backed_up_hashes(db)
    log.info("Backup: %d hashes already marked as backed up in DB", len(already_backed))

    success = True

    # dl/
    dl_files = scan_dir(DL, "dl", already_backed)
    if dl_files:
        if dry_run:
            log.info("Backup [dl]: dry-run — would upload %d samples", len(dl_files))
        else:
            if upload_to_storj(dl_files, "cowrie"):
                hashes = [sha for _, sha in dl_files]
                mark_backed_up(db, hashes)
                log.info("Backup [dl]: marked %d samples as backed up", len(hashes))
                if clean:
                    for fpath, _ in dl_files:
                        fpath.unlink()
                    log.info("Backup [dl]: cleaned %d files", len(dl_files))
            else:
                success = False
                log.error("Backup [dl]: upload failed — samples NOT marked as backed up")

    # unanalyzed/
    ua_files = scan_dir(UNANALYZED, "unanalyzed", already_backed)
    if ua_files:
        if dry_run:
            log.info("Backup [unanalyzed]: dry-run — would upload %d samples", len(ua_files))
        else:
            if upload_to_storj(ua_files, "cowrie-unanalyzed"):
                hashes = [sha for _, sha in ua_files]
                mark_backed_up(db, hashes)
                log.info("Backup [unanalyzed]: marked %d samples as backed up", len(hashes))
            else:
                success = False
                log.error("Backup [unanalyzed]: upload failed — samples NOT marked as backed up")

    # Summary
    total_backed, pending = get_backup_stats(db)
    db.close()
    log.info("Backup: %d total backed up, %d pending", total_backed, pending)
    log.info("=== Backup: %s ===", "complete" if success else "FAILED")
    return success


# ── Main ────────────────────────────────────────────────────────────
def main():
    setup_logging()

    args = set(sys.argv[1:])
    dry_run = "--dry-run" in args
    clean = "--clean" in args
    backup_only = "--backup-only" in args
    vt_only = "--vt-only" in args

    log.info("=" * 60)
    log.info("Pipeline started — flags: %s", " ".join(args) or "(none)")
    start = time.time()
    ok = True

    # Step 1: VT check + refresh
    if not backup_only:
        if not run_vt_check(dry_run=dry_run):
            log.warning("VT step had errors — continuing to backup anyway")

    # Step 2: Backup to Storj
    if not vt_only:
        if not run_backup(dry_run=dry_run, clean=clean):
            ok = False

    elapsed = time.time() - start
    log.info("Pipeline finished in %.0fs — %s", elapsed, "OK" if ok else "ERRORS")
    log.info("=" * 60)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
