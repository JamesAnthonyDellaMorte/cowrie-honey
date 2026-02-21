# Cowrie Honeypot Download Acquisition Architecture Report
Generated: 2026-02-21
Workspace: `/root/cowrie`
Primary sample store: `/root/cowrie/dl`

## Scope
- Focus: how your Dockerized honeypot acquires malware (`DL`), stores it, and hands it into analysis/report workflows.
- Cron is included only as supporting context.

## Executive Summary
- This stack is a proxy-mode Cowrie honeypot in Docker with multiple, overlapping malware collection paths.
- Downloads are captured through three mechanisms:
  - SFTP upload interception in `ssh_proxy/sftp.py`.
  - URL extraction + re-download from attacker commands in `url-capture.py`.
  - File-system executable watcher in `backend/capture.sh`.
- Captures land in `dl/` using hash-prefixed names (`sha9-originalname`) for easy correlation with logs and analysis artifacts.
- The reports/analysis side is already wired, with backup, VirusTotal, YARA, and decompilation helpers.

## Docker + Service Architecture
### Compose and networking
- `docker-compose.yml` runs one service: `cowrie`.
- Exposed ports:
  - `22 -> 2222` (SSH honeypot ingress)
  - `23 -> 2323` (Telnet honeypot ingress)
  - extra SSH mappings: `2200`, `2222`, `10022` all to container `2222`
- `cowrie.cfg` uses proxy backend mode (`[honeypot] backend = proxy`).

### Volume wiring
- Host `./dl` is mounted to `/mnt/captures`.
- `entrypoint.sh` symlinks Cowrie downloads path to `/mnt/captures`.
- Result: all capture workers write into host-visible `dl/`.

### Runtime processes started by entrypoint
- Backend emulation services:
  - `sshd`
  - `inetutils-inetd` (telnet)
- Capture/cleanup workers:
  - `/usr/sbin/rsyslogd` -> actually `backend/capture.sh`
  - `/usr/sbin/syslog-ng` -> actually `url-capture.py`
  - `/usr/sbin/atd` -> actually `backend/miner-killer.sh`
- Cowrie core:
  - `twistd cowrie`

## How Malware Acquisition Works
### Path A: SFTP upload capture
- Implemented in `ssh_proxy/sftp.py`.
- On attacker SFTP `put`, bytes are buffered, SHA256 hashed, and saved as `sha9-basename`.
- Emits structured event `cowrie.session.file_upload` with hash + output filename + duplicate flag.
- This is your cleanest direct record of attacker-pushed binaries.

### Path B: URL replay capture from command input
- Implemented in `url-capture.py`.
- Reads `log/cowrie.json`, extracts `http/https` from `cowrie.command.input`.
- Downloads payloads itself (100MB limit, permissive TLS, dedup by SHA prefix).
- Keeps only executable magic types (ELF/PE/Mach-O), discards recon/noise URLs.
- Replays existing log on startup to backfill missed URLs, then tails live.

### Path C: File-system executable watcher
- Implemented in `backend/capture.sh`.
- Watches writable paths (`/tmp`, `/var/tmp`, `/dev/shm`, `/root`, `/usr`, etc.).
- Captures newly written executable binaries by magic bytes.
- Deduplicates by hash prefix and skips known baseline system binaries.
- Includes partial ELF protection to avoid storing truncated downloads.

### Why this design is strong
- Attackers switch methods frequently (SFTP, dropper scripts, copied binaries).
- Single-source capture misses things.
- Your overlap design increases collection completeness and preserves more analysis value.

## Evidence Snapshot (Current Environment)
### Log coverage analyzed
- `log/cowrie.json*` window: `2026-02-18T08:23:58Z` to `2026-02-21T16:23:45Z`.

### Event volumes
- `cowrie.command.input`: `13,622`
- `cowrie.session.file_upload`: `29`
- `cowrie.session.file_download`: `0`
- No `file_download` events is consistent with your custom proxy-mode collection approach.

### Upload-path telemetry
- File-upload events: `29`
- Unique upload hashes: `7`
- Duplicate flags:
  - `false`: `11`
  - `true`: `18`

### URL-path telemetry
- URL mentions extracted from attacker commands: `335`
- Unique URLs across rotated logs: `19`
- Sessions containing at least one URL: `54`
- Top observed URL families:
  - `http://130.12.180.26:82/f/aarch64/.16`
  - `http://130.12.182.167/f/.b0s`
  - `http://93.185.167.10/f/aarch64/.b0s`
  - `https://178.16.55.224/sh`
  - `http://130.12.180.26:82/f/x86_64/.16`

### Current capture inventory
- `dl/`:
  - `56` files
  - `80M`
  - file types: `40` ELF64 + `16` ELF32
  - top families: `redtail.x86_64`, `redtail.arm8`, `redtail.i686`, `redtail.arm7`
- `unanalyzed/`:
  - `24` files
  - `73M`

## Reports/Analysis Side (Post-Acquisition)
### Existing analysis assets
- `reports/malware-analysis.md`
- `reports/analysis/` (json/pcap artifacts)
- `ghidra_output/` + `ghidra_project/`
- tooling:
  - `reports/vt-check.py`
  - `reports/yara-scan.py`
  - `reports/rules.yar`
  - `reports/stats.py`
  - `reports/decomp-analyze.sh`

### Backup/offload pipeline
- `reports/backup-samples.sh` scans `dl/` and `unanalyzed/`, hashes, zips, and uploads to Storj.
- Intended behavior: dedup and optional cleanup after successful upload.
- Current observed issue from `log/backup.log`:
  - cron-run backup attempts fail because `uplink` is not found in PATH.
- Practical impact:
  - local collection continues
  - offsite backup is not completing reliably

## Minimal note on cron
- Host cron is supporting the pipeline, not driving acquisition logic.
- Core capture is done by Cowrie + the three runtime workers described above.

## End-to-End Flow
1. Attacker connects to exposed SSH/Telnet honeypot ports.
2. Cowrie proxies backend interaction and logs events to `log/cowrie.json*`.
3. Malware enters collection via SFTP upload capture, URL replay capture, and/or file-system watcher.
4. Samples land in `dl/` with hash-prefixed filenames.
5. Analysis workflows pull from `dl/` + `unanalyzed/` into `reports/analysis/` and Ghidra outputs.
6. Backup script attempts offsite archival.

## Key Files
- `docker-compose.yml`
- `Dockerfile`
- `entrypoint.sh`
- `cowrie.cfg`
- `ssh_proxy/sftp.py`
- `url-capture.py`
- `backend/capture.sh`
- `reports/backup-samples.sh`
- `log/cowrie.json`
- `log/cowrie.json.2026-02-18`
- `log/cowrie.json.2026-02-19`
- `log/cowrie.json.2026-02-20`
