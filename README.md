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

## Optional Windows Sensor Pack (RDP + Heralding)
- Added file: `docker-compose.windows.yml`
- Purpose:
  - `rdphoney` on `3389/tcp` for Windows/RDP-focused attacks.
  - `heralding` for additional credential-capture protocols (`110`, `143`, `993`, `995`, `1080`, `5432`, `5900`) without conflicting with Cowrie SSH/Telnet ports.
- Start:
  - `docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d`
- Stop:
  - `docker compose -f docker-compose.yml -f docker-compose.windows.yml down`

## Applied Throughput Tuning (2026-02-21)
This section documents exactly what was changed to increase binary capture rate while keeping host impact moderate.

### 1) Container resources (moderate bump)
- File: `docker-compose.yml`
- Changes:
  - `cpus: 2.0` (was lower)
  - `mem_limit: 3g`
  - `memswap_limit: 4g`
  - `pids_limit: 512`
- Goal:
  - Reduce worker starvation during attack bursts.
  - Improve concurrent URL and file processing without aggressively consuming host resources.

### 2) Watchdog restart policy (less churn)
- File: `backend-watchdog.sh`
- Changes:
  - `THRESHOLD_CPU=90`
  - `THRESHOLD_MEM=92`
  - `CPU_STRIKES_RESTART=30`
- Goal:
  - Avoid restarting Cowrie during short CPU spikes.
  - Preserve active attacker sessions long enough for second-stage payload delivery.

### 3) Miner-killer timing (capture-first behavior)
- File: `backend/miner-killer.sh`
- Changes:
  - Added `MINER_GRACE_SECONDS=1200` (20 min) before killing known miner process names.
  - Added configurable high-CPU controls:
    - `HIGH_CPU_THRESHOLD=50.0`
    - `HIGH_CPU_STRIKES=4`
- Goal:
  - Let payload chains complete before cleanup.
  - Still contain long-running abusive processes.

### 4) URL capture parallelization and resilience
- File: `url-capture.py`
- Changes:
  - Added multi-threaded downloader pool (`ThreadPoolExecutor`).
  - Defaults:
    - `URL_CAPTURE_WORKERS=8`
    - `URL_CAPTURE_MAX_ATTEMPTS=4`
    - `URL_CAPTURE_TIMEOUT=30`
  - Added bounded retry model for failed URL fetches.
  - Added in-flight URL dedup to prevent duplicate concurrent downloads.
  - Added placeholder resolution for `$SERVER_IP` and `${SERVER_IP}` using event `src_ip`.
  - Added ANSI cleanup in command parsing before URL extraction.
- Goal:
  - Increase binaries/minute from URL-based droppers.
  - Recover from transient C2 failures without endless retries.

### 5) File watcher depth and scan cadence
- File: `backend/capture.sh`
- Changes:
  - Added directory-specific depth function:
    - deep scan (`maxdepth 5`) for `/tmp`, `/var/tmp`, `/dev/shm`
    - medium scan (`maxdepth 4`) for `/root`, `/home`
    - default scan (`maxdepth 2`) elsewhere
  - Reduced periodic rescan interval to `30s` (`RESCAN_SECONDS=30`).
- Goal:
  - Catch staged payloads in deeper temp paths.
  - Reduce miss window between inotify and periodic scan.

### 6) Validation and deployment completed
- Validation run:
  - `bash -n backend-watchdog.sh`
  - `bash -n backend/miner-killer.sh`
  - `bash -n backend/capture.sh`
  - `python3 -m py_compile url-capture.py`
  - `docker compose config`
- Deployment:
  - `docker compose up -d --build`
  - Container came up healthy.
- Observed post-deploy:
  - URL capture worker started with 8 workers and replayed historical events.
  - New payload capture log lines appeared after restart.

## Applied YARA Tuning (2026-02-22)
This section documents the triage and YARA improvements made for previously unmatched downloads.

### 1) Samples triaged with `r2`/`rabin2`
- `dl/25c34c028-b_linux`
- `dl/cb7ab5036-s_linux`
- `dl/9e919b5fb-aarch64_sshd`
- Findings:
  - The two `*_linux` samples are UPX-packed i386 ELF payloads with a stable UPX block signature and SSH-brute indicators.
  - The `aarch64_sshd` sample is an ARM64 Dot16/B0s toolkit variant using `libprocesshider` + `ld.so.preload` persistence strings.

### 2) Rule updates
- File: `reports/rules.yar`
- Changes:
  - Expanded `Dot16_B0s_Aarch64_Bot` to also detect ARM64 processhider/sshd variants.
  - Added `Go_SSH_Scanner_UPX` for the new UPX-packed i386 SSH scanner/bruter lineage.

### 3) Verification result
- Run:
  - `python3 reports/yara-scan.py`
- Result:
  - `Scanned: 84`
  - `Matched: 84`
  - `No match: 0`

### 4) New drop wave triage (2026-02-22)
- New unmatched wave characteristics:
  - `43` unmatched files (`38` unique SHA256)
  - all unmatched samples were `ELF64 x86-64`, static, UPX-packed
  - repeated actor-specific UPX signature at first `"/UPX!"` block
  - observed markers from unpacked representative: SSH handling + XMR/RC4 strings
- Rule added:
  - `Obf_UPX_SSH_XMR_x64` in `reports/rules.yar`
  - family tag: `ObfUPX_SSHXMR`
- Verification after rule update:
  - `python3 reports/yara-scan.py`
  - `Scanned: 79`
  - `Matched: 79`
  - `No match: 0`

### 5) IOC report generated (2026-02-22)
- File: `reports/obfupx_sshxmr_ioc_report_2026-02-22.md`
- Includes:
  - r2/rabin2 binary triage findings
  - command-telemetry behavior profile
  - campaign source IP and time window
  - actionable hunting/detection patterns

### 6) Benign tooling rollback + DL cleanup (2026-02-22)
- Per request, removed benign/noise YARA rules from `reports/rules.yar`:
  - `GNU_Binutils_Gprofng_Debian240`
  - `GNU_Bzip2_Utilities`
  - `GNU_XZ_Utilities`
  - `GNU_Nano_Editor`
  - `GNU_Gettext_And_Jansson_Libs`
- Removed the corresponding benign toolchain files from `dl/`:
  - `42` files deleted (Debian `binutils`/`gprofng`, `xz`, `bzip2`, `nano`, `gettext`/`libjansson` related payloads).
- Verification after cleanup:
  - `python3 reports/yara-scan.py`
  - `Scanned: 80`
  - `Matched: 80`
  - `No match: 0`

### 7) Six unmatched sample triage + rule fix (2026-02-23)
- Trigger:
  - Scan result showed `Scanned: 165`, `Matched: 159`, `No match: 6`.
- Triage method:
  - Used `r2`/`rabin2`, `readelf`, and prefix comparison against known samples.
- Findings:
  - `2` files were 96KB truncated pulls of the existing `ObfUPX_SSHXMR` family.
  - `3` files (`*-cache`) shared a distinct UPX header block (`/UPX! fc 0a 0e 16 ...`) and fixed entrypoint (`0x814e90`) tied to SSH/FTP/TCP scanner behavior.
  - `1` file (`a58bf641c-amd64`) was a truncated prefix of known `GoDDoS` amd64 binaries (same Go build-id string and entrypoint).
- Rule updates in `reports/rules.yar`:
  - Relaxed `Obf_UPX_SSH_XMR_x64` size floor to include 96KB truncations.
  - Added `Go_SSH_Scanner_UPX_x64_Cache` (family: `GoSSHScanner`).
  - Added `Go_DDoS_Bot_Partial_amd64` (family: `GoDDoS`).
- Verification:
  - `python3 reports/yara-scan.py`
  - `Scanned: 165`
  - `Matched: 165`
  - `No match: 0`

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
