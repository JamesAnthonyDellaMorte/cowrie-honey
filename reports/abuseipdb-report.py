#!/usr/bin/env python3
"""
Report cowrie honeypot attackers to AbuseIPDB.

Usage:
  python3 abuseipdb-report.py              # Report all new activity
  python3 abuseipdb-report.py --dry-run    # Preview without sending

Async — fires up to 10 concurrent reports. Tracks last-reported timestamp
per IP so re-running only reports NEW activity. Reports include: hassh
fingerprint, SSH client, attack phase, YARA malware classification.
"""

import asyncio
import hashlib
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import aiohttp

# ── Config ──────────────────────────────────────────────────────────
API_KEY = "d52515346e5149dbac18f6ce0bcb62e1b10c9309fa0e9ef437deadf4cd29e29a8ba4c80257d9382b"
API_URL = "https://api.abuseipdb.com/api/v2/report"
LOG = Path("/root/cowrie/log/cowrie.json")
REPORTED = Path("/root/cowrie/reports/.reported_ips")
DL_DIR = Path("/root/cowrie/dl")
RULES_FILE = Path(__file__).parent / "rules.yar"
MAX_CONCURRENT = 10
INTERNAL_IPS = {"10.1.0.49", "172.18.0.1"}

DRY_RUN = "--dry-run" in sys.argv


# ── YARA ────────────────────────────────────────────────────────────
yara_rules = None
try:
    import yara
    yara_rules = yara.compile(filepath=str(RULES_FILE))
    print(f"YARA rules loaded from {RULES_FILE}")
except Exception as e:
    print(f"WARNING: YARA unavailable ({e}), malware ID will be limited")

# SHA256 -> filepath index for dl/
sha_to_file = {}
if DL_DIR.exists():
    for fp in DL_DIR.iterdir():
        if fp.is_file():
            sha_to_file[hashlib.sha256(fp.read_bytes()).hexdigest()] = fp


def yara_identify(hashes):
    """Scan dropped files by SHA256 using YARA rules."""
    if not yara_rules:
        return []
    results = []
    seen = set()
    for h in hashes:
        if h in seen:
            continue
        seen.add(h)
        fp = sha_to_file.get(h)
        if not fp:
            continue
        try:
            for m in yara_rules.match(str(fp)):
                family = m.meta.get("family", "unknown")
                severity = m.meta.get("severity", "?")
                desc = m.meta.get("description", m.rule)
                results.append(f"{family} [{severity}]: {desc}")
        except Exception:
            pass
    return results


# ── Attack classification ───────────────────────────────────────────
def classify_attack(info):
    phases = []
    if info["login_failed"] > 0 and info["login_success"] == 0:
        phases.append("brute-force only")
    if info["login_success"] > 0 and not info["commands"] and not info["uploads"]:
        phases.append("credential stuffing (logged in, no post-exploit)")
    if info["commands"]:
        cmd_text = " ".join(info["commands"]).lower()
        checks = [
            (["uname", "lscpu", "cpuinfo", "nvidia-smi", "lspci", "echo test"], "system recon"),
            (["wget", "curl", "chmod +x", "setup.sh", "/tmp/"], "malware deployment"),
            (["authorized_keys", "chattr", ".ssh"], "SSH backdoor installation"),
            (["grep miner", "kill", "pkill", "c3pool"], "competing miner removal"),
            (["/ip cloud"], "MikroTik router probe"),
            (["telegram", "tdata"], "Telegram data theft"),
        ]
        for keywords, phase in checks:
            if any(k in cmd_text for k in keywords):
                phases.append(phase)
    if info["uploads"]:
        phases.append("malware drop")
    return phases or ["connection only"]


# ── Build comment ───────────────────────────────────────────────────
def build_comment(ip, info, is_returning):
    lines = ["SSH honeypot (Cowrie) attack detected."]
    if is_returning:
        lines.append("NOTE: Returning attacker with new activity.")
    lines.append(f"Attack phases: {', '.join(classify_attack(info))}.")
    if info["hassh"]:
        lines.append(f"HASSH: {info['hassh']}")
    if info["ssh_version"]:
        lines.append(f"SSH client: {info['ssh_version']}")
    total_auth = info["login_success"] + info["login_failed"]
    if total_auth > 0:
        lines.append(f"Auth: {total_auth} attempts ({info['login_success']} success, {info['login_failed']} failed).")
        unique_creds = list(dict.fromkeys(info["logins"]))[:5]
        lines.append(f"Creds: {' | '.join(unique_creds)}")
    if info["commands"]:
        short_cmds = [c[:80] for c in info["commands"][:3]]
        lines.append(f"Post-exploit: {' ; '.join(short_cmds)}")
    if info["uploads"]:
        lines.append(f"Files dropped: {' '.join(info['uploads'][:5])}")
    if info["upload_hashes"]:
        lines.append(f"SHA256: {' '.join(info['upload_hashes'][:3])}")
    yara_results = yara_identify(info["upload_hashes"])
    if yara_results:
        unique_results = list(dict.fromkeys(yara_results))
        lines.append(f"Malware ID (YARA): {' / '.join(unique_results[:3])}")
    comment = " // ".join(lines)
    comment = comment.replace("\n", " ").replace("\r", " ")
    if len(comment) > 1024:
        comment = comment[:1021] + "..."
    return comment


# ── Parse logs ──────────────────────────────────────────────────────
def parse_logs():
    # Load previously reported timestamps
    reported = {}
    if REPORTED.exists():
        for line in REPORTED.read_text().splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 2:
                reported[parts[0]] = parts[1]

    ips = defaultdict(lambda: {
        "logins": [], "commands": [], "uploads": [], "upload_hashes": [],
        "first": None, "last": None, "events": 0,
        "hassh": None, "ssh_version": None, "login_success": 0, "login_failed": 0,
    })

    with open(LOG) as f:
        for line in f:
            try:
                e = json.loads(line)
            except Exception:
                continue
            src = e.get("src_ip", "")
            if not src or src in INTERNAL_IPS:
                continue
            ts = e.get("timestamp", "")
            eid = e.get("eventid", "")
            if src in reported and ts <= reported[src]:
                continue
            ips[src]["events"] += 1
            if ips[src]["first"] is None or ts < ips[src]["first"]:
                ips[src]["first"] = ts
            if ips[src]["last"] is None or ts > ips[src]["last"]:
                ips[src]["last"] = ts
            if eid == "cowrie.login.success":
                ips[src]["login_success"] += 1
                ips[src]["logins"].append(f"{e.get('username','')}/{e.get('password','')}")
            elif eid == "cowrie.login.failed":
                ips[src]["login_failed"] += 1
                ips[src]["logins"].append(f"{e.get('username','')}/{e.get('password','')}")
            elif eid == "cowrie.command.input":
                cmd = e.get("input", "").replace("\n", " ").replace("\r", " ").strip()
                if cmd and cmd not in ips[src]["commands"]:
                    ips[src]["commands"].append(cmd)
            elif "file_upload" in eid or "file_download" in eid:
                fn = e.get("filename", "") or e.get("url", "")
                sha = e.get("shasum", "")
                if fn:
                    ips[src]["uploads"].append(fn)
                if sha:
                    ips[src]["upload_hashes"].append(sha)
            elif eid == "cowrie.client.kex":
                ips[src]["hassh"] = e.get("hassh", "")
            elif eid == "cowrie.client.version":
                ips[src]["ssh_version"] = e.get("version", "")

    # Build report queue
    queue = []
    returning = 0
    for ip, info in sorted(ips.items(), key=lambda x: x[1]["first"] or ""):
        if info["events"] == 0:
            continue
        is_returning = ip in reported
        if is_returning:
            returning += 1
        comment = build_comment(ip, info, is_returning)
        queue.append({
            "ip": ip,
            "categories": "18,22",
            "timestamp": info["last"],
            "comment": comment,
        })

    print(f"{len(queue)} IPs with new activity ({returning} returning)")
    return queue


# ── Async reporting ─────────────────────────────────────────────────
async def report_ip(session, sem, entry, results):
    async with sem:
        ip = entry["ip"]
        try:
            async with session.post(
                API_URL,
                headers={"Key": API_KEY, "Accept": "application/json"},
                data={
                    "ip": entry["ip"],
                    "categories": entry["categories"],
                    "timestamp": entry["timestamp"],
                    "comment": entry["comment"],
                },
            ) as resp:
                body = await resp.json()
                score = body.get("data", {}).get("abuseConfidenceScore")
                if score is not None:
                    print(f"  [OK] {ip} -> confidence: {score}%")
                    results["ok"].append((ip, entry["timestamp"]))
                else:
                    errors = body.get("errors", [])
                    detail = errors[0].get("detail", "unknown") if errors else str(body)
                    print(f"  [FAIL] {ip} -> {detail}")
                    results["fail"] += 1
        except Exception as e:
            print(f"  [ERR] {ip} -> {e}")
            results["fail"] += 1


async def report_all(queue):
    results = {"ok": [], "fail": 0}
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    async with aiohttp.ClientSession() as session:
        tasks = [report_ip(session, sem, entry, results) for entry in queue]
        await asyncio.gather(*tasks)
    return results


# ── Main ────────────────────────────────────────────────────────────
def main():
    REPORTED.touch(exist_ok=True)
    queue = parse_logs()

    if not queue:
        print("Nothing to report.")
        return

    if DRY_RUN:
        for entry in queue:
            print(f"  [DRY RUN] {entry['ip']} (last seen: {entry['timestamp']})")
            print(f"    {entry['comment'][:200]}")
        print(f"\n--- Dry run complete. {len(queue)} IPs would be reported. ---")
        return

    t0 = time.time()
    print(f"Reporting {len(queue)} IPs (max {MAX_CONCURRENT} concurrent)...")
    results = asyncio.run(report_all(queue))
    elapsed = time.time() - t0

    # Update reported timestamps for successful reports
    reported = {}
    if REPORTED.exists():
        for line in REPORTED.read_text().splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 2:
                reported[parts[0]] = parts[1]
    for ip, ts in results["ok"]:
        reported[ip] = ts
    REPORTED.write_text("".join(f"{ip}|{ts}\n" for ip, ts in sorted(reported.items())))

    print(f"\n--- Done in {elapsed:.1f}s ---")
    print(f"  Reported: {len(results['ok'])}")
    print(f"  Failed:   {results['fail']}")
    print(f"  Tracked:  {len(reported)} IPs total")


if __name__ == "__main__":
    main()
