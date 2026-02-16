#!/bin/bash
# Report cowrie honeypot attackers to AbuseIPDB
# Usage: bash abuseipdb-report.sh [--dry-run]
#
# Tracks last-reported timestamp per IP so re-running only reports NEW activity.
# Reports include: hassh fingerprint, SSH client, attack phase, malware family.

API_KEY="d52515346e5149dbac18f6ce0bcb62e1b10c9309fa0e9ef437deadf4cd29e29a8ba4c80257d9382b"
LOG="/root/cowrie/log/cowrie.json"
REPORTED="/root/cowrie/reports/.reported_ips"
QUEUE="/tmp/abuseipdb_queue.txt"
DRY_RUN=false

[ "$1" = "--dry-run" ] && DRY_RUN=true

touch "$REPORTED"

# Step 1: Python generates the report queue
python3 - "$LOG" "$REPORTED" "$QUEUE" <<'PYEOF'
import json, sys, sqlite3
from collections import defaultdict

LOG, REPORTED_FILE, QUEUE_FILE = sys.argv[1], sys.argv[2], sys.argv[3]
VT_DB = '/root/cowrie/reports/vt-cache.db'

# Connect to VT cache (read-only, ignore if missing)
vt_cache = {}
try:
    conn = sqlite3.connect(f'file:{VT_DB}?mode=ro', uri=True)
    for row in conn.execute('SELECT sha256, vt_known, vt_detections, vt_total, vt_label, vt_names FROM samples'):
        vt_cache[row[0]] = {
            'known': row[1], 'detections': row[2], 'total': row[3],
            'label': row[4] or '', 'names': row[5] or '',
        }
    conn.close()
except:
    pass

def vt_lookup(hashes):
    results = []
    for h in hashes:
        info = vt_cache.get(h)
        if info and info['known']:
            results.append(f"{info['label']} ({info['detections']}/{info['total']} VT detections)")
        elif info and not info['known']:
            results.append('unknown (not on VirusTotal)')
    return results

KNOWN_MALWARE = {
    'redtail': 'RedTail cryptominer (XMRig/Monero, likely Lazarus Group)',
    'setup.sh': 'dropper script',
    'clean.sh': 'competing miner killer script',
    'xmrig': 'XMRig cryptominer',
}

def identify_malware(filenames):
    families = set()
    for fn in filenames:
        for sig, family in KNOWN_MALWARE.items():
            if sig in fn.lower():
                families.add(family)
    return families

def classify_attack(info):
    phases = []
    if info['login_failed'] > 0 and info['login_success'] == 0:
        phases.append('brute-force only')
    if info['login_success'] > 0 and not info['commands'] and not info['uploads']:
        phases.append('credential stuffing (logged in, no post-exploit)')
    if info['commands']:
        cmd_text = ' '.join(info['commands']).lower()
        if any(x in cmd_text for x in ['uname', 'lscpu', 'cpuinfo', 'nvidia-smi', 'lspci', 'echo test']):
            phases.append('system recon')
        if any(x in cmd_text for x in ['wget', 'curl', 'chmod +x', 'setup.sh', '/tmp/']):
            phases.append('malware deployment')
        if any(x in cmd_text for x in ['authorized_keys', 'chattr', '.ssh']):
            phases.append('SSH backdoor installation')
        if any(x in cmd_text for x in ['grep miner', 'kill', 'pkill', 'c3pool']):
            phases.append('competing miner removal')
        if any(x in cmd_text for x in ['/ip cloud']):
            phases.append('MikroTik router probe')
        if any(x in cmd_text for x in ['telegram', 'tdata']):
            phases.append('Telegram data theft')
    if info['uploads']:
        phases.append('malware drop')
    return phases or ['connection only']

reported = {}
with open(REPORTED_FILE) as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) >= 2:
            reported[parts[0]] = parts[1]

ips = defaultdict(lambda: {
    'logins': [], 'commands': [], 'uploads': [], 'upload_hashes': [],
    'first': None, 'last': None, 'events': 0,
    'hassh': None, 'ssh_version': None, 'login_success': 0, 'login_failed': 0,
})

with open(LOG) as f:
    for line in f:
        try:
            e = json.loads(line)
        except:
            continue
        src = e.get('src_ip', '')
        if not src or src == '10.1.0.49' or src == '172.18.0.1':
            continue
        ts = e.get('timestamp', '')
        eid = e.get('eventid', '')
        if src in reported and ts <= reported[src]:
            continue
        ips[src]['events'] += 1
        if ips[src]['first'] is None or ts < ips[src]['first']:
            ips[src]['first'] = ts
        if ips[src]['last'] is None or ts > ips[src]['last']:
            ips[src]['last'] = ts
        if eid == 'cowrie.login.success':
            ips[src]['login_success'] += 1
            ips[src]['logins'].append(f"{e.get('username','')}/{e.get('password','')}")
        elif eid == 'cowrie.login.failed':
            ips[src]['login_failed'] += 1
            ips[src]['logins'].append(f"{e.get('username','')}/{e.get('password','')}")
        elif eid == 'cowrie.command.input':
            cmd = e.get('input', '')
            if cmd not in ips[src]['commands']:
                ips[src]['commands'].append(cmd)
        elif 'file_upload' in eid or 'file_download' in eid:
            fn = e.get('filename', '') or e.get('url', '')
            sha = e.get('shasum', '')
            if fn: ips[src]['uploads'].append(fn)
            if sha: ips[src]['upload_hashes'].append(sha)
        elif eid == 'cowrie.client.kex':
            ips[src]['hassh'] = e.get('hassh', '')
        elif eid == 'cowrie.client.version':
            ips[src]['ssh_version'] = e.get('version', '')

new_count = 0
returning = 0
with open(QUEUE_FILE, 'w') as out:
    for ip, info in sorted(ips.items(), key=lambda x: x[1]['first'] or ''):
        if info['events'] == 0:
            continue
        is_returning = ip in reported
        if is_returning:
            returning += 1
        phases = classify_attack(info)
        malware = identify_malware(info['uploads'])
        lines = ['SSH honeypot (Cowrie) attack detected.']
        if is_returning:
            lines.append('NOTE: Returning attacker with new activity.')
        lines.append(f"Attack phases: {', '.join(phases)}.")
        if info['hassh']:
            lines.append(f"HASSH: {info['hassh']}")
        if info['ssh_version']:
            lines.append(f"SSH client: {info['ssh_version']}")
        total_auth = info['login_success'] + info['login_failed']
        if total_auth > 0:
            lines.append(f"Auth: {total_auth} attempts ({info['login_success']} success, {info['login_failed']} failed).")
            unique_creds = list(dict.fromkeys(info['logins']))[:5]
            lines.append(f"Creds: {' | '.join(unique_creds)}")
        if info['commands']:
            short_cmds = [c[:80] for c in info['commands'][:3]]
            lines.append(f"Post-exploit: {' ; '.join(short_cmds)}")
        if info['uploads']:
            lines.append(f"Files dropped: {' '.join(info['uploads'][:5])}")
        if info['upload_hashes']:
            lines.append(f"SHA256: {' '.join(info['upload_hashes'][:3])}")
        # VT-enriched malware identification from cache DB
        vt_results = vt_lookup(info['upload_hashes'])
        if vt_results:
            lines.append(f"VT analysis: {' / '.join(vt_results)}")
        elif malware:
            lines.append(f"Malware family: {' / '.join(malware)}")
        comment = ' // '.join(lines)
        if len(comment) > 1024:
            comment = comment[:1021] + '...'
        out.write(f"{ip}|18,22|{info['last']}|{comment}\n")
        new_count += 1

print(f"{new_count} IPs with new activity ({returning} returning)")
PYEOF

[ $? -ne 0 ] && echo "Python error, aborting." && exit 1

# Step 2: Report each IP from the queue
while IFS='|' read -r ip cats ts comment; do
    if $DRY_RUN; then
        echo "[DRY RUN] $ip (last seen: $ts)"
        echo "  $comment"
        echo ""
    else
        resp=$(curl -s -X POST "https://api.abuseipdb.com/api/v2/report" \
            -H "Key: $API_KEY" \
            -H "Accept: application/json" \
            --data-urlencode "ip=$ip" \
            --data-urlencode "categories=$cats" \
            --data-urlencode "timestamp=$ts" \
            --data-urlencode "comment=$comment" 2>&1)

        score=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('abuseConfidenceScore','err'))" 2>/dev/null)

        if [ "$score" != "err" ] && [ -n "$score" ]; then
            echo "[OK] $ip -> confidence score: $score%"
            sed -i "/^${ip}|/d" "$REPORTED"
            echo "$ip|$ts" >> "$REPORTED"
        else
            echo "[FAIL] $ip -> $resp"
        fi
        sleep 2
    fi
done < "$QUEUE"

tracked=$(wc -l < "$REPORTED" 2>/dev/null || echo 0)
echo ""
echo "--- Done. $tracked IPs tracked total. ---"
