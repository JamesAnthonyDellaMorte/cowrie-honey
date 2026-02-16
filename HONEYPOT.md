# Cowrie SSH Honeypot - Analysis Guide

## Architecture

- **Port 22** — Cowrie honeypot (Docker container `cowrie/cowrie`, restart=always)
- **Port 2222** — Real SSH (LAN only, 10.1.0.0/24)
- Cowrie runs inside Docker, maps host:22 → container:2222
- Malware downloads saved to `/root/cowrie/dl/`
- Container logs contain all activity (JSON logs not writing to file currently — use `docker logs`)

## Quick Commands

### Live monitoring
```bash
# Watch attacks in real-time
docker logs -f cowrie

# Filter for just logins and commands
docker logs cowrie 2>&1 | grep -E "login attempt|CMD:|file_download"

# See only successful logins
docker logs cowrie 2>&1 | grep "login attempt" | grep "succeeded"

# See commands attackers ran
docker logs cowrie 2>&1 | grep "CMD:"
```

### Captured malware
```bash
# List downloaded files
ls -la /root/cowrie/dl/

# Hash a captured file
sha256sum /root/cowrie/dl/*

# Check file type
file /root/cowrie/dl/*

# Look up hash on VirusTotal
VT_KEY=$(cat /root/.config/virustotal/api_key | tr -d '\n')
curl -s -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/files/<HASH>" | python3 -m json.tool
```

### Analysis
```bash
# Top attacker IPs
docker logs cowrie 2>&1 | grep -oP 'New connection: \K[0-9.]+' | sort | uniq -c | sort -rn | head 20

# All username:password combos tried
docker logs cowrie 2>&1 | grep "login attempt" | grep -oP "\[b'[^']+'/b'[^']+'\]" | sort | uniq -c | sort -rn

# All commands executed by attackers
docker logs cowrie 2>&1 | grep "CMD:" | sed 's/.*CMD: //'

# Files attackers tried to download
docker logs cowrie 2>&1 | grep -i "wget\|curl\|tftp" | grep "CMD:"
```

### Container management
```bash
# Restart cowrie
docker restart cowrie

# Stop cowrie
docker stop cowrie

# View container status
docker ps | grep cowrie

# Shell into container (limited — minimal image)
docker exec -it cowrie /bin/sh
```

## What To Look For

### Interesting attack patterns
- **Recon commands**: `uname`, `cat /proc/cpuinfo`, `nproc`, `lspci` — they're checking if your machine is worth mining on
- **Dropper scripts**: `wget http://...` or `curl http://...` — downloading malware
- **Persistence**: modifications to `crontab`, `rc.local`, `authorized_keys`, `systemd`
- **Lateral movement**: scanning for other hosts, checking `~/.ssh/known_hosts`
- **Cleanup**: `history -c`, `rm -rf *.sh` — covering tracks

### Analyzing captured malware
1. Check `/root/cowrie/dl/` for any downloaded files
2. Hash them with `sha256sum`
3. Look up on VirusTotal using the API key at `/root/.config/virustotal/api_key`
4. Use `file` command to identify binary type
5. Use `strings` to look for embedded URLs, wallet addresses, C2 servers
6. Check against known IOCs in `/root/dhpcd_incident/`

## Incident History (2025-11-21 compromise)

The honeypot was set up after discovering a dhpcd (XMRig) crypto miner infection.
Full incident details and IOCs saved in `/root/dhpcd_incident/`:
- `attacker_ssh_key.txt` — backdoor SSH key planted by attacker
- `curl.sh` / `wget.sh` — dropper scripts from 91.92.241.59
- Malware family: V3G4 (Mirai DDoS bot + XMRig miner)
- Attacker IP: 91.92.241.59
- C2 panel found: 159.223.218.15 (OpenClaw "Vex")

## Reporting Attackers

To report captured attacks:
- **DigitalOcean IPs** (104.x, 134.x, 142.x, 146.x, 159.x, 161.x, 164.x, 165.x, 167.x, 178.x, 188.x, 206.x, 209.x): abuse@digitalocean.com
- **General**: Report to IP's abuse contact (check `whois <IP>`)
- **Malware samples**: Upload to VirusTotal, MalwareBazaar (bazaar.abuse.ch)
- **IC3**: ic3.gov for US law enforcement reporting
