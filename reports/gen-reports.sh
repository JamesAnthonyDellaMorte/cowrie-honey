#!/bin/bash
# Generate honeypot reports from cowrie JSON logs
LOG="/root/cowrie/log/cowrie.json"
DIR="/root/cowrie/reports"

# --- Attacker IPs ---
python3 -c "
import json
from collections import Counter
ips = Counter()
with open('$LOG') as f:
    for line in f:
        try:
            e = json.loads(line)
        except:
            continue
        src = e.get('src_ip','')
        if src and src != '10.1.0.49':
            ips[src] += 1

print(f'Attacker IPs (total: {len(ips)} unique)')
print('=' * 50)
for ip, count in ips.most_common():
    # check if they logged in
    print(f'{ip:>20s}  {count:>5d} events')
" > "$DIR/attackers.txt"

# --- Command Frequency ---
python3 -c "
import json
from collections import Counter
cmds = Counter()
with open('$LOG') as f:
    for line in f:
        try:
            e = json.loads(line)
        except:
            continue
        if e.get('eventid') == 'cowrie.command.input' and e.get('src_ip') != '10.1.0.49':
            cmd = e.get('input','').strip()
            # Truncate very long commands for readability
            if len(cmd) > 120:
                cmd = cmd[:120] + '...'
            cmds[cmd] += 1

print(f'Command Frequency (total: {sum(cmds.values())} commands, {len(cmds)} unique)')
print('=' * 50)
for cmd, count in cmds.most_common():
    print(f'{count:>5d}  {cmd}')
" > "$DIR/commands.txt"

echo "Reports written to $DIR/"
echo "  attackers.txt - $(wc -l < "$DIR/attackers.txt") lines"
echo "  commands.txt  - $(wc -l < "$DIR/commands.txt") lines"
