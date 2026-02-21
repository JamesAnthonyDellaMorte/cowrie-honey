#!/bin/bash
# Kills known miner processes, high-CPU consumers, and repairs attacker lockdowns
# to keep the honeypot fresh and accessible.
# Self-healing runs every 30 seconds.
# CPU hogs get 10 minutes before being killed (3 checks, ~3.3 min apart)
# to let attackers finish downloading payloads before we intervene.

SAFE_RE="sshd|twistd|rsyslogd|syslog-ng|inetd|telnetd|login|bash|sleep|inotifywait|atd|init|ps|awk|grep|python3|setpriv|wait|cron|curl|wget"
MINER_RE="xmrig|cpuminer|minerd|ccminer|nbminer|redtail|kdevtmpfsi|kinsing|c3pool|cryptonight|xmr-stak|\.cache|pPTlDTgT|xmr|stratum"

# Track how many times we've seen a PID using high CPU
declare -A cpu_strikes
loop_count=0

while true; do
    sleep 30
    loop_count=$((loop_count + 1))

    # 0. Repair attacker lockdowns — reset critical system files
    echo "# /etc/hosts.deny" > /etc/hosts.deny
    echo "# /etc/hosts.allow" > /etc/hosts.allow
    echo "root:password" | chpasswd 2>/dev/null
    echo "" > /root/.ssh/authorized_keys 2>/dev/null

    # Ensure sshd is alive and accepting connections
    if ! timeout 1 bash -c 'echo > /dev/tcp/127.0.0.1/22' 2>/dev/null; then
        echo "[miner-killer] $(date +%H:%M:%S) backend sshd dead, restarting"
        pkill -9 sshd 2>/dev/null
        sleep 1
        /usr/sbin/sshd -D -e &
    fi

    # 1. Kill processes matching known miner names (immediate, no delay)
    ps -eo pid,comm --no-headers 2>/dev/null | while read pid comm; do
        [ "$pid" -le 2 ] 2>/dev/null && continue
        echo "$comm" | grep -qiE "$SAFE_RE" && continue
        if echo "$comm" | grep -qiE "$MINER_RE"; then
            kill -9 "$pid" 2>/dev/null
            echo "[miner-killer] $(date +%H:%M:%S) killed miner: PID=$pid name=$comm"
        fi
    done

    # 2. Track non-safe processes using >50% CPU
    #    Only check every 7th loop (~3.3 min apart)
    #    3 strikes = ~10 minutes before killing
    if [ $((loop_count % 7)) -eq 0 ]; then
        current_hot=()
        while read pid cpu comm; do
            [ "$pid" -le 2 ] 2>/dev/null && continue
            echo "$comm" | grep -qiE "$SAFE_RE" && continue
            current_hot+=("$pid")
            strikes=${cpu_strikes[$pid]:-0}
            strikes=$((strikes + 1))
            cpu_strikes[$pid]=$strikes

            if [ "$strikes" -ge 3 ]; then
                kill -9 "$pid" 2>/dev/null
                echo "[miner-killer] $(date +%H:%M:%S) killed high-CPU (strike $strikes): PID=$pid name=$comm cpu=$cpu%"
                unset cpu_strikes[$pid]
            else
                echo "[miner-killer] $(date +%H:%M:%S) high-CPU strike $strikes/3: PID=$pid name=$comm cpu=$cpu%"
            fi
        done < <(ps -eo pid,%cpu,comm --no-headers 2>/dev/null | awk '$2 > 50.0 {print $1, $2, $3}')

        # Clear strikes for PIDs that are no longer hot
        for pid in "${!cpu_strikes[@]}"; do
            found=0
            for hot_pid in "${current_hot[@]}"; do
                [ "$pid" = "$hot_pid" ] && found=1 && break
            done
            [ "$found" -eq 0 ] && unset cpu_strikes[$pid]
        done
    fi
done
