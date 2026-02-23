#!/bin/bash
# Kills known miner processes, high-CPU consumers, and repairs attacker lockdowns
# to keep the honeypot fresh and accessible.
# Self-healing runs every 30 seconds.
# Known miner names get a grace period before kill so second-stage payloads can land.
# CPU hogs also get sustained strikes before kill.

SAFE_RE="twistd|rsyslogd|syslog-ng|inetd|telnetd|login|sleep|inotifywait|atd|init|ps|awk|grep|python3|setpriv|wait|cron|curl|wget"
MINER_RE="xmrig|cpuminer|minerd|ccminer|nbminer|redtail|kdevtmpfsi|kinsing|c3pool|cryptonight|xmr-stak|\.cache|pPTlDTgT|xmr|stratum"
MINER_GRACE_SECONDS=300
HIGH_CPU_THRESHOLD=50.0
HIGH_CPU_STRIKES=2

# Protect system sshd/bash (PPID=1) but NOT attacker session children
SSHD_LISTENER_PID=$(ps -eo pid,ppid,comm --no-headers 2>/dev/null | awk '$3=="sshd" && $2==1 {print $1; exit}')
INIT_BASH_PIDS=$(ps -eo pid,ppid,comm --no-headers 2>/dev/null | awk '$3=="bash" && $2==1 {print $1}')

is_protected_pid() {
    local pid="$1" comm="$2"
    [ "$comm" = "sshd" ] && [ "$pid" = "$SSHD_LISTENER_PID" ] && return 0
    [ "$comm" = "bash" ] && echo "$INIT_BASH_PIDS" | grep -qw "$pid" && return 0
    return 1
}

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
        sleep 1
        SSHD_LISTENER_PID=$(ps -eo pid,ppid,comm --no-headers 2>/dev/null | awk '$3=="sshd" && $2==1 {print $1; exit}')
        INIT_BASH_PIDS=$(ps -eo pid,ppid,comm --no-headers 2>/dev/null | awk '$3=="bash" && $2==1 {print $1}')
    fi

    # 1. Kill known miner names after grace period to preserve payload capture.
    ps -eo pid,etimes,comm --no-headers 2>/dev/null | while read pid etimes comm; do
        [ "$pid" -le 2 ] 2>/dev/null && continue
        echo "$comm" | grep -qiE "$SAFE_RE" && continue
        if echo "$comm" | grep -qiE "$MINER_RE"; then
            [ -z "$etimes" ] && etimes=0
            if [ "$etimes" -ge "$MINER_GRACE_SECONDS" ] 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null
                echo "[miner-killer] $(date +%H:%M:%S) killed miner: PID=$pid name=$comm age=${etimes}s"
            fi
        fi
    done

    # 2. Track non-safe processes using high CPU
    #    Only check every 7th loop (~3.3 min apart)
    #    4 strikes = ~13 minutes before killing
    if [ $((loop_count % 7)) -eq 0 ]; then
        current_hot=()
        while read pid cpu comm; do
            [ "$pid" -le 2 ] 2>/dev/null && continue
            echo "$comm" | grep -qiE "$SAFE_RE" && continue
            is_protected_pid "$pid" "$comm" && continue
            current_hot+=("$pid")
            strikes=${cpu_strikes[$pid]:-0}
            strikes=$((strikes + 1))
            cpu_strikes[$pid]=$strikes

            if [ "$strikes" -ge "$HIGH_CPU_STRIKES" ]; then
                kill -9 "$pid" 2>/dev/null
                echo "[miner-killer] $(date +%H:%M:%S) killed high-CPU (strike $strikes): PID=$pid name=$comm cpu=$cpu%"
                unset cpu_strikes[$pid]
            else
                echo "[miner-killer] $(date +%H:%M:%S) high-CPU strike $strikes/${HIGH_CPU_STRIKES}: PID=$pid name=$comm cpu=$cpu%"
            fi
        done < <(ps -eo pid,%cpu,comm --no-headers 2>/dev/null | awk -v threshold="$HIGH_CPU_THRESHOLD" '$2 > threshold {print $1, $2, $3}')

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
