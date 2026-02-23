#!/bin/bash
# Watchdog: monitor cowrie container CPU and memory, restart when thresholds exceeded
# Runs via cron every 2 minutes
# Memory triggers immediate restart (OOM can kill instantly)
# CPU uses sustained-strike logic to avoid restarting during short attack bursts.

CONTAINER="cowrie"
THRESHOLD_CPU=70    # CPU percent (container capped at 75%)
THRESHOLD_MEM=92    # Memory percent of limit
CPU_STRIKES_RESTART=8
STRIKES_FILE="/tmp/cowrie-strikes"
METRICS_LOG="/root/cowrie/log/watchdog-metrics.csv"
RESTART_LOG="/root/cowrie/log/watchdog-restarts.csv"

# Init CSV headers if new
[ ! -f "$METRICS_LOG" ] && echo "timestamp,cpu_pct,mem_mb,mem_pct,pids,trigger,strikes" > "$METRICS_LOG"
[ ! -f "$RESTART_LOG" ] && echo "timestamp,cpu_at_restart,mem_mb,uptime_seconds,pids_at_restart,trigger" > "$RESTART_LOG"

# Get container stats
stats=$(docker stats --no-stream --format "{{.CPUPerc}},{{.MemUsage}},{{.PIDs}}" "$CONTAINER" 2>/dev/null)

if [ -z "$stats" ]; then
    rm -f "$STRIKES_FILE"
    exit 0
fi

cpu=$(echo "$stats" | cut -d',' -f1 | tr -d '%')
mem_raw=$(echo "$stats" | cut -d',' -f2 | cut -d'/' -f1 | xargs)
mem_limit_raw=$(echo "$stats" | cut -d',' -f2 | cut -d'/' -f2 | xargs)
pids=$(echo "$stats" | cut -d',' -f3)
cpu_int=${cpu%.*}

# Parse mem values to MB
mem_mb=$(echo "$mem_raw" | awk '/GiB/{printf "%.0f", $1*1024; next} /MiB/{printf "%.0f", $1; next} /KiB/{printf "%.0f", $1/1024; next} {print 0}')
mem_limit_mb=$(echo "$mem_limit_raw" | awk '/GiB/{printf "%.0f", $1*1024; next} /MiB/{printf "%.0f", $1; next} /KiB/{printf "%.0f", $1/1024; next} {print 0}')

# Memory percent of limit
if [ "$mem_limit_mb" -gt 0 ] 2>/dev/null; then
    mem_pct=$((mem_mb * 100 / mem_limit_mb))
else
    mem_pct=0
fi

# Get container uptime in seconds
started=$(docker inspect --format '{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null)
if [ -n "$started" ]; then
    start_epoch=$(date -d "$started" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    uptime_s=$((now_epoch - start_epoch))
else
    uptime_s=0
fi

ts=$(date -Iseconds)
strikes=$(cat "$STRIKES_FILE" 2>/dev/null || echo 0)

# Memory check — immediate restart (no strikes, OOM can happen fast)
if [ "$mem_pct" -ge "$THRESHOLD_MEM" ]; then
    echo "$ts,$cpu,$mem_mb,$mem_pct,$pids,memory,0" >> "$METRICS_LOG"
    echo "$ts,$cpu,$mem_mb,$uptime_s,$pids,memory" >> "$RESTART_LOG"
    echo "$(date): RESTART — Memory ${mem_pct}% (${mem_mb}MB/${mem_limit_mb}MB), CPU ${cpu}%, up ${uptime_s}s"
    cd /root/cowrie && docker compose down && sleep 2 && docker compose up -d
    rm -f "$STRIKES_FILE"
    exit 0
fi

# CPU check — sustained strikes
if [ "$cpu_int" -ge "$THRESHOLD_CPU" ]; then
    strikes=$((strikes + 1))
    echo "$strikes" > "$STRIKES_FILE"
    echo "$ts,$cpu,$mem_mb,$mem_pct,$pids,cpu,$strikes" >> "$METRICS_LOG"

    if [ "$strikes" -ge "$CPU_STRIKES_RESTART" ]; then
        echo "$ts,$cpu,$mem_mb,$uptime_s,$pids,cpu" >> "$RESTART_LOG"
        echo "$(date): RESTART — CPU ${cpu}% for ${CPU_STRIKES_RESTART} checks, ${mem_pct}% mem, up ${uptime_s}s, ${pids} PIDs"
        cd /root/cowrie && docker compose down && sleep 2 && docker compose up -d
        rm -f "$STRIKES_FILE"
    else
        echo "$(date): CPU ${cpu}% (strike $strikes/${CPU_STRIKES_RESTART}, ${mem_pct}% mem, ${pids} PIDs, up ${uptime_s}s)"
    fi
else
    echo "$ts,$cpu,$mem_mb,$mem_pct,$pids,ok,0" >> "$METRICS_LOG"
    rm -f "$STRIKES_FILE"
fi
