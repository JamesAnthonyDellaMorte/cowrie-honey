#!/bin/bash
SAMPLE="$1"
TIMEOUT="${2:-60}"
OUT="/sandbox/output"

mkdir -p "$OUT/dropped"

# Try UPX unpack for better strings extraction
cp "$SAMPLE" "$OUT/sample.unpacked" 2>/dev/null
upx -d "$OUT/sample.unpacked" 2>"$OUT/upx.log" && echo "1" > "$OUT/was_packed" || echo "0" > "$OUT/was_packed"

# Detect file type
FTYPE=$(file -b "$SAMPLE")
echo "$FTYPE" > "$OUT/file_type"

# Make executable
chmod +x "$SAMPLE"

# Start tcpdump if we have a network interface (not --network=none)
HAS_NET=0
if [ -d /sys/class/net/eth0 ]; then
    HAS_NET=1
    tcpdump -i any -w "$OUT/capture.pcap" -s 0 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 0.5
fi

# strace flags:
#   -f          follow forks
#   -s 512      capture 512 bytes of string args (wallet addrs are ~95 chars)
#   -e trace=network,file,process   relevant syscall categories
STRACE="strace -f -s 512 -e trace=network,file,process"

if echo "$FTYPE" | grep -qiE 'script|text|ascii'; then
    timeout "$TIMEOUT" $STRACE -o "$OUT/strace.log" \
        bash "$SAMPLE" >"$OUT/stdout.log" 2>"$OUT/stderr.log" &
else
    timeout "$TIMEOUT" $STRACE -o "$OUT/strace.log" \
        "$SAMPLE" >"$OUT/stdout.log" 2>"$OUT/stderr.log" &
fi

PID=$!
wait $PID 2>/dev/null
echo "$?" > "$OUT/exit_code"

# Stop tcpdump
if [ "$HAS_NET" = "1" ] && [ -n "$TCPDUMP_PID" ]; then
    sleep 2
    kill "$TCPDUMP_PID" 2>/dev/null
    wait "$TCPDUMP_PID" 2>/dev/null

    # Extract stratum logins (wallet addresses) from pcap
    if [ -f "$OUT/capture.pcap" ]; then
        # tshark: look for JSON stratum login containing wallet
        tshark -r "$OUT/capture.pcap" -Y 'tcp' -T fields -e tcp.payload 2>/dev/null | \
            while read hex; do
                [ -z "$hex" ] && continue
                echo "$hex" | xxd -r -p 2>/dev/null
            done > "$OUT/raw_payloads.txt" 2>/dev/null

        # Also dump readable ASCII from pcap
        strings -n 8 "$OUT/capture.pcap" >> "$OUT/raw_payloads.txt" 2>/dev/null
    fi
fi

# Capture dropped files
for dir in /tmp /var/tmp /dev/shm /root; do
    find "$dir" -newer "$SAMPLE" -type f 2>/dev/null | while read -r f; do
        cp "$f" "$OUT/dropped/" 2>/dev/null
        echo "$f" >> "$OUT/created_files.txt"
    done
done

# Dump strings from any dropped files for IOC extraction
for f in "$OUT/dropped/"*; do
    [ -f "$f" ] && strings -n 8 "$f" >> "$OUT/dropped_strings.txt" 2>/dev/null
done

exit 0
