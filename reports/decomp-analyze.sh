#!/bin/bash
# Decompile and analyze malware samples using Ghidra headless
# Usage: bash decomp-analyze.sh [file|--all]
#   file    analyze a single file
#   --all   analyze all files in dl/

set -e

GHIDRA=/opt/ghidra
JAVA_HOME=/opt/jdk21
export JAVA_HOME
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DL="/root/cowrie/dl"
REPORT_DIR="/root/cowrie/reports/analysis"
PROJECT_DIR="/tmp/ghidra_projects"
UPX="$SCRIPT_DIR/upx"

mkdir -p "$REPORT_DIR" "$PROJECT_DIR"

analyze_file() {
    local f="$1"
    [ ! -f "$f" ] && echo "File not found: $f" && return 1

    local bname=$(basename "$f")
    local hash=$(sha256sum "$f" | cut -d' ' -f1)
    local short_hash="${hash:0:9}"
    # Strip sha9- prefix for display name
    local fname="${bname#*-}"
    [ "$fname" = "$bname" ] && fname="$bname"
    local report="$REPORT_DIR/${short_hash}-${fname}.md"

    # Skip if report already exists
    if [ -f "$report" ]; then
        echo "  [skip] Report exists: $report"
        return 0
    fi

    local ftype=$(file -b "$f")
    local size=$(stat -c%s "$f")

    # Only analyze ELF binaries
    if ! echo "$ftype" | grep -q "ELF"; then
        echo "  [skip] Not ELF: $fname ($ftype)"
        return 0
    fi

    echo ""
    echo "============================================"
    echo "  Analyzing: $fname"
    echo "  Hash: $hash"
    echo "  Type: $ftype"
    echo "============================================"

    # --- 1. Basic info ---
    local arch=$(readelf -h "$f" 2>/dev/null | grep "Machine:" | sed 's/.*Machine:\s*//')
    local stripped="no"
    file -b "$f" | grep -q "stripped" && stripped="yes"
    local linked=$(file -b "$f" | grep -oP "(statically|dynamically) linked" || echo "unknown")

    # --- 2. Try UPX unpack ---
    local unpacked=""
    if [ -x "$UPX" ]; then
        cp "$f" "/tmp/upx_test_$$"
        if "$UPX" -d "/tmp/upx_test_$$" >/dev/null 2>&1; then
            unpacked="/tmp/upx_test_$$"
            echo "  [upx] Unpacked successfully"
        else
            rm -f "/tmp/upx_test_$$"
        fi
    fi

    local target="$f"
    [ -n "$unpacked" ] && target="$unpacked"

    # --- 3. String extraction ---
    local str_file="/tmp/strings_$$"
    strings -n 6 "$target" > "$str_file"
    local total_strings=$(wc -l < "$str_file")

    # Network strings
    local net_strings=$(grep -iE "(http|https|tcp|udp|stratum|pool|\.onion|socks|proxy)://" "$str_file" 2>/dev/null || true)
    # IP addresses
    local ip_strings=$(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?' "$str_file" 2>/dev/null | sort -u || true)
    # Wallet addresses (Monero-length)
    local wallet_strings=$(grep -oE '[a-zA-Z0-9]{90,}' "$str_file" 2>/dev/null | head -5 || true)
    # Shell commands
    local shell_strings=$(grep -iE "(bin/sh|busybox|wget |curl |chmod |crontab|/tmp/|/var/)" "$str_file" 2>/dev/null | head -20 || true)
    # Interesting keywords
    local keyword_strings=$(grep -iE "(password|encrypt|decrypt|bot|flood|ddos|scan|exploit|kill|miner|xmr|monero)" "$str_file" 2>/dev/null | head -20 || true)

    # --- 4. Imports ---
    local imports=$(readelf -W --dyn-syms "$target" 2>/dev/null | grep "FUNC" | grep "UND" | awk '{print $NF}' | grep -v "^$" | sort -u || true)

    # --- 5. Ghidra decompilation ---
    local ghidra_json="/tmp/ghidra_output_$$.json"
    export GHIDRA_OUTPUT="$ghidra_json"
    local proj_name="proj_$$"

    echo "  [ghidra] Running headless analysis..."
    python3 "$GHIDRA/ghidra_decompile.py" "$target" "$ghidra_json" \
        > /tmp/ghidra_log_$$.txt 2>&1 || true

    # Parse Ghidra output
    local ghidra_funcs=""
    local ghidra_strings=""
    local ghidra_interesting=""
    local func_count="?"

    if [ -f "$ghidra_json" ]; then
        func_count=$(python3 -c "import json; d=json.load(open('$ghidra_json')); print(d.get('total_functions','?'))" 2>/dev/null || echo "?")

        ghidra_strings=$(python3 -c "
import json
d=json.load(open('$ghidra_json'))
for s in d.get('strings_of_interest',[]):
    print(f\"  - \`{s['address']}\`: \`{s['value']}\`)
" 2>/dev/null || true)

        ghidra_interesting=$(python3 -c "
import json
d=json.load(open('$ghidra_json'))
for f in d.get('interesting_functions',[]):
    print(f\"### {f['name']} (at {f['address']}, {f['size']} bytes)\")
    print('\`\`\`c')
    code = f.get('decompiled','// decompilation failed')
    # Truncate very long functions
    lines = code.split('\n')
    if len(lines) > 80:
        print('\n'.join(lines[:80]))
        print(f'// ... truncated ({len(lines)} lines total)')
    else:
        print(code)
    print('\`\`\`')
    print()
" 2>/dev/null || true)
    else
        echo "  [ghidra] Warning: no output produced"
    fi

    # --- 6. Build report ---
    cat > "$report" << REPORT_EOF
# Malware Analysis Report: $fname

**Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')

## Binary Info

| Field | Value |
|-------|-------|
| **File** | $fname |
| **SHA256** | \`$hash\` |
| **Size** | $size bytes |
| **Type** | $ftype |
| **Architecture** | $arch |
| **Stripped** | $stripped |
| **Linking** | $linked |
| **UPX Packed** | $([ -n "$unpacked" ] && echo "yes (unpacked for analysis)" || echo "no") |
| **Functions** | $func_count |
| **Strings** | $total_strings |

## Network Indicators

### URLs / Pool Addresses
\`\`\`
$([ -n "$net_strings" ] && echo "$net_strings" || echo "(none found)")
\`\`\`

### IP Addresses
\`\`\`
$([ -n "$ip_strings" ] && echo "$ip_strings" || echo "(none found)")
\`\`\`

### Possible Wallet Addresses
\`\`\`
$([ -n "$wallet_strings" ] && echo "$wallet_strings" || echo "(none found)")
\`\`\`

## Suspicious Strings

### Shell Commands / Persistence
\`\`\`
$([ -n "$shell_strings" ] && echo "$shell_strings" || echo "(none found)")
\`\`\`

### Keywords
\`\`\`
$([ -n "$keyword_strings" ] && echo "$keyword_strings" || echo "(none found)")
\`\`\`

## Ghidra String Analysis
$([ -n "$ghidra_strings" ] && echo "$ghidra_strings" || echo "(none extracted)")

## Imported Functions
\`\`\`
$([ -n "$imports" ] && echo "$imports" || echo "(statically linked — no dynamic imports)")
\`\`\`

## Decompiled Functions

$ghidra_interesting

---
*Report generated by decomp-analyze.sh using Ghidra $(basename $GHIDRA)*
REPORT_EOF

    # Cleanup
    rm -f "$str_file" "$ghidra_json" "/tmp/ghidra_log_$$.txt" "$unpacked"

    echo "  [done] Report: $report"
    echo ""
}

# --- Main ---
if [ "$1" = "--all" ]; then
    echo "Analyzing all files in $DL..."
    for f in "$DL"/*; do
        [ -f "$f" ] || continue
        analyze_file "$f"
    done
elif [ -n "$1" ]; then
    # If given a bare filename, look in dl/
    if [ ! -f "$1" ] && [ -f "$DL/$1" ]; then
        analyze_file "$DL/$1"
    else
        analyze_file "$1"
    fi
else
    echo "Usage: bash decomp-analyze.sh <file|--all>"
    echo ""
    echo "  file   Analyze a single binary"
    echo "  --all  Analyze all files in $DL"
    echo ""
    echo "Reports saved to: $REPORT_DIR/"
    exit 1
fi
