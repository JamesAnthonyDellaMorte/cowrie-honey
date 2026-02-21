#!/bin/bash
# Checks all samples in dl/ for partial downloads (missing section headers)
# Usage: ./check-partials.sh [--clean]
#   --clean  removes partial files instead of just listing them

DIR="${1:-/root/cowrie/dl}"
CLEAN=0

if [ "$1" = "--clean" ]; then
    DIR="${2:-/root/cowrie/dl}"
    CLEAN=1
elif [ "$2" = "--clean" ]; then
    CLEAN=1
fi

full=0
partial=0
removed=0

for f in "$DIR"/*; do
    [ -f "$f" ] || continue
    actual=$(stat -c%s "$f")
    info=$(file -b "$f")
    base=$(basename "$f")

    if echo "$info" | grep -q "missing section headers"; then
        expected=$(echo "$info" | grep -oP 'missing section headers at \K[0-9]+')
        pct=$((actual * 100 / expected))
        echo "PARTIAL: $base — $actual / $expected bytes (${pct}%)"
        partial=$((partial + 1))
        if [ "$CLEAN" -eq 1 ]; then
            rm "$f"
            removed=$((removed + 1))
        fi
    else
        full=$((full + 1))
    fi
done

echo ""
echo "Full: $full  Partial: $partial"
[ "$CLEAN" -eq 1 ] && [ "$removed" -gt 0 ] && echo "Removed: $removed"
