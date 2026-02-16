#!/bin/bash
# Check cowrie downloads against VirusTotal with local SQLite cache
# Only queries VT for hashes we haven't seen before.
# Usage: bash vt-check.sh [--force]  (--force re-checks everything)

VT_KEY=$(cat /root/.config/virustotal/api_key)
DL="/root/cowrie/dl"
DB="/root/cowrie/reports/vt-cache.db"
FORCE=false

[ "$1" = "--force" ] && FORCE=true

# Init SQLite database
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS samples (
    sha256 TEXT PRIMARY KEY,
    first_seen TEXT DEFAULT (datetime('now')),
    filename TEXT,
    filesize INTEGER,
    filetype TEXT,
    vt_known INTEGER DEFAULT 0,
    vt_detections INTEGER DEFAULT 0,
    vt_total INTEGER DEFAULT 0,
    vt_label TEXT DEFAULT '',
    vt_names TEXT DEFAULT '',
    checked_at TEXT DEFAULT (datetime('now'))
);"

NEW=0
CACHED=0
CHECKED=0
UNKNOWN=0

for f in "$DL"/*; do
    [ -L "$f" ] && continue
    [ ! -f "$f" ] && continue
    hash=$(sha256sum "$f" | cut -d' ' -f1)
    size=$(stat -c%s "$f" 2>/dev/null)
    # Strip "sha9-" prefix if present to get original name
    bname=$(basename "$f")
    fname="${bname#*-}"
    [ "$fname" = "$bname" ] && fname="$bname"

    # Skip empty files
    [ "$size" = "0" ] && continue

    # Check cache first (unless --force)
    if ! $FORCE; then
        cached=$(sqlite3 "$DB" "SELECT vt_known, vt_detections, vt_total, vt_label, vt_names FROM samples WHERE sha256='$hash';")
        if [ -n "$cached" ]; then
            IFS='|' read -r known det total label names <<< "$cached"
            if [ "$known" = "1" ]; then
                echo "  [cache] $hash -> $det/$total detections - $label  [$names]"
            else
                echo "  [cache] ****** UNKNOWN: $hash ******"
                UNKNOWN=$((UNKNOWN+1))
            fi
            CACHED=$((CACHED+1))
            continue
        fi
    fi

    # Not in cache - query VT
    filetype=$(file -b "$f" | cut -c1-60)

    http_code=$(curl -s -o /tmp/vt_resp.json -w "%{http_code}" \
        "https://www.virustotal.com/api/v3/files/$hash" -H "x-apikey: $VT_KEY")

    if [ "$http_code" = "404" ]; then
        echo ""
        echo "  ****** NEW UNKNOWN SAMPLE ******"
        echo "  Hash: $hash"
        echo "  Size: ${size}B"
        echo "  Type: $filetype"
        echo "  NOT ON VIRUSTOTAL - NEEDS ANALYSIS"
        echo "  ********************************"
        echo ""
        sqlite3 "$DB" "INSERT OR REPLACE INTO samples (sha256, filename, filesize, filetype, vt_known, checked_at)
            VALUES ('$hash', '$(echo "$fname" | sed "s/'/''/g")', $size, '$(echo "$filetype" | sed "s/'/''/g")', 0, datetime('now'));"
        NEW=$((NEW+1))
        UNKNOWN=$((UNKNOWN+1))
    elif [ "$http_code" = "200" ]; then
        # Parse VT response and cache it
        IFS='|' read -r det total label names < <(python3 -c "
import json
d=json.load(open('/tmp/vt_resp.json'))
a=d.get('data',{}).get('attributes',{})
s=a.get('last_analysis_stats',{})
names=a.get('names',[])[:3]
label=a.get('popular_threat_classification',{}).get('suggested_threat_label','unknown')
mal=s.get('malicious',0)
total=mal+s.get('undetected',0)
n=', '.join(names) if names else '?'
print(f'{mal}|{total}|{label}|{n}')
")
        echo "  [new]   $hash -> $det/$total detections - $label  [$names]"
        sqlite3 "$DB" "INSERT OR REPLACE INTO samples (sha256, filename, filesize, filetype, vt_known, vt_detections, vt_total, vt_label, vt_names, checked_at)
            VALUES ('$hash', '$(echo "$fname" | sed "s/'/''/g")', $size, '$(echo "$filetype" | sed "s/'/''/g")', 1, $det, $total, '$(echo "$label" | sed "s/'/''/g")', '$(echo "$names" | sed "s/'/''/g")', datetime('now'));"
    else
        echo "  [error] VT API $http_code for $hash"
    fi
    CHECKED=$((CHECKED+1))
    sleep 15  # VT rate limit (4 req/min on free tier)
done

echo ""
echo "--- Summary ---"
echo "Total files:   $(ls -1 "$DL"/ 2>/dev/null | wc -l)"
echo "From cache:    $CACHED"
echo "Queried VT:    $CHECKED"
echo "Unknown (new): $UNKNOWN"
echo ""
echo "Cache: $DB ($(sqlite3 "$DB" "SELECT COUNT(*) FROM samples;") samples stored)"
