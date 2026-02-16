#!/bin/bash
# Check cowrie downloads against VirusTotal with local SQLite cache
# Three-pass design:
#   Pass 1: Check local cache (instant)
#   Pass 2: Lookup uncached hashes on VT (4/min rate limit)
#   Pass 3: Upload unknowns, then poll for results
#
# Usage: bash vt-check.sh [--force] [--no-upload]
#   --force      re-checks everything (ignores cache)
#   --no-upload  skip uploading unknown samples

VT_KEY=$(cat /root/.config/virustotal/api_key)
DL="/root/cowrie/dl"
DB="/root/cowrie/reports/vt-cache.db"
UNANALYZED="/root/cowrie/unanalyzed"
FORCE=false
UPLOAD=true

for arg in "$@"; do
    [ "$arg" = "--force" ] && FORCE=true
    [ "$arg" = "--no-upload" ] && UPLOAD=false
done

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
    vt_link TEXT DEFAULT '',
    checked_at TEXT DEFAULT (datetime('now'))
);"
sqlite3 "$DB" "ALTER TABLE samples ADD COLUMN vt_link TEXT DEFAULT '';" 2>/dev/null
mkdir -p "$UNANALYZED"

# Helper: parse VT JSON response
parse_vt() {
    python3 -c "
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
"
}

# Helper: save known sample to DB
save_known() {
    local hash="$1" fname="$2" size="$3" filetype="$4" det="$5" total="$6" label="$7" names="$8" vt_link="$9"
    sqlite3 "$DB" "INSERT OR REPLACE INTO samples (sha256, filename, filesize, filetype, vt_known, vt_detections, vt_total, vt_label, vt_names, vt_link, checked_at)
        VALUES ('$hash', '$(echo "$fname" | sed "s/'/''/g")', $size, '$(echo "$filetype" | sed "s/'/''/g")', 1, $det, $total, '$(echo "$label" | sed "s/'/''/g")', '$(echo "$names" | sed "s/'/''/g")', '$vt_link', datetime('now'));"
}

CACHED=0
LOOKED_UP=0
UPLOADED=0
UNKNOWN=0

# Build file list
declare -a FILES=() HASHES=() SIZES=() FNAMES=() BNAMES=()
for f in "$DL"/*; do
    [ -L "$f" ] && continue
    [ ! -f "$f" ] && continue
    size=$(stat -c%s "$f" 2>/dev/null)
    [ "$size" = "0" ] && continue
    bname=$(basename "$f")
    fname="${bname#*-}"
    [ "$fname" = "$bname" ] && fname="$bname"
    hash=$(sha256sum "$f" | cut -d' ' -f1)
    FILES+=("$f")
    HASHES+=("$hash")
    SIZES+=("$size")
    FNAMES+=("$fname")
    BNAMES+=("$bname")
done

TOTAL=${#FILES[@]}
echo "  Found $TOTAL files in $DL"
echo ""

# ============================================================
# PASS 1: Check local cache
# ============================================================
echo "--- Pass 1: Local cache ---"
declare -a UNCACHED_IDX=()
P1_KNOWN=0
P1_UNKNOWN=0

for i in "${!FILES[@]}"; do
    hash="${HASHES[$i]}"
    vt_link="https://www.virustotal.com/gui/file/$hash"

    if ! $FORCE; then
        cached=$(sqlite3 "$DB" "SELECT vt_known, vt_detections, vt_total, vt_label, vt_names FROM samples WHERE sha256='$hash';")
        if [ -n "$cached" ]; then
            IFS='|' read -r known det total label names <<< "$cached"
            if [ "$known" = "1" ]; then
                echo "  [cache] ${hash:0:16}... -> $det/$total - $label  [$names]"
                P1_KNOWN=$((P1_KNOWN+1))
            else
                echo "  [cache] ****** UNKNOWN: ${hash:0:16}... ******"
                cp -n "${FILES[$i]}" "$UNANALYZED/${BNAMES[$i]}" 2>/dev/null
                UNKNOWN=$((UNKNOWN+1))
                P1_UNKNOWN=$((P1_UNKNOWN+1))
            fi
            CACHED=$((CACHED+1))
            continue
        fi
    fi
    UNCACHED_IDX+=("$i")
done

echo "  Known: $P1_KNOWN | Unknown: $P1_UNKNOWN | Need lookup: ${#UNCACHED_IDX[@]}"
echo ""

# ============================================================
# PASS 2: VT lookups for uncached files
# ============================================================
declare -a UNKNOWN_IDX=()
LOOKUPS=0

if [ ${#UNCACHED_IDX[@]} -gt 0 ]; then
    echo "--- Pass 2: VT lookups ---"
    P2_KNOWN=0
    P2_UNKNOWN=0
    P2_ERROR=0

    for i in "${UNCACHED_IDX[@]}"; do
        hash="${HASHES[$i]}"
        fname="${FNAMES[$i]}"
        size="${SIZES[$i]}"
        f="${FILES[$i]}"
        bname="${BNAMES[$i]}"
        vt_link="https://www.virustotal.com/gui/file/$hash"
        filetype=$(file -b "$f" | cut -c1-60)

        # Rate limit: 4 lookups per minute
        if [ "$LOOKUPS" -ge 4 ]; then
            echo "  [rate] 4 lookups sent, waiting 60s..."
            sleep 60
            LOOKUPS=0
        fi

        http_code=$(curl -s -o /tmp/vt_resp.json -w "%{http_code}" \
            "https://www.virustotal.com/api/v3/files/$hash" -H "x-apikey: $VT_KEY")
        LOOKUPS=$((LOOKUPS+1))
        LOOKED_UP=$((LOOKED_UP+1))

        if [ "$http_code" = "200" ]; then
            IFS='|' read -r det total label names < <(parse_vt)
            echo "  [new]   ${hash:0:16}... -> $det/$total - $label  [$names]"
            save_known "$hash" "$fname" "$size" "$filetype" "$det" "$total" "$label" "$names" "$vt_link"
            P2_KNOWN=$((P2_KNOWN+1))
        elif [ "$http_code" = "404" ]; then
            echo "  [new]   ${hash:0:16}... -> NOT ON VT ($fname)"
            sqlite3 "$DB" "INSERT OR REPLACE INTO samples (sha256, filename, filesize, filetype, vt_known, vt_link, checked_at)
                VALUES ('$hash', '$(echo "$fname" | sed "s/'/''/g")', $size, '$(echo "$filetype" | sed "s/'/''/g")', 0, '$vt_link', datetime('now'));"
            cp -n "$f" "$UNANALYZED/$bname" 2>/dev/null
            UNKNOWN_IDX+=("$i")
            UNKNOWN=$((UNKNOWN+1))
            P2_UNKNOWN=$((P2_UNKNOWN+1))
        else
            echo "  [error] VT API $http_code for ${hash:0:16}..."
            P2_ERROR=$((P2_ERROR+1))
        fi
    done

    echo "  Known: $P2_KNOWN | Unknown: $P2_UNKNOWN | Errors: $P2_ERROR"
    echo ""
fi

# ============================================================
# PASS 3: Upload unknowns, then poll for results
# ============================================================
if $UPLOAD && [ ${#UNKNOWN_IDX[@]} -gt 0 ]; then
    echo "--- Pass 3: Upload & analyze ---"

    # Upload all unknowns (no rate limit on uploads)
    declare -a UPLOADED_IDX=()
    for i in "${UNKNOWN_IDX[@]}"; do
        f="${FILES[$i]}"
        fname="${FNAMES[$i]}"
        hash="${HASHES[$i]}"
        vt_link="https://www.virustotal.com/gui/file/$hash"

        echo "  [upload] $fname -> VT..."
        up_code=$(curl -s -o /tmp/vt_upload.json -w "%{http_code}" \
            -X POST "https://www.virustotal.com/api/v3/files" \
            -H "x-apikey: $VT_KEY" \
            --form "file=@$f")
        if [ "$up_code" = "200" ]; then
            echo "  [upload] Submitted! $vt_link"
            UPLOADED_IDX+=("$i")
            UPLOADED=$((UPLOADED+1))
        else
            echo "  [upload] Failed (HTTP $up_code)"
        fi
    done

    # Poll for results
    if [ ${#UPLOADED_IDX[@]} -gt 0 ]; then
        echo ""
        echo "  Waiting for VT to process ${#UPLOADED_IDX[@]} samples..."
        LOOKUPS=0

        for attempt in $(seq 1 10); do
            # Check if any are still pending
            declare -a STILL_PENDING=()
            for i in "${UPLOADED_IDX[@]}"; do
                known=$(sqlite3 "$DB" "SELECT vt_known FROM samples WHERE sha256='${HASHES[$i]}';")
                [ "$known" != "1" ] && STILL_PENDING+=("$i")
            done
            [ ${#STILL_PENDING[@]} -eq 0 ] && break

            sleep 30
            echo "  [poll] Check $attempt/10 — ${#STILL_PENDING[@]} pending..."

            for i in "${STILL_PENDING[@]}"; do
                hash="${HASHES[$i]}"
                fname="${FNAMES[$i]}"
                size="${SIZES[$i]}"
                f="${FILES[$i]}"
                bname="${BNAMES[$i]}"
                vt_link="https://www.virustotal.com/gui/file/$hash"
                filetype=$(file -b "$f" | cut -c1-60)

                if [ "$LOOKUPS" -ge 4 ]; then
                    echo "  [rate] 4 lookups sent, waiting 60s..."
                    sleep 60
                    LOOKUPS=0
                fi

                poll_code=$(curl -s -o /tmp/vt_resp.json -w "%{http_code}" \
                    "https://www.virustotal.com/api/v3/files/$hash" -H "x-apikey: $VT_KEY")
                LOOKUPS=$((LOOKUPS+1))

                if [ "$poll_code" = "200" ]; then
                    IFS='|' read -r det total label names < <(parse_vt)
                    if [ "$total" -gt 0 ] 2>/dev/null; then
                        echo "  [done]  ${hash:0:16}... -> $det/$total - $label  [$names]"
                        save_known "$hash" "$fname" "$size" "$filetype" "$det" "$total" "$label" "$names" "$vt_link"
                        # Remove from unanalyzed since we got results
                        rm -f "$UNANALYZED/$bname" 2>/dev/null
                        UNKNOWN=$((UNKNOWN-1))
                    fi
                fi
            done
        done

        # Report any still pending
        P3_DONE=0
        P3_PENDING=0
        for i in "${UPLOADED_IDX[@]}"; do
            known=$(sqlite3 "$DB" "SELECT vt_known FROM samples WHERE sha256='${HASHES[$i]}';")
            if [ "$known" != "1" ]; then
                echo "  [pending] ${FNAMES[$i]} — check later: https://www.virustotal.com/gui/file/${HASHES[$i]}"
                P3_PENDING=$((P3_PENDING+1))
            else
                P3_DONE=$((P3_DONE+1))
            fi
        done
        echo "  Uploaded: $UPLOADED | Analyzed: $P3_DONE | Pending: $P3_PENDING"
    fi
    echo ""
fi

echo "--- Summary ---"
echo "Total files:   $TOTAL"
echo "From cache:    $CACHED"
echo "Looked up:     $LOOKED_UP"
echo "Uploaded:      $UPLOADED"
echo "Unknown:       $UNKNOWN"
echo ""
echo "Cache: $DB ($(sqlite3 "$DB" "SELECT COUNT(*) FROM samples;") samples stored)"
