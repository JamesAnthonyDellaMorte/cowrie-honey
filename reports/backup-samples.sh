#!/bin/bash
# Backup new malware samples to Storj (deduplicated via vt-cache.db)
# Usage: backup-samples.sh [--dry-run]
#
# Scans dl/ and unanalyzed/, hashes every file, skips partials,
# skips any SHA256 already marked backed_up in the DB,
# zips new samples with password "infected", uploads to Storj.
# Tracks backup state in vt-cache.db (backed_up column).

set -e

COWRIE="/root/cowrie"
BUCKET="sj://cowrie/samples"
ACCESS="cowrie"
DB="$COWRIE/reports/vt-cache.db"
PASSWORD="infected"
DRY_RUN=false

[ "$1" = "--dry-run" ] && DRY_RUN=true

shopt -s nullglob

# Ensure backed_up column exists
sqlite3 "$DB" "ALTER TABLE samples ADD COLUMN backed_up INTEGER DEFAULT 0;" 2>/dev/null || true


is_partial_elf() {
    local src="$1"
    local magic
    magic=$(od -A n -t x1 -N 4 "$src" 2>/dev/null | tr -d ' ')
    [ "$magic" != "7f454c46" ] && return 1
    local size=$(stat -c%s "$src" 2>/dev/null)
    local class
    class=$(od -A n -t x1 -j 4 -N 1 "$src" 2>/dev/null | tr -d ' ')
    local shoff
    if [ "$class" = "02" ]; then
        shoff=$(od -A n -t u8 -j 40 -N 8 "$src" 2>/dev/null | tr -d ' ')
    else
        shoff=$(od -A n -t u4 -j 32 -N 4 "$src" 2>/dev/null | tr -d ' ')
    fi
    [ -n "$shoff" ] && [ "$shoff" -gt 0 ] 2>/dev/null && [ "$size" -lt "$shoff" ]
}

upload_dir() {
    local DIR="$1"
    local LABEL="$2"
    local CLEANUP="$3"

    if [ ! -d "$DIR" ]; then
        echo "[$LABEL] Directory not found: $DIR"
        return
    fi

    local NEW_FILES=()
    local NEW_HASHES=()
    local SKIPPED=0
    local PARTIALS=0

    for f in "$DIR"/*; do
        [ -f "$f" ] || continue

        # Remove partials
        if is_partial_elf "$f"; then
            echo "[$LABEL] Removing partial: $(basename "$f")"
            rm -f "$f"
            PARTIALS=$((PARTIALS + 1))
            continue
        fi

        sha=$(sha256sum "$f" | cut -d' ' -f1)

        # Check DB for backed_up flag
        backed=$(sqlite3 "$DB" "SELECT backed_up FROM samples WHERE sha256='$sha';" 2>/dev/null)
        if [ "$backed" = "1" ]; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        NEW_FILES+=("$f")
        NEW_HASHES+=("$sha")
    done

    echo "[$LABEL] Scanned $(( ${#NEW_FILES[@]} + SKIPPED )) files: ${#NEW_FILES[@]} new, $SKIPPED backed up, $PARTIALS partials removed"

    if [ ${#NEW_FILES[@]} -eq 0 ]; then
        return
    fi

    if $DRY_RUN; then
        echo "[$LABEL] Would upload ${#NEW_FILES[@]} new samples"
        return
    fi

    local DATE=$(date +%Y%m%d-%H%M%S)
    local ARCHIVE="/tmp/${LABEL}-${DATE}.zip"
    local REMOTE="${BUCKET}/${LABEL}-${DATE}.zip"

    zip -q -P "$PASSWORD" "$ARCHIVE" -j "${NEW_FILES[@]}"

    local SIZE=$(du -h "$ARCHIVE" | cut -f1)
    echo "[$LABEL] Uploading $SIZE (${#NEW_FILES[@]} samples) to $REMOTE..."

    uplink cp "$ARCHIVE" "$REMOTE" --access "$ACCESS"

    # Mark as backed up in DB
    for h in "${NEW_HASHES[@]}"; do
        sqlite3 "$DB" "INSERT OR IGNORE INTO samples (sha256, backed_up) VALUES ('$h', 1);
                       UPDATE samples SET backed_up=1 WHERE sha256='$h';"
    done

    rm -f "$ARCHIVE"

    if [ "$CLEANUP" = "delete" ]; then
        for f in "${NEW_FILES[@]}"; do
            rm -f "$f"
        done
        echo "[$LABEL] Cleaned up ${#NEW_FILES[@]} files from $DIR"
    fi

    echo "[$LABEL] Done. ${#NEW_FILES[@]} new samples uploaded."
}

upload_dir "$COWRIE/dl" "cowrie" "delete"
upload_dir "$COWRIE/unanalyzed" "cowrie-unanalyzed"

TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM samples WHERE backed_up=1;")
echo ""
echo "--- $TOTAL unique samples backed up total ---"
