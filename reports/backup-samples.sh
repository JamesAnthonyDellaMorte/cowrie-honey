#!/bin/bash
# Backup new malware samples to Storj (deduplicated by SHA256)
# Usage: backup-samples.sh [--dry-run]
#
# Scans dl/ and unanalyzed/, hashes every file, skips any SHA256
# already backed up, zips new unique samples with password "infected",
# uploads to Storj as separate archives per directory.
# Tracks all backed-up hashes in a single .backed_up_hashes file.

set -e

COWRIE="/root/cowrie"
BUCKET="sj://cowrie/samples"
ACCESS="cowrie"
BACKED_UP="$COWRIE/reports/.backed_up_hashes"
PASSWORD="infected"
DRY_RUN=false

[ "$1" = "--dry-run" ] && DRY_RUN=true

touch "$BACKED_UP"
shopt -s nullglob

upload_dir() {
    local DIR="$1"
    local LABEL="$2"
    local CLEANUP="$3"  # "delete" to remove files after upload

    if [ ! -d "$DIR" ]; then
        echo "[$LABEL] Directory not found: $DIR"
        return
    fi

    local NEW_FILES=()
    local NEW_HASHES=()
    local SKIPPED=0

    for f in "$DIR"/*; do
        [ -f "$f" ] || continue
        sha=$(sha256sum "$f" | cut -d' ' -f1)
        if grep -qxF "$sha" "$BACKED_UP" 2>/dev/null; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi
        NEW_FILES+=("$f")
        NEW_HASHES+=("$sha")
    done

    echo "[$LABEL] Scanned $(( ${#NEW_FILES[@]} + SKIPPED )) files: ${#NEW_FILES[@]} new, $SKIPPED already backed up"

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

    # Mark as backed up
    for h in "${NEW_HASHES[@]}"; do
        echo "$h" >> "$BACKED_UP"
    done

    rm -f "$ARCHIVE"

    # Delete source files after successful upload
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

TOTAL=$(wc -l < "$BACKED_UP")
echo ""
echo "--- $TOTAL unique samples backed up total ---"
