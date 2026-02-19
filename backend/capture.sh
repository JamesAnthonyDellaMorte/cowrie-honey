#!/bin/bash
# Watches common directories for new files and copies them to the capture dir
# with sha9-originalname format

# Hidden capture dir — the shared volume is mounted here
CAPTURE_DIR="/var/spool/.captured"
# Staging dir inside the container (not on shared volume) to avoid
# attackers seeing or writing directly to the capture dir
STAGE_DIR="/var/spool/.staging"
mkdir -p "$CAPTURE_DIR" "$STAGE_DIR"

IGNORE=".bashrc .profile .bash_history .bash_logout"

capture_file() {
    local src="$1"
    [ ! -f "$src" ] && return
    [ -L "$src" ] && return
    local name=$(basename "$src")
    # Skip files in our own dirs
    [[ "$src" == */captured/* ]] && return
    [[ "$src" == */staging/* ]] && return
    for ign in $IGNORE; do [ "$name" = "$ign" ] && return; done
    local size=$(stat -c%s "$src" 2>/dev/null)
    [ "$size" = "0" ] && return

    local sha=$(sha256sum "$src" | cut -d' ' -f1)
    local name=$(basename "$src")
    local friendly="${sha:0:9}-${name}"

    # Check if we already have this hash
    for existing in "$CAPTURE_DIR"/*; do
        [ -f "$existing" ] || continue
        if [[ "$(basename "$existing")" == "${sha:0:9}-"* ]]; then
            return
        fi
    done

    # Stage then move atomically to the shared volume
    cp "$src" "$STAGE_DIR/$friendly" 2>/dev/null && \
        mv "$STAGE_DIR/$friendly" "$CAPTURE_DIR/$friendly" 2>/dev/null
    echo "[capture] $friendly ($size bytes)"
}

# Clean up any files in the capture dir that don't match sha9-name format
# (e.g. junk written directly by attackers)
cleanup_junk() {
    for f in "$CAPTURE_DIR"/*; do
        [ -f "$f" ] || continue
        local base=$(basename "$f")
        # Valid files match: 9 hex chars, dash, then a name
        if [[ ! "$base" =~ ^[0-9a-f]{9}- ]]; then
            rm -f "$f" 2>/dev/null
            echo "[capture] removed junk: $base"
        fi
    done
}

# Initial cleanup
cleanup_junk

# Capture anything already there
for f in /root/* /root/.* /tmp/* /var/tmp/*; do
    [ -f "$f" ] && capture_file "$f"
done

# Watch for new files in attacker-accessible dirs AND the capture dir (for junk cleanup)
while true; do
    inotifywait -q -r -e create,modify,close_write /root /tmp /var/tmp "$CAPTURE_DIR" 2>/dev/null | while read dir event file; do
        fullpath="${dir}${file}"
        if [[ "$fullpath" == "$CAPTURE_DIR"/* ]]; then
            # File appeared in capture dir — clean if it's junk
            base=$(basename "$fullpath")
            if [[ ! "$base" =~ ^[0-9a-f]{9}- ]]; then
                rm -f "$fullpath" 2>/dev/null
                echo "[capture] removed junk: $base"
            fi
        else
            capture_file "$fullpath"
        fi
    done
    sleep 5
done
