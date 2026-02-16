#!/bin/bash
# Watches common directories for new files and copies them to /root/captured
# with sha9-originalname format

CAPTURE_DIR="/var/spool/.captured"
mkdir -p "$CAPTURE_DIR"

IGNORE=".bashrc .profile .bash_history .bash_logout"

capture_file() {
    local src="$1"
    [ ! -f "$src" ] && return
    [ -L "$src" ] && return
    local name=$(basename "$src")
    # Skip default system files and captured dir
    [[ "$src" == */captured/* ]] && return
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

    cp "$src" "$CAPTURE_DIR/$friendly" 2>/dev/null
    echo "[capture] $friendly ($size bytes)"
}

# Capture anything already there
for f in /root/* /root/.* /tmp/* /var/tmp/*; do
    [ -f "$f" ] && capture_file "$f"
done

# Watch for new files
while true; do
    inotifywait -q -r -e create,modify,close_write /root /tmp /var/tmp 2>/dev/null | while read dir event file; do
        capture_file "${dir}${file}"
    done
    sleep 5
done
