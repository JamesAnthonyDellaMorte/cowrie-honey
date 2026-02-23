#!/bin/bash
# Watches all writable directories for new executable binaries dropped by attackers
# and copies them to the capture dir with sha9-originalname format.
# Uses an MD5 baseline of system binaries taken at startup to avoid capturing OS files.

CAPTURE_DIR="/mnt/captures"
STAGE_DIR="/var/spool/.staging"
BASELINE="/var/spool/.baseline_md5"
mkdir -p "$CAPTURE_DIR" "$STAGE_DIR"

WATCH_DIRS="/root /tmp /var/tmp /dev/shm /bin /etc /home /usr /opt /run"
RESCAN_SECONDS=30

scan_depth() {
    case "$1" in
        /tmp|/var/tmp|/dev/shm) echo 5 ;;
        /root|/home) echo 4 ;;
        *) echo 2 ;;
    esac
}

# --- Build baseline of all existing binaries at startup ---
# MD5 is fast and sufficient for dedup (not used for security)
echo "[capture] Building system baseline..."
find /bin /usr/bin /usr/sbin /sbin /usr/local/bin /etc /opt /run \
    -maxdepth 2 -type f -executable 2>/dev/null \
    | xargs -P4 md5sum 2>/dev/null \
    | cut -d' ' -f1 \
    | sort -u > "$BASELINE"
echo "[capture] Baseline: $(wc -l < "$BASELINE") system binaries fingerprinted"

# Rebuild baseline whenever apt/dpkg installs new packages
rebuild_baseline() {
    find /bin /usr/bin /usr/sbin /sbin /usr/local/bin /etc /opt /run \
        /usr/lib /usr/share -maxdepth 3 -type f -executable 2>/dev/null \
        | xargs -P4 md5sum 2>/dev/null \
        | cut -d' ' -f1 \
        | sort -u > "$BASELINE"
    echo "[capture] Baseline rebuilt: $(wc -l < "$BASELINE") binaries"
}

# Watch dpkg database for changes and rebuild baseline
dpkg_watcher() {
    while true; do
        inotifywait -qq -e close_write /var/lib/dpkg/status 2>/dev/null
        echo "[capture] dpkg database changed, rebuilding baseline..."
        sleep 5  # let apt finish installing everything
        rebuild_baseline
    done
}
dpkg_watcher &

is_system_binary() {
    local md5
    md5=$(md5sum "$1" 2>/dev/null | cut -d' ' -f1)
    grep -qF "$md5" "$BASELINE"
}

# Only capture files with known executable magic bytes
is_executable_binary() {
    local src="$1"
    local magic
    magic=$(od -A n -t x1 -N 4 "$src" 2>/dev/null | tr -d ' ')
    case "$magic" in
        7f454c46) return 0 ;;  # ELF (Linux, BSD, etc.)
        4d5a*) return 0 ;;     # PE/MZ (Windows .exe/.dll)
        feedface) return 0 ;;  # Mach-O 32-bit
        feedfacf) return 0 ;;  # Mach-O 64-bit
        cefaedfe) return 0 ;;  # Mach-O 32-bit (reversed)
        cffaedfe) return 0 ;;  # Mach-O 64-bit (reversed)
        cafebabe) return 0 ;;  # Mach-O Universal / Java class
    esac
    return 1
}

is_core_dump() {
    local src="$1"
    local magic
    magic=$(od -A n -t x1 -N 4 "$src" 2>/dev/null | tr -d ' ')
    [ "$magic" != "7f454c46" ] && return 1

    # e_type at bytes 16-17: ET_CORE == 0x0004
    local etype
    etype=$(od -A n -t x1 -j 16 -N 2 "$src" 2>/dev/null | tr -d ' ')
    case "$etype" in
        0400|0004) return 0 ;;
    esac
    return 1
}

capture_file() {
    local src="$1"
    [ ! -f "$src" ] && return
    [ -L "$src" ] && return
    [[ "$src" == */captured/* ]] && return
    [[ "$src" == */staging/* ]] && return
    local size=$(stat -c%s "$src" 2>/dev/null)
    [ "$size" = "0" ] && return
    is_executable_binary "$src" || return
    if is_core_dump "$src"; then
        echo "[capture] skipped core dump: $(basename "$src")"
        return
    fi
    is_system_binary "$src" && return
    # Skip files owned by installed packages (e.g. attacker ran apt install)
    dpkg -S "$src" >/dev/null 2>&1 && return

    # Skip truncated ELF downloads — if section header offset > file size, it's partial
    local magic
    magic=$(od -A n -t x1 -N 4 "$src" 2>/dev/null | tr -d ' ')
    if [ "$magic" = "7f454c46" ]; then
        local shoff
        # ELF64: section header offset at byte 40, 8 bytes LE
        # ELF32: section header offset at byte 32, 4 bytes LE
        local class
        class=$(od -A n -t x1 -j 4 -N 1 "$src" 2>/dev/null | tr -d ' ')
        if [ "$class" = "02" ]; then
            shoff=$(od -A n -t u8 -j 40 -N 8 "$src" 2>/dev/null | tr -d ' ')
        else
            shoff=$(od -A n -t u4 -j 32 -N 4 "$src" 2>/dev/null | tr -d ' ')
        fi
        if [ -n "$shoff" ] && [ "$shoff" -gt 0 ] 2>/dev/null && [ "$size" -lt "$shoff" ]; then
            echo "[capture] skipped partial: $(basename "$src") ($size / $shoff bytes)"
            # Signal host to rescue this file
            echo "$(basename "$src")" > /mnt/captures/.rescue
            return
        fi
    fi

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
cleanup_junk() {
    for f in "$CAPTURE_DIR"/*; do
        [ -f "$f" ] || continue
        local base=$(basename "$f")
        if [[ ! "$base" =~ ^[0-9a-f]{9}- ]]; then
            rm -f "$f" 2>/dev/null
            echo "[capture] removed junk: $base"
        fi
    done
}

# Initial cleanup
cleanup_junk

# Initial scan of all watched dirs
for dir in $WATCH_DIRS; do
    depth=$(scan_depth "$dir")
    find "$dir" -maxdepth "$depth" -type f 2>/dev/null | while IFS= read -r f; do
        capture_file "$f"
    done
done

# Periodic rescan — catches anything inotifywait missed
rescan_loop() {
    while true; do
        sleep "$RESCAN_SECONDS"
        for dir in $WATCH_DIRS; do
            depth=$(scan_depth "$dir")
            find "$dir" -maxdepth "$depth" -type f -newer "$BASELINE" 2>/dev/null | while IFS= read -r f; do
                capture_file "$f"
            done
        done
    done
}
rescan_loop &

# Watch for new files in real-time
while true; do
    inotifywait -m -q -r -e close_write,moved_to $WATCH_DIRS "$CAPTURE_DIR" 2>/dev/null | while read dir event file; do
        fullpath="${dir}${file}"
        if [[ "$fullpath" == "$CAPTURE_DIR"/* ]]; then
            base=$(basename "$fullpath")
            if [[ ! "$base" =~ ^[0-9a-f]{9}- ]]; then
                sleep 1
                rm -f "$fullpath" 2>/dev/null
                echo "[capture] removed junk: $base"
            fi
        else
            # Delay for system paths — give dpkg time to register apt-installed files
            case "$fullpath" in
                /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/share/*|/bin/*|/sbin/*) sleep 10 ;;
            esac
            capture_file "$fullpath"
        fi
    done
    sleep 5
done
