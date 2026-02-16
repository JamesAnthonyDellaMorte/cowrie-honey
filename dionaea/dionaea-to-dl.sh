#!/bin/bash
# Watch Dionaea binaries dir and copy new samples to cowrie dl/ with sha9-name format
BINARIES="/opt/dionaea/var/lib/dionaea/binaries"
DL="/dl"

mkdir -p "$DL"

copy_file() {
    local src="$1"
    [ ! -f "$src" ] && return
    [ -L "$src" ] && return
    local size=$(stat -c%s "$src" 2>/dev/null)
    [ "$size" = "0" ] && return

    local sha=$(sha256sum "$src" | cut -d' ' -f1)
    local md5name=$(basename "$src")

    # Check if already copied by sha prefix
    for existing in "$DL"/*; do
        [ -f "$existing" ] || continue
        if [[ "$(basename "$existing")" == "${sha:0:9}-"* ]]; then
            return
        fi
    done

    # Try to figure out a real name from file type
    local ftype=$(file -b "$src" 2>/dev/null)
    local ext=""
    case "$ftype" in
        *"PE32+ executable"*) ext=".exe" ;;
        *"PE32 executable"*)  ext=".exe" ;;
        *"MS-DOS executable"*) ext=".exe" ;;
        *"DLL"*)              ext=".dll" ;;
        *"ELF"*)              ext=".elf" ;;
        *"Zip archive"*)      ext=".zip" ;;
        *"gzip"*)             ext=".gz" ;;
        *"PDF"*)              ext=".pdf" ;;
        *"HTML"*)             ext=".html" ;;
        *"ASCII text"*)       ext=".txt" ;;
        *"data"*)             ext=".bin" ;;
        *)                    ext=".bin" ;;
    esac

    local friendly="${sha:0:9}-${md5name}${ext}"
    cp "$src" "$DL/$friendly" 2>/dev/null
    echo "[dionaea-dl] $friendly ($size bytes)"
}

# Process existing files
for f in "$BINARIES"/*; do
    [ -f "$f" ] && copy_file "$f"
done

# Watch for new files
while true; do
    inotifywait -q -r -e create,close_write "$BINARIES" 2>/dev/null | while read dir event file; do
        copy_file "${dir}${file}"
    done
    sleep 5
done
