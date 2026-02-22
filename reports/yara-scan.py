#!/usr/bin/env python3
"""
YARA scanner for honeypot malware samples.

Usage:
  python3 yara-scan.py              # Scan dl/ directory
  python3 yara-scan.py <file>       # Scan single file
  python3 yara-scan.py --unanalyzed # Scan unanalyzed/ directory
"""

import os
import sys
import hashlib
from pathlib import Path

import yara

RULES_FILE = Path(__file__).parent / "rules.yar"
DL = Path("/root/cowrie/dl")
UNANALYZED = Path("/root/cowrie/unanalyzed")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_file(rules, filepath):
    """Scan a single file and return matches."""
    try:
        matches = rules.match(str(filepath))
        return matches
    except Exception as e:
        return []


def scan_directory(rules, directory):
    """Scan all files in a directory."""
    files = sorted([f for f in directory.iterdir() if f.is_file()])
    if not files:
        print(f"  No files in {directory}")
        return

    matched = 0
    unmatched = 0
    family_counts = {}

    for fp in files:
        matches = scan_file(rules, fp)
        sha = sha256_file(fp)[:16]
        size = fp.stat().st_size
        name = fp.name

        if matches:
            matched += 1
            for m in matches:
                family = m.meta.get("family", "unknown")
                severity = m.meta.get("severity", "?")
                family_counts[family] = family_counts.get(family, 0) + 1

                # Show matched strings
                matched_strs = []
                for sm in m.strings:
                    for inst in sm.instances:
                        raw = inst.matched_data
                        if all(32 <= b < 127 for b in raw):
                            s = raw.decode("ascii")[:40]
                        else:
                            s = raw.hex(" ")[:40]
                        matched_strs.append(f"${sm.identifier}={s}")
                        break  # one instance per string is enough

                strs_preview = ", ".join(matched_strs[:3])
                print(f"  [{severity:8s}] {sha}... {name:40s} {size:>9,}B  -> {m.rule} ({family})")
                if matched_strs:
                    print(f"             matched: {strs_preview}")
        else:
            unmatched += 1
            print(f"  [  none  ] {sha}... {name:40s} {size:>9,}B  -> NO MATCH")

    print(f"\n--- Results ---")
    print(f"  Scanned:   {matched + unmatched}")
    print(f"  Matched:   {matched}")
    print(f"  No match:  {unmatched}")
    if family_counts:
        print(f"\n  Families detected:")
        for fam, count in sorted(family_counts.items(), key=lambda x: -x[1]):
            print(f"    {fam:25s} {count}")


def main():
    if not RULES_FILE.exists():
        print(f"Error: rules file not found: {RULES_FILE}")
        sys.exit(1)

    print(f"Loading rules from {RULES_FILE}...")
    rules = yara.compile(filepath=str(RULES_FILE))
    print(f"Rules loaded.\n")

    if len(sys.argv) > 1 and sys.argv[1] == "--unanalyzed":
        print(f"=== Scanning {UNANALYZED} ===\n")
        scan_directory(rules, UNANALYZED)
    elif len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        fp = Path(sys.argv[1])
        matches = scan_file(rules, fp)
        if matches:
            for m in matches:
                print(f"  MATCH: {m.rule} (family={m.meta.get('family','?')}, severity={m.meta.get('severity','?')})")
        else:
            print("  No matches.")
    else:
        print(f"=== Scanning {DL} ===\n")
        scan_directory(rules, DL)


if __name__ == "__main__":
    main()
