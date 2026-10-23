#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
----------------------------
Builds a SHA-256 baseline of a directory, then compares the directory against it
and reports files that were ADDED, REMOVED, or MODIFIED. That's the same idea
behind tools like Tripwire, OSSEC, and Wazuh's syscheck.

MITRE ATT&CK detections: T1565.001 Stored Data Manipulation, T1505.003 Web Shell,
T1546 Event Triggered Execution (modified startup/config files)

Usage:
    python3 file_integrity_monitor.py baseline ./demo_dir          # create baseline.json
    python3 file_integrity_monitor.py check    ./demo_dir          # compare against it
    python3 file_integrity_monitor.py check    ./demo_dir --watch 30   # re-check every 30s
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime


def sha256(path, chunk=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(root, exclude):
    result = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.abspath(full) in exclude:
                continue
            rel = os.path.relpath(full, root)
            try:
                st = os.stat(full)
                result[rel] = {"sha256": sha256(full), "size": st.st_size,
                               "mode": oct(st.st_mode & 0o777), "mtime": st.st_mtime}
            except (PermissionError, FileNotFoundError) as e:
                print(f"[!] Skipped {rel}: {e}", file=sys.stderr)
    return result


def compare(old, new):
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    modified, perms = [], []
    for f in sorted(set(old) & set(new)):
        if old[f]["sha256"] != new[f]["sha256"]:
            modified.append(f)
        elif old[f]["mode"] != new[f]["mode"]:
            perms.append(f"{f} ({old[f]['mode']} -> {new[f]['mode']})")
    return added, removed, modified, perms


def main():
    p = argparse.ArgumentParser(description="Simple SHA-256 file integrity monitor.")
    p.add_argument("mode", choices=["baseline", "check"])
    p.add_argument("directory")
    p.add_argument("-b", "--baseline-file", default="baseline.json")
    p.add_argument("--watch", type=int, metavar="SECONDS", help="keep checking on an interval")
    args = p.parse_args()

    if not os.path.isdir(args.directory):
        sys.exit(f"[!] {args.directory} is not a directory")
    exclude = {os.path.abspath(args.baseline_file)}

    if args.mode == "baseline":
        snap = snapshot(args.directory, exclude)
        with open(args.baseline_file, "w") as f:
            json.dump({"created": datetime.now().isoformat(timespec="seconds"),
                       "root": os.path.abspath(args.directory), "files": snap}, f, indent=2)
        print(f"[+] Baseline of {len(snap)} file(s) saved to {args.baseline_file}")
        return

    try:
        with open(args.baseline_file) as f:
            base = json.load(f)
    except FileNotFoundError:
        sys.exit(f"[!] No baseline at {args.baseline_file}. Run 'baseline' first.")

    while True:
        added, removed, modified, perms = compare(base["files"], snapshot(args.directory, exclude))
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not any([added, removed, modified, perms]):
            print(f"[{stamp}] [+] OK: no changes since baseline ({base['created']})")
        else:
            print(f"[{stamp}] [!] Integrity changes detected since {base['created']}:")
            for label, items in (("MODIFIED", modified), ("ADDED", added),
                                 ("REMOVED", removed), ("PERMISSIONS", perms)):
                for i in items:
                    print(f"    {label:<12} {i}")
        if not args.watch:
            sys.exit(1 if any([added, removed, modified, perms]) else 0)
        time.sleep(args.watch)


if __name__ == "__main__":
    main()
