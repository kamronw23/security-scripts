#!/usr/bin/env python3
"""
SSH Brute-Force Detector
------------------------
Parses a Linux auth log (e.g. /var/log/auth.log or /var/log/secure) and flags
source IPs with repeated failed SSH logins, the classic sign of a brute-force
or password-spraying attempt.

MITRE ATT&CK: T1110 - Brute Force (T1110.001 Password Guessing, T1110.003 Password Spraying)

Usage:
    python3 ssh_bruteforce_detector.py sample_auth.log
    python3 ssh_bruteforce_detector.py /var/log/auth.log --threshold 10
    python3 ssh_bruteforce_detector.py sample_auth.log --csv report.csv
"""

import argparse
import csv
import re
import sys
from collections import defaultdict

FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: "
    r"(?:Failed \S+ for (?:invalid user )?|Invalid user )(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze(lines):
    stats = defaultdict(lambda: {"failures": 0, "users": set(), "first": None,
                                 "last": None, "success_after": []})
    for line in lines:
        m = FAILED_RE.search(line)
        if m:
            s = stats[m["ip"]]
            s["failures"] += 1
            if m["user"]:
                s["users"].add(m["user"])
            s["first"] = s["first"] or m["ts"]
            s["last"] = m["ts"]
            continue
        m = ACCEPTED_RE.search(line)
        if m and m["ip"] in stats and stats[m["ip"]]["failures"]:
            # A success after failures from the same IP may mean the attack worked.
            stats[m["ip"]]["success_after"].append(f'{m["user"]} @ {m["ts"]}')
    return stats


def main():
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs.")
    p.add_argument("logfile")
    p.add_argument("-t", "--threshold", type=int, default=5,
                   help="failed attempts before an IP is flagged (default: 5)")
    p.add_argument("--csv", help="write flagged IPs to a CSV file")
    args = p.parse_args()

    try:
        with open(args.logfile, errors="replace") as f:
            stats = analyze(f)
    except OSError as e:
        sys.exit(f"[!] Could not read {args.logfile}: {e}")

    flagged = sorted(((ip, s) for ip, s in stats.items() if s["failures"] >= args.threshold),
                     key=lambda x: (bool(x[1]["success_after"]), x[1]["failures"]), reverse=True)

    print(f"[*] Analyzed {args.logfile}: {len(stats)} IP(s) with failed logins, "
          f"{len(flagged)} at or above threshold {args.threshold}\n")
    for ip, s in flagged:
        sev = "CRITICAL" if s["success_after"] else ("HIGH" if s["failures"] >= args.threshold * 4 else "MEDIUM")
        print(f"[{sev}] {ip}: {s['failures']} failures, {len(s['users'])} usernames tried "
              f"({s['first']} -> {s['last']})")
        print(f"         users: {', '.join(sorted(s['users'])[:10])}")
        for hit in s["success_after"]:
            print(f"         !!! SUCCESSFUL LOGIN after failures: {hit}  -> investigate now")
    if not flagged:
        print("[+] No IPs exceeded the threshold.")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "failures", "unique_users", "first_seen", "last_seen", "success_after_failures"])
            for ip, s in flagged:
                w.writerow([ip, s["failures"], len(s["users"]), s["first"], s["last"], "; ".join(s["success_after"])])
        print(f"\n[*] CSV report written to {args.csv}")


if __name__ == "__main__":
    main()
