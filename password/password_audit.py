#!/usr/bin/env python3
"""
Password Audit Tool
-------------------
Scores password strength (length, character variety, entropy, common patterns) and
checks whether the password appears in known breaches using the Have I Been Pwned
"Pwned Passwords" API.

Privacy: HIBP uses k-anonymity. Only the FIRST 5 characters of the password's SHA-1
hash are sent; the match happens locally. The password itself never leaves your machine.

Usage:
    python3 password_audit.py                 # prompts securely (input hidden)
    python3 password_audit.py --offline       # skip the breach check
"""

import argparse
import getpass
import hashlib
import math
import re
import string
import urllib.request

COMMON = {"password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou",
          "monkey", "dragon", "football", "baseball", "abc123", "111111", "sunshine"}
KEYBOARD_RUNS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def pwned_count(password):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix}",
                                 headers={"User-Agent": "kamronw23-password-audit", "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=10) as r:
        for line in r.read().decode().splitlines():
            h, _, count = line.partition(":")
            if h == suffix:
                return int(count)
    return 0


def score(pw):
    issues = []
    pool = sum(n for cls, n in ((string.ascii_lowercase, 26), (string.ascii_uppercase, 26),
                                (string.digits, 10), (string.punctuation, 32))
               if any(c in cls for c in pw))
    entropy = len(pw) * math.log2(pool) if pool else 0

    if len(pw) < 12:
        issues.append(f"Only {len(pw)} characters; aim for 14+ (a passphrase is easiest)")
    if not re.search(r"[A-Z]", pw): issues.append("No uppercase letters")
    if not re.search(r"[a-z]", pw): issues.append("No lowercase letters")
    if not re.search(r"\d", pw): issues.append("No digits")
    if not re.search(r"[^\w\s]", pw): issues.append("No symbols")
    if re.search(r"(.)\1{2,}", pw): issues.append("Repeated characters (e.g. 'aaa')")
    low = pw.lower()
    leet = low.translate(str.maketrans("@4310$!7", "aaeiosit"))
    if any(w in leet for w in COMMON): issues.append("Contains a very common password/word")
    if any(run[i:i + 4] in low for run in KEYBOARD_RUNS for i in range(len(run) - 3)):
        issues.append("Contains a keyboard/number sequence")
    if re.search(r"(19|20)\d{2}", pw): issues.append("Contains what looks like a year")

    penalty = 10 * max(0, len(issues) - 1)
    effective = max(0, entropy - penalty)
    if any(w in leet for w in COMMON):
        effective = min(effective, 30)  # dictionary words get cracked first, whatever the length
    rating = ("VERY WEAK" if effective < 28 else "WEAK" if effective < 40 else
              "MODERATE" if effective < 60 else "STRONG" if effective < 80 else "VERY STRONG")
    return entropy, rating, issues


def main():
    p = argparse.ArgumentParser(description="Audit a password's strength and breach exposure.")
    p.add_argument("--offline", action="store_true", help="don't query Have I Been Pwned")
    args = p.parse_args()

    pw = getpass.getpass("Password to audit (hidden): ")
    if not pw:
        return
    entropy, rating, issues = score(pw)
    print(f"\n[*] Length: {len(pw)}   Estimated entropy: {entropy:.0f} bits   Rating: {rating}")
    for i in issues:
        print(f"    - {i}")

    if not args.offline:
        try:
            n = pwned_count(pw)
            if n:
                print(f"\n[!] Found in {n:,} known breaches. Do NOT use this password anywhere.")
            else:
                print("\n[+] Not found in the Have I Been Pwned breach corpus.")
        except Exception as e:
            print(f"\n[?] Breach check unavailable ({e}). Rerun with --offline to skip it.")


if __name__ == "__main__":
    main()
