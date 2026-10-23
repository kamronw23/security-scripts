#!/usr/bin/env python3
"""
IOC Extractor
-------------
Pulls Indicators of Compromise out of any text: logs, phishing emails, threat
reports, pasted alerts. Handles "defanged" indicators (hxxp://, example[.]com,
1.2.3[.]4) and can defang output so it's safe to paste into tickets.

Extracts: IPv4 addresses, domains, URLs, email addresses, MD5/SHA1/SHA256 hashes, CVE IDs

Usage:
    python3 ioc_extractor.py sample_phish.eml
    cat alert.txt | python3 ioc_extractor.py -
    python3 ioc_extractor.py report.txt --json --defang
"""

import argparse
import ipaddress
import json
import re
import sys

PATTERNS = {
    "url":    re.compile(r"\bhttps?://[^\s\"'<>()\]]+", re.I),
    "email":  re.compile(r"\b[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),
    "ipv4":   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1":   re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5":    re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "cve":    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
}

# Common file extensions that look like TLDs and would be false-positive "domains".
NOT_TLDS = {"exe", "dll", "txt", "log", "pdf", "doc", "docx", "xls", "xlsx", "zip", "png",
            "jpg", "gif", "py", "ps1", "sh", "js", "html", "htm", "php", "json", "xml", "eml", "bat",
            "from", "mailfrom", "helo"}  # header fields like header.from / smtp.mailfrom


def refang(text):
    return (text.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
                .replace("[dot]", ".").replace("[@]", "@").replace("[:]", ":"))


def defang(ioc):
    return ioc.replace("http", "hxxp").replace(".", "[.]")


def extract(text):
    text = refang(text)
    found = {k: set() for k in PATTERNS}
    for kind, rx in PATTERNS.items():
        for m in rx.findall(text):
            found[kind].add(m.rstrip(".,;:").lower() if kind != "url" else m.rstrip(".,;:"))

    # Validate IPs and tag private ones (internal hosts are context, not threat intel).
    valid_ips = set()
    for ip in found["ipv4"]:
        try:
            valid_ips.add(str(ipaddress.ip_address(ip)))
        except ValueError:
            pass
    found["ipv4"] = valid_ips

    # Drop "domains" that are really IPs, filenames, or parts of emails/URLs already captured.
    email_domains = {e.split("@")[1] for e in found["email"]}
    found["domain"] = {d for d in found["domain"]
                       if d.rsplit(".", 1)[-1] not in NOT_TLDS and not d.replace(".", "").isdigit()}
    found["domain"] |= email_domains
    # Hash patterns overlap: a SHA256 contains 32/40-char substrings only at word boundaries, so just dedupe.
    found["md5"] -= {h for h in found["md5"] if any(h in s for s in found["sha1"] | found["sha256"])}
    return found


def main():
    p = argparse.ArgumentParser(description="Extract IOCs from text.")
    p.add_argument("file", help="input file, or - for stdin")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--defang", action="store_true", help="defang URLs/domains/IPs in output")
    p.add_argument("--public-only", action="store_true", help="hide private/internal IPs")
    args = p.parse_args()

    text = sys.stdin.read() if args.file == "-" else open(args.file, errors="replace").read()
    iocs = extract(text)
    if args.public_only:
        iocs["ipv4"] = {i for i in iocs["ipv4"] if ipaddress.ip_address(i).is_global}

    out = {}
    for kind, items in iocs.items():
        items = sorted(items)
        if args.defang and kind in ("url", "domain", "ipv4", "email"):
            items = [defang(i) for i in items]
        out[kind] = items

    if args.json:
        print(json.dumps(out, indent=2))
        return
    total = sum(len(v) for v in out.values())
    print(f"[*] Extracted {total} unique IOC(s)\n")
    for kind, items in out.items():
        if not items:
            continue
        print(f"== {kind.upper()} ({len(items)}) ==")
        for i in items:
            note = ""
            if kind == "ipv4":
                ip = ipaddress.ip_address(i.replace("[.]", "."))
                note = "" if ip.is_global else "  (internal/reserved)"
            print(f"  {i}{note}")
        print()


if __name__ == "__main__":
    main()
