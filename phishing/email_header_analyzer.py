#!/usr/bin/env python3
"""
Email Header Analyzer
---------------------
Reads a raw email (.eml) and highlights the things a SOC analyst checks first
when a user reports a phishing email:

  * SPF / DKIM / DMARC results (Authentication-Results header)
  * From vs. Return-Path vs. Reply-To mismatches (spoofing / reply hijacking)
  * The Received hop chain (where the message actually came from)
  * Display-name tricks ("PayPal Support" <random@evil.tld>)
  * Lookalike-domain hints and urgency keywords in the subject

MITRE ATT&CK: T1566 - Phishing (T1566.001 Attachment, T1566.002 Link)

Usage:
    python3 email_header_analyzer.py sample_phish.eml
"""

import argparse
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

URGENCY = ["urgent", "immediately", "suspended", "verify", "password", "invoice",
           "action required", "unusual activity", "locked", "final notice", "payment"]
BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "netflix", "bank",
          "docusign", "google", "outlook", "chase", "wellsfargo"]


def domain_of(addr):
    return parseaddr(addr or "")[1].rpartition("@")[2].lower()


def auth_result(auth_header, mech):
    m = re.search(rf"\b{mech}=(\w+)", auth_header or "", re.I)
    return m.group(1).lower() if m else "none"


def main():
    p = argparse.ArgumentParser(description="Triage a suspicious email's headers.")
    p.add_argument("eml")
    args = p.parse_args()
    try:
        with open(args.eml, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except OSError as e:
        sys.exit(f"[!] {e}")

    findings = []
    frm, rp, rt = msg.get("From", ""), msg.get("Return-Path", ""), msg.get("Reply-To", "")
    subj = msg.get("Subject", "")
    from_dom, rp_dom, rt_dom = domain_of(frm), domain_of(rp), domain_of(rt)
    display = parseaddr(frm)[0]

    print("=" * 60)
    print(f"Subject     : {subj}")
    print(f"From        : {frm}")
    print(f"Return-Path : {rp or '(none)'}")
    print(f"Reply-To    : {rt or '(none)'}")
    print(f"Date        : {msg.get('Date', '')}")
    print(f"Message-ID  : {msg.get('Message-ID', '')}")
    print("=" * 60)

    auth = " ".join(msg.get_all("Authentication-Results", []))
    print("\n[Authentication]")
    for mech in ("spf", "dkim", "dmarc"):
        r = auth_result(auth, mech)
        flag = "OK " if r == "pass" else "BAD"
        print(f"  [{flag}] {mech.upper():<5} = {r}")
        if r != "pass":
            findings.append((3 if mech == "dmarc" else 2, f"{mech.upper()} did not pass ({r})"))

    if rp_dom and rp_dom != from_dom:
        findings.append((2, f"Return-Path domain ({rp_dom}) differs from From domain ({from_dom})"))
    if rt_dom and rt_dom != from_dom:
        findings.append((3, f"Reply-To domain ({rt_dom}) differs from From domain ({from_dom}): replies go elsewhere"))
    for b in BRANDS:
        if b in display.lower() and b not in from_dom:
            findings.append((3, f"Display name mentions '{b}' but sender domain is {from_dom}"))
        if b in from_dom and not re.search(rf"(^|\.){b}\.(com|net|org)$", from_dom):
            findings.append((2, f"Possible lookalike domain: {from_dom} (contains '{b}')"))
    if re.search(r"xn--|[0-9](?=[a-z])|[a-z](?=[0-9])", from_dom):
        findings.append((1, f"Sender domain has punycode or digit substitution: {from_dom}"))
    hits = [w for w in URGENCY if w in subj.lower()]
    if hits:
        findings.append((1, f"Urgency/pressure words in subject: {', '.join(hits)}"))

    print("\n[Received chain] (bottom = origin)")
    hops = msg.get_all("Received", [])
    for i, h in enumerate(reversed(hops), 1):
        h = " ".join(str(h).split())
        ip = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", h)
        print(f"  {i}. {h[:110]}{'...' if len(h) > 110 else ''}")
        if ip and i == 1:
            print(f"     -> Originating IP: {ip.group(1)} (look up in AbuseIPDB / VirusTotal)")

    body = msg.get_body(preferencelist=("html", "plain"))
    if body:
        links = sorted(set(re.findall(r"https?://[^\s\"'<>]+", body.get_content())))
        if links:
            print("\n[Links in body] (do NOT click; check in a sandbox / URLScan)")
            for l in links[:15]:
                print("  " + l.replace("http", "hxxp").replace(".", "[.]"))
    atts = [a.get_filename() for a in msg.iter_attachments() if a.get_filename()]
    if atts:
        print("\n[Attachments]")
        for a in atts:
            risky = re.search(r"\.(exe|js|vbs|scr|iso|img|html?|docm|xlsm|zip|lnk|one)$", a, re.I)
            print(f"  {'[RISKY] ' if risky else ''}{a}")
            if risky:
                findings.append((3, f"Risky attachment type: {a}"))

    score = sum(s for s, _ in findings)
    verdict = "LIKELY PHISHING" if score >= 7 else "SUSPICIOUS" if score >= 3 else "LOW RISK"
    print(f"\n[Findings] risk score {score} -> {verdict}")
    for s, f in sorted(findings, reverse=True):
        print(f"  {'!' * s:<3} {f}")


if __name__ == "__main__":
    main()
