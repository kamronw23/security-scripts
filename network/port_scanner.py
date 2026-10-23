#!/usr/bin/env python3
"""
Lab Port Scanner
----------------
A small multithreaded TCP connect scanner with banner grabbing, for auditing
hosts YOU OWN or are authorized to test (your home lab, your own VMs). It helps
answer "what services did I accidentally leave exposed?"

!!! Only scan systems you have explicit permission to scan. !!!

Usage:
    python3 port_scanner.py 127.0.0.1
    python3 port_scanner.py 192.168.56.101 -p 1-1024
    python3 port_scanner.py 192.168.56.101 -p 22,80,443,3389 --timeout 1
"""

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
RISKY = {21: "FTP (cleartext)", 23: "Telnet (cleartext)", 135: "MS-RPC", 139: "NetBIOS",
         445: "SMB (ransomware/wormable target)", 3389: "RDP (brute-force target)",
         5900: "VNC", 6379: "Redis (often unauthenticated)", 9200: "Elasticsearch (often unauthenticated)",
         27017: "MongoDB (often unauthenticated)"}


def parse_ports(spec):
    if not spec:
        return TOP_PORTS
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = map(int, part.split("-"))
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def probe(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                if port in (80, 8080, 8443):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(128).decode(errors="replace").strip().splitlines()[0]
            except (socket.timeout, OSError, IndexError):
                banner = ""
            return port, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def main():
    p = argparse.ArgumentParser(description="TCP connect scanner for your own lab hosts.")
    p.add_argument("host")
    p.add_argument("-p", "--ports", help="e.g. 1-1024 or 22,80,443 (default: common ports)")
    p.add_argument("--timeout", type=float, default=0.5)
    p.add_argument("--threads", type=int, default=100)
    args = p.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        sys.exit(f"[!] Can't resolve {args.host}")
    if ipaddress.ip_address(ip).is_global:
        print(f"[!] {ip} is a public address. Make sure you're authorized to scan it.")
        if input("    Type 'yes' to continue: ").strip().lower() != "yes":
            sys.exit(0)

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.host} ({ip}): {len(ports)} port(s), started {datetime.now():%H:%M:%S}\n")
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        results = [r for r in ex.map(lambda pt: probe(ip, pt, args.timeout), ports) if r]

    if not results:
        print("[+] No open ports found.")
    for port, banner in sorted(results):
        try:
            svc = socket.getservbyport(port)
        except OSError:
            svc = "?"
        warn = f"  <-- review: {RISKY[port]}" if port in RISKY else ""
        print(f"  {port:>5}/tcp open  {svc:<12} {banner[:50]}{warn}")
    print(f"\n[*] Done: {len(results)} open port(s).")


if __name__ == "__main__":
    main()
