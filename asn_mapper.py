#!/usr/bin/env python3
"""
ASN Mapper — Autonomous System Number Reconnaissance Tool
Maps company infrastructure from ASN: CIDR ranges, IP blocks, BGP prefixes.
Author: Omar Khalid (amooryx) | github.com/amooryx/asn-mapper
AUTHORIZED USE ONLY.
"""

import argparse
import json
import re
import socket
import sys
import urllib.request

BGPVIEW_API = "https://api.bgpview.io"

def get_asn_details(asn: int) -> dict:
    url = f"{BGPVIEW_API}/asn/{asn}"
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read()).get("data", {})

def get_asn_prefixes(asn: int) -> list[dict]:
    url = f"{BGPVIEW_API}/asn/{asn}/prefixes"
    with urllib.request.urlopen(url, timeout=15) as resp:
        data = json.loads(resp.read())
        return data.get("data", {}).get("ipv4_prefixes", []) + \
               data.get("data", {}).get("ipv6_prefixes", [])

def get_asn_peers(asn: int) -> dict:
    url = f"{BGPVIEW_API}/asn/{asn}/peers"
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read()).get("data", {})

def search_by_org(query: str) -> list[dict]:
    url = f"{BGPVIEW_API}/search?query_term={urllib.request.quote(query)}"
    with urllib.request.urlopen(url, timeout=15) as resp:
        data = json.loads(resp.read()).get("data", {})
        return data.get("asns", [])

def ip_to_asn(ip: str) -> dict:
    url = f"{BGPVIEW_API}/ip/{ip}"
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read()).get("data", {})

def main():
    parser = argparse.ArgumentParser(
        description="ASN Mapper — Infrastructure OSINT via ASN (Authorized use only)",
    )
    subparsers = parser.add_subparsers(dest="cmd")

    asn_p = subparsers.add_parser("asn",    help="Look up an ASN")
    asn_p.add_argument("asn",    type=int,  help="ASN number (e.g., 15169)")
    asn_p.add_argument("--out",  help="Output JSON file")

    org_p = subparsers.add_parser("org",    help="Search ASNs by org name")
    org_p.add_argument("query",  help="Org name or keyword")
    org_p.add_argument("--out",  help="Output JSON file")

    ip_p = subparsers.add_parser("ip",     help="Find ASN for an IP")
    ip_p.add_argument("ip",      help="IP address")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    if args.cmd == "asn":
        print(f"[*] Looking up ASN{args.asn} ...")
        details  = get_asn_details(args.asn)
        prefixes = get_asn_prefixes(args.asn)
        name = details.get("name", "Unknown")
        desc = details.get("description_short", "")
        print(f"  [+] ASN{args.asn}: {name} ({desc})")
        print(f"  [+] Country: {details.get('country_code')}")
        print(f"  [+] {len(prefixes)} IP prefixes announced")
        for p in prefixes[:20]:
            print(f"      {p.get('prefix',''):20s}  {p.get('name','')}")
        result = {"asn": args.asn, "details": details, "prefixes": prefixes}
        if args.out:
            with open(args.out, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[*] Results → {args.out}")

    elif args.cmd == "org":
        print(f"[*] Searching ASNs for '{args.query}' ...")
        asns = search_by_org(args.query)
        print(f"  [+] {len(asns)} results")
        for a in asns:
            print(f"    ASN{a.get('asn')}: {a.get('name')} ({a.get('country_code')}) — {a.get('description')}")
        if hasattr(args, "out") and args.out:
            with open(args.out, "w") as f:
                json.dump(asns, f, indent=2)

    elif args.cmd == "ip":
        print(f"[*] IP-to-ASN lookup: {args.ip}")
        data = ip_to_asn(args.ip)
        prefixes = data.get("prefixes", [])
        for p in prefixes:
            asn = p.get("asn", {})
            print(f"  Prefix: {p.get('prefix')}  ASN{asn.get('asn')}: {asn.get('name')} ({asn.get('country_code')})")

if __name__ == "__main__":
    main()
