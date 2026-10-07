#!/usr/bin/env python3
"""
Look up ASN, BGP prefix, and IP-origin information using the BGPView API.
Authorized use only.
"""

import argparse
import ipaddress
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BGPVIEW_API = "https://api.bgpview.io"
REQUEST_TIMEOUT = 15
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_ASN = 4_294_967_295
MAX_QUERY_LENGTH = 200


class BGPViewError(RuntimeError):
    """Raised when BGPView cannot provide a valid response."""


def parse_asn(value: str) -> int:
    try:
        asn = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("ASN must be a whole number") from exc
    if not 1 <= asn <= MAX_ASN:
        raise argparse.ArgumentTypeError(f"ASN must be between 1 and {MAX_ASN}")
    return asn


def parse_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP address: {value}") from exc


def parse_query(value: str) -> str:
    query = value.strip()
    if not query:
        raise argparse.ArgumentTypeError("organization query cannot be empty")
    if len(query) > MAX_QUERY_LENGTH:
        raise argparse.ArgumentTypeError(
            f"organization query must be no longer than {MAX_QUERY_LENGTH} characters"
        )
    return query


def _get_data(path: str, params: dict[str, str] | None = None) -> dict:
    url = f"{BGPVIEW_API}{path}"
    if params:
        url = f"{url}?{urlencode(params)}"
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "asn-mapper/1.0"})
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise BGPViewError(f"BGPView returned HTTP {exc.code} for {path}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise BGPViewError(f"Could not reach BGPView for {path}: {exc}") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise BGPViewError(f"BGPView response for {path} exceeds the 10 MiB limit")

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BGPViewError(f"BGPView returned invalid JSON for {path}") from exc
    if not isinstance(payload, dict):
        raise BGPViewError(f"BGPView returned an unexpected response for {path}")
    status = payload.get("status")
    if status != "ok":
        message = payload.get("status_message") or "unspecified API error"
        raise BGPViewError(f"BGPView rejected {path}: {message}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise BGPViewError(f"BGPView response for {path} has no valid data object")
    return data


def _expect_list(data: dict, key: str, path: str) -> list:
    value = data.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise BGPViewError(f"BGPView response for {path} has no valid {key} records")
    return value


def get_asn_details(asn: int) -> dict:
    return _get_data(f"/asn/{asn}")


def get_asn_prefixes(asn: int) -> list[dict]:
    path = f"/asn/{asn}/prefixes"
    data = _get_data(path)
    return _expect_list(data, "ipv4_prefixes", path) + _expect_list(data, "ipv6_prefixes", path)


def get_asn_peers(asn: int) -> dict:
    return _get_data(f"/asn/{asn}/peers")


def search_by_org(query: str) -> list[dict]:
    path = "/search"
    data = _get_data(path, {"query_term": query})
    return _expect_list(data, "asns", path)


def ip_to_asn(ip: str) -> dict:
    return _get_data(f"/ip/{ip}")


def _write_json(path: str, result: object) -> None:
    with open(path, "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2, ensure_ascii=False)
        output.write("\n")


def _add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out", help="Write the complete result to a JSON file")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Look up ASN and BGP prefix information via BGPView (authorized use only).",
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    asn_parser = subparsers.add_parser("asn", help="Look up an ASN and its announced prefixes")
    asn_parser.add_argument("asn", type=parse_asn, help="ASN number (e.g., 15169)")
    _add_output_argument(asn_parser)

    org_parser = subparsers.add_parser("org", help="Search ASNs by organization name")
    org_parser.add_argument("query", type=parse_query, help="Organization name or keyword")
    _add_output_argument(org_parser)

    ip_parser = subparsers.add_parser("ip", help="Find the origin ASN for an IP address")
    ip_parser.add_argument("ip", type=parse_ip, help="IPv4 or IPv6 address")
    _add_output_argument(ip_parser)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "asn":
            print(f"[*] Looking up AS{args.asn} ...")
            details = get_asn_details(args.asn)
            prefixes = get_asn_prefixes(args.asn)
            print(f"  [+] AS{args.asn}: {details.get('name', 'Unknown')} ({details.get('description_short', '')})")
            print(f"  [+] Country: {details.get('country_code', 'Unknown')}")
            print(f"  [+] {len(prefixes)} IP prefixes announced")
            for prefix in prefixes[:20]:
                print(f"      {prefix.get('prefix', ''):20s}  {prefix.get('name', '')}")
            result = {"asn": args.asn, "details": details, "prefixes": prefixes}
        elif args.cmd == "org":
            print(f"[*] Searching ASNs for {args.query!r} ...")
            asns = search_by_org(args.query)
            print(f"  [+] {len(asns)} results")
            for result_item in asns:
                print(
                    f"    AS{result_item.get('asn')}: {result_item.get('name')} "
                    f"({result_item.get('country_code')}) — {result_item.get('description')}"
                )
            result = asns
        else:
            print(f"[*] IP-to-ASN lookup: {args.ip}")
            data = ip_to_asn(args.ip)
            prefixes = _expect_list(data, "prefixes", f"/ip/{args.ip}")
            for prefix in prefixes:
                asn = prefix.get("asn", {})
                if not isinstance(asn, dict):
                    raise BGPViewError(f"BGPView response for /ip/{args.ip} has an invalid ASN record")
                print(
                    f"  Prefix: {prefix.get('prefix')}  AS{asn.get('asn')}: "
                    f"{asn.get('name')} ({asn.get('country_code')})"
                )
            if not prefixes:
                print("  [!] BGPView returned no origin prefixes for this address.")
            result = {"ip": args.ip, "data": data}

        if args.out:
            _write_json(args.out, result)
            print(f"[*] Results saved to {args.out}")
        return 0
    except BGPViewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not write output: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
