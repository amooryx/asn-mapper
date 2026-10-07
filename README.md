<div align="center">
  <img src="./banner.svg" alt="asn-mapper" width="800">
</div>

# asn-mapper

Small command-line lookups for Autonomous System Numbers (ASNs), announced BGP
prefixes, and IP origin data. Results are provided by the public BGPView API.

> **Authorized use only.** This tool performs read-only lookups against BGPView;
> it does not scan networks or probe returned prefixes.

## Requirements

- Python 3.10 or newer
- Network access to `api.bgpview.io`

No third-party Python packages are required.

## Usage

```text
python asn_mapper.py asn 15169 [--out result.json]
python asn_mapper.py org "Google LLC" [--out results.json]
python asn_mapper.py ip 8.8.8.8 [--out result.json]
```

- `asn` prints organization details and a sample of up to 20 announced prefixes;
  `--out` includes the complete prefix list in JSON.
- `org` searches by organization name; its query is URL-encoded before being
  sent to the provider.
- `ip` accepts IPv4 and IPv6 addresses and reports the origin prefix records.
  `--out` is also available for this command.
- ASN inputs must be in the range 1–4,294,967,295, and IP inputs are validated
  locally before any request is made.

Each invocation makes at most two sequential API requests (the ASN lookup uses
two); each request has a 15-second timeout and response bodies are capped at
10 MiB. The tool does not retry failed requests. API, transport,
invalid-response, and output-file failures are reported to stderr and return a
nonzero exit status rather than being treated as empty successful results.
Search terms and queried IPs are sent to BGPView.

## Development

Run the offline regression tests with:

```text
python -m unittest discover -s tests -v
```

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) |
[@amooryx](https://github.com/amooryx)
