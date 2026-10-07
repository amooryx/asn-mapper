import io
import json
import tempfile
import unittest
from argparse import ArgumentTypeError
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import asn_mapper


def api_response(payload):
    return io.BytesIO(json.dumps(payload).encode("utf-8"))


class InputValidationTests(unittest.TestCase):
    def test_asn_range(self):
        self.assertEqual(asn_mapper.parse_asn("1"), 1)
        self.assertEqual(asn_mapper.parse_asn(str(asn_mapper.MAX_ASN)), asn_mapper.MAX_ASN)
        for value in ("0", "-1", str(asn_mapper.MAX_ASN + 1), "abc"):
            with self.subTest(value=value), self.assertRaises(ArgumentTypeError):
                asn_mapper.parse_asn(value)

    def test_ip_validation_and_canonicalization(self):
        self.assertEqual(asn_mapper.parse_ip("2001:0db8::1"), "2001:db8::1")
        self.assertEqual(asn_mapper.parse_ip("192.0.2.1"), "192.0.2.1")
        with self.assertRaises(ArgumentTypeError):
            asn_mapper.parse_ip("not-an-ip")

    def test_organization_query_is_trimmed_and_bounded(self):
        self.assertEqual(asn_mapper.parse_query(" ACME "), "ACME")
        with self.assertRaises(ArgumentTypeError):
            asn_mapper.parse_query("   ")
        with self.assertRaises(ArgumentTypeError):
            asn_mapper.parse_query("x" * (asn_mapper.MAX_QUERY_LENGTH + 1))


class BGPViewTests(unittest.TestCase):
    @patch("asn_mapper.urlopen")
    def test_search_encodes_query_and_applies_timeout(self, urlopen):
        urlopen.return_value = api_response({"status": "ok", "data": {"asns": [{"asn": 64500}]}})

        results = asn_mapper.search_by_org("ACME & Sons")

        self.assertEqual(results, [{"asn": 64500}])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.bgpview.io/search?query_term=ACME+%26+Sons")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], asn_mapper.REQUEST_TIMEOUT)

    @patch("asn_mapper.urlopen")
    def test_prefixes_combine_ipv4_and_ipv6(self, urlopen):
        urlopen.return_value = api_response(
            {
                "status": "ok",
                "data": {
                    "ipv4_prefixes": [{"prefix": "192.0.2.0/24"}],
                    "ipv6_prefixes": [{"prefix": "2001:db8::/32"}],
                },
            }
        )

        self.assertEqual(
            asn_mapper.get_asn_prefixes(64500),
            [{"prefix": "192.0.2.0/24"}, {"prefix": "2001:db8::/32"}],
        )

    @patch("asn_mapper.urlopen")
    def test_http_failure_is_actionable(self, urlopen):
        urlopen.side_effect = HTTPError("https://api.bgpview.io/asn/64500", 503, "Unavailable", {}, None)

        with self.assertRaisesRegex(asn_mapper.BGPViewError, "HTTP 503"):
            asn_mapper.get_asn_details(64500)

    @patch("asn_mapper.urlopen", side_effect=URLError("offline"))
    def test_transport_failure_is_actionable(self, urlopen):
        with self.assertRaisesRegex(asn_mapper.BGPViewError, "Could not reach BGPView"):
            asn_mapper.get_asn_details(64500)

    @patch("asn_mapper.MAX_RESPONSE_BYTES", 1)
    @patch("asn_mapper.urlopen")
    def test_oversized_response_is_rejected(self, urlopen):
        urlopen.return_value = io.BytesIO(b"{}")

        with self.assertRaisesRegex(asn_mapper.BGPViewError, "exceeds the 10 MiB limit"):
            asn_mapper.get_asn_details(64500)

    @patch("asn_mapper.urlopen")
    def test_bad_json_and_api_error_are_explicit(self, urlopen):
        urlopen.return_value = io.BytesIO(b"{")
        with self.assertRaisesRegex(asn_mapper.BGPViewError, "invalid JSON"):
            asn_mapper.get_asn_details(64500)

        urlopen.return_value = api_response(
            {"status": "error", "status_message": "Not found", "data": {}}
        )
        with self.assertRaisesRegex(asn_mapper.BGPViewError, "Not found"):
            asn_mapper.get_asn_details(64500)

    @patch("asn_mapper.urlopen")
    def test_unexpected_response_shape_is_explicit(self, urlopen):
        urlopen.return_value = api_response({"status": "ok", "data": {"asns": None}})

        with self.assertRaisesRegex(asn_mapper.BGPViewError, "valid asns records"):
            asn_mapper.search_by_org("ACME")


class CommandLineTests(unittest.TestCase):
    def test_invalid_target_is_rejected_before_network_access(self):
        with patch("asn_mapper.urlopen") as urlopen:
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit_info:
                asn_mapper.main(["asn", "0"])
            self.assertEqual(exit_info.exception.code, 2)
            urlopen.assert_not_called()

    @patch("asn_mapper.ip_to_asn", return_value={"prefixes": []})
    def test_ip_command_writes_json_and_reports_empty_origin(self, lookup):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "result.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = asn_mapper.main(["ip", "2001:0db8::1", "--out", str(output_path)])

            self.assertEqual(result, 0)
            self.assertIn("no origin prefixes", stdout.getvalue())
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8")),
                {"ip": "2001:db8::1", "data": {"prefixes": []}},
            )
            lookup.assert_called_once_with("2001:db8::1")

    @patch("asn_mapper.get_asn_details", side_effect=asn_mapper.BGPViewError("provider unavailable"))
    def test_provider_failure_has_clean_cli_error(self, lookup):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = asn_mapper.main(["asn", "64500"])

        self.assertEqual(result, 2)
        self.assertIn("error: provider unavailable", stderr.getvalue())
        lookup.assert_called_once_with(64500)


if __name__ == "__main__":
    unittest.main()
