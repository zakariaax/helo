"""Unit tests for name parsing, RDAP/DNS classification, and the local server."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

import checker
import server


class ParseTests(unittest.TestCase):
    def test_plain_label_and_noise(self) -> None:
        outcome = checker.parse_input("  MyApp  \n\n# comment\nbrandname\n", "COM\n net ")
        self.assertIsNone(outcome.error)
        self.assertEqual([name.ascii for name in outcome.names], ["myapp", "brandname"])
        self.assertEqual([tld.ascii for tld in outcome.tlds], ["com", "net"])

    def test_full_domain_url_email_and_uk_suffix(self) -> None:
        text = "\n".join(
            [
                "HTTPS://WWW.Example.COM/path?q=1",
                "hello@brand.co.uk",
                "www.shop.com.au",
                "myapp.io.",
            ]
        )
        outcome = checker.parse_input(text, "com, io")
        self.assertEqual([name.ascii for name in outcome.names], ["example", "brand", "shop", "myapp"])
        self.assertEqual([tld.ascii for tld in outcome.tlds], ["com", "io"])

    def test_idn_and_punycode_share_a_label(self) -> None:
        books = "bücher"
        outcome = checker.parse_input(books + "\n" + "xn--bcher-kva.com", "com")
        self.assertEqual(len(outcome.names), 1)
        self.assertEqual(outcome.names[0].ascii, "xn--bcher-kva")
        self.assertEqual(outcome.names[0].display, books)
        self.assertEqual(outcome.duplicate_count, 1)

    def test_bad_tokens_are_skipped_not_available(self) -> None:
        outcome = checker.parse_input("good\nmy_app\nco.uk\n...\n", "com\nnot a tld\nio")
        self.assertEqual([name.ascii for name in outcome.names], ["good"])
        self.assertTrue(outcome.skipped)
        self.assertIsNone(outcome.error)

    def test_spaces_split_into_labels(self) -> None:
        outcome = checker.parse_input("alpha beta", "org")
        self.assertEqual([name.ascii for name in outcome.names], ["alpha", "beta"])

    def test_limits(self) -> None:
        too_many = "\n".join(f"name{i}" for i in range(checker.MAX_NAMES + 1))
        outcome = checker.parse_input(too_many, "com")
        self.assertIn(str(checker.MAX_NAMES), outcome.error or "")
        too_many_tlds = " ".join(f"t{i}" for i in range(checker.MAX_TLDS + 1))
        outcome = checker.parse_input("brand", too_many_tlds)
        self.assertIn(str(checker.MAX_TLDS), outcome.error or "")


class ClassifyTests(unittest.TestCase):
    def setUp(self) -> None:
        checker.clear_memory_cache()

    def test_rdap_answers(self) -> None:
        registered = checker.classify_rdap(
            200,
            b'{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["client transfer prohibited"]}',
        )
        self.assertEqual(registered["status"], "registered")
        self.assertEqual(registered["confidence"], "high")
        self.assertIn("client transfer prohibited", registered["detail"])
        available = checker.classify_rdap(404, b'{"errorCode":404,"title":"Not Found"}')
        self.assertEqual(available["status"], "available")
        empty = checker.classify_rdap(404, b"")
        self.assertEqual(empty["status"], "available")
        wrapped = checker.classify_rdap(200, b'{"errorCode":404}')
        self.assertEqual(wrapped["status"], "available")
        self.assertIsNone(checker.classify_rdap(429, b""))
        self.assertIsNone(checker.classify_rdap(200, b'{"errorCode":500}'))

    def test_dns_answers(self) -> None:
        nxdomain = checker.classify_dns({"Status": 3}, [])
        self.assertEqual(nxdomain["status"], "available")
        self.assertEqual(nxdomain["confidence"], "low")
        taken = checker.classify_dns({"Status": 0, "Answer": [{"type": 2, "data": "ns1.example.net"}]}, [])
        self.assertEqual(taken["status"], "registered")
        self.assertEqual(taken["confidence"], "medium")
        nodata = checker.classify_dns({"Status": 0, "Authority": [{"type": 6}]}, [{"Status": 0}, {"Status": 0}])
        self.assertEqual(nodata["status"], "unknown")
        failed = checker.classify_dns({"Status": "2"}, [])
        self.assertEqual(failed["status"], "unknown")
        self.assertEqual(checker.classify_dns(None, [None])["status"], "doh-failed")

    def test_rdap_url_and_longest_suffix(self) -> None:
        self.assertEqual(
            checker.rdap_domain_url("https://rdap.example/com/v1/", "Example.COM"),
            "https://rdap.example/com/v1/domain/example.com",
        )
        boot = checker.Bootstrap(
            {"uk": ["https://uk.example/"], "co.uk": ["https://couk.example/"]},
            None,
            None,
            0,
        )
        self.assertEqual(checker.urls_for_domain("brand.co.uk", boot), ["https://couk.example/"])
        self.assertEqual(checker.urls_for_domain("brand.uk", boot), ["https://uk.example/"])
        self.assertEqual(checker.urls_for_domain("brand.io", boot), [])

    def test_rdap_hit_and_dns_fallback_and_failed_rdap(self) -> None:
        boot = checker.Bootstrap({"com": ["https://rdap.example/com/v1/"]}, None, None, 0)
        body = b'{"objectClassName":"domain","ldhName":"EXAMPLE.COM"}'
        with mock.patch.object(checker, "http_get", return_value=(200, body, None)):
            result = checker.check_pair("example", "example", checker.ParsedName("com", "com"), boot, fresh=True)
        self.assertEqual(result["status"], "registered")
        self.assertEqual(result["method"], "rdap")

        def dns_get(url, accept, timeout, retries):
            self.assertNotIn("rdap.example", url)
            return 200, b'{"Status":3}', None

        with mock.patch.object(checker, "http_get", side_effect=dns_get):
            result = checker.check_pair("missing", "missing", checker.ParsedName("io", "io"), boot, fresh=True)
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["method"], "dns")
        self.assertIn("No public RDAP", result["detail"])

        calls = []

        def rdap_down(url, accept, timeout, retries):
            calls.append(url)
            return None, b"", "TimeoutError"

        with mock.patch.object(checker, "http_get", side_effect=rdap_down):
            result = checker.check_pair("example", "example", checker.ParsedName("com", "com"), boot, fresh=True)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["method"], "rdap")
        self.assertTrue(calls)
        self.assertTrue(all("dns" not in url for url in calls))


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.httpd = server.make_server("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.boot = checker.Bootstrap(
            {"com": ["https://rdap.example/com/v1/"]},
            "2026-01-01T00:00:00Z",
            None,
            0,
        )

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def _request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, str]:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()

    def test_index_and_defaults(self) -> None:
        status, body = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Bulk TLD checker", body)
        self.assertIn('id="check"', body)
        status, body = self._request("GET", "/api/defaults")
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIn("com", data["text"])
        self.assertEqual(data["maxNames"], checker.MAX_NAMES)

    def test_parse_and_check_stream(self) -> None:
        with mock.patch.object(checker, "get_bootstrap", return_value=self.boot):
            status, body = self._request(
                "POST",
                "/api/parse",
                {"names": "HTTPS://Example.COM\nbad_name", "tlds": "COM\nio"},
            )
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["names"][0]["ascii"], "example")
        self.assertEqual(data["coverage"]["rdap"], ["com"])
        self.assertEqual(data["coverage"]["dns"], ["io"])
        self.assertEqual(data["skippedCount"], 1)

        def fake_check(ascii_name, display, tld, boot, fresh=False):
            return {
                "type": "result",
                "name": ascii_name,
                "display": display,
                "tld": tld.ascii,
                "tldDisplay": tld.display,
                "fqdn": f"{ascii_name}.{tld.ascii}",
                "status": "unknown" if tld.ascii == "io" else "registered",
                "method": "dns" if tld.ascii == "io" else "rdap",
                "confidence": "low" if tld.ascii == "io" else "high",
                "detail": "test",
                "cached": False,
            }

        with mock.patch.object(checker, "get_bootstrap", return_value=self.boot), mock.patch.object(
            checker, "check_pair", side_effect=fake_check
        ):
            status, body = self._request(
                "POST",
                "/api/check",
                {"checks": [{"name": "example", "tld": "com"}, {"name": "example", "tld": "io"}]},
            )
        self.assertEqual(status, 200)
        self.assertIn('"method": "rdap"', body)
        self.assertIn('"method": "dns"', body)
        self.assertIn('"type": "done"', body)

    def test_rejects_a_domain_in_the_check_list(self) -> None:
        with mock.patch.object(checker, "get_bootstrap", return_value=self.boot):
            request = urllib.request.Request(
                self.base + "/api/check",
                data=json.dumps({"checks": [{"name": "example.com", "tld": "com"}]}).encode(),
                method="POST",
            )
            request.add_header("Content-Type", "application/json")
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
