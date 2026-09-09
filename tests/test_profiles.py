#!/usr/bin/env python3

import json
import unittest
from pathlib import Path

from scripts.compile_profile import compatibility

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "rules" / "http-attacks.json").read_text(encoding="utf-8"))
CF_PROFILE = json.loads((ROOT / "profiles" / "cloudflare-log-explorer.json").read_text(encoding="utf-8"))


class ProfileTests(unittest.TestCase):
    def test_cloudflare_set_is_preserved(self):
        selected = [rule for rule in CATALOG["rules"] if compatibility(rule, CF_PROFILE)[0]]
        self.assertEqual(len(selected), 43)

    def test_body_rule_is_excluded_with_reason(self):
        rule = next(rule for rule in CATALOG["rules"] if rule["id"] == "http.sqli.request-body")
        compatible, reason = compatibility(rule, CF_PROFILE)
        self.assertFalse(compatible)
        self.assertIn("requestbody", reason["missing_fields"])
        self.assertIn("request_body", reason["missing_capabilities"])

    def test_uri_rule_remains_enabled(self):
        rule = next(rule for rule in CATALOG["rules"] if rule["id"] == "http.sqli.generic")
        self.assertTrue(compatibility(rule, CF_PROFILE)[0])


if __name__ == "__main__":
    unittest.main()
