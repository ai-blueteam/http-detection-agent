"""Behavior and capability boundaries for the expanded multi-source catalog."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.compile_profile import compatibility
from scripts.evaluate_catalog import evaluate, transform

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "rules/http-attacks.json").read_text(encoding="utf-8"))
CASES = json.loads((ROOT / "tests/fixtures/http-superset-expansion.json").read_text(encoding="utf-8"))["rules"]
RULES = {r["id"]: r for r in CATALOG["rules"]}
FULL = json.loads((ROOT / "profiles/multisource-full-http.json").read_text(encoding="utf-8"))
CF = json.loads((ROOT / "profiles/cloudflare-log-explorer.json").read_text(encoding="utf-8"))


class SupersetTests(unittest.TestCase):
    def test_path_extraction_tolerates_hostile_authority(self):
        self.assertEqual(transform("http://[invalid/login?q=x", ["path_only"]), "/login")
        self.assertEqual(transform("//[invalid/api/login", ["path_only"]), "/api/login")
        self.assertEqual(transform("/not-login?q=/login", ["path_only"]), "/not-login")
        self.assertEqual(transform("/lo\tgin", ["path_only"]), "/lo\tgin")

    def test_positive_negative_and_missing_event_values(self):
        for case in CASES:
            rule = RULES[case["rule_id"]]
            isolated = {"rules": [rule]}
            for expected, events in [(True, case["positive"]), (False, case["negative"])]:
                for event in events:
                    with self.subTest(rule=rule["id"], event=event):
                        self.assertEqual(bool(evaluate(isolated, event)), expected)
            for event in [{}, {f: None for f in rule["required_fields"]}]:
                with self.subTest(rule=rule["id"], missing=True):
                    self.assertEqual(evaluate(isolated, event), [])

    def test_every_candidate_has_fixtures_and_real_requirements(self):
        self.assertEqual(len(CASES), len({c["rule_id"] for c in CASES}))
        for case in CASES:
            rule = RULES[case["rule_id"]]
            self.assertGreaterEqual(len(case["positive"]), 2)
            self.assertGreaterEqual(len(case["negative"]), 2)
            self.assertEqual(rule["status"], "test")
            self.assertFalse(compatibility(rule, CF)[0], rule["id"])
            self.assertTrue(compatibility(rule, FULL)[0], rule["id"])
            for cap in rule["requirements"]["capabilities"]:
                partial = {**FULL, "capabilities": [c for c in FULL["capabilities"] if c != cap]}
                self.assertFalse(compatibility(rule, partial)[0], (rule["id"], cap))
            for field in rule["requirements"]["all_fields"]:
                partial = {**FULL, "fields": [f for f in FULL["fields"] if f != field]}
                self.assertFalse(compatibility(rule, partial)[0], (rule["id"], field))

    def test_cloudflare_rule_contents_match_preserved_baseline(self):
        selected = [r for r in CATALOG["rules"] if compatibility(r, CF)[0]]
        lock = json.loads((ROOT / "rulesets/cloudflare-baseline.lock.json").read_text(encoding="utf-8"))
        serialized = json.dumps(selected, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        self.assertEqual(len(selected), lock["rule_count"])
        self.assertEqual(hashlib.sha256(serialized.encode()).hexdigest(), lock["rules_sha256"])
        saved = json.loads((ROOT / "rulesets/cloudflare-http-requests.json").read_text(encoding="utf-8"))
        self.assertEqual(selected, saved["rules"])

    def test_graphql_alternative_metric_and_projection(self):
        rule = RULES["http.api.graphql-complexity"]
        for field in ["graphqlmaxdepth", "graphqlaliascount"]:
            profile = {"fields": [field], "capabilities": ["graphql_ast"]}
            self.assertTrue(compatibility(rule, profile)[0])
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "profile.json"
                path.write_text(json.dumps(profile))
                run = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/required_fields.py"), "--profile", str(path)],
                    check=True, capture_output=True, text=True, encoding="utf-8",
                )
                self.assertEqual(run.stdout.strip(), field)
        ok, reason = compatibility(rule, {"fields": [], "capabilities": ["graphql_ast"]})
        self.assertFalse(ok)
        self.assertEqual(reason["missing_any_field_groups"], [["graphqlmaxdepth", "graphqlaliascount"]])

    def test_compiled_sets_and_generated_reports_are_current(self):
        for profile_name, set_name in [
            ("cloudflare-log-explorer", "cloudflare-http-requests"),
            ("multisource-full-http", "multisource-http"),
        ]:
            profile = json.loads((ROOT / f"profiles/{profile_name}.json").read_text(encoding="utf-8"))
            selected = [r for r in CATALOG["rules"] if compatibility(r, profile)[0]]
            saved = json.loads((ROOT / f"rulesets/{set_name}.json").read_text(encoding="utf-8"))
            # Reports are local outputs, not release fixtures. Exercise the real
            # compiler in a temporary directory so a fresh checkout is sufficient.
            with tempfile.TemporaryDirectory() as temp:
                compiled_path = Path(temp) / "compiled.json"
                report_path = Path(temp) / "report.json"
                subprocess.run(
                    [sys.executable, str(ROOT / "scripts/compile_profile.py"),
                     str(ROOT / f"profiles/{profile_name}.json"),
                     "--write", str(compiled_path), "--report", str(report_path)],
                    check=True, capture_output=True, text=True, encoding="utf-8",
                )
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(json.loads(compiled_path.read_text(encoding="utf-8")), saved)
            self.assertEqual(saved["rules"], selected)
            self.assertEqual(report["selected_rule_ids"], [r["id"] for r in selected])
            self.assertEqual(report["excluded_count"], len(CATALOG["rules"]) - len(selected))
            for reason in report["excluded"]:
                self.assertEqual(
                    {k: v for k, v in reason.items() if k != "id"},
                    compatibility(RULES[reason["id"]], profile)[1],
                )


if __name__ == "__main__":
    unittest.main()
