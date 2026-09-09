"""Standalone validation and upstream-license packaging regression checks."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_portable_skill_copies_do_not_drift(self):
        for name in ["http-detection-scan", "http-detection-rules"]:
            codex = ROOT / ".agents/skills" / name / "SKILL.md"
            claude = ROOT / ".claude/skills" / name / "SKILL.md"
            self.assertEqual(codex.read_bytes(), claude.read_bytes())

    def test_validator_runs_outside_checkout_without_external_schema(self):
        from scripts import validate_catalog

        self.assertEqual(validate_catalog.CF_PROFILE.parent, ROOT / "profiles")
        with tempfile.TemporaryDirectory() as temp:
            run = subprocess.run(
                [sys.executable, str(ROOT / "scripts/validate_catalog.py")],
                cwd=temp, capture_output=True, text=True, encoding="utf-8",
            )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_all_catalog_source_license_texts_are_packaged(self):
        licenses = {
            "Apache-2.0": "Apache-2.0.txt",
            "DRL-1.1": "DRL-1.1.md",
            "Elastic-2.0": "Elastic-2.0.txt",
            "CC-BY-SA-4.0": "CC-BY-SA-4.0.md",
        }
        for directory in ["rules", "rulesets"]:
            for catalog_path in (ROOT / directory).glob("*.json"):
                catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
                for source in catalog.get("sources", []):
                    with self.subTest(catalog=catalog_path.name, source=source["id"]):
                        filename = licenses[source["license"]]
                        self.assertGreater((ROOT / "LICENSES" / filename).stat().st_size, 500)
        self.assertTrue((ROOT / "LICENSES/MITRE-CAR-NOTICE.txt").is_file())
        self.assertIn("MIT License", (ROOT / "LICENSE").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
