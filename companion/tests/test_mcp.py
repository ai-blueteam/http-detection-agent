"""Synthetic end-to-end MCP/CLI parity and companion boundary tests."""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp import Client
from mcp.client.stdio import StdioServerParameters

COMPANION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPANION))
from backend import Backend, ROOT
from server import create_server

BINARY = Path(os.environ.get("HTTP_DETECTION_BINARY", ROOT / "target/debug" / ("http-detect.exe" if os.name == "nt" else "http-detect")))
PROFILE = "cloudflare-log-explorer"


class CompanionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="http-agent-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.backend = Backend(binary=BINARY, data_roots=[self.inputs], output_root=self.base / "out")
        self.source = self.inputs / "traffic with spaces.ndjson"
        self.source.write_text(json.dumps({"clientrequesturi": "/?q=1 UNION SELECT password", "clientrequestmethod": "GET"}) + "\n")

    async def test_sdk_tools_and_defaults(self):
        async with Client(create_server(self.backend)) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            self.assertEqual(set(tools), {"list_profiles", "get_rule", "inspect_rules", "scan_http"})
            self.assertFalse(tools["scan_http"].annotations.read_only_hint)
            self.assertFalse(tools["scan_http"].annotations.destructive_hint)
            self.assertTrue(tools["get_rule"].annotations.read_only_hint)
            self.assertEqual(tools["scan_http"].input_schema["properties"]["status"]["default"], "production")
            result = await client.call_tool("list_profiles", {})
            self.assertFalse(result.is_error)
            self.assertEqual(len(result.structured_content["profiles"]), 3)
            invalid = await client.call_tool("inspect_rules", {"profile": PROFILE, "status": "bogus"})
            self.assertTrue(invalid.is_error)

    async def test_stdio_handshake_inspect_and_scan(self):
        params = StdioServerParameters(command=sys.executable, args=[
            str(COMPANION / "server.py"), "--binary", str(BINARY),
            "--data-root", str(self.inputs), "--output-root", str(self.base / "stdio-out"),
        ])
        async with Client(params, read_timeout_seconds=30) as client:
            self.assertEqual(client.server_info.name, "http-detection-agent")
            result = await client.call_tool("inspect_rules", {"profile": PROFILE, "status": "all", "events_only": False})
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["selected_rules"], 43)
            result = await client.call_tool("scan_http", {"input_path": str(self.source), "profile": PROFILE})
            self.assertFalse(result.is_error)
            data = result.structured_content
            self.assertTrue(data["summary"]["complete"])
            self.assertEqual(data["summary"]["records"], 1)
            self.assertGreater(data["summary"]["event_findings"], 0)
            self.assertNotIn("findings", data["artifacts"])
            self.assertNotIn("1 UNION SELECT password", json.dumps(data))
            self.assertTrue(all(r["provenance"] and r["sources"] for r in data["matched_rules"]))

    async def test_scan_matches_cli_and_preserves_findings(self):
        data = await self.backend.scan_http(str(self.source), PROFILE, save_findings=True)
        self.assertTrue(data["summary"]["complete"])
        findings = Path(data["artifacts"]["findings"])
        original = findings.read_bytes()
        self.assertTrue(original)
        run = subprocess.run([str(BINARY), "scan", str(self.source), "--catalog", str(ROOT / "rules/http-attacks.json"),
            "--profile", str(ROOT / "profiles/cloudflare-log-explorer.json"), "--events-only", "--counts-only", "--quiet"],
            check=True, capture_output=True, text=True, encoding="utf-8")
        direct = json.loads(run.stderr)
        self.assertEqual(data["summary"]["rule_counts"], direct["rule_counts"])
        self.assertEqual(data["summary"]["match_digest_sha256"], direct["match_digest_sha256"])
        next_run = await self.backend.scan_http(str(self.source), PROFILE, save_findings=True)
        self.assertNotEqual(data["artifacts"]["run_directory"], next_run["artifacts"]["run_directory"])
        self.assertEqual(findings.read_bytes(), original)
        for line in original.splitlines():
            self.assertTrue(json.loads(line)["provenance"])

    async def test_legacy_stdio_handshake_and_rule_attribution(self):
        params = StdioServerParameters(command=sys.executable, args=[
            str(COMPANION / "server.py"), "--binary", str(BINARY),
            "--data-root", str(self.inputs), "--output-root", str(self.base / "legacy-out"),
        ])
        async with Client(params, mode="legacy", read_timeout_seconds=30) as client:
            result = await client.call_tool("get_rule", {"rule_id": "http.sqli.generic"})
            self.assertFalse(result.is_error)
            self.assertTrue(result.structured_content["rule"]["provenance"])
            self.assertTrue(result.structured_content["sources"])
            unknown = await client.call_tool("get_rule", {"rule_id": "not-a-rule"})
            self.assertTrue(unknown.is_error)

    async def test_reject_paths_profiles_and_resource_expansion(self):
        outside = self.base / "outside.ndjson"
        outside.write_text("{}\n")
        for candidate in [str(outside), "-", "https://example.invalid/a.ndjson", str(self.inputs), str(self.inputs / "../outside.ndjson")]:
            with self.subTest(candidate=candidate), self.assertRaises((ValueError, FileNotFoundError)):
                await self.backend.scan_http(candidate, PROFILE)
        with self.assertRaises(ValueError):
            await self.backend.scan_http(str(self.source), "../../other")
        with self.assertRaises(ValueError):
            await self.backend.scan_http(str(self.source), PROFILE, threads=256)
        self.assertFalse((self.base / "out").exists())

    async def test_symlink_escape_is_rejected(self):
        outside = self.base / "outside.ndjson"
        outside.write_text("{}\n")
        link = self.inputs / "linked.ndjson"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("Symlink creation is unavailable for this OS account")
        with self.assertRaises(ValueError):
            await self.backend.scan_http(str(link), PROFILE)

    async def test_invalid_input_is_not_a_success_or_raw_error_leak(self):
        self.source.write_text("PRIVATE_TEST_MARKER not json\n")
        data = await self.backend.scan_http(str(self.source), PROFILE)
        self.assertFalse(data["summary"]["complete"])
        self.assertNotEqual(data["exit_code"], 0)
        self.assertNotIn("PRIVATE_TEST_MARKER", json.dumps(data))

    async def test_aggregate_requires_valid_timestamps(self):
        data = await self.backend.scan_http(str(self.source), PROFILE, events_only=False)
        self.assertFalse(data["summary"]["complete"])
        self.assertNotEqual(data["exit_code"], 0)

    async def test_timeout_and_cancellation_stop_engine(self):
        class Process:
            returncode = None
            def kill(self):
                self.returncode = -9
            async def wait(self):
                if self.returncode is None:
                    await asyncio.sleep(10)
                return self.returncode
        process = Process()
        async def launch(*args, **kwargs):
            self.assertNotIn("shell", kwargs)
            return process
        self.backend.timeout = 0.01
        with patch("asyncio.create_subprocess_exec", launch):
            with self.assertRaises(asyncio.TimeoutError):
                await self.backend.run(["inspect"], None, None)
        self.assertEqual(process.returncode, -9)
        process = Process()
        self.backend.timeout = 30
        with patch("asyncio.create_subprocess_exec", launch):
            task = asyncio.create_task(self.backend.run(["inspect"], None, None))
            await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(process.returncode, -9)


if __name__ == "__main__":
    unittest.main()
