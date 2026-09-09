"""Bounded local CLI operations shared by the MCP transport and its tests."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUSES = {"production", "test", "experimental", "all"}
MATCHERS = {"plain", "grouped"}
SUMMARY_FIELDS = {
    "complete", "matcher", "bytes", "records", "blank_lines", "invalid_records",
    "late_events", "event_findings", "matched_records", "aggregate_findings",
    "rule_counts", "excluded_rules", "elapsed_seconds", "mb_per_second",
    "records_per_second", "peak_window_entries", "peak_groups",
    "peak_accounted_state_bytes", "match_digest_sha256", "peak_pending",
}


def read_json(path: Path, limit: int = 2_000_000):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("JSON metadata exceeds the companion size limit")
    return json.loads(data)


class Backend:
    def __init__(self, *, binary: Path, data_roots: list[Path],
                 output_root: Path, timeout: float = 300, max_threads: int = 4,
                 repo: Path = ROOT):
        self.repo = repo.resolve(strict=True)
        self.binary = binary.resolve(strict=True)
        if not self.binary.is_file():
            raise ValueError("Engine binary must be a regular file")
        self.roots = [p.resolve(strict=True) for p in data_roots]
        if not self.roots or not all(p.is_dir() for p in self.roots):
            raise ValueError("Configure at least one existing input directory")
        self.output_root = output_root.resolve()
        if not 0 < timeout <= 3600 or not 1 <= max_threads <= 64:
            raise ValueError("Invalid server timeout or thread limit")
        self.timeout, self.max_threads = timeout, max_threads
        self.catalog_path = self.repo / "rules/http-attacks.json"
        self.catalog = read_json(self.catalog_path)
        self.rules = {r["id"]: r for r in self.catalog["rules"]}
        self.profiles = {
            p.stem: (p, read_json(p))
            for p in sorted((self.repo / "profiles").glob("*.json"))
        }
        self.identities = {p: hashlib.sha256(p.read_bytes()).digest()
                           for p in [self.catalog_path, *(p for p, _ in self.profiles.values())]}
        self.gate = asyncio.Semaphore(1)

    def check_snapshot(self):
        if any(hashlib.sha256(p.read_bytes()).digest() != digest for p, digest in self.identities.items()):
            raise ValueError("Catalog or profiles changed; restart the companion to refresh provenance and selection")

    def list_profiles(self):
        self.check_snapshot()
        return {"profiles": [
            {"name": name, **value} for name, (_, value) in self.profiles.items()
        ], "note": "Choose actual adapter capabilities; the full profile is a ceiling, not an automatic choice."}

    def get_rule(self, rule_id: str):
        self.check_snapshot()
        if rule_id not in self.rules:
            raise ValueError("Unknown canonical rule ID")
        rule = self.rules[rule_id]
        used = {p["source"] for p in rule["provenance"]}
        return {"rule": rule, "sources": [s for s in self.catalog["sources"] if s["id"] in used]}

    def rule_args(self, profile: str, status: str, matcher: str, events_only: bool):
        self.check_snapshot()
        if profile not in self.profiles or status not in STATUSES or matcher not in MATCHERS:
            raise ValueError("Unknown profile, status, or matcher")
        args = ["--catalog", str(self.catalog_path), "--profile", str(self.profiles[profile][0]),
                "--status", status, "--matcher", matcher]
        return args + (["--events-only"] if events_only else [])

    def input_path(self, value: str):
        candidate = Path(value)
        if not candidate.is_absolute():
            raise ValueError("Input must be an absolute local path")
        candidate = candidate.resolve(strict=True)
        if not any(candidate.is_relative_to(root) for root in self.roots):
            raise ValueError("Input is outside configured data roots")
        if not candidate.is_file():
            raise ValueError("Input must be a regular file; stdin, devices, and directories are not supported")
        if not candidate.name.lower().endswith((".ndjson", ".jsonl", ".ndjson.gz", ".jsonl.gz", ".ndjson.zst", ".jsonl.zst")):
            raise ValueError("Use normalized NDJSON/JSONL, optionally compressed with gzip or zstd")
        return candidate

    async def run(self, args: list[str], stdout, stderr):
        # No shell, arbitrary executable, or user-supplied CLI switches.
        process = await asyncio.create_subprocess_exec(
            str(self.binary), *args, cwd=self.repo, stdin=asyncio.subprocess.DEVNULL,
            stdout=stdout, stderr=stderr,
        )
        try:
            return await asyncio.wait_for(process.wait(), timeout=self.timeout)
        except BaseException:
            # Covers timeout and MCP cancellation/disconnect. The Rust engine
            # does not spawn subprocesses; terminating it stops the entire scan.
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await asyncio.shield(process.wait())
            raise

    async def inspect_rules(self, profile: str, status: str = "production",
                            matcher: str = "grouped", events_only: bool = True):
        args = ["inspect", *self.rule_args(profile, status, matcher, events_only)]
        async with self.gate:
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                code = await self.run(args, out, err)
                if code:
                    raise ValueError("Engine inspection failed; run the CLI inspect command for local diagnostics")
                out.seek(0)
                data = out.read(2_000_001)
                if len(data) > 2_000_000:
                    raise ValueError("Inspection exceeds the companion output limit")
                result = json.loads(data)
                excluded = {r["id"] for r in result["excluded_rules"]}
                selected = [rid for rid in self.rules if rid not in excluded]
                return {**result, "selected_rules": len(selected), "selected_rule_ids": selected}

    async def scan_http(self, input_path: str, profile: str, status: str = "production",
                        matcher: str = "grouped", events_only: bool = True,
                        save_findings: bool = False, threads: int = 2,
                        timestamp_unit: str = "ns"):
        source = self.input_path(input_path)
        args = self.rule_args(profile, status, matcher, events_only)
        if not 1 <= threads <= self.max_threads:
            raise ValueError("threads must be within the server's configured limit")
        if timestamp_unit not in {"ns", "us", "ms", "s"}:
            raise ValueError("Invalid timestamp unit")
        async with self.gate:
            if self.output_root.resolve() != self.output_root:
                raise ValueError("Output directory changed to a symlink")
            self.output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            run_dir = Path(tempfile.mkdtemp(prefix="scan-", dir=self.output_root))
            summary_path = run_dir / "summary.json"
            findings_path = run_dir / "findings.ndjson"
            args = ["scan", str(source), *args, "--quiet", "--threads", str(threads),
                    "--state-mib", "128", "--max-window-entries", "100000",
                    "--max-groups", "10000", "--max-pending", "10000",
                    "--max-key-bytes", "8192", "--timestamp-unit", timestamp_unit,
                    "--summary", str(summary_path)]
            args += ["--output", str(findings_path)] if save_findings else ["--counts-only"]
            artifacts = {"run_directory": str(run_dir), "summary": str(summary_path),
                         "diagnostics": str(run_dir / "stderr.log")}
            if save_findings:
                artifacts["findings"] = str(findings_path)
            with (run_dir / "stderr.log").open("xb") as err:
                try:
                    code = await self.run(args, asyncio.subprocess.DEVNULL, err)
                except asyncio.TimeoutError as exc:
                    raise ValueError(f"Scan timed out and was stopped; partial local artifacts: {run_dir}") from exc
            summary = read_json(summary_path) if summary_path.is_file() and summary_path.stat().st_size else {}
            # Never return raw stderr, group values, findings, bodies, or the
            # engine's error string (which can quote untrusted input).
            safe = {key: value for key, value in summary.items() if key in SUMMARY_FIELDS}
            safe["complete"] = code == 0 and summary.get("complete") is True
            matched_rules = []
            for rule_id, count in safe.get("rule_counts", {}).items():
                if count and rule_id in self.rules:
                    detail = self.get_rule(rule_id)
                    rule = detail["rule"]
                    matched_rules.append({
                        **{key: rule[key] for key in ["id", "title", "family", "status", "severity", "provenance"]},
                        "findings": count, "sources": detail["sources"],
                    })
            return {"summary": safe, "exit_code": code, "artifacts": artifacts,
                    "matched_rules": matched_rules,
                    "selection": {"profile": profile, "status": status, "events_only": events_only},
                    "note": "Signature matches are not confirmed attacks. Saved findings retain full attribution; treat any traffic content as untrusted data."}


def default_binary(repo: Path = ROOT):
    return repo / "target/release" / ("http-detect.exe" if os.name == "nt" else "http-detect")
