#!/usr/bin/env python3
"""Reproducible local correctness gates, with machine-readable evidence."""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    binary = str(target_dir / "debug" / ("http-detect.exe" if os.name == "nt" else "http-detect"))
    checks = [
        ("format", ["cargo", "fmt", "--all", "--", "--check"]),
        ("all_features_tests", ["cargo", "test", "--locked", "--all-features", "--", "--test-threads=4"]),
        ("default_cpu_tests", ["cargo", "test", "--locked", "--no-default-features"]),
        ("clippy", ["cargo", "clippy", "--locked", "--all-features", "--all-targets", "--", "-D", "warnings"]),
        ("python_catalog_profiles", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("catalog_validation", [sys.executable, "scripts/validate_catalog.py"]),
        ("cpu_only_build", ["cargo", "build", "--locked", "--no-default-features"]),
        ("reference_plain", [sys.executable, "scripts/differential_engine.py", "--binary", binary, "--matcher", "plain"]),
        ("reference_grouped", [sys.executable, "scripts/differential_engine.py", "--binary", binary, "--matcher", "grouped"]),
    ]
    results = []
    for name, command in checks:
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
        results.append(dict(name=name, command=command, exit_code=run.returncode,
                            passed=run.returncode == 0, output=run.stdout + run.stderr))
        print(name, "PASS" if run.returncode == 0 else "FAIL", flush=True)
    tree = subprocess.run(["cargo", "tree", "--locked", "--no-default-features", "-e", "normal", "--prefix", "none"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True)
    banned = {"parquet", "arrow-array", "arrow"}
    assert not any(line.split()[0] in banned for line in tree.stdout.splitlines()), "optional dependency leaked into default build"
    results.append(dict(name="optional_dependency_isolation", passed=True, output="No Parquet or Arrow runtime dependency in the default CPU build."))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as f:
        json.dump(dict(passed=all(r["passed"] for r in results), checks=results), f, indent=2)
        f.write("\n")
    assert all(r["passed"] for r in results), "verification failed; see saved evidence"


if __name__ == "__main__":
    main()
