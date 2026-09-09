#!/usr/bin/env python3
"""Zero-dependency semantic validation for the normalized HTTP rule catalog."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "rules" / "http-attacks.json"
CATALOG_SCHEMA = ROOT / "schema" / "http-detection-catalog.schema.json"
EXTENSIONS = ROOT / "schema" / "normalized-http-extensions.json"
CF_PROFILE = ROOT / "profiles" / "cloudflare-log-explorer.json"

RUST_UNSUPPORTED = ("(?=", "(?!", "(?<=", "(?<!", "\\1", "\\2", "(?P=")


def walk_conditions(node):
    if "all" in node:
        for item in node["all"]:
            yield from walk_conditions(item)
    elif "any" in node:
        for item in node["any"]:
            yield from walk_conditions(item)
    elif "not" in node:
        yield from walk_conditions(node["not"])
    else:
        yield node


def fail(errors, message):
    errors.append(message)


def main() -> int:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    json.loads(CATALOG_SCHEMA.read_text(encoding="utf-8"))
    cloudflare = json.loads(CF_PROFILE.read_text(encoding="utf-8"))
    extensions = json.loads(EXTENSIONS.read_text(encoding="utf-8"))
    fields = set(cloudflare["fields"]) | set(extensions["fields"])
    known_capabilities = set(extensions["capabilities"])
    source_ids = {source["id"] for source in catalog["sources"]}
    errors = []
    seen_ids = set()

    if catalog.get("schema_version") != "1.0.0":
        fail(errors, "unsupported schema_version")
    if catalog.get("regex_dialect") != "rust-regex":
        fail(errors, "regex_dialect must be rust-regex")
    if catalog.get("timestamp_field") != "edgeendtimestamp":
        fail(errors, "timestamp_field must be edgeendtimestamp")
    if catalog.get("timestamp_field") not in cloudflare["fields"]:
        fail(errors, "timestamp_field is absent from the bundled Cloudflare profile")

    for rule in catalog["rules"]:
        rid = rule["id"]
        if rid in seen_ids:
            fail(errors, f"duplicate rule id: {rid}")
        seen_ids.add(rid)

        unknown_required = set(rule["required_fields"]) - fields
        if unknown_required:
            fail(errors, f"{rid}: unknown required fields {sorted(unknown_required)}")

        for provenance in rule["provenance"]:
            if provenance["source"] not in source_ids:
                fail(errors, f"{rid}: unknown source {provenance['source']}")
            if provenance["source"] == "sigma" and not provenance["authors"]:
                fail(errors, f"{rid}: DRL-1.1 requires Sigma author attribution")

        requirements = rule["requirements"]
        requirement_fields = set(requirements["all_fields"])
        for group in requirements["any_fields"]:
            requirement_fields.update(group)
        unknown_requirement_fields = requirement_fields - fields
        if unknown_requirement_fields:
            fail(errors, f"{rid}: requirements reference unknown fields {sorted(unknown_requirement_fields)}")
        unknown_capabilities = set(requirements["capabilities"]) - known_capabilities
        if unknown_capabilities:
            fail(errors, f"{rid}: requirements reference unknown capabilities {sorted(unknown_capabilities)}")
        if not requirement_fields.issubset(set(rule["required_fields"])):
            fail(errors, f"{rid}: requirements fields must be included in required_fields")
        for field in rule["required_fields"]:
            capability = extensions["fields"].get(field, {}).get("capability")
            if capability and capability not in requirements["capabilities"]:
                fail(errors, f"{rid}: extension field {field} requires capability {capability}")

        root = rule.get("match") or rule["aggregate"]["having"]
        conditions = list(walk_conditions(root))
        if "aggregate" in rule and "prefilter" in rule["aggregate"]:
            conditions += list(walk_conditions(rule["aggregate"]["prefilter"]))
        if "aggregate" in rule:
            for metric in rule["aggregate"]["metrics"]:
                if metric.get("field") and metric["field"] not in fields:
                    fail(errors, f"{rid}: metric references unknown field {metric['field']}")
                if "where" in metric:
                    conditions += list(walk_conditions(metric["where"]))
            for field in rule["aggregate"]["group_by"]:
                if field not in fields:
                    fail(errors, f"{rid}: group_by references unknown field {field}")

        referenced = set()
        for condition in conditions:
            field = condition.get("field")
            if field:
                referenced.add(field)
                if field not in fields:
                    fail(errors, f"{rid}: predicate references unknown field {field}")
            if condition["op"] in {"regex", "map_value_regex", "map_key_value_regex", "array_value_regex"}:
                pattern = condition.get("value", "")
                if any(token in pattern for token in RUST_UNSUPPORTED):
                    fail(errors, f"{rid}: regex uses unsupported Rust-regex feature: {pattern}")
                try:
                    re.compile(pattern)
                except re.error as exc:
                    fail(errors, f"{rid}: invalid regex {pattern!r}: {exc}")
                if shutil.which("rg"):
                    compiled = subprocess.run(
                        ["rg", "--text", "--regexp", pattern, os.devnull],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        text=True, encoding="utf-8",
                        check=False,
                    )
                    if compiled.returncode == 2:
                        fail(errors, f"{rid}: Rust regex rejected {pattern!r}: {compiled.stderr.strip()}")

        missing_declarations = referenced - set(rule["required_fields"])
        if missing_declarations:
            fail(errors, f"{rid}: undeclared required fields {sorted(missing_declarations)}")
        ungated = referenced - requirement_fields
        if ungated:
            fail(errors, f"{rid}: evaluator fields absent from requirements {sorted(ungated)}")

    if errors:
        print("catalog validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    event_count = sum(rule["kind"] == "event" for rule in catalog["rules"])
    aggregate_count = len(catalog["rules"]) - event_count
    print(f"PASS: {len(catalog['rules'])} unique rules ({event_count} event, {aggregate_count} aggregate)")
    print("PASS: every referenced field exists in the bundled Cloudflare profile or normalized HTTP extensions")
    print("PASS: provenance is complete and regexes avoid unsupported Rust-regex constructs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
