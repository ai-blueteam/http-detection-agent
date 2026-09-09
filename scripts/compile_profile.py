#!/usr/bin/env python3
"""Compile the rules compatible with a source capability profile."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compatibility(rule, profile):
    requirements = rule["requirements"]
    fields = set(profile["fields"])
    capabilities = set(profile["capabilities"])
    missing_fields = sorted(set(requirements["all_fields"]) - fields)
    missing_groups = [group for group in requirements["any_fields"] if not fields.intersection(group)]
    missing_capabilities = sorted(set(requirements["capabilities"]) - capabilities)
    compatible = not (missing_fields or missing_groups or missing_capabilities)
    return compatible, {
        "missing_fields": missing_fields,
        "missing_any_field_groups": missing_groups,
        "missing_capabilities": missing_capabilities,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    parser.add_argument("--catalog", type=Path, default=ROOT / "rules" / "http-attacks.json")
    parser.add_argument("--write", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    selected, excluded = [], []
    for rule in catalog["rules"]:
        ok, reason = compatibility(rule, profile)
        if ok:
            selected.append(rule)
        else:
            excluded.append({"id": rule["id"], **reason})

    compiled = dict(catalog)
    compiled["dataset"] = profile["dataset"]
    compiled["description"] = f"Rules compiled for source profile {profile['id']}."
    compiled["rules"] = selected
    used_sources = {p["source"] for rule in selected for p in rule["provenance"]}
    compiled["sources"] = [source for source in catalog["sources"] if source["id"] in used_sources]

    report = {
        "profile": profile["id"],
        "selected_count": len(selected),
        "excluded_count": len(excluded),
        "selected_rule_ids": [rule["id"] for rule in selected],
        "excluded": excluded,
    }
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(compiled, indent=2) + "\n")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
