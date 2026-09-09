#!/usr/bin/env python3
"""Print the field projection required by enabled catalog rules."""

import argparse
import json
from pathlib import Path

from compile_profile import compatibility

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=ROOT / "rules" / "http-attacks.json")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--status", action="append", choices=["production", "test", "experimental"])
    parser.add_argument("--kind", action="append", choices=["event", "aggregate"])
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    profile = json.loads(args.profile.read_text(encoding="utf-8")) if args.profile else None
    rules = [
        rule for rule in catalog["rules"]
        if (not args.status or rule["status"] in args.status)
        and (not args.kind or rule["kind"] in args.kind)
        and (not profile or compatibility(rule, profile)[0])
    ]
    fields = {field for rule in rules for field in rule["required_fields"]}
    if profile is not None:
        fields.intersection_update(profile["fields"])
    print(", ".join(sorted(fields)))


if __name__ == "__main__":
    main()
