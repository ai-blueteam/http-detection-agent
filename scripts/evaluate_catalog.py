#!/usr/bin/env python3
"""Small reference evaluator for event rules; the Rust engine remains the target."""

from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def normalize_event(event):
    return {str(key).lower(): value for key, value in event.items()}


def transform(value, transforms):
    result = value
    for item in transforms or []:
        if not isinstance(result, str):
            return result
        if item == "lowercase":
            result = result.lower()
        elif item == "url_decode_1":
            result = unquote(result)
        elif item == "url_decode_2":
            result = unquote(unquote(result))
        elif item == "html_entity_decode":
            result = html.unescape(result)
        elif item == "path_only":
            # Lexical extraction, matching the Rust contract even for malformed
            # attacker-controlled authorities; this is not URL validation.
            result = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*:", "", result, count=1)
            if result.startswith("//"):
                authority_end = re.search(r"[/#?]", result[2:])
                result = result[2 + authority_end.start():] if authority_end else ""
            result = re.split(r"[?#]", result, maxsplit=1)[0]
    return result


def string_pair(left, right, insensitive):
    left, right = str(left), str(right)
    return (left.lower(), right.lower()) if insensitive else (left, right)


def predicate(node, event):
    op = node["op"]
    value = event.get(node.get("field"))
    value = transform(value, node.get("transforms"))
    insensitive = "i" in node.get("flags", [])

    if op == "exists":
        return value is not None
    if op == "is_null":
        return value is None
    if op in {"map_key_exists", "map_key_value_regex"}:
        if not isinstance(value, dict):
            return False
        lowered = {str(k).lower(): v for k, v in value.items()}
        selected = lowered.get(node["key"].lower())
        if op == "map_key_exists":
            return node["key"].lower() in lowered
        return selected is not None and re.search(node["value"], str(selected), re.I if insensitive else 0) is not None
    if op == "map_value_regex":
        return isinstance(value, dict) and any(re.search(node["value"], str(v), re.I if insensitive else 0) for v in value.values())
    if op == "array_contains_any":
        if not isinstance(value, list):
            return False
        actual = {str(v).lower() if insensitive else str(v) for v in value}
        wanted = {str(v).lower() if insensitive else str(v) for v in node["values"]}
        return bool(actual & wanted)
    if op == "array_value_regex":
        return isinstance(value, list) and any(re.search(node["value"], str(v), re.I if insensitive else 0) for v in value)
    if op == "array_duplicate_header_name":
        if not isinstance(value, list):
            return False
        names = [str(item).split(":", 1)[0].strip().lower() for item in value if ":" in str(item)]
        ignored = {str(item).lower() for item in node.get("values", [])}
        names = [name for name in names if name not in ignored]
        return len(names) != len(set(names))
    if value is None:
        return False
    if op in {"lt", "lte", "gt", "gte"}:
        try:
            left, right = float(value), float(node["value"])
        except (TypeError, ValueError):
            return False
        return {"lt": left < right, "lte": left <= right, "gt": left > right, "gte": left >= right}[op]
    if op == "regex":
        return re.search(node["value"], str(value), re.I if insensitive else 0) is not None
    if op in {"in", "not_in"}:
        left = str(value).lower() if insensitive else value
        values = [str(v).lower() if insensitive else v for v in node["values"]]
        result = left in values
        return result if op == "in" else not result
    left, right = string_pair(value, node.get("value", ""), insensitive)
    if op == "eq":
        return left == right
    if op == "neq":
        return left != right
    if op == "contains":
        return right in left
    if op == "contains_any":
        return any(string_pair(value, candidate, insensitive)[1] in left for candidate in node["values"])
    if op == "starts_with":
        return left.startswith(right)
    if op == "ends_with":
        return left.endswith(right)
    raise ValueError(f"unsupported operator: {op}")


def matches(node, event):
    if "all" in node:
        return all(matches(item, event) for item in node["all"])
    if "any" in node:
        return any(matches(item, event) for item in node["any"])
    if "not" in node:
        return not matches(node["not"], event)
    return predicate(node, event)


def evaluate(catalog, event):
    normalized = normalize_event(event)
    return [rule for rule in catalog["rules"] if rule["kind"] == "event" and matches(rule["match"], normalized)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("event", type=Path, help="JSON object containing one Cloudflare http_requests event")
    parser.add_argument("--catalog", type=Path, default=ROOT / "rules" / "http-attacks.json")
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    event = json.loads(args.event.read_text(encoding="utf-8"))
    hits = evaluate(catalog, event)
    print(json.dumps([{"id": rule["id"], "title": rule["title"], "severity": rule["severity"], "provenance": rule["provenance"]} for rule in hits], indent=2))


if __name__ == "__main__":
    main()
