---
name: http-detection-rules
description: Inspect, explain, or maintain http-detection-agent signatures and capability profiles, preserving provenance, regression coverage, and the locked Cloudflare baseline.
---

# HTTP detection rules

Use `get_rule`, `inspect_rules`, and `list_profiles` over MCP for inspection, or read the intended checkout and use the `http-detect` CLI. MCP intentionally exposes no rule-editing or shell tool. Modify files only when the user asks for a change.

## Inspect and explain

Start with rules/http-attacks.json, the relevant profile, schema/normalized-http-extensions.json, and the matching rule's provenance. Explain what is observed, what is missing, and why requirements select or exclude the rule. Requirements describe adapter guarantees, not non-null values in each request. Do not broaden an adapter's capability advertisement to make a rule eligible.

The original engine/tooling is MIT; rules retain their upstream licenses. Read THIRD_PARTY_NOTICES.md before adapting or redistributing source material. Do not relabel mixed-license data MIT or drop authors from findings.

## When implementing a requested rule change

Deduplicate by behavior and reuse stable families for variants. Keep upstream revision, source path, authors, adaptation relationship, and applicable licenses. Add new heuristics as test candidates, with positive, negative, missing-field, and missing-capability cases. Synthetic parser fields test consumer behavior; they do not implement a parser.

Follow the catalog contract: Rust-compatible regexes, ordered transforms, exactly one/two URL decode passes, literal plus preservation, case-insensitive field/header names, and null preservation. Review the checkout's README.md and docs/SUPERSET_EXPANSION.md when working on richer parsed-field rules.

The 43-rule Cloudflare baseline has a content lock. Do not alter that lock to silence a test or prune body-only rules from the superset just because Cloudflare cannot run them. Ask for direction if the requested change necessarily modifies the protected baseline.

Regenerate affected compiled profiles and run:

```sh
python3 scripts/validate_catalog.py
python3 -m unittest discover -s tests -v
cargo test --locked --all-features
cargo build --locked
python3 scripts/differential_engine.py --binary target/debug/http-detect --matcher plain
python3 scripts/differential_engine.py --binary target/debug/http-detect --matcher grouped
```

On Windows use the available Python launcher and `target/debug/http-detect.exe`. The bundled verification runner provides the same checks and chooses the binary suffix automatically. Keep generated results, captured traffic, and local paths out of commits. Report test results separately from traffic accuracy and production readiness.
