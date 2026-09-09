# http-detection-agent

`http-detection-agent` is a fast, local HTTP attack detector. It combines a normalized, deduplicated rule catalog with a bounded Rust engine, so the same detections can run across web servers, reverse proxies, gateways, WAFs, honeypots, and other HTTP telemetry.

Use it as:

- the `http-detect` command-line tool;
- a local MCP server for Codex, Claude Code, and other compatible agents; or
- a rules and schema foundation for your own detection pipeline.

The catalog contains **76 detections across 62 behavior families**. Rules carry field and visibility requirements, allowing the engine to enable only the detections a particular log source can support.

## Highlights

- Streaming NDJSON/JSONL input, with gzip and zstd support
- Event and event-time aggregate detections
- Explicit request-body, response-body, header, parser, and state requirements
- Per-profile coverage reports with exact exclusion reasons
- Bounded memory, line, key, group, and window limits
- Full rule provenance, authorship, and upstream licensing in findings
- Portable Linux, macOS, and Windows CI
- No hosted service, model API key, or external schema checkout required

Coverage includes injection attacks, traversal, request smuggling, webshell traffic, unsafe uploads, SSRF, XXE, deserialization, GraphQL and JWT abuse, exploit paths, scanner activity, login bursts, floods, and distributed payload campaigns.

## Quick start

Requires Rust 1.88 or newer.

```sh
git clone https://github.com/ai-blueteam/http-detection-agent.git
cd http-detection-agent
cargo build --release --locked
```

Inspect the rules supported by a source profile:

```sh
target/release/http-detect inspect \
  --profile /path/to/source-profile.json \
  --status production
```

Scan normalized HTTP events:

```sh
target/release/http-detect scan /path/to/requests.ndjson \
  --profile /path/to/source-profile.json \
  --status production \
  --output findings.ndjson \
  --summary summary.json
```

Windows builds use `target/release/http-detect.exe`. Existing output files are never overwritten.

## Input and source profiles

Each input line is one normalized HTTP event. Field names are case-insensitive, missing values remain null, and values are transformed only as specified by each rule.

```json
{"edgeendtimestamp":"2026-09-08T18:30:00Z","clientip":"192.0.2.10","clientrequestmethod":"GET","clientrequesthost":"example.test","clientrequesturi":"/search?q=hello","clientrequestuseragent":"ExampleBrowser/1.0"}
```

A source profile tells the engine which fields and semantic capabilities the adapter guarantees. This matters because a field name alone cannot prove that bodies are complete, duplicate headers were preserved, or structured values were actually parsed.

Bundled profiles include a full normalized vocabulary, an Internet-background-noise mapping, and Cloudflare HTTP request compatibility. The full profile is a capability ceiling for adapters that implement the complete contract; do not use it to claim fields your source does not provide.

Create or adjust a profile using [the source-profile schema](schema/source-profile.schema.json), then compile an adapter-specific ruleset and coverage report:

```sh
python3 scripts/compile_profile.py /path/to/source-profile.json \
  --write rulesets/my-source.json \
  --report runtime/my-source-coverage.json
```

The report lists every selected rule and every exclusion with its missing fields, alternatives, or capabilities. Compatibility is decided once when rules load, not by whether an optional field happens to be populated on an individual event.

See [the normalized field contract](schema/normalized-http-extensions.json) and [superset notes](docs/SUPERSET_EXPANSION.md) when building an adapter.

## MCP and agent use

The optional stdio MCP companion provides four tools:

- `list_profiles` — list bundled source profiles
- `inspect_rules` — show eligible rules and coverage gaps
- `get_rule` — inspect logic, requirements, provenance, and licenses
- `scan_http` — run a bounded local scan and return an attributed summary

It accepts authorized local normalized logs and does not expose a network listener, upload traffic, call an LLM, change a WAF, or block clients. Two portable skills are included for MCP-assisted or CLI-only workflows.

See [MCP and agent setup](docs/AGENT_COMPANION.md) for Codex, Claude Code, Windows, macOS, and Linux instructions.

## Rule model

Every detection defines:

- `required_fields` — all fields the evaluator may read;
- `requirements.all_fields` — fields the adapter must provide;
- `requirements.any_fields` — alternative field groups;
- `requirements.capabilities` — guarantees such as complete body visibility, raw header preservation, parsed structures, or stateful windows;
- `family` and `variant` — stable behavior grouping for deduplication; and
- `provenance` — upstream IDs, paths, authors, relationships, and licenses.

Rules are deduplicated by behavior rather than source text. A canonical rule can combine the strongest compatible logic from several sources while retaining every applicable attribution.

The generic reader does not infer multipart, JSON-path, GraphQL AST, JWT, or other parsed metadata from raw text. Those detections activate only for adapters that explicitly provide the documented fields and capabilities.

## Project layout

```text
rules/http-attacks.json                  Canonical 76-rule catalog
rulesets/                                Compiled source-specific catalogs
profiles/                                Bundled capability profiles
schema/                                  Catalog, profile, and field contracts
src/                                     Rust engine and CLI
companion/                               Optional local MCP server
.agents/skills/, .claude/skills/         Portable agent skills
scripts/                                 Validation and profile tools
tests/                                   Synthetic regression fixtures
```

## Validation

Python 3.9 or newer is required for catalog tooling. Run the complete local verification suite with:

```sh
python3 scripts/verify_engine.py --output runtime/verification.json
```

For the optional MCP companion, Python 3.10+ and `uv` are required:

```sh
uv sync --project companion --locked
uv run --project companion --locked python -m unittest discover -s companion/tests -v
```

Synthetic regression fixtures verify behavior and compatibility, but they do not establish real-world precision, recall, or exploit success. Start production deployments in alert-only mode and tune them against representative, labeled traffic.

## Licensing

The original engine, tooling, companion, skills, and documentation are [MIT licensed](LICENSE). Adapted detection rules retain their upstream terms and attribution, summarized once in [third-party notices](THIRD_PARTY_NOTICES.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for rule changes and [SECURITY.md](SECURITY.md) for responsible reporting and operational guidance.
