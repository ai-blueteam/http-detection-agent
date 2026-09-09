# http-detection-agent

A normalized, deduplicated, multi-source HTTP attack ruleset with a Rust reference engine. Its base field vocabulary is recorded in the bundled [Cloudflare profile](profiles/cloudflare-log-explorer.json); [normalized HTTP extensions](schema/normalized-http-extensions.json) describe richer sources. No separate checkout or local dataset is needed to build or run the synthetic tests.

The original engine code and project tooling are [MIT licensed](LICENSE). The detection catalog is **mixed-license**, not MIT-only: upstream rule licenses and attribution remain in force. See [third-party notices](THIRD_PARTY_NOTICES.md), including the Elastic-derived rules' restrictions, before redistributing rules or offering a hosted service.

Use the `http-detect` CLI directly, or connect the optional [local MCP companion and portable agent skills](docs/AGENT_COMPANION.md) to Codex or Claude Code. The companion returns attributed scan summaries without exposing raw traffic and keeps MCP dependencies separate from the Rust engine.

The superset in [`rules/http-attacks.json`](rules/http-attacks.json) contains 76 detections across 62 families: the preserved 43-rule Cloudflare set and 33 additional detections gated by richer HTTP visibility. The latest expansion adds 23 test-status candidates with 51 positive and 72 negative fixtures. All original 53 rule definitions and their statuses are preserved. See [the expansion notes](docs/SUPERSET_EXPANSION.md) for coverage, adapter contracts, source decisions, and remaining gaps.

## What is covered

- Cloudflare WAF actions and attack scores
- Scanner identification and URI/path enumeration
- HTTP method abuse, request smuggling, CRLF injection, and encoding evasion
- Path traversal, sensitive-file discovery, RFI, and SSRF
- Unix/Windows command injection, PHP/Node/LDAP injection, and webshell traffic
- SQL injection, XSS, SSTI, Java deserialization, and JNDI/Log4Shell
- Request-body variants for SQLi, XSS, SSTI, command injection, Java deserialization, Log4Shell, Spring4Shell, and React2Shell
- Raw duplicate-header request smuggling and response-body information leakage
- Upload filenames and PHP content; multipart charset and transfer-encoding anomalies
- Directory listings and CGI, PHP, or Ruby source exposed in responses
- Parsed JSON prototype pollution and NoSQL authentication operators
- GraphQL introspection, depth/alias thresholds, and operation batching
- JWT unsecured algorithms and key-identifier traversal
- Body-level metadata SSRF, XXE, Text4Shell, Confluence OGNL, and Ivanti EPM SQL execution attempts
- Product-specific exploit paths for F5, Spring, SharePoint, ColdFusion, Confluence, ScreenConnect, Ivanti, Jenkins, WordPress Bricks, Tomcat, Fortinet, and cPanel/WHM
- Failed-login bursts, request floods, sensitive-path sweeps, and distributed payload campaigns

The catalog is intentionally inbound and request-focused. It does not import outbound proxy/C2 detections unless they also describe a credible inbound attack signal.

The implemented CPU-only streaming engine, dataset adapter, operational limits, and correctness checks are documented in [ENGINE.md](ENGINE.md). Captured traffic, local scan results, benchmark reports, and build outputs are not distributed.

## Files

```text
rules/http-attacks.json                  Canonical multi-source superset
rulesets/cloudflare-http-requests.json   Preserved compiled 43-rule Cloudflare set
rulesets/multisource-http.json           Compiled full-capability 76-rule set
rulesets/cloudflare-baseline.lock.json   Content hash protecting all 43 Cloudflare definitions
profiles/cloudflare-log-explorer.json    Cloudflare field/capability advertisement
profiles/multisource-full-http.json      Full normalized HTTP capability profile
schema/http-detection-catalog.schema.json Format contract for Rust/Serde models
schema/normalized-http-extensions.json   Optional fields and capability definitions
schema/source-profile.schema.json        Adapter-profile contract
scripts/compile_profile.py               Requirements-based ruleset compiler
scripts/validate_catalog.py              Schema-field, ID, provenance, and regex audit
scripts/evaluate_catalog.py              Small event-rule reference evaluator
scripts/required_fields.py               Query projection generator
tests/test_catalog.py                    Positive and negative regression fixtures
tests/fixtures/http-superset-expansion.json  123 synthetic candidate cases
tests/test_superset.py, tests/superset_contract.rs  Python/Rust behavior and capability gates
docs/SUPERSET_EXPANSION.md                Expansion audit and parsed-field contracts
Cargo.toml, src/                         Rust loader, selector, event/aggregate engine, and CLI
THIRD_PARTY_NOTICES.md                   Source and license obligations
LICENSE, LICENSES/                       MIT code license and upstream terms/notices
CONTRIBUTING.md, SECURITY.md             Contribution and security guidance
companion/                              Optional stdio MCP server and dependency lock
.agents/skills/, .claude/skills/          Portable scanning and rule-maintenance skills
docs/AGENT_COMPANION.md                  Codex/Claude Code setup and CLI fallback
```

## Validation

Requires Rust 1.88 or newer and Python 3.9 or newer. Python tooling uses only the standard library. Run from this directory:

```bash
python3 scripts/validate_catalog.py
python3 -m unittest discover -s tests -v
python3 scripts/required_fields.py --profile profiles/cloudflare-log-explorer.json --status production
python3 scripts/compile_profile.py profiles/cloudflare-log-explorer.json
cargo test --locked --all-targets
cargo run -- inspect --profile profiles/cloudflare-log-explorer.json --status all
```

Evaluate one Cloudflare event locally:

```bash
python3 scripts/evaluate_catalog.py event.json
```

The Python reference evaluator implements only `kind: event`. The Rust engine implements both event rules and the saved aggregate rules, with tested grouping, windows, metrics, prefilters, and thresholds. See [ENGINE.md](ENGINE.md) for event-time and alert-rearming semantics.

The Rust CLI accepts NDJSON, gzip, or zstd input and selects rules from the adapter profile before scanning. For example:

```bash
cargo run --release -- scan requests.ndjson \
  --profile profiles/cloudflare-log-explorer.json \
  --status production \
  --output findings.ndjson \
  --summary scan-summary.json
```

Input is streamed in bounded batches. Existing output files are not overwritten, and the summary records excluded rules and their exact requirements failures.

## Rust engine contract

Use `serde`/`serde_json` to deserialize the schema's tagged shapes and the Rust `regex` crate for patterns. The catalog deliberately avoids lookaround and backreferences unsupported by `regex`.

Evaluation order is significant:

1. Lowercase incoming field names. Do not lowercase field values globally.
2. Treat absent values as JSON null. Do not coerce null to an empty string.
3. Apply each predicate's `transforms` in listed order.
4. `url_decode_1` decodes once; `url_decode_2` decodes exactly twice. Do not decode repeatedly until stable.
5. Percent decoding does not convert `+` to a space. This avoids corrupting literal plus signs; signatures include plus variants where relevant.
6. Header and cookie map keys are case-insensitive.
7. Apply `flags: ["i"]` to regex and textual comparison operators.
8. Evaluate aggregate windows in event-time order using `edgeendtimestamp`. Define and test a late-event policy before production.
9. Bound URI/group-key size and cardinality. The distributed-campaign rule explicitly groups attacker-controlled URI data.
10. Emit full `provenance` with each finding. This is mandatory for Sigma-derived detections under DRL-1.1.

Every rule includes:

- `required_fields`: the superset of fields its evaluator may read;
- `requirements.all_fields`: fields that must all exist in the adapter schema;
- `requirements.any_fields`: alternative field groups where at least one field must exist;
- `requirements.capabilities`: semantic guarantees that field names alone cannot prove, such as complete request-body visibility, raw duplicate-header preservation, or stateful window support;
- `family` and `variant`: the canonical behavior and its URI/body/header/aggregate implementation, used to deduplicate findings.

The engine must evaluate requirements against the adapter profile once during rule loading, not against non-null values in each event. A compatible rule can still receive null for an optional field on an individual request.

`multisource-full-http.json` describes the maximum vocabulary, not the capabilities of every HTTP source. The generic Rust input path accepts normalized fields; it does not derive multipart, JSON-key, GraphQL AST, or JWT metadata from raw bodies or Authorization headers. Those rules require a source adapter that supplies the documented parsed fields. Existing Cloudflare and Internet-background-noise adapters do not advertise those parser capabilities.

Compile an adapter-specific set with:

```bash
python3 scripts/compile_profile.py profiles/cloudflare-log-explorer.json \
  --write rulesets/cloudflare-http-requests.json \
  --report runtime/cloudflare-compatibility.json
```

The report records every excluded rule and its missing fields, alternative groups, and capabilities. Never silently skip incompatible rules.

## Deduplication policy

Rules are deduplicated by behavior, not by source text or upstream ID. One canonical rule may cite multiple upstream detections:

- SQLi, XSS, traversal, scanner agents, and SSTI merge the strongest compatible CRS and Sigma logic.
- Log4Shell merges CRS, Google Cloud, and Splunk coverage.
- Spring4Shell merges Google Cloud and Splunk URL-level logic and has a separately gated body variant.
- SharePoint ToolPane merges the Chronicle and Splunk variants and retains both CVEs.
- Request smuggling merges CRS and Splunk with map-based and raw-header variants.

Canonical IDs are stable, source-neutral names such as `http.sqli.generic`. Variants share a `family`; the engine should deduplicate matches from the same transaction by family while retaining every matching variant as evidence. Upstream IDs and authors live in `provenance`, preventing duplicate alerts without losing attribution.

## Source review and selection

All revisions are pinned in the catalog so the audit can be reproduced.

| Source | Reviewed scope | Canonical rules citing source | Selection notes |
|---|---:|---:|---|
| OWASP CRS | 453 request `SecRule` directives plus response rules | 44 | Generic HTTP signatures, with upload, multipart, JSON-key, and response variants. Full libinjection and ModSecurity transaction semantics remain outside the evaluator. |
| SigmaHQ | 45 web rules; 13 generic webserver rules | 15 | Generic inbound webserver rules selected. Proxy-only, outbound C2, product error-log, and low-confidence malformed-agent rules were excluded. |
| Google Cloud security analytics | 5 HTTP load-balancer analytics | 3 | Log4Shell and Spring4Shell were directly useful. IAP and Cloud Armor provider-specific status fields are absent from the target schema. |
| Google SecOps community | 379 community rules | 1 | The SharePoint ToolPane rule had directly mappable request fields. Most rules target identity, endpoint, cloud audit, or other UDM data. |
| MITRE CAR | 102 analytics | 4 | No direct HTTP signature exists. CAR-2021-01-001's distinct-target model was carefully adapted to URI/path scanning and burst behaviors. |
| Splunk Security Content | 84 web detections | 19 | URL/method/status/cookie/header signatures plus locally refined body candidates for Text4Shell, Confluence, and Ivanti EPM. Alert-only and non-HTTP context is excluded. |
| Elastic detection-rules | 2,095 rules; 337 broad HTTP-field candidates | 2 | cPanel/WHM and React2Shell variants are retained with exact capability requirements. Most apparent candidates are endpoint/cloud rules or require process and packet context beyond the normalized HTTP model. |
| OWASP Cheat Sheet Series | 5 selected guidance documents | 11 | Upload, JSON/NoSQL, XXE, GraphQL, and JWT guidance adapted into local candidate heuristics. Numeric GraphQL thresholds are local policy choices, not upstream detection rules. |

Counts describe the pinned source revisions and rules citing each source; one canonical rule can cite multiple sources.

Synthetic regression fixtures exercise behavior and compatibility; they do not establish precision, recall, false-positive rates, or production performance.

## Known visibility gaps

The Cloudflare profile has rich edge and WAF metadata, but no request body, response body, or raw duplicate-header representation. The superset catalogs those detections, while the profile compiler excludes them with explicit reasons. The preserved Cloudflare ruleset therefore cannot evaluate:

- POST-body-only SQLi, XSS, SSTI, deserialization, React2Shell, or Spring4Shell payloads;
- file-upload content, multipart parser anomalies, or magic bytes in uploaded files;
- response-body data leakage and webshell output;
- duplicate raw header instances when ingest has already collapsed them into a JSON object;
- packet/connection properties such as destination port and TCP framing;
- endpoint follow-on behavior, outbound C2, process creation, or file writes.

Do not compensate by pretending URI-only rules cover request bodies. A body-capable adapter must advertise `request_body` or `response_body` only when capture is complete within documented truncation/decompression limits. Body retention requires explicit size, privacy, and redaction controls.

## Production tuning

Run all rules in alert-only mode first. Tune by hostname, route, verified bots, trusted scanner ranges, and known administration sources. Preserve attempts returning 4xx/404: an unsuccessful exploit is still valuable reconnaissance telemetry. Status constraints are present only where they materially improve a source rule's precision.

The catalog detects; it does not authorize blocking. Keep mitigation, rate limiting, and WAF mutation as separate reviewed workflows.

## Upstream resources

- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma)
- [Google Cloud security analytics](https://github.com/GoogleCloudPlatform/security-analytics)
- [Google SecOps community detection rules](https://github.com/chronicle/detection-rules/tree/main/rules/community)
- [MITRE CAR](https://car.mitre.org/analytics/)
- [Elastic detection rules](https://github.com/elastic/detection-rules/tree/main/rules)
- [Splunk Security Content](https://research.splunk.com/detections/)
- [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries)
