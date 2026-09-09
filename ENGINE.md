# http-detection-agent engine

A CPU-only Rust streaming detector using the saved, attributed HTTP catalog. The engine supports two strategies built on the ordinary Rust `regex` crate, with the same parsing, normalization and rule semantics.

## Build and run

```sh
cargo build --release --locked

target/release/http-detect inspect \
  --profile profiles/internet-background-noise.json --status all --matcher plain

target/release/http-detect scan requests.ndjson \
  --profile profiles/internet-background-noise.json --status all \
  --events-only --threads 18 --matcher plain \
  --output findings.ndjson --summary summary.json
```

`--matcher plain` compiles each regex pattern once and evaluates predicates on demand with `Regex::is_match`. It does not use RegexSet or share predicate-result caches across rules. `--matcher grouped` uses RegexSet plus shared predicate-result caching. Both preserve short-circuit conditions, SIMD JSON tapes, field projection, lazy transformed-text caching, parallel chunks and exact findings. The default is `grouped`; choose a strategy using measurements on your own representative input.

`--status all` includes test/candidate rules; the safer rule-status default is `production`. No rules, transforms, severities or provenance are changed by matcher selection.

The current catalog has 76 rules. Its 23 latest additions are test-status candidates; the production selection is unchanged. The normalized-field signatures run under both CPU matchers, but parsed upload, JSON, GraphQL, and JWT fields must come from an adapter implementing [their contracts](docs/SUPERSET_EXPANSION.md). The generic NDJSON reader does not parse those protocols.

## Input preparation and event-time sorting

The detector reads normalized NDJSON/JSONL, optionally compressed with gzip or zstd. Convert source-specific exports with a trusted adapter that implements the [normalized field contract](schema/normalized-http-extensions.json) and advertises only the capabilities it actually preserves.

```sh
mkdir -p runtime
target/release/http-detect sort-by-time requests.ndjson \
  --output runtime/requests-sorted.ndjson --temp-dir runtime \
  --memory-mib 512 --summary runtime/sort.json

target/release/http-detect scan runtime/requests-sorted.ndjson \
  --profile /path/to/source-profile.json --status production \
  --max-key-bytes 8192 --matcher grouped \
  --output runtime/findings.ndjson --summary runtime/scan.json
```

Source timestamps may be unordered, so exact aggregate evaluation requires event-time-ordered input or an explicit bounded lateness policy. Event-only scanning requires neither sorting nor timestamps. Output paths must be new: findings, summaries and sorted datasets are never overwritten. Runtime traffic and generated reports remain local and gitignored. Findings and summaries can contain sensitive source paths, group keys, or traffic metadata; review them before sharing.

## Execution and limits

1. Resolve status/profile requirements once; report every excluded rule.
2. Stream line-aligned NDJSON chunks from files, gzip (including concatenated members), zstd or stdin. Inputs are processed in argument order, without loading the complete dataset into RAM.
3. Rayon workers project fields from reusable SIMD JSON tapes and normalize text lazily. Each worker processes records within bounded chunks using the selected ordinary Rust regex strategy.
4. An ordered coordinator emits event findings and evaluates exact sliding windows. Counts-only still evaluates rules and hashes ordered findings; it only omits individual finding serialization.

- Missing fields stay null. Field names and map keys are case-insensitive; values are not globally lowercased. Transform order matters. Percent decoding is exactly one or two passes and preserves literal `+`. HTML decoding includes numeric and legacy semicolonless entities.
- Aggregate windows are `(event_time − window, event_time]`; equal timestamps preserve input order. Default late-event policy is an error. `--lateness-seconds` enables bounded reordering; explicit `--late-policy drop` counts every dropped contribution. Integers default to nanoseconds; other units, RFC3339 and UTC SQL timestamps are supported.
- Thresholds are evaluated after expiration and insertion on each contributing request for a group. An alert rearms when that observed state falls below threshold or the group expires. There is no timer-only rearming between contributing requests. Steady expire/insert transitions do not generate duplicate crossing alerts.
- Findings are per rule/variant, not unique malicious requests. Downstream family rollups must retain every contributing variant's evidence and attribution.
- Default chunks: 4 MiB; maximum line: 1 MiB. Invalid JSON, oversized lines, bad aggregate timestamps, oversized keys and exhausted budgets fail visibly. `--invalid-policy skip` is explicit and counted.
- Defaults: 1,000,000 window entries; 200,000 groups; 200,000 pending records; 4,096-byte keys; 1,024 MiB accounted aggregate state. The sorting example raises the key limit to 8,192 bytes for long URI group keys. `--state-mib` budgets logical state, not process RSS; parser, regex, allocator and output buffers need additional memory. There is no silent state eviction.
- Every finding includes rule ID, family, severity, confidence, source metadata and upstream author provenance. Event findings include line/byte location; aggregates include group, time window and metric evidence. Do not strip attribution from displayed matches.
- Failed scans can leave partial output. Check exit status, `complete`, counters and errors before consuming results. Sort failures can also leave a partial destination; retry with a new output name.
- The corpus is unlabeled. Counts, matcher equivalence and throughput do not establish precision, recall, false-positive rates or exploit success. Captured bodies may be incomplete. Keep production rollouts alert-only pending independent, environment-specific review.

## Rule tuning

The canonical duplicate-header rule exempts repeated `Accept-Encoding` and `Connection` alone based on RFC 9110's list grammar. Duplicate `Host`, `Content-Length` and `Transfer-Encoding` still alert. This is not a complete HTTP framing validator; other legitimate repeatable headers can still require tuning.

`rules/ibn-observed.json` is an opt-in, test-status overlay containing one conjunctive D-Link NAS command-execution attempt rule. It is separate from the 76-rule canonical catalog. Its provenance describes the dataset that motivated it; no captured requests are shipped. A request pattern does not prove successful exploitation, and this candidate needs independent labeling and environment-specific review.

## Correctness checks

```sh
python3 scripts/verify_engine.py --output runtime/verification.json
```

This runs formatting, Rust tests, Clippy, Python tests, catalog validation, and Python/Rust differential fixtures under both matchers. It builds the binary used for comparison instead of relying on an existing release executable. Only synthetic fixtures are needed. Verification output is local and should not be committed.

The engine is MIT licensed. Separately loaded catalogs retain their recorded upstream terms; do not remove source attribution from findings.
