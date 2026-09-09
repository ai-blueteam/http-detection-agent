# Security

This detector analyzes untrusted input and produces security signals; it does not prove exploitation or authorize blocking. Start with alert-only use and validate behavior against your own labeled traffic.

Keep input size, aggregate state, group-key, decompression, and event-order limits enabled. Only trusted adapters may advertise capabilities or populate parsed metadata. Missing or truncated telemetry must not be represented as complete capture.

Logs, normalized bodies, findings, summaries, and local verification output can expose sensitive data. Keep them out of public issues and commits. The `.gitignore` covers common generated artifacts, but cannot recognize every private file.

For a suspected vulnerability, use the repository's private vulnerability reporting channel if enabled, or contact a maintainer privately. Do not post an unpatched exploit, credentials, customer traffic, or personal data in a public issue. Provide a minimal synthetic reproducer, affected version, expected behavior, and impact.

There is currently no published support SLA or independently certified security guarantee. Dependencies and rule sources retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The optional Parquet dependency currently brings in `paste` 1.0.15, covered by [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html), an unmaintained-crate notice. This dependency is absent from the default CPU-only build. It is not suppressed in dependency audits; replacing the legacy Parquet pin requires a high-row-group-count compatibility check.

## Known optional-importer advisory

The `parquet` feature also brings in `thrift` 0.17.0, flagged by [GHSA-2f9f-gq7v-9h6m / CVE-2026-43868](https://github.com/advisories/GHSA-2f9f-gq7v-9h6m) for excessive resource consumption while decoding malformed compact-protocol values. **Do not use the legacy importer on untrusted Parquet files.** The alert remains open; it is not dismissed or presented as fixed.

The default Rust build and MCP's normalized NDJSON/JSONL scan path do not depend on Parquet or Thrift. The companion does not expose the Parquet importer.

Upgrading the optional reader is pending a compatibility fix: Parquet 59.3.0 removes the Thrift dependency, but [its metadata reader](https://github.com/apache/arrow-rs/blob/59.3.0/parquet/src/file/metadata/thrift/mod.rs) still converts row-group indexes to signed 16-bit ordinals and rejects legacy files with more than 32,768 groups. A replacement must cover both malformed-input handling and those high-row-group-count files. Until then, use the default build with normalized logs produced by a maintained, independently reviewed adapter.
