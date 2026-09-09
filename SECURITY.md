# Security

This detector analyzes untrusted input and produces security signals; it does not prove exploitation or authorize blocking. Start with alert-only use and validate behavior against your own labeled traffic.

Keep input size, aggregate state, group-key, decompression, and event-order limits enabled. Only trusted adapters may advertise capabilities or populate parsed metadata. Missing or truncated telemetry must not be represented as complete capture.

Logs, normalized bodies, findings, summaries, and local verification output can expose sensitive data. Keep them out of public issues and commits. The `.gitignore` covers common generated artifacts, but cannot recognize every private file.

For a suspected vulnerability, use the repository's private vulnerability reporting channel if enabled, or contact a maintainer privately. Do not post an unpatched exploit, credentials, customer traffic, or personal data in a public issue. Provide a minimal synthetic reproducer, affected version, expected behavior, and impact.

There is currently no published support SLA or independently certified security guarantee. Dependencies and rule sources retain their own licenses.
