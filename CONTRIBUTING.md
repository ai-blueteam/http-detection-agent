# Contributing

Use Rust 1.88 or newer and Python 3.9 or newer. Python tooling requires no third-party packages. Run commands from the repository root.

```sh
python3 scripts/verify_engine.py --output runtime/verification.json
```

Use a new output filename for repeated verification runs. No downloaded traffic or separate schema checkout is required. Preserve synthetic tests and add positive, negative, missing-field, and missing-capability cases for rule changes.

For MCP changes, also run `uv run --project companion --locked python -m unittest discover -s companion/tests -v` after building the debug binary. Keep the two skill copies in `.agents/skills/` and `.claude/skills/` identical. See [the companion guide](docs/AGENT_COMPANION.md) for setup. CI runs the engine and companion checks on Linux, macOS, and Windows.

Keep canonical IDs stable, retain source revisions/authors/licenses, and regenerate the compiled profiles when changing catalog data. Do not update the Cloudflare baseline lock merely to make a test pass; changes to that preserved set need explicit review. New heuristics stay `test` until independently reviewed and tuned.

Original code contributions are under the project's MIT license. Detection rules are separately licensed according to their provenance; do not copy incompatible upstream material or label mixed-license rules MIT. Keep every applicable upstream notice and mark adaptations. See [third-party notices](THIRD_PARTY_NOTICES.md).

Never commit real traffic, findings, credentials, local paths, generated results, caches, or build outputs. Use fictional fixtures with reserved example domains and addresses. Ignore rules are a safety net, not a substitute for reviewing the exact staged files and Git history before publication.

See [SECURITY.md](SECURITY.md) for responsible vulnerability reporting.
