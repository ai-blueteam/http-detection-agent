# MCP and agent skills

`http-detection-agent` works as a standalone Rust CLI (`http-detect`), an optional local MCP server, or either interface guided by portable skills. No model API key is required by this project. Agent clients have their own authentication and permissions.

## Build and install the optional companion

From the checkout, with Rust 1.88+, Python 3.10+, and [uv](https://docs.astral.sh/uv/):

```sh
cargo build --release --locked
uv sync --project companion --locked
```

The SDK and transitive Python dependencies are pinned in `companion/uv.lock`. The Rust CLI does not depend on Python or MCP. Use an absolute checkout path in client configuration, and explicitly choose the directory containing logs the agent may analyze.

```sh
uv run --project /path/to/http-detection-agent/companion --locked python /path/to/http-detection-agent/companion/server.py --data-root /path/to/authorized-logs
```

This starts a **stdio-only** server, not an HTTP listener. A terminal invocation waits for MCP messages; do not type shell commands into it. `--help` describes startup options. On Windows, the default binary is `target/release/http-detect.exe`; quoted forward-slash paths such as `C:/work/http-detection-agent` work in the commands and JSON below. The server is independent of the client's working directory.

## Connect Codex

```sh
codex mcp add http-detection-agent -- uv run --project /path/to/http-detection-agent/companion --locked python /path/to/http-detection-agent/companion/server.py --data-root /path/to/authorized-logs
```

Alternatively merge this entry into your Codex configuration, substituting real absolute paths. Do not overwrite other servers:

```toml
[mcp_servers.http-detection-agent]
command = "uv"
args = ["run", "--project", "/path/to/http-detection-agent/companion", "--locked", "python", "/path/to/http-detection-agent/companion/server.py", "--data-root", "/path/to/authorized-logs"]
startup_timeout_sec = 30
tool_timeout_sec = 330
```

Install dependencies before connecting so startup does not wait for downloads. The client timeout should exceed the companion's scan timeout. These settings follow the [official Codex MCP documentation](https://developers.openai.com/codex/mcp/).

## Connect Claude Code

```sh
claude mcp add --transport stdio --scope local http-detection-agent -- uv run --project /path/to/http-detection-agent/companion --locked python /path/to/http-detection-agent/companion/server.py --data-root /path/to/authorized-logs
```

For project-level configuration, merge an entry like this into `.mcp.json` and review it before enabling it:

```json
{
  "mcpServers": {
    "http-detection-agent": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--project", "/path/to/http-detection-agent/companion", "--locked", "python", "/path/to/http-detection-agent/companion/server.py", "--data-root", "/path/to/authorized-logs"]
    }
  }
}
```

Use the client's supported timeout settings for long scans; cancellation stops the engine. Local machine configuration is gitignored. See [Claude Code's MCP guide](https://code.claude.com/docs/en/mcp) for scopes, approval, and timeout configuration.

## Tools and boundaries

| Tool | Purpose | Local writes |
|---|---|---|
| `list_profiles` | Bundled field/capability profiles | None |
| `inspect_rules` | Eligible IDs/counts and exact exclusions | None retained |
| `get_rule` | Predicates, requirements, status, sources, authors, licenses | None |
| `scan_http` | Run the Rust detector and return an attributed summary | New private run directory; optional findings |

Scans default to production rules, event-only evaluation, two threads, and counts-only output. A profile is always required. Set `save_findings=true` to retain complete attributed findings locally; raw findings, bodies, IP/group values, and stderr are not returned by MCP. Matched-rule metadata retains authors and source licenses even for counts-only results.

- `--data-root` is required and repeatable; inputs must be regular normalized `.ndjson`/`.jsonl` files, optionally suffixed `.gz` or `.zst`, within those directories after symlink resolution. URLs, stdin, device paths, and arbitrary shell switches are not accepted.
- `--output-root` defaults to `runtime/mcp`. Each scan creates a unique directory; earlier files are never overwritten. The server does not expose file deletion or arbitrary file reading.
- One engine operation runs at a time. Default timeout: 300 seconds; maximum: 3,600. Default thread ceiling: four. MCP scans cap accounted aggregate state at 128 MiB, 100,000 window entries, 10,000 groups/pending records, and 8,192-byte keys; engine line/batch limits remain enabled. These are not an OS sandbox or a process-RSS guarantee. Counts-only is the lightweight default; opt-in findings can consume substantial disk space.
- For aggregate rules, use `events_only=false` with event-time-ordered input and the correct `timestamp_unit`. Invalid and late events fail visibly. Use the CLI for Parquet import, sorting, custom profiles/overlays, or different resource limits.
- Check `summary.complete` and `exit_code`. Failure, timeout, or cancellation can leave partial local files, which must not be described as a successful scan. Diagnostics can contain untrusted/private text; do not blindly paste them into an agent conversation.
- The checkout, configured binary, profiles, and output directory are trusted operator-controlled configuration. Restart after changing catalog/profile files. Do not expose this stdio companion as an unauthenticated network service or point it at untrusted executable files.

The server does not change WAF settings, block clients, execute payloads, upload traffic, or call an LLM. Normal MCP responses become visible to the connected agent and its configured model provider. Match counts are not ground-truth labels or proof of exploitation.

## Portable skills, with or without MCP

Two skills are checked in for automatic project discovery:

- `http-detection-scan`: compatibility-aware scanning, triage, and safe interpretation.
- `http-detection-rules`: rule explanation/maintenance, attribution, fixtures, and baseline preservation.

Codex copies live in `.agents/skills/`; identical Claude Code copies live in `.claude/skills/`. Tests check that they stay in sync. They use standard `SKILL.md` name/description frontmatter and do not depend on client-specific hooks or tool allowlists. Their discovery paths follow the [Codex skills guide](https://developers.openai.com/codex/skills/) and [Claude Code skills guide](https://code.claude.com/docs/en/skills).

Examples:

```text
Codex: $http-detection-scan analyze my normalized access logs and explain excluded rules
Claude Code: /http-detection-scan analyze my normalized access logs
Either agent: Explain this detection and its visibility requirements using http-detection-rules
```

With no MCP server connected, the skills use `http-detect` and the checkout's scripts directly. To use them from another repository, copy the two complete skill folders to that agent's supported user skill directory and tell the agent where this checkout is installed. No global configuration or user skills are installed automatically by this repository.

## Verify the companion

```sh
cargo build --locked
uv run --project companion --locked python -m unittest discover -s companion/tests -v
```

Tests use synthetic temporary inputs, launch a real stdio SDK client/server, compare results with the CLI, and check path, output, attribution, timeout, and cancellation behavior. The server uses the [official Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk); protocol negotiation and framing are handled by that SDK, not a custom JSON-RPC implementation.
