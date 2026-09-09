# Third-party notices

The original engine, tooling, MCP companion, skills, and documentation are covered by the project's [MIT license](LICENSE). Detection rules and adapted rule data retain their applicable upstream terms; the MIT license does not relicense them.

Rules have been normalized, combined, deduplicated, and tuned for this project's HTTP schema. Each rule records its sources, authors, upstream IDs, revision paths, adaptation relationship, and licenses in its `provenance`.

| Material | Terms |
|---|---|
| OWASP Core Rule Set, Google Cloud security analytics, Google SecOps community rules, MITRE CAR, and Splunk Security Content | [Apache-2.0](LICENSES/Apache-2.0.txt); MITRE's [NOTICE](LICENSES/MITRE-CAR-NOTICE.txt) is included. |
| SigmaHQ detection rules | [DRL-1.1](LICENSES/DRL-1.1.md); retain rule author attribution when reproducing rules or displaying matches. |
| Elastic detection rules used by `http.exploit.cpanel-crlf-auth-bypass` and `http.exploit.react2shell-request-body` | [Elastic-2.0](LICENSES/Elastic-2.0.txt); review its hosted or managed service restrictions. |
| OWASP Cheat Sheet guidance adapted into candidate rules | [CC-BY-SA-4.0](LICENSES/CC-BY-SA-4.0.md); the adaptations are modified material. |
| Internet-background-noise-derived opt-in overlay | Dataset attribution and revision are retained in `rules/ibn-observed.json`; no captured traffic is distributed. |

Dependencies keep their own licenses. Exact Rust and optional MCP dependency versions are pinned in `Cargo.lock` and `companion/uv.lock`; no dependency source or prebuilt binary is vendored here.

This summary is not legal advice. Review the included terms for your distribution or service model.
