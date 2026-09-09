# Third-party notices

## License scope

The original Rust engine, Python tooling, MCP companion, agent skills, and project-authored documentation are licensed under [MIT](LICENSE), copyright 2026 Ghost Security Inc. and http-detection-agent contributors. Cargo's `license = "MIT"` describes the engine code; rules are loaded separately, not embedded into that binary. Historical author attribution in rule provenance is retained unchanged.

The detection data in `rules/`, its compiled copies in `rulesets/`, and any adapted source material retain their applicable upstream terms. This repository is **not an MIT-only rules distribution**. Adding the MIT license does not remove Apache notice obligations, Sigma match-attribution requirements, Creative Commons share-alike terms, or Elastic restrictions. No third-party material is relicensed by this project.

The catalog contains normalized and modified detection logic derived from or corroborated by the sources below. Each catalog rule retains source IDs, paths, authors, and its relationship to the upstream work.

Modification notice: upstream logic and guidance have been selected, deduplicated, translated to the normalized HTTP field model, combined with other predicates, and tuned for the documented capability and transform contracts. These are modified adaptations, not original upstream releases. Multiple sources may apply to one rule; retaining one source's notice does not cancel the others.

## Apache License 2.0 sources

- OWASP ModSecurity Core Rule Set — Copyright OWASP CRS contributors — [source and license](https://github.com/coreruleset/coreruleset/blob/main/LICENSE)
- Google Cloud security analytics — Copyright Google LLC — [source and license](https://github.com/GoogleCloudPlatform/security-analytics/blob/main/LICENSE)
- Google SecOps community detection rules — Copyright Google LLC and contributors — [source and license](https://github.com/chronicle/detection-rules/blob/main/LICENSE)
- MITRE Cyber Analytics Repository — Copyright The MITRE Corporation — [source license](https://github.com/mitre-attack/car/blob/master/LICENSE.txt) and [notice](https://github.com/mitre-attack/car/blob/master/NOTICE.txt)
- Splunk Security Content — Copyright Splunk Inc. and contributors — [source and license](https://github.com/splunk/security_content/blob/develop/LICENSE)

These works are licensed under the [Apache License 2.0](LICENSES/Apache-2.0.txt). The normalized rules are modified from their original formats and data models. MITRE's [original NOTICE](LICENSES/MITRE-CAR-NOTICE.txt) is included unchanged.

## Detection Rule License 1.1 source

SigmaHQ detection rules are licensed under [DRL-1.1](LICENSES/DRL-1.1.md). DRL requires author attribution both when reproducing rules and when displaying matches. Sigma-derived catalog entries therefore include non-empty `authors`; a conforming engine must show that provenance in finding output. The included license text is from [Detection-Rule-License revision bcbdc605172d00390572cd774ba395ec9e975dfc](https://github.com/SigmaHQ/Detection-Rule-License/blob/bcbdc605172d00390572cd774ba395ec9e975dfc/LICENSE.Detection.Rules.md).

## Elastic License 2.0 source

The `http.exploit.cpanel-crlf-auth-bypass` and `http.exploit.react2shell-request-body` rules are adapted from Elastic's detection-rules repository, attributed to Elastic in their upstream author fields, under the [Elastic License 2.0](LICENSES/Elastic-2.0.txt). They have been modified for the normalized HTTP model and must retain this notice. Elastic License 2.0 includes limitations on providing the licensed software as a hosted or managed service; review the license before distributing or commercializing a service containing these rules. The included terms come from the catalog's pinned Elastic revision. These rules are not covered by the engine's MIT grant.

This notice is operational guidance, not legal advice.

## OWASP Cheat Sheet Series

The new rules citing `owasp-cheatsheets` adapt guidance from five documents in the [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries/tree/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b), by the OWASP Cheat Sheet Series Team, under [CC-BY-SA-4.0](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/LICENSE.md). The catalog records the exact document and section for each use.

These are modified adaptations into normalized field predicates, with locally chosen thresholds and synthetic tests. They are not executable rules published by OWASP. Retain attribution, the license link, and the modification notice; adapted material is offered under [CC-BY-SA-4.0](LICENSES/CC-BY-SA-4.0.md). The full terms from the pinned upstream revision are included. This does not relicense unrelated Rust engine code or other source-derived rules.

## Optional dataset adapter and independently authored overlay

The optional importer supports [Internet-background-noise](https://huggingface.co/datasets/burpheart/Internet-background-noise), by burpheart, revision `a92ffd4bb88d12a9c8860c375d4135fe24d0c4ce`, whose dataset card specifies Apache-2.0. Downloads, captured traffic, scan results, and benchmark artifacts are not redistributed in this repository. The opt-in `rules/ibn-observed.json` candidate was independently authored from observed request patterns; its attribution and dataset revision are retained in every corresponding finding.

## Rust dependencies

Dependencies retain their upstream licenses. Exact versions are pinned in `Cargo.lock`; `cargo metadata --locked --all-features --format-version 1` exposes the packages' declared license expressions and source locations. No vendored dependency source or prebuilt binary is distributed here. Distributors of compiled binaries must also provide the applicable dependency notices.

`src/html.rs` uses the `html-escape` crate's named entity table at runtime and implements HTML character-reference handling; see that crate's upstream license when distributing linked binaries.

## Optional MCP dependencies

The companion uses the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), under MIT, without vendoring it. `companion/uv.lock` pins its transitive dependencies, which retain their own licenses. Installing the companion does not change detection-rule licenses.
