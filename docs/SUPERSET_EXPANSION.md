# HTTP superset expansion

The canonical catalog grows from 53 to 76 rules (71 event, 5 aggregate), across 62 behavior families. All 23 additions are `test` candidates: the production selection remains 46 rules. The original 43 Cloudflare rule definitions are protected by [a content lock](../rulesets/cloudflare-baseline.lock.json) and a regression test, including predicates, tuning and provenance.

The full profile selects 76 rules; Cloudflare selects 43 and records 33 exclusions. Rule status and compatibility are independent filters: use `--status all` or `--status test` to inspect candidate coverage.

## Added coverage and source decisions

Five upload rules cover script/config/session filenames, traversal and PHP execution content. Two multipart rules cover selected charset declarations and deprecated part transfer encoding. Four response rules cover directory listings and CGI/PHP/Ruby source. Seven structured API rules cover GraphQL (3), JWT (2) and JSON injection (2). Five request-body rules add metadata SSRF, XXE and payload conjunctions for Text4Shell, Confluence and Ivanti EPM.

These are selected adaptations, not a complete translation of CRS or source-query syntax. Product rules require payload evidence alongside the relevant endpoint when applicable. Response codes are not treated as proof of exploitation. GraphQL introspection and numeric thresholds are policy-dependent signals; thresholds of depth >20, aliases >100 and batch size >10 are local candidates.

| Rule | Required capabilities | Pinned upstream evidence | Positive / negative fixtures |
|---|---|---|---|
| `http.upload.server-script` | file_upload_metadata | [crs: 933110](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf); [owasp-cheatsheets: File_Upload_Cheat_Sheet#extension-validation](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/File_Upload_Cheat_Sheet.md) | 4 / 3 |
| `http.upload.path-traversal` | file_upload_metadata | [owasp-cheatsheets: File_Upload_Cheat_Sheet#filename-safety](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/File_Upload_Cheat_Sheet.md) | 2 / 3 |
| `http.upload.server-config` | file_upload_metadata | [owasp-cheatsheets: File_Upload_Cheat_Sheet#filename-safety](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/File_Upload_Cheat_Sheet.md) | 2 / 2 |
| `http.upload.php-session-file` | file_upload_metadata | [crs: 933220](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf) | 2 / 3 |
| `http.upload.php-execution-content` | file_upload_content | [crs: 933100, 933160](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf); [owasp-cheatsheets: File_Upload_Cheat_Sheet#filename-safety](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/File_Upload_Cheat_Sheet.md) | 2 / 4 |
| `http.multipart.deprecated-transfer-encoding` | multipart_metadata | [crs: 922120](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/REQUEST-922-MULTIPART-ATTACK.conf) | 2 / 2 |
| `http.multipart.unsafe-charset` | multipart_metadata | [crs: 922100, 922110](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/REQUEST-922-MULTIPART-ATTACK.conf) | 2 / 3 |
| `http.response.directory-listing` | response_body | [crs: 950130](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/RESPONSE-950-DATA-LEAKAGES.conf) | 2 / 2 |
| `http.response.cgi-source` | response_body | [crs: 950140](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/RESPONSE-950-DATA-LEAKAGES.conf) | 2 / 3 |
| `http.response.php-source` | response_body | [crs: 953110, 953120](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf) | 2 / 3 |
| `http.response.ruby-template-source` | response_body | [crs: 956110](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/RESPONSE-956-DATA-LEAKAGES-RUBY.conf) | 2 / 3 |
| `http.api.graphql-introspection` | graphql_ast | [owasp-cheatsheets: GraphQL_Cheat_Sheet#introspection--graphiql](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/GraphQL_Cheat_Sheet.md) | 2 / 4 |
| `http.api.graphql-complexity` | graphql_ast | [owasp-cheatsheets: GraphQL_Cheat_Sheet#query-limiting-depth--amount](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/GraphQL_Cheat_Sheet.md) | 3 / 4 |
| `http.api.graphql-batch` | graphql_batch | [owasp-cheatsheets: GraphQL_Cheat_Sheet#batching-attacks](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/GraphQL_Cheat_Sheet.md) | 2 / 3 |
| `http.authentication.jwt-none` | parsed_jwt | [owasp-cheatsheets: JSON_Web_Token_Cheat_Sheet#unsecured-jwts](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/JSON_Web_Token_Cheat_Sheet.md) | 2 / 3 |
| `http.authentication.jwt-kid-traversal` | parsed_jwt | [owasp-cheatsheets: JSON_Web_Token_Cheat_Sheet#trusting-key-material-named-in-the-token-header](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/JSON_Web_Token_Cheat_Sheet.md) | 2 / 3 |
| `http.api.json-prototype-pollution` | parsed_json_body | [crs: 934130](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf) | 2 / 4 |
| `http.api.nosql-auth-operator` | parsed_json_body | [owasp-cheatsheets: NoSQL_Security_Cheat_Sheet#prevent-nosql-injection](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/NoSQL_Security_Cheat_Sheet.md) | 2 / 4 |
| `http.ssrf.cloud-metadata-request-body` | request_body | [crs: 934110](https://github.com/coreruleset/coreruleset/blob/4cfbeecdb815d1f6b10e52214fe9cb72008f2318/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf) | 2 / 3 |
| `http.xxe.external-entity-request-body` | request_body | [owasp-cheatsheets: XML_External_Entity_Prevention_Cheat_Sheet#general-guidance](https://github.com/OWASP/CheatSheetSeries/blob/382113ba1fbd7e99ffa21bcf90d7fd8a19be546b/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md) | 3 / 3 |
| `http.exploit.text4shell-request-body` | request_body | [splunk-security-content: 19a481e0-c97c-4d14-b1db-75a708eb592e](https://github.com/splunk/security_content/blob/4cd62e811c5eddf1245c780d48823d7b38998566/detections/web/exploit_public_facing_application_via_apache_commons_text.yml) | 3 / 3 |
| `http.exploit.confluence-ognl-request-body` | request_body | [splunk-security-content: f56936c0-ae6f-4eeb-91ff-ecc1448c6105](https://github.com/splunk/security_content/blob/4cd62e811c5eddf1245c780d48823d7b38998566/detections/web/confluence_pre_auth_rce_via_ognl_injection_cve_2023_22527.yml) | 2 / 4 |
| `http.exploit.ivanti-epm-recordgoodapp-sqli` | request_body | [splunk-security-content: e20564ca-c86c-4e30-acdb-a8486673426f](https://github.com/splunk/security_content/blob/4cd62e811c5eddf1245c780d48823d7b38998566/detections/web/ivanti_epm_sql_injection_remote_code_execution.yml) | 2 / 3 |

Source IDs, authors, revision, license and the adaptation relationship are retained in every rule and finding. OWASP Cheat Sheet adaptations add CC-BY-SA-4.0 attribution. Existing CRS, Sigma, Splunk, Elastic and other source revisions remain pinned.

## Adapter contract

The [full profile](../profiles/multisource-full-http.json) describes a capability ceiling. It is not an actual adapter and must not be selected blindly for arbitrary access logs. The existing Cloudflare and Internet-background-noise profiles are unchanged. The latter can use the five new raw-body signatures when test rules are enabled; it does not acquire upload/JSON/GraphQL/JWT parsers.

The Rust engine evaluates normalized fields with existing operators. This expansion adds signatures and field contracts; it does not implement protocol parsers. Adapters may supply these fields from native application telemetry or a bounded parser. The [field definitions](../schema/normalized-http-extensions.json) specify exact meanings:

| Fields | Required producer behavior |
|---|---|
| `uploadedfilenames` | Actual file-part client filenames before path sanitization; decode MIME filename syntax and preserve separators/nulls. |
| `uploadedfilecontents` | Separate bounded decoded text for each actual file part; never concatenate file contents or ordinary form values. |
| `multipartpartheaders`, `multipartcharsets` | Actual part headers and every charset declaration, including repeats and global `_charset_`; preserve multipart boundaries. |
| `requestjsonpaths` | Fully parsed JSON property paths with decoded keys and RFC 6901 escaping. Include intermediate objects; reject duplicate keys and partial parses. |
| `graphqlfieldnames` | Actual selected-operation field names after fragment resolution; exclude aliases, strings, comments and unused operations. |
| `graphqlmaxdepth`, `graphqlaliascount` | Structural metrics after fragment expansion, with cycles rejected. Either metric can enable the complexity rule. Root fields have depth 1. |
| `graphqlbatchsize` | Count validated HTTP GraphQL operation request objects; do not count an arbitrary JSON array as GraphQL. |
| `jwtalgorithm`, `jwtkeyid` | String `alg`/`kid` from the protected header of the authentication compact JWS. JSON key selection is case-sensitive; duplicate keys, ambiguous tokens, malformed base64url and JWE do not supply these fields. Do not fetch keys or infer verification success. |

Only the trusted adapter may create these top-level metadata fields. Client-supplied JSON properties with the same names must stay inside request data.

Profiles are evaluated once when loading rules. For a particular event, omitted, truncated, malformed or parser-limit-exceeding metadata must remain null; never substitute zero or empty arrays for an incomplete parse. Rules still evaluate as compatible, but cannot establish coverage of the missing event data. Keep producer-side coverage/error counters to distinguish an unevaluated signal from a clean request.

The file-content rule tests same-element proximity, the JSON rule tests key paths rather than descriptions, and GraphQL/JWT rules deliberately do not activate on raw text containing matching words. Fixtures exercise these boundaries. Supplying only `requestbody` does not enable structural parser capabilities.

## Deduplication and preservation

New URI/body or disclosure variants reuse existing behavior families where appropriate: traversal, cloud metadata SSRF, Confluence OGNL, and Node/prototype pollution. CGI/PHP/Ruby response variants share `http.response.source-disclosure`. The engine continues emitting attributed per-rule evidence; downstream transaction/family rollups can combine the variants without dropping provenance. It does not deduplicate the same transaction across separate log sources without a reliable transaction identifier.

The Cloudflare content hash is SHA-256 over its ordered rule array with recursively sorted keys, compact UTF-8 JSON and one trailing LF. Catalog-level source notes may evolve without changing that rule lock. Compiled catalogs include only sources actually cited by their selected rules.

## Verification and use

[Shared fixtures](../tests/fixtures/http-superset-expansion.json) contain 51 positive and 72 negative cases. Python tests check behavior, null inputs, field/capability failures, alternative fields, compiled-artifact freshness and the Cloudflare hash. Rust runs every fixture under both plain Regex and grouped RegexSet. The differential suite also includes all 123 new cases.

Run the checks below to verify a checkout. Generated reports are local outputs, not release fixtures. Lexical path extraction has a regression test for malformed URL authorities and is compared against Rust by the differential suite.

```sh
python3 scripts/validate_catalog.py
python3 -m unittest discover -s tests -v
cargo test --locked --no-default-features --all-targets
cargo build --locked --no-default-features
python3 scripts/differential_engine.py --binary target/debug/http-detect --matcher plain
python3 scripts/differential_engine.py --binary target/debug/http-detect --matcher grouped

python3 scripts/compile_profile.py profiles/multisource-full-http.json \
  --write rulesets/multisource-http.json --report runtime/multisource-compatibility.json
target/debug/http-detect inspect --profile profiles/multisource-full-http.json --status all
```

For actual scanning, select the profile of the adapter that produced the input. `required_fields.py --profile ...` projects only fields that profile can supply, including partial alternative-field groups.

The parser-field fixtures are synthetic adapter outputs, not parser implementations or real-traffic acceptance tests. They do not establish throughput, precision, recall, or false-positive rates.

## Remaining detection gaps

- Multipart parser disagreement, archive contents, binary file magic and decompression bombs need parser-specific evidence and resource accounting.
- JWT algorithm/key confusion needs issuer policy and verification outcomes; a header containing `jku` or `jwk` alone is insufficient.
- GraphQL resolver cost, authorization bypass, IDOR and REST business-logic abuse need schema, identity and object-ownership context.
- XXE is a bounded syntax heuristic; XML comments, alternate encodings and parser-specific entity behavior need a richer XML view.
- Full CRS transformations, libinjection and transaction scoring remain beyond these simplified signatures.
- Generic source-disclosure patterns require route tuning for public code/documentation hosting.

These gaps remain explicit requirements for later adapters or rule families.
