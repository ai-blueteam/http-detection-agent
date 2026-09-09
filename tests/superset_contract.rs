use http_detection_agent::{
    catalog::{Catalog, Profile},
    engine::{Engine, Matcher},
};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

fn load_json(path: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap(),
    )
    .unwrap()
}

fn catalog() -> Catalog {
    Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/http-attacks.json")).unwrap()
}

fn hits(engine: &Engine, input: &Value) -> BTreeSet<String> {
    let mut bytes = serde_json::to_vec(input).unwrap();
    let tape = simd_json::to_tape(&mut bytes).unwrap();
    let mut event = engine.event(tape.as_value()).unwrap();
    engine
        .events
        .iter()
        .filter(|(_, expr)| engine.evaluate(expr, &mut event))
        .map(|(id, _)| engine.catalog.rules[*id].id.clone())
        .collect()
}

#[test]
fn expanded_signatures_match_positive_and_reject_near_misses_in_both_matchers() {
    let fixtures = load_json("tests/fixtures/http-superset-expansion.json");
    for matcher in [Matcher::Plain, Matcher::Grouped] {
        let engine = Engine::compile_with_matcher(catalog(), matcher).unwrap();
        for case in fixtures["rules"].as_array().unwrap() {
            let id = case["rule_id"].as_str().unwrap();
            for (kind, expected) in [("positive", true), ("negative", false)] {
                for event in case[kind].as_array().unwrap() {
                    assert_eq!(
                        hits(&engine, event).contains(id),
                        expected,
                        "{matcher:?}: {id} {kind}: {event}"
                    );
                }
            }
            assert!(!hits(&engine, &serde_json::json!({})).contains(id));
        }
    }
}

#[test]
fn profiles_and_parser_capabilities_gate_candidates_before_evaluation() {
    let fixtures = load_json("tests/fixtures/http-superset-expansion.json");
    let cf: Profile =
        serde_json::from_value(load_json("profiles/cloudflare-log-explorer.json")).unwrap();
    let full: Profile =
        serde_json::from_value(load_json("profiles/multisource-full-http.json")).unwrap();
    let mut cf_catalog = catalog();
    let excluded = cf_catalog.select("all", false, Some(&cf));
    assert_eq!(cf_catalog.rules.len(), 43);
    for case in fixtures["rules"].as_array().unwrap() {
        let id = case["rule_id"].as_str().unwrap();
        assert!(excluded.iter().any(|r| r.id == id));
    }
    let mut all = catalog();
    assert!(all.select("all", false, Some(&full)).is_empty());
    assert_eq!(all.rules.len(), catalog().rules.len());
    for capability in [
        "parsed_jwt",
        "graphql_ast",
        "parsed_json_body",
        "multipart_metadata",
        "file_upload_content",
    ] {
        let mut profile: Profile =
            serde_json::from_value(load_json("profiles/multisource-full-http.json")).unwrap();
        profile.capabilities.remove(capability);
        let mut partial = catalog();
        partial.select("all", false, Some(&profile));
        assert!(
            partial.rules.iter().all(|r| !r
                .requirements
                .capabilities
                .iter()
                .any(|c| c == capability))
        );
    }
    let profile: Profile = serde_json::from_value(serde_json::json!({
        "id": "depth-only", "fields": ["graphqlmaxdepth"], "capabilities": ["graphql_ast"]
    }))
    .unwrap();
    let mut partial = catalog();
    partial.select("all", false, Some(&profile));
    assert_eq!(partial.rules.len(), 1);
    assert_eq!(partial.rules[0].id, "http.api.graphql-complexity");
}
