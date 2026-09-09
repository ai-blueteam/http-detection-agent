use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Catalog {
    pub schema_version: String,
    pub regex_dialect: String,
    pub timestamp_field: String,
    pub sources: Vec<Value>,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    pub family: String,
    pub variant: String,
    pub title: String,
    pub kind: String,
    pub status: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub provenance: Vec<Value>,
    pub required_fields: Vec<String>,
    pub requirements: Requirements,
    #[serde(rename = "match")]
    pub condition: Option<Condition>,
    pub aggregate: Option<Aggregate>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Requirements {
    pub all_fields: Vec<String>,
    pub any_fields: Vec<Vec<String>>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Condition {
    All { all: Vec<Condition> },
    Any { any: Vec<Condition> },
    Not { not: Box<Condition> },
    Predicate(Predicate),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Predicate {
    pub field: Option<String>,
    pub metric: Option<String>,
    pub op: Op,
    pub value: Option<Value>,
    #[serde(default)]
    pub values: Vec<Value>,
    pub key: Option<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub transforms: Vec<Transform>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Neq,
    In,
    NotIn,
    Contains,
    ContainsAny,
    StartsWith,
    EndsWith,
    Regex,
    Exists,
    IsNull,
    Lt,
    Lte,
    Gt,
    Gte,
    MapKeyExists,
    MapValueRegex,
    MapKeyValueRegex,
    ArrayContainsAny,
    ArrayValueRegex,
    ArrayDuplicateHeaderName,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Lowercase,
    #[serde(rename = "url_decode_1")]
    UrlDecode1,
    #[serde(rename = "url_decode_2")]
    UrlDecode2,
    HtmlEntityDecode,
    PathOnly,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    pub group_by: Vec<String>,
    pub window_seconds: i64,
    pub prefilter: Option<Condition>,
    pub metrics: Vec<Metric>,
    pub having: Condition,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metric {
    pub name: String,
    pub op: MetricOp,
    pub field: Option<String>,
    #[serde(rename = "where")]
    pub condition: Option<Condition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetricOp {
    Count,
    DistinctCount,
    Min,
    Max,
    Sum,
}

#[derive(Deserialize)]
pub struct Profile {
    pub id: String,
    pub fields: HashSet<String>,
    pub capabilities: HashSet<String>,
}

#[derive(Debug, Serialize)]
pub struct Excluded {
    pub id: String,
    pub reason: String,
}

impl Catalog {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = serde_json::from_reader(std::fs::File::open(path)?)
            .with_context(|| format!("invalid catalog {}", path.display()))?;
        ensure!(c.schema_version == "1.0.0", "unsupported catalog version");
        ensure!(c.regex_dialect == "rust-regex", "unsupported regex dialect");
        ensure!(
            c.timestamp_field == "edgeendtimestamp",
            "unsupported timestamp field"
        );
        let mut ids = HashSet::new();
        for r in &c.rules {
            ensure!(ids.insert(&r.id), "duplicate rule {}", r.id);
            match r.kind.as_str() {
                "event" => ensure!(
                    r.condition.is_some() && r.aggregate.is_none(),
                    "invalid event {}",
                    r.id
                ),
                "aggregate" => ensure!(
                    r.aggregate.is_some() && r.condition.is_none(),
                    "invalid aggregate {}",
                    r.id
                ),
                _ => bail!("unsupported rule kind {}", r.kind),
            }
            ensure!(!r.provenance.is_empty(), "missing provenance for {}", r.id);
            for p in &r.provenance {
                ensure!(
                    c.sources.iter().any(|s| s["id"] == p["source"]),
                    "unknown provenance source in {}",
                    r.id
                );
                ensure!(
                    p["authors"].is_array()
                        && p["upstream_ids"].is_array()
                        && p["path"].is_string(),
                    "invalid provenance in {}",
                    r.id
                );
                if p["source"] == "sigma" {
                    ensure!(
                        !p["authors"].as_array().unwrap().is_empty(),
                        "missing Sigma attribution in {}",
                        r.id
                    );
                }
            }
        }
        Ok(c)
    }

    pub fn select(
        &mut self,
        status: &str,
        events_only: bool,
        profile: Option<&Profile>,
    ) -> Vec<Excluded> {
        let mut excluded = Vec::new();
        self.rules.retain(|r| {
            let reason = if status != "all" && r.status != status {
                Some(format!("status {} excluded by {status}", r.status))
            } else if events_only && r.kind == "aggregate" {
                Some("event-only mode".into())
            } else if let Some(p) = profile {
                let fields: Vec<_> = r.requirements.all_fields.iter().filter(|f| !p.fields.contains(*f)).collect();
                let groups: Vec<_> = r.requirements.any_fields.iter().filter(|g| !g.iter().any(|f| p.fields.contains(f))).collect();
                let caps: Vec<_> = r.requirements.capabilities.iter().filter(|c| !p.capabilities.contains(*c)).collect();
                if fields.is_empty() && groups.is_empty() && caps.is_empty() { None }
                else { Some(format!("profile {}: missing fields {fields:?}, alternatives {groups:?}, capabilities {caps:?}", p.id)) }
            } else { None };
            if let Some(reason) = reason { excluded.push(Excluded { id: r.id.clone(), reason }); false } else { true }
        });
        excluded
    }
}
