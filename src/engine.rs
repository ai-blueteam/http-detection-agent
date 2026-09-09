use crate::catalog::*;
use anyhow::{Result, bail, ensure};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde_json::Value as Json;
use simd_json::{prelude::*, tape::Value};
use std::{borrow::Cow, collections::HashMap};

/// Both strategies use the ordinary Rust regex crate and the same input pipeline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    /// Compile each pattern once; evaluate predicates directly on demand.
    Plain,
    /// Share predicate results and scan related patterns with RegexSet.
    #[default]
    Grouped,
}

#[derive(Clone, Debug)]
pub enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    Pred(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Slot {
    pub field: usize,
    pub transforms: Vec<Transform>,
}

#[derive(Clone)]
pub struct CompiledPredicate {
    pub spec: Predicate,
    pub slot: usize,
    pub regex: Option<(usize, usize)>,
    individual: Option<Regex>,
    text: String,
    texts: Vec<String>,
}

#[derive(Clone)]
pub struct RegexGroup {
    pub slot: usize,
    pub op: Op,
    pub key: Option<String>,
    pub patterns: Vec<String>,
    pub set: RegexSet,
}

#[derive(Clone)]
pub struct MetricPlan {
    pub spec: Metric,
    pub field: Option<usize>,
    pub condition: Option<Expr>,
}
#[derive(Clone)]
pub struct AggregatePlan {
    pub rule: usize,
    pub spec: Aggregate,
    pub fields: Vec<usize>,
    pub prefilter: Option<Expr>,
    pub metrics: Vec<MetricPlan>,
}

#[derive(Clone)]
pub struct Engine {
    pub matcher: Matcher,
    pub catalog: Catalog,
    pub fields: Vec<String>,
    field_ids: HashMap<String, usize>,
    pub slots: Vec<Slot>,
    pub predicates: Vec<CompiledPredicate>,
    predicate_ids: HashMap<String, usize>,
    pub groups: Vec<RegexGroup>,
    pub events: Vec<(usize, Expr)>,
    pub aggregates: Vec<AggregatePlan>,
    pub timestamp: usize,
}

pub struct Event<'a, 'b> {
    pub fields: Vec<Value<'a, 'b>>,
    texts: Vec<Option<Option<Cow<'b, str>>>>,
    predicates: Vec<Option<bool>>,
    matches: Vec<Option<Vec<bool>>>,
}

pub fn json_text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        Json::Bool(true) => "True".into(),
        Json::Bool(false) => "False".into(),
        Json::Null => "None".into(),
        _ => v.to_string(),
    }
}

pub fn scalar(v: Value<'_, '_>) -> Json {
    if let Some(s) = v.as_str() {
        Json::String(s.to_owned())
    } else if let Some(n) = v.as_i64() {
        n.into()
    } else if let Some(n) = v.as_u64() {
        n.into()
    } else if let Some(n) = v.as_f64() {
        Json::from(n)
    } else if let Some(b) = v.as_bool() {
        b.into()
    } else {
        Json::Null
    }
}

pub fn text_value<'b>(v: Value<'_, 'b>) -> Option<Cow<'b, str>> {
    if v.is_null() {
        None
    } else if let Some(s) = v.into_string() {
        Some(Cow::Borrowed(s))
    } else if v.as_array().is_some() || v.as_object().is_some() {
        None
    } else {
        Some(Cow::Owned(json_text(&scalar(v))))
    }
}

pub fn transform<'a>(mut s: Cow<'a, str>, transforms: &[Transform]) -> Cow<'a, str> {
    for t in transforms {
        match t {
            Transform::Lowercase => {
                if s.chars().any(char::is_uppercase) {
                    s = Cow::Owned(s.to_lowercase());
                }
            }
            Transform::UrlDecode1 | Transform::UrlDecode2 => {
                for _ in 0..if *t == Transform::UrlDecode2 { 2 } else { 1 } {
                    if s.contains('%') {
                        s = Cow::Owned(
                            percent_encoding::percent_decode_str(&s)
                                .decode_utf8_lossy()
                                .into_owned(),
                        );
                    }
                }
            }
            Transform::HtmlEntityDecode => {
                if s.contains('&') {
                    s = Cow::Owned(crate::html::decode(&s));
                }
            }
            Transform::PathOnly => {
                // RFC-style URI path extraction; preserve semicolons and literal plus signs.
                let mut path = s.as_ref();
                if let Some(i) = path.find(':') {
                    let scheme = &path[..i];
                    if scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                        && scheme
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                    {
                        path = &path[i + 1..];
                    }
                }
                if let Some(authority) = path.strip_prefix("//") {
                    path = authority
                        .find(['/', '?', '#'])
                        .map_or("", |i| &authority[i..]);
                }
                path = path.split(['?', '#']).next().unwrap_or("");
                if path != s {
                    s = Cow::Owned(path.to_owned());
                }
            }
        }
    }
    s
}

impl Engine {
    pub fn compile(catalog: Catalog) -> Result<Self> {
        Self::compile_with_matcher(catalog, Matcher::default())
    }

    pub fn compile_with_matcher(catalog: Catalog, matcher: Matcher) -> Result<Self> {
        let mut e = Self {
            matcher,
            catalog,
            fields: vec![],
            field_ids: HashMap::new(),
            slots: vec![],
            predicates: vec![],
            predicate_ids: HashMap::new(),
            groups: vec![],
            events: vec![],
            aggregates: vec![],
            timestamp: 0,
        };
        e.timestamp = e.field("edgeendtimestamp");
        for (idx, rule) in e.catalog.rules.clone().into_iter().enumerate() {
            if let Some(condition) = rule.condition {
                let expr = e.compile_expr(&condition)?;
                e.events.push((idx, expr));
            }
            if let Some(spec) = rule.aggregate {
                ensure!(
                    spec.window_seconds > 0 && spec.window_seconds <= 31_536_000,
                    "invalid aggregate window in {}",
                    rule.id
                );
                ensure!(
                    !spec.group_by.is_empty() && !spec.metrics.is_empty(),
                    "empty aggregate in {}",
                    rule.id
                );
                let fields = spec.group_by.iter().map(|f| e.field(f)).collect();
                let prefilter = spec
                    .prefilter
                    .as_ref()
                    .map(|c| e.compile_expr(c))
                    .transpose()?;
                let mut metrics = vec![];
                let mut names = std::collections::HashSet::new();
                for m in &spec.metrics {
                    ensure!(names.insert(m.name.clone()), "duplicate metric {}", m.name);
                    ensure!(
                        m.op == MetricOp::Count || m.field.is_some(),
                        "metric field required"
                    );
                    let field = m.field.as_ref().map(|f| e.field(f));
                    let condition = m
                        .condition
                        .as_ref()
                        .map(|c| e.compile_expr(c))
                        .transpose()?;
                    metrics.push(MetricPlan {
                        spec: m.clone(),
                        field,
                        condition,
                    });
                }
                validate_having(&spec.having, &names)?;
                e.aggregates.push(AggregatePlan {
                    rule: idx,
                    spec,
                    fields,
                    prefilter,
                    metrics,
                });
            }
        }
        if matcher == Matcher::Grouped {
            for group in &mut e.groups {
                group.set = RegexSetBuilder::new(&group.patterns)
                    .size_limit(64 << 20)
                    .dfa_size_limit(8 << 20)
                    .build()?;
            }
        }
        Ok(e)
    }

    fn field(&mut self, name: &str) -> usize {
        let name = name.to_lowercase();
        if let Some(id) = self.field_ids.get(&name) {
            *id
        } else {
            let id = self.fields.len();
            self.fields.push(name.clone());
            self.field_ids.insert(name, id);
            id
        }
    }

    fn compile_expr(&mut self, c: &Condition) -> Result<Expr> {
        Ok(match c {
            Condition::All { all } => {
                ensure!(!all.is_empty(), "empty all condition");
                Expr::All(
                    all.iter()
                        .map(|c| self.compile_expr(c))
                        .collect::<Result<_>>()?,
                )
            }
            Condition::Any { any } => {
                ensure!(!any.is_empty(), "empty any condition");
                Expr::Any(
                    any.iter()
                        .map(|c| self.compile_expr(c))
                        .collect::<Result<_>>()?,
                )
            }
            Condition::Not { not } => Expr::Not(Box::new(self.compile_expr(not)?)),
            Condition::Predicate(p) => {
                let key = serde_json::to_string(p)?;
                if let Some(id) = self.predicate_ids.get(&key) {
                    return Ok(Expr::Pred(*id));
                }
                ensure!(p.metric.is_none(), "metric predicate outside having");
                let field = self.field(
                    p.field
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing predicate field"))?,
                );
                ensure!(
                    p.flags
                        .iter()
                        .all(|f| matches!(f.as_str(), "i" | "m" | "s")),
                    "unsupported regex flag"
                );
                let slot = Slot {
                    field,
                    transforms: p.transforms.clone(),
                };
                let slot = if let Some(id) = self.slots.iter().position(|s| s == &slot) {
                    id
                } else {
                    self.slots.push(slot);
                    self.slots.len() - 1
                };
                let mut regex = None;
                let mut individual = None;
                if matches!(
                    p.op,
                    Op::Regex | Op::MapValueRegex | Op::MapKeyValueRegex | Op::ArrayValueRegex
                ) {
                    let pattern = p
                        .value
                        .as_ref()
                        .and_then(Json::as_str)
                        .ok_or_else(|| anyhow::anyhow!("regex requires string value"))?;
                    let pattern = format!("(?{}:{pattern})", p.flags.concat());
                    // Validate individually, so one malformed pattern cannot quietly disable coverage.
                    let compiled = RegexBuilder::new(&pattern)
                        .size_limit(64 << 20)
                        .dfa_size_limit(8 << 20)
                        .build()?;
                    if self.matcher == Matcher::Plain {
                        individual = Some(compiled);
                    }
                    if p.op == Op::MapKeyValueRegex {
                        ensure!(p.key.is_some(), "map regex requires key");
                    }
                    let group_key = p.key.as_ref().map(|s| s.to_lowercase());
                    let g = if let Some(g) = self
                        .groups
                        .iter()
                        .position(|g| g.slot == slot && g.op == p.op && g.key == group_key)
                    {
                        g
                    } else {
                        self.groups.push(RegexGroup {
                            slot,
                            op: p.op,
                            key: group_key,
                            patterns: vec![],
                            set: RegexSet::empty(),
                        });
                        self.groups.len() - 1
                    };
                    let n = self.groups[g].patterns.len();
                    self.groups[g].patterns.push(pattern);
                    regex = Some((g, n));
                }
                if p.op == Op::MapKeyExists {
                    ensure!(p.key.is_some(), "map key required");
                }
                if matches!(
                    p.op,
                    Op::Eq
                        | Op::Neq
                        | Op::Lt
                        | Op::Lte
                        | Op::Gt
                        | Op::Gte
                        | Op::Contains
                        | Op::StartsWith
                        | Op::EndsWith
                ) {
                    ensure!(p.value.is_some(), "predicate value required");
                }
                let insensitive = p.flags.iter().any(|f| f == "i");
                let norm = |s: String| if insensitive { s.to_lowercase() } else { s };
                let text = norm(p.value.as_ref().map(json_text).unwrap_or_default());
                let texts = p.values.iter().map(|v| norm(json_text(v))).collect();
                let id = self.predicates.len();
                self.predicates.push(CompiledPredicate {
                    spec: p.clone(),
                    slot,
                    regex,
                    individual,
                    text,
                    texts,
                });
                self.predicate_ids.insert(key, id);
                Expr::Pred(id)
            }
        })
    }

    pub fn event<'a, 'b>(&self, root: Value<'a, 'b>) -> Result<Event<'a, 'b>> {
        let object = root
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("each NDJSON record must be an object"))?;
        let mut fields = vec![Value::null(); self.fields.len()];
        // One projection pass; ignore unneeded subtrees without allocating a DOM.
        for (key, value) in &object {
            let lower;
            let key = if key.bytes().any(|b| b.is_ascii_uppercase()) {
                lower = key.to_ascii_lowercase();
                lower.as_str()
            } else {
                key
            };
            if let Some(id) = self.field_ids.get(key) {
                fields[*id] = value;
            }
        }
        Ok(Event {
            fields,
            texts: vec![None; self.slots.len()],
            predicates: vec![
                None;
                if self.matcher == Matcher::Grouped {
                    self.predicates.len()
                } else {
                    0
                }
            ],
            matches: vec![
                None;
                if self.matcher == Matcher::Grouped {
                    self.groups.len()
                } else {
                    0
                }
            ],
        })
    }

    pub fn evaluate(&self, expr: &Expr, event: &mut Event<'_, '_>) -> bool {
        match expr {
            Expr::All(xs) => xs.iter().all(|x| self.evaluate(x, event)),
            Expr::Any(xs) => xs.iter().any(|x| self.evaluate(x, event)),
            Expr::Not(x) => !self.evaluate(x, event),
            Expr::Pred(id) => {
                if self.matcher == Matcher::Plain {
                    return self.predicate(&self.predicates[*id], event);
                }
                if let Some(v) = event.predicates[*id] {
                    return v;
                }
                let result = self.predicate(&self.predicates[*id], event);
                event.predicates[*id] = Some(result);
                result
            }
        }
    }

    fn predicate(&self, p: &CompiledPredicate, event: &mut Event<'_, '_>) -> bool {
        let v = event.fields[self.slots[p.slot].field];
        let spec = &p.spec;
        if spec.op == Op::Exists {
            return !v.is_null();
        }
        if spec.op == Op::IsNull {
            return v.is_null();
        }
        if let Some((group, pattern)) = p.regex {
            if let Some(regex) = &p.individual {
                return match spec.op {
                    Op::Regex => event.text(p.slot, self).is_some_and(|s| regex.is_match(s)),
                    Op::MapValueRegex | Op::MapKeyValueRegex => v.as_object().is_some_and(|map| {
                        map.iter().any(|(key, value)| {
                            (spec.op == Op::MapValueRegex
                                || spec
                                    .key
                                    .as_ref()
                                    .is_some_and(|wanted| wanted.eq_ignore_ascii_case(key)))
                                && text_value(value).is_some_and(|s| regex.is_match(&s))
                        })
                    }),
                    Op::ArrayValueRegex => v.as_array().is_some_and(|array| {
                        array
                            .iter()
                            .any(|value| text_value(value).is_some_and(|s| regex.is_match(&s)))
                    }),
                    _ => unreachable!(),
                };
            }
            if event.matches[group].is_none() {
                let g = &self.groups[group];
                let mut hits = vec![false; g.patterns.len()];
                let mut check = |s: &str| {
                    for i in g.set.matches(s).iter() {
                        hits[i] = true;
                    }
                };
                match g.op {
                    Op::Regex => {
                        if let Some(s) = event.text(g.slot, self) {
                            check(s);
                        }
                    }
                    Op::MapValueRegex | Op::MapKeyValueRegex => {
                        if let Some(map) = v.as_object() {
                            for (k, value) in &map {
                                if (g.op == Op::MapValueRegex
                                    || g.key
                                        .as_ref()
                                        .is_some_and(|key| key.eq_ignore_ascii_case(k)))
                                    && let Some(s) = text_value(value)
                                {
                                    check(&s);
                                }
                            }
                        }
                    }
                    Op::ArrayValueRegex => {
                        if let Some(array) = v.as_array() {
                            for value in &array {
                                if let Some(s) = text_value(value) {
                                    check(&s);
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }
                event.matches[group] = Some(hits);
            }
            return event.matches[group].as_ref().unwrap()[pattern];
        }
        if spec.op == Op::MapKeyExists {
            return v.as_object().is_some_and(|o| {
                o.iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case(spec.key.as_ref().unwrap()))
            });
        }
        let insensitive = spec.flags.iter().any(|f| f == "i");
        if spec.op == Op::ArrayContainsAny {
            return v.as_array().is_some_and(|a| {
                a.iter().any(|v| {
                    text_value(v).is_some_and(|s| {
                        p.texts.iter().any(|x| {
                            if insensitive {
                                s.to_lowercase() == *x
                            } else {
                                s == *x
                            }
                        })
                    })
                })
            });
        }
        if spec.op == Op::ArrayDuplicateHeaderName {
            let Some(a) = v.as_array() else {
                return false;
            };
            let mut names = std::collections::HashSet::new();
            for v in &a {
                if let Some(s) = v.as_str()
                    && let Some((name, _)) = s.split_once(':')
                {
                    let name = name.trim().to_lowercase();
                    if !spec
                        .values
                        .iter()
                        .any(|x| json_text(x).to_lowercase() == name)
                        && !names.insert(name)
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        if v.is_null() {
            return false;
        }
        if matches!(spec.op, Op::Lt | Op::Lte | Op::Gt | Op::Gte) {
            let left = text_value(v).and_then(|s| s.parse::<f64>().ok());
            let right = spec
                .value
                .as_ref()
                .and_then(|v| json_text(v).parse::<f64>().ok());
            return left
                .zip(right)
                .is_some_and(|(l, r)| compare_number(l, r, spec.op));
        }
        let Some(s) = event.text(p.slot, self) else {
            return false;
        };
        let lower;
        let s = if insensitive {
            lower = s.to_lowercase();
            lower.as_str()
        } else {
            s
        };
        match spec.op {
            Op::Eq => s == p.text,
            Op::Neq => s != p.text,
            Op::Contains => s.contains(&p.text),
            Op::ContainsAny => p.texts.iter().any(|x| s.contains(x)),
            Op::StartsWith => s.starts_with(&p.text),
            Op::EndsWith => s.ends_with(&p.text),
            Op::In | Op::NotIn => {
                let found = if insensitive || v.as_str().is_some() {
                    spec.values
                        .iter()
                        .zip(&p.texts)
                        .any(|(original, x)| (insensitive || original.is_string()) && s == x)
                } else {
                    spec.values.contains(&scalar(v))
                };
                if spec.op == Op::NotIn { !found } else { found }
            }
            _ => unreachable!(),
        }
    }
}

impl<'a, 'b> Event<'a, 'b> {
    pub fn text(&mut self, slot: usize, engine: &Engine) -> Option<&str> {
        if self.texts[slot].is_none() {
            let spec = &engine.slots[slot];
            let value = self.fields[spec.field];
            let text = text_value(value).map(|s| {
                if value.as_str().is_some() {
                    transform(s, &spec.transforms)
                } else {
                    s
                }
            });
            self.texts[slot] = Some(text);
        }
        self.texts[slot].as_ref().unwrap().as_deref()
    }
}

pub fn compare_number(l: f64, r: f64, op: Op) -> bool {
    if !l.is_finite() || !r.is_finite() {
        return false;
    }
    match op {
        Op::Eq => l == r,
        Op::Neq => l != r,
        Op::Lt => l < r,
        Op::Lte => l <= r,
        Op::Gt => l > r,
        Op::Gte => l >= r,
        _ => false,
    }
}

fn validate_having(c: &Condition, names: &std::collections::HashSet<String>) -> Result<()> {
    match c {
        Condition::All { all } => {
            ensure!(!all.is_empty(), "empty having");
            for c in all {
                validate_having(c, names)?;
            }
        }
        Condition::Any { any } => {
            ensure!(!any.is_empty(), "empty having");
            for c in any {
                validate_having(c, names)?;
            }
        }
        Condition::Not { not } => validate_having(not, names)?,
        Condition::Predicate(p) => {
            ensure!(
                p.field.is_none() && p.metric.as_ref().is_some_and(|m| names.contains(m)),
                "unknown having metric"
            );
            ensure!(
                p.transforms.is_empty() && p.flags.is_empty(),
                "having flags/transforms unsupported"
            );
            if !matches!(p.op, Op::Eq | Op::Neq | Op::Lt | Op::Lte | Op::Gt | Op::Gte) {
                bail!("having requires numeric comparison");
            }
            ensure!(
                p.value.as_ref().is_some_and(Json::is_number),
                "having requires numeric value"
            );
        }
    }
    Ok(())
}
