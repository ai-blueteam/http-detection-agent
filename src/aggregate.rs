use crate::{
    catalog::{Condition, MetricOp},
    engine::{AggregatePlan, Engine, Event, compare_number, scalar},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub struct Contribution {
    pub plan: usize,
    pub key: String,
    pub values: Vec<Value>,
}

pub fn prepare(
    engine: &Engine,
    event: &mut Event<'_, '_>,
    max_key_bytes: usize,
) -> Result<Vec<Contribution>> {
    let mut output = vec![];
    for (id, plan) in engine.aggregates.iter().enumerate() {
        if plan
            .prefilter
            .as_ref()
            .is_some_and(|p| !engine.evaluate(p, event))
        {
            continue;
        }
        let keys: Vec<_> = plan
            .fields
            .iter()
            .map(|f| scalar(event.fields[*f]))
            .collect();
        // Missing identity cannot define a meaningful source/campaign group.
        if keys.iter().any(Value::is_null) {
            continue;
        }
        let key = serde_json::to_string(&keys)?;
        ensure!(
            key.len() <= max_key_bytes,
            "aggregate group key exceeds --max-key-bytes (rule {})",
            engine.catalog.rules[plan.rule].id
        );
        let mut values = vec![];
        for m in &plan.metrics {
            let value = if m
                .condition
                .as_ref()
                .is_some_and(|p| !engine.evaluate(p, event))
            {
                Value::Null
            } else if m.spec.op == MetricOp::Count {
                Value::from(1)
            } else {
                scalar(event.fields[m.field.unwrap()])
            };
            ensure!(
                value.to_string().len() <= max_key_bytes,
                "aggregate metric value exceeds --max-key-bytes"
            );
            values.push(value);
        }
        output.push(Contribution {
            plan: id,
            key,
            values,
        });
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug)]
struct Number(f64);
impl PartialEq for Number {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o).is_eq()
    }
}
impl Eq for Number {}
impl PartialOrd for Number {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Number {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&o.0)
    }
}

#[derive(Default)]
struct MetricState {
    sum: f64,
    distinct: HashMap<String, u64>,
    numbers: BTreeMap<Number, u64>,
}

impl MetricState {
    fn update(&mut self, op: MetricOp, value: &Value, add: bool) {
        if value.is_null() {
            return;
        }
        match op {
            MetricOp::DistinctCount => {
                let key = value.to_string();
                if add {
                    *self.distinct.entry(key).or_default() += 1;
                } else if let Some(n) = self.distinct.get_mut(&key) {
                    *n -= 1;
                    if *n == 0 {
                        self.distinct.remove(&key);
                    }
                }
            }
            MetricOp::Count | MetricOp::Sum => {
                if let Some(n) = number(value) {
                    self.sum += if add { n } else { -n };
                }
            }
            MetricOp::Min | MetricOp::Max => {
                if let Some(n) = number(value) {
                    let key = Number(n);
                    if add {
                        *self.numbers.entry(key).or_default() += 1;
                    } else if let Some(n) = self.numbers.get_mut(&key) {
                        *n -= 1;
                        if *n == 0 {
                            self.numbers.remove(&key);
                        }
                    }
                }
            }
        }
    }
    fn value(&self, op: MetricOp) -> Option<f64> {
        match op {
            MetricOp::DistinctCount => Some(self.distinct.len() as f64),
            MetricOp::Count | MetricOp::Sum => Some(self.sum),
            MetricOp::Min => self.numbers.first_key_value().map(|(n, _)| n.0),
            MetricOp::Max => self.numbers.last_key_value().map(|(n, _)| n.0),
        }
    }
}

fn number(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .filter(|x| x.is_finite())
}

struct Group {
    entries: usize,
    metrics: Vec<MetricState>,
    alerted: bool,
}
struct Entry {
    timestamp: i64,
    key: Arc<str>,
    values: Vec<Value>,
    charged_bytes: usize,
}
struct Window {
    plan: AggregatePlan,
    groups: HashMap<Arc<str>, Group>,
    entries: VecDeque<Entry>,
}

#[derive(Debug, Serialize)]
pub struct AggregateHit {
    #[serde(skip)]
    pub rule: usize,
    pub window_start_ns_exclusive: i64,
    pub window_end_ns_inclusive: i64,
    pub group: BTreeMap<String, Value>,
    pub metrics: BTreeMap<String, Option<f64>>,
}

pub struct Aggregator {
    windows: Vec<Window>,
    max_entries: usize,
    max_groups: usize,
    entries: usize,
    groups: usize,
    pub peak_entries: usize,
    pub peak_groups: usize,
    bytes: usize,
    max_bytes: usize,
    pub peak_bytes: usize,
}

impl Aggregator {
    pub fn new(plans: &[AggregatePlan], max_entries: usize, max_groups: usize) -> Self {
        Self {
            windows: plans
                .iter()
                .cloned()
                .map(|plan| Window {
                    plan,
                    groups: HashMap::new(),
                    entries: VecDeque::new(),
                })
                .collect(),
            max_entries,
            max_groups,
            entries: 0,
            groups: 0,
            peak_entries: 0,
            peak_groups: 0,
            bytes: 0,
            max_bytes: usize::MAX,
            peak_bytes: 0,
        }
    }

    /// Conservative accounting for entry storage, group keys and metric indexes;
    /// this budget is separate from parsing buffers and allocator overhead.
    pub fn with_byte_budget(mut self, bytes: usize) -> Self {
        self.max_bytes = bytes;
        self
    }

    pub fn advance(&mut self, timestamp: i64) {
        for w in &mut self.windows {
            let cutoff = timestamp.saturating_sub(w.plan.spec.window_seconds * 1_000_000_000);
            while w.entries.front().is_some_and(|e| e.timestamp <= cutoff) {
                let old = w.entries.pop_front().unwrap();
                self.entries -= 1;
                self.bytes -= old.charged_bytes;
                let g = w.groups.get_mut(&old.key).unwrap();
                g.entries -= 1;
                for ((state, metric), value) in
                    g.metrics.iter_mut().zip(&w.plan.metrics).zip(&old.values)
                {
                    state.update(metric.spec.op, value, false);
                }
                if g.entries == 0 {
                    w.groups.remove(&old.key);
                    self.groups -= 1;
                }
            }
        }
    }

    pub fn push(
        &mut self,
        timestamp: i64,
        contributions: Vec<Contribution>,
    ) -> Result<Vec<AggregateHit>> {
        self.advance(timestamp);
        let mut hits = vec![];
        for c in contributions {
            let charged_bytes = 256
                + c.key.len() * 2
                + c.values
                    .iter()
                    .map(|v| 192 + v.as_str().map_or(32, str::len) * 3)
                    .sum::<usize>();
            ensure!(
                charged_bytes <= self.max_bytes.saturating_sub(self.bytes),
                "aggregate byte budget reached; increase --state-mib"
            );
            ensure!(
                self.entries < self.max_entries,
                "aggregate entry limit reached; increase --max-window-entries or partition input by complete group keys"
            );
            let w = &mut self.windows[c.plan];
            let key = if let Some((key, _)) = w.groups.get_key_value(c.key.as_str()) {
                Arc::clone(key)
            } else {
                ensure!(
                    self.groups < self.max_groups,
                    "aggregate group limit reached; increase --max-groups"
                );
                let key: Arc<str> = Arc::from(c.key);
                w.groups.insert(
                    Arc::clone(&key),
                    Group {
                        entries: 0,
                        metrics: (0..w.plan.metrics.len())
                            .map(|_| MetricState::default())
                            .collect(),
                        alerted: false,
                    },
                );
                self.groups += 1;
                key
            };
            let g = w.groups.get_mut(&key).unwrap();
            g.entries += 1;
            for ((state, metric), value) in g.metrics.iter_mut().zip(&w.plan.metrics).zip(&c.values)
            {
                state.update(metric.spec.op, value, true);
            }
            let matched = having(&w.plan.spec.having, g, &w.plan);
            if matched && !g.alerted {
                let keys: Vec<Value> = serde_json::from_str(&key)?;
                hits.push(AggregateHit {
                    rule: w.plan.rule,
                    window_start_ns_exclusive: timestamp
                        .saturating_sub(w.plan.spec.window_seconds * 1_000_000_000),
                    window_end_ns_inclusive: timestamp,
                    group: w.plan.spec.group_by.iter().cloned().zip(keys).collect(),
                    metrics: w
                        .plan
                        .metrics
                        .iter()
                        .zip(&g.metrics)
                        .map(|(m, s)| (m.spec.name.clone(), s.value(m.spec.op)))
                        .collect(),
                });
            }
            g.alerted = matched;
            w.entries.push_back(Entry {
                timestamp,
                key,
                values: c.values,
                charged_bytes,
            });
            self.entries += 1;
            self.bytes += charged_bytes;
        }
        self.peak_entries = self.peak_entries.max(self.entries);
        self.peak_groups = self.peak_groups.max(self.groups);
        self.peak_bytes = self.peak_bytes.max(self.bytes);
        Ok(hits)
    }
}

fn having(c: &Condition, g: &Group, p: &AggregatePlan) -> bool {
    match c {
        Condition::All { all } => all.iter().all(|c| having(c, g, p)),
        Condition::Any { any } => any.iter().any(|c| having(c, g, p)),
        Condition::Not { not } => !having(not, g, p),
        Condition::Predicate(pred) => {
            let i = p
                .metrics
                .iter()
                .position(|m| Some(&m.spec.name) == pred.metric.as_ref())
                .unwrap();
            g.metrics[i]
                .value(p.metrics[i].spec.op)
                .is_some_and(|left| {
                    compare_number(
                        left,
                        pred.value.as_ref().and_then(Value::as_f64).unwrap(),
                        pred.op,
                    )
                })
        }
    }
}
