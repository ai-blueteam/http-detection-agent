use crate::{
    aggregate::{self, Aggregator, Contribution},
    catalog::Excluded,
    engine::{Engine, Event},
    input::{Batch, Reader},
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, NaiveDateTime};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use simd_json::{Buffers, Tape, prelude::*};
use std::{
    cmp::{Ordering, Reverse},
    collections::{BTreeMap, BinaryHeap},
    io::Write,
    path::PathBuf,
    sync::mpsc::sync_channel,
    time::Instant,
};

#[derive(Clone)]
pub struct Config {
    pub inputs: Vec<PathBuf>,
    pub threads: usize,
    pub batch_bytes: usize,
    pub max_line_bytes: usize,
    pub max_key_bytes: usize,
    pub max_window_entries: usize,
    pub max_state_bytes: usize,
    pub max_groups: usize,
    pub max_pending: usize,
    pub lateness_ns: i64,
    pub drop_late: bool,
    pub skip_invalid: bool,
    pub timestamp_multiplier: i64,
    pub counts_only: bool,
    pub quiet: bool,
}

#[derive(Default, Serialize)]
pub struct Summary {
    pub complete: bool,
    pub matcher: crate::engine::Matcher,
    pub bytes: u64,
    pub records: u64,
    pub blank_lines: u64,
    pub invalid_records: u64,
    pub late_events: u64,
    pub event_findings: u64,
    pub matched_records: u64,
    pub aggregate_findings: u64,
    pub rule_counts: BTreeMap<String, u64>,
    pub excluded_rules: Vec<Excluded>,
    pub elapsed_seconds: f64,
    pub mb_per_second: f64,
    pub records_per_second: f64,
    pub peak_window_entries: usize,
    pub peak_groups: usize,
    pub peak_accounted_state_bytes: usize,
    pub match_digest_sha256: Option<String>,
    pub peak_pending: usize,
    pub error: Option<String>,
}

struct Record {
    line: u64,
    offset: u64,
    timestamp: Option<i64>,
    hits: Vec<usize>,
    contributions: Vec<Contribution>,
}
struct BatchResult {
    source: String,
    bytes: usize,
    records: Vec<Record>,
    invalid: u64,
    blanks: u64,
}
struct Pending {
    timestamp: i64,
    seq: u64,
    contributions: Vec<Contribution>,
}
impl PartialEq for Pending {
    fn eq(&self, o: &Self) -> bool {
        (self.timestamp, self.seq) == (o.timestamp, o.seq)
    }
}
impl Eq for Pending {}
impl PartialOrd for Pending {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Pending {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.timestamp, self.seq).cmp(&(o.timestamp, o.seq))
    }
}

#[derive(Clone)]
struct Worker {
    engine: Engine,
}

pub fn timestamp(v: simd_json::tape::Value<'_, '_>, multiplier: i64) -> Result<i64> {
    if let Some(s) = v.as_str() {
        if let Ok(n) = s.parse::<i64>() {
            return n
                .checked_mul(multiplier)
                .ok_or_else(|| anyhow::anyhow!("timestamp overflow"));
        }
        if let Ok(t) = DateTime::parse_from_rfc3339(s) {
            return t
                .timestamp_nanos_opt()
                .ok_or_else(|| anyhow::anyhow!("timestamp outside nanosecond range"));
        }
        if let Ok(t) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
            return t
                .and_utc()
                .timestamp_nanos_opt()
                .ok_or_else(|| anyhow::anyhow!("timestamp outside nanosecond range"));
        }
    }
    if let Some(n) = v.as_i64() {
        return n
            .checked_mul(multiplier)
            .ok_or_else(|| anyhow::anyhow!("timestamp overflow"));
    }
    bail!(
        "aggregate evaluation requires a valid edgeendtimestamp; specify --timestamp-unit for numeric timestamps, or use --events-only"
    )
}

fn finish_record(
    engine: &Engine,
    event: &mut Event<'_, '_>,
    line: u64,
    offset: u64,
    config: &Config,
) -> Result<Record> {
    let hits = engine
        .events
        .iter()
        .filter_map(|(id, expr)| engine.evaluate(expr, event).then_some(*id))
        .collect();
    let timestamp = if engine.aggregates.is_empty() {
        None
    } else {
        Some(timestamp(
            event.fields[engine.timestamp],
            config.timestamp_multiplier,
        )?)
    };
    let contributions = aggregate::prepare(engine, event, config.max_key_bytes)?;
    Ok(Record {
        line,
        offset,
        timestamp,
        hits,
        contributions,
    })
}

impl Worker {
    fn process(&self, batch: &mut Batch, config: &Config) -> Result<BatchResult> {
        let mut result = BatchResult {
            source: batch.source.clone(),
            bytes: batch.data.len(),
            records: vec![],
            invalid: 0,
            blanks: 0,
        };
        let mut buffers = Buffers::default();
        let mut tape = Tape::null();
        let total = batch.data.len();
        let mut offset = 0;
        for (i, raw) in batch.data.split_mut(|b| *b == b'\n').enumerate() {
            if offset == total {
                break;
            }
            let line = batch.first_line + i as u64;
            let location = batch.offset + offset as u64;
            offset += raw.len() + 1;
            if raw.iter().all(u8::is_ascii_whitespace) {
                result.blanks += 1;
                continue;
            }
            ensure!(
                raw.len() <= config.max_line_bytes,
                "{}:{line} exceeds --max-line-bytes",
                batch.source
            );
            tape = tape.reset();
            let parsed = simd_json::fill_tape(raw, &mut buffers, &mut tape)
                .map_err(anyhow::Error::from)
                .and_then(|_| self.engine.event(tape.as_value()))
                .and_then(|mut event| {
                    finish_record(&self.engine, &mut event, line, location, config)
                });
            match parsed {
                Ok(record) => result.records.push(record),
                Err(_) if config.skip_invalid => result.invalid += 1,
                Err(e) => {
                    return Err(e.context(format!(
                        "{}:{line} (decompressed byte {location})",
                        batch.source
                    )));
                }
            }
        }
        Ok(result)
    }
}

fn write_hit(
    out: &mut dyn Write,
    engine: &Engine,
    rule: usize,
    details: serde_json::Value,
) -> Result<()> {
    let rule = &engine.catalog.rules[rule];
    let sources: Vec<_> = engine
        .catalog
        .sources
        .iter()
        .filter(|s| rule.provenance.iter().any(|p| p["source"] == s["id"]))
        .collect();
    serde_json::to_writer(
        &mut *out,
        &json!({"rule_id":rule.id,"family":rule.family,"variant":rule.variant,"title":rule.title,"kind":rule.kind,"status":rule.status,"severity":rule.severity,"confidence":rule.confidence,"category":rule.category,"provenance":rule.provenance,"sources":sources,"details":details}),
    )?;
    out.write_all(b"\n")?;
    Ok(())
}

pub fn run(
    engine: &Engine,
    config: &Config,
    excluded: Vec<Excluded>,
    out: &mut dyn Write,
) -> Summary {
    let start = Instant::now();
    let mut summary = Summary {
        matcher: engine.matcher,
        excluded_rules: excluded,
        ..Summary::default()
    };
    let result = run_inner(engine, config, out, &mut summary);
    summary.elapsed_seconds = start.elapsed().as_secs_f64();
    summary.mb_per_second = summary.bytes as f64 / 1_000_000.0 / summary.elapsed_seconds;
    summary.records_per_second = summary.records as f64 / summary.elapsed_seconds;
    summary.complete = result.is_ok();
    if let Err(e) = result {
        summary.error = Some(format!("{e:#}"));
    }
    summary
}

fn run_inner(
    engine: &Engine,
    config: &Config,
    out: &mut dyn Write,
    summary: &mut Summary,
) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build()?;
    let worker = Worker {
        engine: engine.clone(),
    };
    let mut aggregator = Aggregator::new(
        &engine.aggregates,
        config.max_window_entries,
        config.max_groups,
    )
    .with_byte_budget(config.max_state_bytes);
    let mut event_digest = Sha256::new();
    let mut aggregate_digest = Sha256::new();
    let mut pending: BinaryHeap<Reverse<Pending>> = BinaryHeap::new();
    let mut max_time = i64::MIN;
    let mut emitted_time = i64::MIN;
    let mut seq = 0u64;
    let started = Instant::now();
    let mut last_progress = Instant::now();
    let mut process_pending =
        |p: Pending, agg: &mut Aggregator, out: &mut dyn Write, s: &mut Summary| -> Result<()> {
            for hit in agg.push(p.timestamp, p.contributions)? {
                aggregate_digest.update((hit.rule as u64).to_le_bytes());
                aggregate_digest.update(serde_json::to_vec(&hit)?);
                s.aggregate_findings += 1;
                *s.rule_counts
                    .entry(engine.catalog.rules[hit.rule].id.clone())
                    .or_default() += 1;
                if !config.counts_only {
                    write_hit(out, engine, hit.rule, serde_json::to_value(&hit)?)?;
                }
            }
            Ok(())
        };
    // A bounded reader channel overlaps I/O/decompression with CPU work.
    std::thread::scope(|scope| -> Result<()> {
        let (tx, rx) = sync_channel(2);
        scope.spawn(move || {
            for path in &config.inputs {
                let read = (|| -> Result<()> {
                    let mut reader = Reader::new(path, config.batch_bytes, config.max_line_bytes)?;
                    while let Some(batch) = reader.next_batch()? {
                        if tx.send(Ok(batch)).is_err() {
                            return Ok(());
                        }
                    }
                    Ok(())
                })();
                if let Err(e) = read {
                    let _ = tx.send(Err(e));
                    return;
                }
            }
        });
        loop {
            let mut wave = Vec::with_capacity(config.threads);
            for _ in 0..config.threads {
                match rx.recv() {
                    Ok(batch) => wave.push(batch?),
                    Err(_) => break,
                }
            }
            if wave.is_empty() {
                break;
            }
            let results: Vec<_> = pool.install(|| {
                wave.par_iter_mut()
                    .map_init(|| worker.clone(), |w, b| w.process(b, config))
                    .collect()
            });
            for result in results {
                let result = result?;
                summary.bytes += result.bytes as u64;
                summary.invalid_records += result.invalid;
                summary.blank_lines += result.blanks;
                for record in result.records {
                    summary.records += 1;
                    summary.matched_records += u64::from(!record.hits.is_empty());
                    for rule in record.hits {
                        event_digest.update(summary.records.to_le_bytes());
                        event_digest.update((rule as u64).to_le_bytes());
                        summary.event_findings += 1;
                        *summary
                            .rule_counts
                            .entry(engine.catalog.rules[rule].id.clone())
                            .or_default() += 1;
                        if !config.counts_only {
                            write_hit(
                                out,
                                engine,
                                rule,
                                json!({"source":result.source,"line":record.line,"byte_offset":record.offset,"timestamp_ns":record.timestamp}),
                            )?;
                        }
                    }
                    if let Some(timestamp) = record.timestamp {
                        if timestamp < emitted_time {
                            if config.drop_late {
                                summary.late_events += 1;
                                continue;
                            }
                            bail!(
                                "{}:{} event is older than the emitted watermark; set --lateness-seconds for bounded reordering, or explicitly --late-policy drop",
                                result.source,
                                record.line
                            );
                        }
                        seq += 1;
                        max_time = max_time.max(timestamp);
                        let watermark = max_time.saturating_sub(config.lateness_ns);
                        ensure!(
                            pending.len() < config.max_pending,
                            "reorder buffer limit reached; increase --max-pending or reduce --lateness-seconds"
                        );
                        pending.push(Reverse(Pending {
                            timestamp,
                            seq,
                            contributions: record.contributions,
                        }));
                        summary.peak_pending = summary.peak_pending.max(pending.len());
                        while pending.peek().is_some_and(|p| p.0.timestamp <= watermark) {
                            let p = pending.pop().unwrap().0;
                            emitted_time = p.timestamp;
                            process_pending(p, &mut aggregator, out, summary)?;
                        }
                    }
                }
            }
            if !config.quiet && last_progress.elapsed().as_secs() >= 5 {
                eprintln!(
                    "scanned {:.2} GB | {} records | {:.1} MB/s | {} findings",
                    summary.bytes as f64 / 1e9,
                    summary.records,
                    summary.bytes as f64 / 1e6 / started.elapsed().as_secs_f64(),
                    summary.event_findings + summary.aggregate_findings
                );
                last_progress = Instant::now();
            }
        }
        drop(rx);
        Ok(())
    })?;
    while let Some(Reverse(p)) = pending.pop() {
        process_pending(p, &mut aggregator, out, summary)?;
    }
    summary.peak_window_entries = aggregator.peak_entries;
    summary.peak_groups = aggregator.peak_groups;
    summary.peak_accounted_state_bytes = aggregator.peak_bytes;
    let mut digest = Sha256::new();
    digest.update(event_digest.finalize());
    digest.update(aggregate_digest.finalize());
    summary.match_digest_sha256 = Some(format!("{:x}", digest.finalize()));
    out.flush().context("flush findings")?;
    Ok(())
}
