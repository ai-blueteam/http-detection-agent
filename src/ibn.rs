//! Adapter for burpheart/Internet-background-noise's escaped honeypot schema.
//! Normalization is a separate, measured import stage, outside scan benchmarks.
use anyhow::{Result, anyhow, ensure};
use arrow_array::{
    Array, Int64Array, LargeStringArray, RecordBatch, StringArray, StringViewArray,
    TimestampMillisecondArray,
};
use parquet::arrow::{ProjectionMask, arrow_reader::ParquetRecordBatchReaderBuilder};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

pub fn metadata(path: &Path) -> Result<Value> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
    let groups: Vec<_> = reader.metadata().row_groups().iter().enumerate().map(|(id, g)| json!({"id":id,"rows":g.num_rows(),"uncompressed_column_bytes":g.total_byte_size(),"compressed_column_bytes":g.compressed_size()})).collect();
    Ok(
        json!({"file":path,"file_bytes":std::fs::metadata(path)?.len(),"rows":reader.metadata().file_metadata().num_rows(),"schema":reader.schema().to_string(),"row_groups":groups}),
    )
}

fn string<'a>(batch: &'a RecordBatch, field: &str, row: usize) -> Option<&'a str> {
    let a = batch.column_by_name(field)?;
    if a.is_null(row) {
        return None;
    }
    if let Some(a) = a.as_any().downcast_ref::<StringArray>() {
        Some(a.value(row))
    } else if let Some(a) = a.as_any().downcast_ref::<LargeStringArray>() {
        Some(a.value(row))
    } else {
        a.as_any()
            .downcast_ref::<StringViewArray>()
            .map(|a| a.value(row))
    }
}

/// Decode the source's Go-style display escapes once. Escaped bytes map to the
/// corresponding Unicode code point, preserving binary signatures such as AC ED.
/// This is a searchable text view, not a reconstruction of original packet bytes.
pub fn unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(escaped) = chars.next() else {
            out.push('\\');
            break;
        };
        let simple = match escaped {
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'v' => Some('\x0b'),
            'f' => Some('\x0c'),
            'b' => Some('\x08'),
            'a' => Some('\x07'),
            '\\' => Some('\\'),
            '"' => Some('"'),
            '\'' => Some('\''),
            _ => None,
        };
        if let Some(c) = simple {
            out.push(c);
            continue;
        }
        let digits = match escaped {
            'x' => 2,
            'u' => 4,
            'U' => 8,
            _ => 0,
        };
        if digits > 0 {
            let mut peek = chars.clone();
            let candidate: String = peek.by_ref().take(digits).collect();
            if candidate.len() == digits
                && let Ok(n) = u32::from_str_radix(&candidate, 16)
                && let Some(c) = char::from_u32(n)
            {
                chars = peek;
                out.push(c);
                continue;
            }
        }
        out.push('\\');
        out.push(escaped);
    }
    out
}

fn header<'a>(map: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a str> {
    map.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_str())
}

#[derive(Default, Serialize)]
pub struct ImportSummary {
    pub rows: u64,
    pub normalized_bytes: u64,
    pub invalid_header_maps: u64,
    pub missing_timestamps: u64,
    pub raw_header_rows: u64,
    pub escaped_body_rows: u64,
    pub timestamp_regressions: u64,
    pub max_timestamp_regression_ms: i64,
    pub elapsed_seconds: f64,
    pub rows_per_second: f64,
    pub labels: &'static str,
}

struct Normalized {
    bytes: Vec<u8>,
    timestamp: Option<i64>,
    invalid_headers: bool,
    raw_headers: bool,
    escaped_body: bool,
}

fn normalize(batch: &RecordBatch, row: usize, ordinal: u64) -> Result<Normalized> {
    let path = string(batch, "Path", row).unwrap_or("");
    let header_json = string(batch, "Header", row).unwrap_or("{}");
    let headers = serde_json::from_str::<serde_json::Map<String, Value>>(header_json);
    let invalid_headers = headers.is_err();
    let headers = headers.unwrap_or_default();
    let ts = batch.column_by_name("TimeStamp").and_then(|a| {
        if a.is_null(row) {
            None
        } else if let Some(a) = a.as_any().downcast_ref::<TimestampMillisecondArray>() {
            Some(a.value(row))
        } else {
            a.as_any()
                .downcast_ref::<Int64Array>()
                .map(|a| a.value(row))
        }
    });
    let body = string(batch, "Body", row).unwrap_or("");
    let escaped_body = body.contains('\\');
    let body = unescape(body);
    let data = string(batch, "Data", row).unwrap_or("");
    // Limit raw-header extraction to the header block. Body content is never headers.
    let decoded_data = if let Some(end) = data.find("\\r\\n\\r\\n") {
        unescape(&data[..end])
    } else if let Some(end) = data.find("\r\n\r\n") {
        data[..end].to_owned()
    } else {
        String::new()
    };
    let raw: Vec<_> = decoded_data
        .split("\r\n")
        .skip(1)
        .filter(|line| line.contains(':'))
        .collect();
    let raw_headers = !raw.is_empty();
    let uri_path = crate::engine::transform(
        std::borrow::Cow::Borrowed(path),
        &[crate::catalog::Transform::PathOnly],
    );
    let cookies: BTreeMap<_, _> = header(&headers, "cookie")
        .unwrap_or("")
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .collect();
    let timestamp_ns = ts
        .map(|ts| {
            ts.checked_mul(1_000_000)
                .ok_or_else(|| anyhow!("timestamp overflow"))
        })
        .transpose()?;
    let value = json!({
        "edgeendtimestamp":timestamp_ns,
        "clientip":string(batch,"SrcIp",row),
        "clientrequestmethod":string(batch,"Method",row),
        "clientrequesturi":path,
        "clientrequestpath":uri_path,
        "clientrequestuseragent":string(batch,"UserAgent",row),
        "clientrequesthost":header(&headers,"host"),
        "clientrequestreferer":header(&headers,"referer"),
        "requestheaders":headers,
        "requestheadersraw":if raw_headers {Some(raw)} else {None},
        "cookies":cookies,
        "requestbody":body,
        "ibn_row":ordinal,
        "ibn_body_hash":string(batch,"Body_hash",row),
        "ibn_data_hash":string(batch,"Data_hash",row)
    });
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(Normalized {
        bytes,
        timestamp: ts,
        invalid_headers,
        raw_headers,
        escaped_body,
    })
}

pub fn import(
    input: &Path,
    output: &Path,
    limit: Option<usize>,
    offset: usize,
    batch_rows: usize,
    threads: usize,
) -> Result<ImportSummary> {
    ensure!(
        (1..=16384).contains(&batch_rows),
        "--batch-rows must be 1..16384"
    );
    let started = Instant::now();
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(input)?)?;
    let names = [
        "SrcIp",
        "Method",
        "Path",
        "Header",
        "TimeStamp",
        "UserAgent",
        "Body",
        "Data",
        "Body_hash",
        "Data_hash",
    ];
    for name in names {
        ensure!(
            builder.schema().column_with_name(name).is_some(),
            "missing Internet-background-noise field {name}"
        );
    }
    let projection = ProjectionMask::columns(builder.parquet_schema(), names);
    let mut builder = builder
        .with_projection(projection)
        .with_batch_size(batch_rows)
        .with_offset(offset);
    if let Some(limit) = limit {
        builder = builder.with_limit(limit);
    }
    let reader = builder.build()?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let mut out = BufWriter::with_capacity(
        8 << 20,
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    let mut summary = ImportSummary {
        labels: "unlabeled; error is a capture/parser flag, not an attack label",
        ..ImportSummary::default()
    };
    let mut previous = None;
    let mut last_progress = Instant::now();
    for batch in reader {
        let batch = batch?;
        let start_row = offset as u64 + summary.rows;
        let normalized: Vec<_> = pool.install(|| {
            (0..batch.num_rows())
                .into_par_iter()
                .map(|row| normalize(&batch, row, start_row + row as u64))
                .collect()
        });
        for value in normalized {
            let n = value?;
            summary.rows += 1;
            summary.normalized_bytes += n.bytes.len() as u64;
            summary.invalid_header_maps += u64::from(n.invalid_headers);
            summary.missing_timestamps += u64::from(n.timestamp.is_none());
            summary.raw_header_rows += u64::from(n.raw_headers);
            summary.escaped_body_rows += u64::from(n.escaped_body);
            if let Some(ts) = n.timestamp {
                if let Some(prev) = previous
                    && ts < prev
                {
                    summary.timestamp_regressions += 1;
                    summary.max_timestamp_regression_ms =
                        summary.max_timestamp_regression_ms.max(prev - ts);
                }
                previous = Some(ts);
            }
            out.write_all(&n.bytes)?;
        }
        if last_progress.elapsed().as_secs() >= 5 {
            eprintln!(
                "imported {} rows / {:.2} GB normalized",
                summary.rows,
                summary.normalized_bytes as f64 / 1e9
            );
            last_progress = Instant::now();
        }
    }
    out.flush()?;
    summary.elapsed_seconds = started.elapsed().as_secs_f64();
    summary.rows_per_second = summary.rows as f64 / summary.elapsed_seconds;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    #[test]
    fn escape_view_is_single_pass_and_preserves_binary_signature() {
        assert_eq!(super::unescape(r"a\r\nb\x3cscript\x3e"), "a\r\nb<script>");
        assert_eq!(super::unescape(r"\xac\xed\x00\x05"), "\u{ac}\u{ed}\0\x05");
        assert_eq!(super::unescape(r"\\x3c"), r"\x3c");
        assert_eq!(super::unescape(r"a\q\xzz"), r"a\q\xzz");
    }
}
