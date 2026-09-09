//! Stable external event-time sort with bounded runs and a bounded merge fan-in.
use crate::{input::Reader, scan::timestamp};
use anyhow::{Result, anyhow, ensure};
use rayon::prelude::*;
use serde::Serialize;
use simd_json::Buffers;
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct Record {
    time: i64,
    sequence: u64,
    data: Vec<u8>,
}

fn write_record(out: &mut impl Write, r: &Record) -> Result<()> {
    out.write_all(&r.time.to_le_bytes())?;
    out.write_all(&r.sequence.to_le_bytes())?;
    out.write_all(&(r.data.len() as u32).to_le_bytes())?;
    out.write_all(&r.data)?;
    Ok(())
}

fn read_record(input: &mut impl Read, max_line: usize) -> Result<Option<Record>> {
    let mut time = [0; 8];
    if input.read(&mut time[..1])? == 0 {
        return Ok(None);
    }
    input.read_exact(&mut time[1..])?;
    let mut sequence = [0; 8];
    input.read_exact(&mut sequence)?;
    let mut len = [0; 4];
    input.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    ensure!(len <= max_line, "corrupt sort run record size");
    let mut data = vec![0; len];
    input.read_exact(&mut data)?;
    Ok(Some(Record {
        time: i64::from_le_bytes(time),
        sequence: u64::from_le_bytes(sequence),
        data,
    }))
}

fn merge(
    paths: &[PathBuf],
    out: &mut impl Write,
    max_line: usize,
    final_output: bool,
) -> Result<()> {
    let mut readers = paths
        .iter()
        .map(|p| Ok(BufReader::with_capacity(64 << 10, File::open(p)?)))
        .collect::<Result<Vec<_>>>()?;
    let mut heap = BinaryHeap::new();
    for (i, input) in readers.iter_mut().enumerate() {
        if let Some(r) = read_record(input, max_line)? {
            heap.push(Reverse((r, i)));
        }
    }
    while let Some(Reverse((record, i))) = heap.pop() {
        if final_output {
            out.write_all(&record.data)?;
            out.write_all(b"\n")?;
        } else {
            write_record(out, &record)?;
        }
        if let Some(r) = read_record(&mut readers[i], max_line)? {
            heap.push(Reverse((r, i)));
        }
    }
    Ok(())
}

#[derive(Serialize)]
pub struct SortSummary {
    pub records: u64,
    pub initial_runs: usize,
    pub merge_passes: usize,
    pub run_memory_budget_bytes: usize,
    pub elapsed_seconds: f64,
}

pub fn sort(
    input: &Path,
    output: &Path,
    temp_parent: &Path,
    memory_bytes: usize,
    max_line: usize,
) -> Result<SortSummary> {
    ensure!(
        memory_bytes >= 8 << 20 && max_line > 0 && max_line <= 64 << 20,
        "invalid sort memory/line limits"
    );
    let mut out = BufWriter::with_capacity(
        4 << 20,
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    let scratch = tempfile::Builder::new()
        .prefix("http-sort-")
        .tempdir_in(temp_parent)?;
    let started = Instant::now();
    let mut reader = Reader::new(input, 4 << 20, max_line)?;
    let mut records = vec![];
    let mut bytes = 0;
    let mut runs = vec![];
    let mut sequence = 0;
    let mut buffers = Buffers::default();
    let mut parse = vec![];
    let flush = |records: &mut Vec<Record>, runs: &mut Vec<PathBuf>| -> Result<()> {
        records.par_sort_unstable_by_key(|r| (r.time, r.sequence));
        let path = scratch.path().join(format!("run-{}.bin", runs.len()));
        let mut file = BufWriter::with_capacity(1 << 20, File::create(&path)?);
        for r in records.drain(..) {
            write_record(&mut file, &r)?;
        }
        file.flush()?;
        runs.push(path);
        Ok(())
    };
    while let Some(batch) = reader.next_batch()? {
        for raw in batch.data.split(|b| *b == b'\n') {
            if raw.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            ensure!(
                raw.len() <= max_line,
                "sort record exceeds --max-line-bytes"
            );
            parse.clear();
            parse.extend_from_slice(raw);
            let tape = simd_json::to_tape_with_buffers(&mut parse, &mut buffers)?;
            let object = tape
                .as_value()
                .as_object()
                .ok_or_else(|| anyhow!("sort requires NDJSON objects"))?;
            let value = object
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("edgeendtimestamp"))
                .map(|(_, v)| v)
                .last()
                .ok_or_else(|| anyhow!("sort requires edgeendtimestamp"))?;
            let time = timestamp(value, 1)?;
            if !records.is_empty() && bytes + raw.len() + 64 > memory_bytes {
                flush(&mut records, &mut runs)?;
                bytes = 0;
            }
            bytes += raw.len() + 64;
            records.push(Record {
                time,
                sequence,
                data: raw.to_vec(),
            });
            sequence += 1;
        }
    }
    if !records.is_empty() {
        flush(&mut records, &mut runs)?;
    }
    let initial_runs = runs.len();
    let mut passes = 0;
    // Never exhaust file descriptors on a 500 GB input with many small runs.
    while runs.len() > 32 {
        let mut next = vec![];
        for (n, group) in runs.chunks(32).enumerate() {
            let path = scratch.path().join(format!("merge-{passes}-{n}.bin"));
            let mut file = BufWriter::with_capacity(1 << 20, File::create(&path)?);
            merge(group, &mut file, max_line, false)?;
            file.flush()?;
            next.push(path);
        }
        // These are exclusively generated scratch files inside this TempDir.
        for p in runs {
            std::fs::remove_file(p)?;
        }
        runs = next;
        passes += 1;
    }
    merge(&runs, &mut out, max_line, true)?;
    out.flush()?;
    Ok(SortSummary {
        records: sequence,
        initial_runs,
        merge_passes: passes + 1,
        run_memory_budget_bytes: memory_bytes,
        elapsed_seconds: started.elapsed().as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn preserves_json_escapes_and_equal_time_order() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("in");
        let output = temp.path().join("out");
        let a = r#"{"edgeendtimestamp":2,"x":"a\\b","n":0}"#;
        let b = r#"{"edgeendtimestamp":1,"n":1}"#;
        let c = r#"{"edgeendtimestamp":2,"n":2}"#;
        std::fs::write(&input, format!("{a}\n{b}\n{c}")).unwrap();
        let report = super::sort(&input, &output, temp.path(), 8 << 20, 4096).unwrap();
        assert_eq!(report.records, 3);
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            format!("{b}\n{a}\n{c}\n")
        );
    }
}
