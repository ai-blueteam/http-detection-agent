use anyhow::{Context, Result, ensure};
use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
};

pub fn open(path: &Path) -> Result<Box<dyn Read + Send>> {
    let source: Box<dyn Read + Send> = if path.as_os_str() == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?)
    };
    let mut reader = BufReader::with_capacity(1 << 20, source);
    let magic = reader.fill_buf()?;
    if magic.starts_with(&[0x1f, 0x8b]) {
        Ok(Box::new(flate2::read::MultiGzDecoder::new(reader)))
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Ok(Box::new(zstd::stream::read::Decoder::with_buffer(reader)?))
    } else {
        Ok(Box::new(reader))
    }
}

pub struct Batch {
    pub data: Vec<u8>,
    pub source: String,
    pub first_line: u64,
    pub offset: u64,
}

pub struct Reader {
    input: Box<dyn Read + Send>,
    pending: Vec<u8>,
    target: usize,
    max_line: usize,
    source: String,
    line: u64,
    offset: u64,
    eof: bool,
}

impl Reader {
    pub fn new(path: &Path, target: usize, max_line: usize) -> Result<Self> {
        ensure!(
            target > 0 && max_line > 0,
            "batch and line limits must be positive"
        );
        Ok(Self {
            input: open(path)?,
            pending: vec![],
            target,
            max_line,
            source: path.display().to_string(),
            line: 1,
            offset: 0,
            eof: false,
        })
    }

    pub fn next_batch(&mut self) -> Result<Option<Batch>> {
        if self.eof && self.pending.is_empty() {
            return Ok(None);
        }
        let mut data = std::mem::take(&mut self.pending);
        loop {
            let old = data.len();
            let extra = self
                .target
                .saturating_sub(old)
                .max(4096)
                .min(self.max_line + 1);
            data.resize(old + extra, 0);
            let n = self.input.read(&mut data[old..])?;
            data.truncate(old + n);
            if n == 0 {
                self.eof = true;
                break;
            }
            if data.len() >= self.target
                && let Some(i) = memchr::memrchr(b'\n', &data)
            {
                self.pending = data.split_off(i + 1);
                break;
            }
            if !data.contains(&b'\n') {
                ensure!(
                    data.len() <= self.max_line,
                    "{}:{} exceeds --max-line-bytes",
                    self.source,
                    self.line
                );
            }
        }
        if data.is_empty() {
            return Ok(None);
        }
        let lines = memchr::memchr_iter(b'\n', &data).count() as u64;
        let batch = Batch {
            source: self.source.clone(),
            first_line: self.line,
            offset: self.offset,
            data,
        };
        self.line += lines;
        self.offset += batch.data.len() as u64;
        Ok(Some(batch))
    }
}
