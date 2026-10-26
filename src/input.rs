//! Input enumeration and line reading (design §5).
//!
//! `-d` recurses; regular files only; `.gz` is decoded transparently; `.xz/.bz2/.zst`, binary
//! files (NUL in the sample), `wtmp`/`btmp`/`lastlog`, journal files and empty files are skipped
//! with a warning in the error log.

use crate::logsource::LogSourceTag;
use crate::parsers::LogFormat;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// One file (or stream) to scan.
#[derive(Clone, Debug)]
pub struct ScanTarget {
    pub path: PathBuf,
    /// Shown in the `LogFile` column.
    pub display_name: String,
    /// Tags added to every event of this target (live analysis: a path the user named for a logsource).
    pub extra_tags: Vec<LogSourceTag>,
    /// A forced format (`--log-format`), otherwise sniffed.
    pub format: Option<LogFormat>,
}

impl ScanTarget {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            display_name: path.display().to_string(),
            extra_tags: Vec::new(),
            format: None,
        }
    }
}

/// Why a file was not scanned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    Empty,
    Binary,
    UnsupportedCompression,
    NotALogFile,
    UnrecognizedFormat,
    Unreadable(String),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::Empty => write!(f, "empty file"),
            SkipReason::Binary => write!(f, "binary file"),
            SkipReason::UnsupportedCompression => {
                write!(f, "unsupported compression (only .gz is read)")
            }
            SkipReason::NotALogFile => write!(f, "not a text log file"),
            SkipReason::UnrecognizedFormat => write!(f, "unrecognized log format"),
            SkipReason::Unreadable(e) => write!(f, "could not read: {e}"),
        }
    }
}

/// Enumerate the files under `-d` (recursively) or the single `-f` file.
pub fn enumerate(path: &Path, forced_format: Option<LogFormat>) -> Vec<ScanTarget> {
    let mut out = Vec::new();
    if path.is_file() {
        let mut t = ScanTarget::new(path);
        t.format = forced_format;
        out.push(t);
        return out;
    }
    walk(path, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    for t in &mut out {
        t.format = forced_format;
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<ScanTarget>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        crate::errorlog::log_warn(&format!("Could not read directory {}", dir.display()));
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.is_file() {
            out.push(ScanTarget::new(&p));
        }
    }
}

/// Files that are never logs we can read, by name or extension.
pub fn quick_skip_reason(path: &Path) -> Option<SkipReason> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with(".xz")
        || name.ends_with(".bz2")
        || name.ends_with(".zst")
        || name.ends_with(".lz4")
        || name.ends_with(".zip")
    {
        return Some(SkipReason::UnsupportedCompression);
    }
    if name.ends_with(".journal")
        || name.ends_with(".journal~")
        || name.starts_with("wtmp")
        || name.starts_with("btmp")
        || name.starts_with("lastlog")
        || name.ends_with(".pcap")
        || name.ends_with(".pcap.gz")
        || name.ends_with(".pcapng")
    {
        return Some(SkipReason::NotALogFile);
    }
    match std::fs::metadata(path) {
        Ok(m) if m.len() == 0 => Some(SkipReason::Empty),
        Ok(_) => None,
        Err(e) => Some(SkipReason::Unreadable(e.to_string())),
    }
}

/// Open a file for line reading, decoding gzip when the name ends with `.gz`.
pub fn open_reader(path: &Path) -> std::io::Result<Box<dyn BufRead + Send>> {
    let file = std::fs::File::open(path)?;
    let is_gz = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"));
    if is_gz {
        let dec = flate2::read::MultiGzDecoder::new(BufReader::new(file));
        Ok(Box::new(BufReader::with_capacity(1 << 16, dec)))
    } else {
        Ok(Box::new(BufReader::with_capacity(1 << 16, file)))
    }
}

/// Read up to `max` non-blank lines (lossy UTF-8, `\r` stripped) for format sniffing; `binary`
/// is set when a NUL byte is seen.
pub fn read_sample(path: &Path, max: usize) -> std::io::Result<(Vec<String>, bool)> {
    let mut reader = open_reader(path)?;
    let mut sample = Vec::new();
    let mut buf = Vec::new();
    let mut binary = false;
    while sample.len() < max {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if buf.contains(&0u8) {
            binary = true;
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches(['\n', '\r']);
        if !line.trim().is_empty() {
            sample.push(line.to_string());
        }
    }
    Ok((sample, binary))
}

/// Iterate over the lines of a reader as lossy UTF-8 strings without the trailing newline/CR.
pub struct Lines<R: Read> {
    reader: BufReader<R>,
    buf: Vec<u8>,
}

impl<R: Read> Lines<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::with_capacity(1 << 16, reader),
            buf: Vec::new(),
        }
    }
}

impl<R: Read> Iterator for Lines<R> {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.buf.clear();
        match self.reader.read_until(b'\n', &mut self.buf) {
            Ok(0) => None,
            Ok(_) => {
                let line = String::from_utf8_lossy(&self.buf);
                Some(Ok(line.trim_end_matches(['\n', '\r']).to_string()))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Lossy line iterator over a boxed reader.
pub fn lines(reader: Box<dyn BufRead + Send>) -> Lines<Box<dyn BufRead + Send>> {
    Lines::new(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gz_and_plain_files_are_read_the_same_way() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("syslog");
        std::fs::write(&plain, "line one\r\nline two\n").unwrap();
        let gz = dir.path().join("syslog.2.gz");
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&gz).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(b"old one\nold two\n").unwrap();
        enc.finish().unwrap();
        let (s, bin) = read_sample(&plain, 10).unwrap();
        assert_eq!(s, vec!["line one", "line two"]);
        assert!(!bin);
        let got: Vec<String> = lines(open_reader(&gz).unwrap())
            .map(|l| l.unwrap())
            .collect();
        assert_eq!(got, vec!["old one", "old two"]);
        let targets = enumerate(dir.path(), None);
        assert_eq!(targets.len(), 2);
        assert_eq!(
            quick_skip_reason(&dir.path().join("x.xz")),
            Some(SkipReason::Unreadable(
                std::io::Error::from(std::io::ErrorKind::NotFound).to_string()
            ))
            .map(|_| SkipReason::UnsupportedCompression)
        );
    }

    #[test]
    fn binary_files_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("wtmp.bin");
        std::fs::write(&bin, b"abc\0def\n").unwrap();
        let (_, binary) = read_sample(&bin, 10).unwrap();
        assert!(binary);
        assert_eq!(
            quick_skip_reason(&dir.path().join("wtmp")),
            Some(SkipReason::NotALogFile)
        );
    }
}
