//! Error/warning log file.
//!
//! Warnings and errors raised while processing logs are written to
//! `logs/errorlog-<YYYYMMDD_HHMMSS>.log` instead of the terminal, exactly like Hayabusa and
//! Suzaku: a directory full of unreadable files would otherwise bury the results, and the run
//! prints a single pointer to the file at the end. The file is created lazily on the first
//! message, so a clean run leaves no `logs/` directory behind. Its first line is the command line
//! that produced it. `-Q, --quiet-errors` disables the file; messages are then dropped.

use chrono::Local;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

const LOG_DIR: &str = "logs";

static QUIET: AtomicBool = AtomicBool::new(false);

struct ErrorLog {
    path: PathBuf,
    writer: BufWriter<File>,
    count: usize,
}

fn state() -> &'static Mutex<Option<ErrorLog>> {
    static STATE: OnceLock<Mutex<Option<ErrorLog>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

/// Disable the error log (`-Q, --quiet-errors`).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Records a non-fatal warning. Not shown on the terminal.
pub fn log_warn(msg: &str) {
    write_entry("WARNING", msg);
}

/// Records an error. Not shown on the terminal, except by the call sites that also print it.
pub fn log_error(msg: &str) {
    write_entry("ERROR", msg);
}

/// Path of the log file, once one has been created.
pub fn log_path() -> Option<PathBuf> {
    state()
        .lock()
        .ok()
        .and_then(|s| s.as_ref().map(|log| log.path.clone()))
}

/// Number of messages recorded so far.
pub fn entry_count() -> usize {
    state()
        .lock()
        .ok()
        .and_then(|s| s.as_ref().map(|log| log.count))
        .unwrap_or(0)
}

fn write_entry(level: &str, msg: &str) {
    if QUIET.load(Ordering::Relaxed) {
        return;
    }
    let line = format!("[{level}] {msg}");
    let Ok(mut guard) = state().lock() else {
        eprintln!("{line}");
        return;
    };
    if guard.is_none() {
        match create_log(Path::new(LOG_DIR), &command_line()) {
            Ok(log) => *guard = Some(log),
            Err(e) => {
                eprintln!("Cannot write to the error log in ./{LOG_DIR}: {e}");
                eprintln!("{line}");
                return;
            }
        }
    }
    let Some(log) = guard.as_mut() else { return };
    if writeln!(log.writer, "{line}")
        .and_then(|_| log.writer.flush())
        .is_err()
    {
        eprintln!("{line}");
        return;
    }
    log.count += 1;
}

fn command_line() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

fn create_log(dir: &Path, command_line: &str) -> std::io::Result<ErrorLog> {
    fs::create_dir_all(dir)?;
    let name = format!("errorlog-{}.log", Local::now().format("%Y%m%d_%H%M%S"));
    let path = dir.join(name);
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{command_line}")?;
    writer.flush()?;
    Ok(ErrorLog {
        path,
        writer,
        count: 0,
    })
}
