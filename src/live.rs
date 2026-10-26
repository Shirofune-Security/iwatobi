//! Live analysis (`-l`): find the local log files the loaded rules need (design §7, amendment A14).

use crate::input::ScanTarget;
use crate::logsource::LogSourceSpec;
use std::path::Path;

/// Embedded default location table.
pub const DEFAULT_LOG_LOCATIONS: &str = include_str!("../config/log_locations.yaml");

/// One row of `config/log_locations.yaml`.
#[derive(Clone, Debug)]
pub struct LocationRow {
    pub logsource: LogSourceSpec,
    pub patterns: Vec<String>,
}

/// Parse the location table.
pub fn parse_log_locations(yaml: &str) -> Result<Vec<LocationRow>, String> {
    let _ = yaml;
    Ok(Vec::new())
}

#[derive(Clone, Debug, Default)]
pub struct LiveOptions {
    pub no_wizard: bool,
    pub no_color: bool,
    /// `--since` for journalctl, when a time filter was given.
    pub since: Option<String>,
}

/// The result of live discovery.
#[derive(Debug, Default)]
pub struct LiveDiscovery {
    pub targets: Vec<ScanTarget>,
    /// Logsources needed by rules for which no file was found (and the user skipped them).
    pub skipped: Vec<LogSourceSpec>,
    /// A running `journalctl` export to read as syslog, when used.
    pub journal: Option<std::process::Child>,
    /// Human-readable notes for the terminal (permission warnings, partial journal, ...).
    pub notes: Vec<String>,
}

/// Find the files for `needs` (the distinct logsources of the loaded rules), prompting when
/// allowed. Returns an error only when live analysis is impossible on this platform.
pub fn discover(
    needs: &[LogSourceSpec],
    rows: &[LocationRow],
    opts: &LiveOptions,
    rules_dir_for_prompt: &Path,
) -> Result<LiveDiscovery, String> {
    let _ = (needs, rows, opts, rules_dir_for_prompt);
    if !cfg!(target_os = "linux") {
        return Err("live analysis is only supported on Linux".to_string());
    }
    Ok(LiveDiscovery::default())
}
