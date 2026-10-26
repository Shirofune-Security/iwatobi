//! Output: profiles, row rendering, and the stdout / CSV / JSON / JSONL writers (design §9,
//! amendment A15).

pub mod tags;

use crate::cli::OutputFormat;
use crate::correlate::{BaseHit, CorrelationHit};
use crate::detect::Detection;
use crate::rules::RuleMeta;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Embedded default profiles.
pub const DEFAULT_PROFILES: &str = include_str!("../../config/profiles.yaml");

/// What a profile column shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placeholder {
    Timestamp,
    RuleTitle,
    Level,
    Computer,
    LogSource,
    Details,
    ExtraFieldInfo,
    AllFieldInfo,
    RawLine,
    LineNumber,
    LogFile,
    MitreTactics,
    MitreTags,
    OtherTags,
    RuleFile,
    RuleID,
    RuleAuthor,
    RuleCreationDate,
    RuleModifiedDate,
    Status,
    Description,
    References,
    FalsePositives,
}

impl Placeholder {
    /// `%Timestamp%` → `Placeholder::Timestamp`.
    pub fn parse(spec: &str) -> Option<Placeholder> {
        let name = spec.trim().trim_matches('%');
        Some(match name {
            "Timestamp" => Placeholder::Timestamp,
            "RuleTitle" => Placeholder::RuleTitle,
            "Level" => Placeholder::Level,
            "Computer" => Placeholder::Computer,
            "LogSource" => Placeholder::LogSource,
            "Details" => Placeholder::Details,
            "ExtraFieldInfo" => Placeholder::ExtraFieldInfo,
            "AllFieldInfo" => Placeholder::AllFieldInfo,
            "RawLine" => Placeholder::RawLine,
            "LineNumber" => Placeholder::LineNumber,
            "LogFile" => Placeholder::LogFile,
            "MitreTactics" => Placeholder::MitreTactics,
            "MitreTags" => Placeholder::MitreTags,
            "OtherTags" => Placeholder::OtherTags,
            "RuleFile" => Placeholder::RuleFile,
            "RuleID" => Placeholder::RuleID,
            "RuleAuthor" => Placeholder::RuleAuthor,
            "RuleCreationDate" => Placeholder::RuleCreationDate,
            "RuleModifiedDate" => Placeholder::RuleModifiedDate,
            "Status" => Placeholder::Status,
            "Description" => Placeholder::Description,
            "References" => Placeholder::References,
            "FalsePositives" => Placeholder::FalsePositives,
            _ => return None,
        })
    }
}

/// An output profile: ordered columns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub columns: Vec<(String, Placeholder)>,
}

impl Profile {
    pub fn uses(&self, p: Placeholder) -> bool {
        self.columns.iter().any(|(_, c)| *c == p)
    }
}

/// Parse `config/profiles.yaml` (name → column → `%Placeholder%`), keeping column order.
pub fn parse_profiles(yaml: &str) -> Result<BTreeMap<String, Profile>, String> {
    let _ = yaml;
    Ok(BTreeMap::new())
}

/// A rendered cell. CSV/stdout join structured values with ` ¦ `; JSON keeps the structure.
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    Text(String),
    Number(i64),
    Null,
    /// Ordered key/value pairs (Details, ExtraFieldInfo, AllFieldInfo).
    Map(Vec<(String, serde_json::Value)>),
    /// A list (tags, references, false positives).
    List(Vec<String>),
}

/// One output row.
#[derive(Clone, Debug)]
pub struct Row {
    /// For `--sort`: the event instant (None sorts last), then title, then file/line.
    pub sort_key: (Option<DateTime<Utc>>, String, String, usize),
    pub level: String,
    pub cells: Vec<Cell>,
}

#[derive(Clone, Debug)]
pub struct RenderOptions {
    pub utc: bool,
}

/// Render a detection with a profile.
pub fn render_detection(
    det: &Detection,
    meta: &RuleMeta,
    profile: &Profile,
    opts: &RenderOptions,
) -> Row {
    let _ = (det, meta, profile, opts);
    Row {
        sort_key: (None, String::new(), String::new(), 0),
        level: String::new(),
        cells: Vec::new(),
    }
}

/// Render a correlation hit with a profile.
pub fn render_correlation(
    hit: &CorrelationHit,
    members: &[&BaseHit],
    meta: &RuleMeta,
    profile: &Profile,
    opts: &RenderOptions,
) -> Row {
    let _ = (hit, members, meta, profile, opts);
    Row {
        sort_key: (None, String::new(), String::new(), 0),
        level: String::new(),
        cells: Vec::new(),
    }
}

/// Format a timestamp for the `Timestamp` column: `2026-10-24 15:35:38.673 +00:00`
/// (local time, or UTC with `-U`).
pub fn format_timestamp(t: &DateTime<Utc>, utc: bool) -> String {
    let _ = (t, utc);
    String::new()
}

/// The concrete output file paths for `-o` and the selected types (`<base>.<ext>` per type).
pub fn resolve_output_targets(
    output: &Path,
    types: &[OutputFormat],
) -> Vec<(OutputFormat, PathBuf)> {
    let mut seen = std::collections::HashSet::new();
    types
        .iter()
        .copied()
        .filter(|f| seen.insert(*f))
        .map(|fmt| {
            let mut path = output.to_path_buf();
            if path.extension().and_then(|e| e.to_str()) != Some(fmt.extension()) {
                path.set_extension(fmt.extension());
            }
            (fmt, path)
        })
        .collect()
}

/// The writers of one run. `stdout_profile` is used when no `-o` is given; `file_profile` for files.
pub struct Writers {
    pub paths: Vec<PathBuf>,
}

impl Writers {
    pub fn new(
        output: Option<&Path>,
        types: &[OutputFormat],
        stdout_profile: &Profile,
        file_profile: &Profile,
        no_color: bool,
        sort: bool,
    ) -> Result<Writers, String> {
        let _ = (output, types, stdout_profile, file_profile, no_color, sort);
        Ok(Writers { paths: Vec::new() })
    }

    /// Whether rows go to the terminal.
    pub fn writes_stdout(&self) -> bool {
        self.paths.is_empty()
    }

    /// Write (or buffer, with `--sort`) one rendered row. `row` is rendered with the profile the
    /// writer set expects (stdout profile when writing to the terminal, file profile otherwise).
    pub fn write(&mut self, row: Row) {
        let _ = row;
    }

    /// Flush buffered rows (sorted) and close the files.
    pub fn finish(&mut self) -> Result<(), String> {
        Ok(())
    }
}
