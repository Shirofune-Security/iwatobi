//! Rule loading: YAML documents → sigma-rust rules, with keyword normalization (design §6,
//! amendment A11), correlation files (A12/A13), filtering and load statistics.

use crate::logsource::LogSourceSpec;
use sigma_rust::{Rule, SigmaCorrelationRule};
use std::path::Path;

/// Rule metadata rendered by the output, shared by detection and correlation rules.
#[derive(Clone, Debug, Default)]
pub struct RuleMeta {
    pub title: String,
    pub id: Option<String>,
    /// Lowercase Sigma level (`informational` when the rule has none).
    pub level: String,
    /// Lowercase status, if any.
    pub status: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub description: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
    /// File name of the rule (without directories).
    pub rule_file: String,
}

/// A detection rule ready to run.
pub struct LoadedRule {
    pub rule: Rule,
    pub meta: RuleMeta,
    pub logsource: LogSourceSpec,
}

/// A base rule of a correlation file (only reported through its correlation).
pub struct BaseRule {
    /// The `name:` (or id/title) the correlation references it by.
    pub name: String,
    pub rule: Rule,
    pub meta: RuleMeta,
    pub logsource: LogSourceSpec,
}

/// A correlation rule with its base rules.
pub struct CorrelationRule {
    pub spec: SigmaCorrelationRule,
    pub meta: RuleMeta,
    pub base_rules: Vec<BaseRule>,
    /// Indices into `base_rules`, in the order of the correlation's `rules:` list.
    pub rule_order: Vec<usize>,
}

/// Which rules to keep (`-m`, `-D`, `-u`, `--include/exclude-status`, `--include/exclude-tag`).
#[derive(Clone, Debug, Default)]
pub struct RuleFilters {
    pub min_level: String,
    pub enable_deprecated: bool,
    pub enable_unsupported: bool,
    pub include_status: Vec<String>,
    pub exclude_status: Vec<String>,
    pub include_tag: Vec<String>,
    pub exclude_tag: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct LoadStats {
    pub files_seen: usize,
    pub loaded: usize,
    pub correlations: usize,
    pub skipped_unsupported_logsource: usize,
    pub skipped_status: usize,
    pub skipped_level: usize,
    pub skipped_tag: usize,
    pub failed: usize,
}

pub struct RuleSet {
    pub rules: Vec<LoadedRule>,
    pub correlations: Vec<CorrelationRule>,
    pub stats: LoadStats,
}

/// Load every `*.yml`/`*.yaml` under `path` (or the single file) and apply the filters.
pub fn load_rules(path: &Path, filters: &RuleFilters) -> RuleSet {
    let _ = (path, filters);
    RuleSet {
        rules: Vec::new(),
        correlations: Vec::new(),
        stats: LoadStats::default(),
    }
}

/// Rewrite a rule document so keyword selections match anywhere in the log message
/// (design §6 and amendment A11). Safe to call on correlation documents (no `detection`).
pub fn normalize_detection(doc: &mut yaml_serde::Value) {
    let _ = doc;
}

/// `informational`=1 .. `critical`=5, 0 for unknown text.
pub fn level_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "informational" | "info" => 1,
        "low" => 2,
        "medium" | "med" => 3,
        "high" => 4,
        "critical" | "crit" => 5,
        _ => 0,
    }
}

/// Canonical lowercase level name (`info` → `informational`, `crit` → `critical`).
pub fn canonical_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "info" | "informational" => "informational".to_string(),
        "med" | "medium" => "medium".to_string(),
        "crit" | "critical" => "critical".to_string(),
        other => other.to_string(),
    }
}
