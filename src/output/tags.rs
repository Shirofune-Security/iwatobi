//! MITRE ATT&CK tag classification (`config/mitre_tactics.txt`, the same table as Suzaku/Hayabusa).

pub const DEFAULT_MITRE_TACTICS: &str = include_str!("../../config/mitre_tactics.txt");

/// A Sigma tag split into the three output columns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitTags {
    /// Abbreviated tactics, e.g. `InitAccess`.
    pub tactics: Vec<String>,
    /// Technique / software / group IDs, e.g. `T1190`, `S0001`, `G0001`.
    pub mitre: Vec<String>,
    /// Everything else, e.g. `cve.2026-109618`.
    pub other: Vec<String>,
}

/// Split rule tags using the tactic table (`tag_full_str,tag_output_str` CSV).
pub fn split_tags(tags: &[String], tactic_table: &str) -> SplitTags {
    let _ = (tags, tactic_table);
    SplitTags::default()
}
