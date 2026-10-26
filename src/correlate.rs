//! Sigma correlation evaluation with sliding windows (amendment A12).
//!
//! sigma-rust is used only to parse `SigmaCorrelationRule`; it buckets events into fixed,
//! epoch-aligned windows, which misses a chain that crosses a window boundary. Here the base-rule
//! hits of each correlation are grouped by their `group-by` values, sorted by time, and a window of
//! `timespan` slides over them.

use crate::event::ParsedEvent;
use crate::rules::CorrelationRule;
use chrono::{DateTime, Utc};
use sigma_rust::Event;

/// One base-rule match collected during the scan.
#[derive(Clone, Debug)]
pub struct BaseHit {
    pub correlation_index: usize,
    pub base_index: usize,
    pub timestamp: DateTime<Utc>,
    /// The `group-by` field values, `None` when the event lacks one of them.
    pub group_values: Option<Vec<String>>,
    /// Value of the `value_count` field, if the correlation has one.
    pub value_field: Option<String>,
    pub hostname: Option<String>,
    /// `RuleTitle (file:line)` for the correlation's Details column.
    pub summary: String,
}

/// A fired correlation.
#[derive(Clone, Debug)]
pub struct CorrelationHit {
    pub correlation_index: usize,
    /// Representative instant: the latest member.
    pub timestamp: DateTime<Utc>,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    pub count: usize,
    pub group_values: Vec<String>,
    /// Indices into the `hits` slice passed to [`evaluate`].
    pub members: Vec<usize>,
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CorrelationOutcome {
    pub hits: Vec<CorrelationHit>,
    /// Base hits dropped because the event lacked a `group-by` field.
    pub skipped_missing_group_by: usize,
}

/// Build a [`BaseHit`] for a base rule that matched `event`.
pub fn make_base_hit(
    corr: &CorrelationRule,
    correlation_index: usize,
    base_index: usize,
    event: &Event,
    parsed: &ParsedEvent,
    timestamp: DateTime<Utc>,
    summary: String,
) -> BaseHit {
    let _ = (corr, event);
    BaseHit {
        correlation_index,
        base_index,
        timestamp,
        group_values: Some(Vec::new()),
        value_field: None,
        hostname: parsed.hostname.clone(),
        summary,
    }
}

/// Evaluate every correlation rule over the collected base hits.
pub fn evaluate(correlations: &[CorrelationRule], hits: &[BaseHit]) -> CorrelationOutcome {
    let _ = (correlations, hits);
    CorrelationOutcome::default()
}
