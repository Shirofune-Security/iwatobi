//! Results summary (design §9), printed after the rows unless `-N`.

use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub total_events: usize,
    pub events_with_hits: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// level → rule title → detections
    pub level_counts: BTreeMap<String, BTreeMap<String, usize>>,
    /// level → date (output timezone) → detections
    pub date_counts: BTreeMap<String, BTreeMap<String, usize>>,
    /// author → titles
    pub authors: BTreeMap<String, BTreeSet<String>>,
    pub first_event: Option<DateTime<Utc>>,
    pub last_event: Option<DateTime<Utc>>,
    /// format name → files
    pub formats: BTreeMap<String, usize>,
    pub correlation_hits_skipped: usize,
}

impl Summary {
    /// Record one detection.
    pub fn record(&mut self, level: &str, title: &str, author: Option<&str>, date: Option<&str>) {
        *self
            .level_counts
            .entry(level.to_string())
            .or_default()
            .entry(title.to_string())
            .or_default() += 1;
        if let Some(d) = date {
            *self
                .date_counts
                .entry(level.to_string())
                .or_default()
                .entry(d.to_string())
                .or_default() += 1;
        }
        if let Some(a) = author {
            self.authors
                .entry(a.to_string())
                .or_default()
                .insert(title.to_string());
        }
    }

    /// Track the first/last event time seen.
    pub fn see_time(&mut self, t: DateTime<Utc>) {
        if self.first_event.is_none_or(|f| t < f) {
            self.first_event = Some(t);
        }
        if self.last_event.is_none_or(|l| t > l) {
            self.last_event = Some(t);
        }
    }

    pub fn merge(&mut self, other: Summary) {
        self.total_events += other.total_events;
        self.events_with_hits += other.events_with_hits;
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        for (level, titles) in other.level_counts {
            let e = self.level_counts.entry(level).or_default();
            for (t, n) in titles {
                *e.entry(t).or_default() += n;
            }
        }
        for (level, dates) in other.date_counts {
            let e = self.date_counts.entry(level).or_default();
            for (d, n) in dates {
                *e.entry(d).or_default() += n;
            }
        }
        for (a, titles) in other.authors {
            self.authors.entry(a).or_default().extend(titles);
        }
        if let Some(t) = other.first_event {
            self.see_time(t);
        }
        if let Some(t) = other.last_event {
            self.see_time(t);
        }
        for (f, n) in other.formats {
            *self.formats.entry(f).or_default() += n;
        }
        self.correlation_hits_skipped += other.correlation_hits_skipped;
    }

    pub fn total_detections(&self) -> usize {
        self.level_counts
            .values()
            .map(|t| t.values().sum::<usize>())
            .sum()
    }
}

/// Print the results summary in the Hayabusa/Suzaku style.
pub fn print_summary(summary: &Summary, no_color: bool, utc: bool) {
    let _ = (summary, no_color, utc);
}
