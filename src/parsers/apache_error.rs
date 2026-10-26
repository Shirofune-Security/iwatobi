//! Apache 2.2 / 2.4 error log parser. See design §4.4 and amendments A3, A4.

use super::{LineParser, ParseContext, continuation_event};
use crate::event::ParsedEvent;
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset};

pub fn matches_entry(line: &str) -> bool {
    let _ = line;
    false
}

pub struct ApacheErrorParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
}

impl ApacheErrorParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self { ctx, last_ts: None }
    }
}

impl LineParser for ApacheErrorParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let mut ev = continuation_event(
            line,
            &LogSourceTag::APACHE_ERROR,
            &[LogSourceTag::APACHE_ERROR_CANONICAL],
            self.last_ts,
        );
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}
