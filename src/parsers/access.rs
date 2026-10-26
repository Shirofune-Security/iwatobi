//! Web server access logs: text (common / combined / vhost_combined) and JSON lines.
//! Fields follow the Sigma `webserver` taxonomy; see design §4.2, §4.3 and amendments A2, A10.

use super::{LineParser, ParseContext, continuation_event};
use crate::event::ParsedEvent;
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset};

/// Whether `line` is a common/combined access log entry.
pub fn matches_entry(line: &str) -> bool {
    let _ = line;
    false
}

/// Whether `line` is a JSON object that looks like an access record (method/status/uri keys).
pub fn matches_json_entry(line: &str) -> bool {
    let _ = line;
    false
}

pub struct AccessLogParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
}

impl AccessLogParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self { ctx, last_ts: None }
    }
}

impl LineParser for AccessLogParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let mut ev = continuation_event(line, &LogSourceTag::WEBSERVER, &[], self.last_ts);
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}

pub struct AccessJsonParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
}

impl AccessJsonParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self { ctx, last_ts: None }
    }
}

impl LineParser for AccessJsonParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let mut ev = continuation_event(line, &LogSourceTag::WEBSERVER, &[], self.last_ts);
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}
