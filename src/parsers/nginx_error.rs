//! nginx error log parser. See design §4.5 and amendments A3, A8.

use super::{LineParser, ParseContext, continuation_event};
use crate::event::ParsedEvent;
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset};

pub fn matches_entry(line: &str) -> bool {
    let _ = line;
    false
}

pub struct NginxErrorParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
}

impl NginxErrorParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self { ctx, last_ts: None }
    }
}

impl LineParser for NginxErrorParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let mut ev = continuation_event(
            line,
            &LogSourceTag::NGINX_ERROR,
            &[LogSourceTag::NGINX_ERROR_CANONICAL],
            self.last_ts,
        );
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}
