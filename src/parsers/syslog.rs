//! Syslog-family parser (RFC 3164, RFC 5424, rsyslog ISO, `journalctl -o short-iso`) and the
//! date-first "AppLog" shape (vsftpd.log, xferlog, clamd.log). See design §4.1 and amendments A1, A5.

use super::{LineParser, ParseContext, continuation_event};
use crate::event::ParsedEvent;
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset};

/// Whether `line` starts a syslog record (any of the four syslog shapes).
pub fn matches_entry(line: &str) -> bool {
    let _ = line;
    false
}

/// Whether `line` starts a date-first application log record (`Sun Oct 26 17:39:01 2026 ...`).
pub fn matches_applog_entry(line: &str) -> bool {
    let _ = line;
    false
}

/// Service tags implied by a syslog process name (amendment A1), e.g. `sshd-session` →
/// `[LINUX_SSHD, LINUX_AUTH]`, `crontab` → `[LINUX_CRON]`, `php-fpm8.3` → `[PHP_ERROR_LOG]`.
pub fn service_tags_for_process(process: &str) -> Vec<LogSourceTag> {
    let _ = process;
    Vec::new()
}

pub struct SyslogParser {
    ctx: ParseContext,
    applog: bool,
    last_ts: Option<DateTime<FixedOffset>>,
}

impl SyslogParser {
    pub fn new(ctx: ParseContext, applog: bool) -> Self {
        Self {
            ctx,
            applog,
            last_ts: None,
        }
    }
}

impl LineParser for SyslogParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let _ = self.applog;
        let mut ev = continuation_event(
            line,
            &LogSourceTag::LINUX_SYSLOG,
            &self.ctx.hints.service_tags,
            self.last_ts,
        );
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}
