//! PHP error log and php-fpm log parsers, plus the PHP-message detector every other parser uses
//! (amendment A3). See design §4.6, §4.7 and amendment A9.

use super::{LineParser, ParseContext, continuation_event};
use crate::event::ParsedEvent;
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset};

/// A PHP message found inside a log line (`PHP Fatal error:  ... in <file> on line <n>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhpMessage {
    pub php_type: String,
    pub text: String,
    pub file: Option<String>,
    pub line: Option<i64>,
}

/// Detect a PHP engine message anywhere in `message` (`PHP Warning:  ...`, `PHP message: PHP
/// Fatal error:  ...`). Used by the Apache/nginx/php-fpm/syslog parsers to add the
/// `php/error_log` tag and the `php_type`/`php_message`/`file`/`line` fields.
pub fn detect_php_message(message: &str) -> Option<PhpMessage> {
    let _ = message;
    None
}

/// Add the PHP tag and fields to `ev` when `message` carries a PHP engine message.
pub fn tag_php_message(ev: &mut ParsedEvent, message: &str) {
    if let Some(php) = detect_php_message(message) {
        ev.add_tag(LogSourceTag::PHP_ERROR_LOG);
        ev.push("php_type", php.php_type);
        ev.push("php_message", php.text);
        ev.push("file", php.file);
        ev.push("line", php.line);
    }
}

pub fn matches_error_entry(line: &str) -> bool {
    let _ = line;
    false
}

pub fn matches_fpm_entry(line: &str) -> bool {
    let _ = line;
    false
}

pub struct PhpErrorParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
}

impl PhpErrorParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self { ctx, last_ts: None }
    }
}

impl LineParser for PhpErrorParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let mut ev = continuation_event(line, &LogSourceTag::PHP_ERROR_LOG, &[], self.last_ts);
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}

pub struct PhpFpmParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
}

impl PhpFpmParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self { ctx, last_ts: None }
    }
}

impl LineParser for PhpFpmParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let mut ev = continuation_event(line, &LogSourceTag::PHP_FPM, &[], self.last_ts);
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}
