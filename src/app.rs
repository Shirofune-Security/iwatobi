//! The `dfir-timeline` command: load rules, find inputs, scan, correlate, write, summarize.

use crate::cli::{TimelineOptions, offset_to_seconds};
use crate::color::IwatobiColor;
use crate::correlate::{self, BaseHit};
use crate::detect::{ScanOptions, ScanResult, TimeFilter, scan_lines, scan_target};
use crate::errorlog::log_warn;
use crate::input::{self, ScanTarget};
use crate::live;
use crate::logsource::LogSourceSpec;
use crate::output::{
    self, Profile, RenderOptions, Writers, render_correlation, render_detection,
    resolve_output_targets,
};
use crate::parsers::{LogFormat, ParseContext};
use crate::rules::{self, RuleFilters, RuleSet};
use crate::summary::{self, Summary};
use crate::util::{self, error_msg, fatal_error, p, p_label, warn_msg};
use chrono::{DateTime, Utc};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Exit status of the command (0 = ok, 1 = usage/runtime error).
pub fn run(opts: &TimelineOptions) -> i32 {
    let no_color = opts.common.no_color;
    crate::errorlog::set_quiet(opts.general.quiet_errors);
    if let Some(n) = opts.general.threads
        && n > 0
        && let Err(e) = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
    {
        log_warn(&format!("Could not set the thread count: {e}"));
    }

    // --- validate inputs -----------------------------------------------------------------
    if let Some(f) = &opts.input.filepath
        && !f.is_file()
    {
        error_msg(
            no_color,
            &format!("File {} does not exist or is not a file.", f.display()),
        );
        return 1;
    }
    if let Some(d) = &opts.input.directory
        && !d.is_dir()
    {
        error_msg(
            no_color,
            &format!(
                "Directory {} does not exist or is not a directory.",
                d.display()
            ),
        );
        return 1;
    }
    if let Some(out) = &opts.output.output
        && !opts.output.clobber
    {
        let existing: Vec<String> = resolve_output_targets(out, &opts.output.output_types)
            .into_iter()
            .filter(|(_, p)| p.exists())
            .map(|(_, p)| p.display().to_string())
            .collect();
        if !existing.is_empty() {
            error_msg(
                no_color,
                &format!(
                    "The output file already exists: {}. Please specify a different filename or add the -C, --clobber option to overwrite.",
                    existing.join(", ")
                ),
            );
            return 1;
        }
    }

    // --- profiles ------------------------------------------------------------------------
    let profiles = match output::parse_profiles(&util::asset(
        "config/profiles.yaml",
        output::DEFAULT_PROFILES,
    )) {
        Ok(p) => p,
        Err(e) => {
            error_msg(
                no_color,
                &format!("Could not read config/profiles.yaml: {e}"),
            );
            return 1;
        }
    };
    let pick = |name: &str| -> Option<Profile> { profiles.get(name).cloned() };
    let (stdout_profile, file_profile) = match &opts.output.profile {
        Some(name) => match pick(name) {
            Some(pr) => (pr.clone(), pr),
            None => {
                error_msg(
                    no_color,
                    &format!(
                        "Profile '{name}' does not exist. Available profiles: {}",
                        profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                );
                return 1;
            }
        },
        None => match (pick("standard"), pick("verbose")) {
            (Some(s), Some(v)) => (s, v),
            _ => {
                error_msg(
                    no_color,
                    "config/profiles.yaml must define the 'standard' and 'verbose' profiles.",
                );
                return 1;
            }
        },
    };

    // --- rules ---------------------------------------------------------------------------
    let rules_path = if opts.general.rules == Path::new("./rules") {
        util::resolve_default_dir("rules")
    } else {
        opts.general.rules.clone()
    };
    if !rules_path.exists() {
        error_msg(
            no_color,
            &format!(
                "Rule file or directory does not exist: {}",
                rules_path.display()
            ),
        );
        return 1;
    }
    let filters = RuleFilters {
        min_level: opts.filter.min_level.clone(),
        enable_deprecated: opts.filter.enable_deprecated_rules,
        enable_unsupported: opts.filter.enable_unsupported_rules,
        include_status: lower(&opts.filter.include_status),
        exclude_status: lower(&opts.filter.exclude_status),
        include_tag: lower(&opts.filter.include_tag),
        exclude_tag: lower(&opts.filter.exclude_tag),
    };
    let ruleset = rules::load_rules(&rules_path, &filters);
    print_rule_stats(&ruleset, no_color);
    if ruleset.rules.is_empty() && ruleset.correlations.is_empty() {
        error_msg(
            no_color,
            "Iwatobi could not load any rules. Please check the -r, --rules path.",
        );
        return 1;
    }

    // --- time filter ------------------------------------------------------------------------
    let time_filter = match build_time_filter(opts) {
        Ok(f) => f,
        Err(e) => {
            error_msg(no_color, &e);
            return 1;
        }
    };

    // --- inputs ------------------------------------------------------------------------------
    let tz = opts.general.timezone.unwrap_or_default();
    let mut targets: Vec<ScanTarget> = Vec::new();
    let mut hostname_hint = None;
    let mut journal: Option<std::process::Child> = None;
    let mut skipped_logsources: Vec<LogSourceSpec> = Vec::new();
    if opts.input.live_analysis {
        hostname_hint = util::local_hostname();
        let table = match &opts.general.log_locations {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    error_msg(no_color, &format!("Could not read {}: {e}", path.display()));
                    return 1;
                }
            },
            None => util::asset("config/log_locations.yaml", live::DEFAULT_LOG_LOCATIONS),
        };
        let rows = match live::parse_log_locations(&table) {
            Ok(r) => r,
            Err(e) => {
                error_msg(
                    no_color,
                    &format!("Could not parse the log location table: {e}"),
                );
                return 1;
            }
        };
        let needs = needed_logsources(&ruleset);
        let live_opts = live::LiveOptions {
            no_wizard: opts.general.no_wizard,
            no_color,
            since: time_filter.start.map(|s| format!("@{}", s.timestamp())),
        };
        match live::discover(&needs, &rows, &live_opts, &rules_path) {
            Ok(d) => {
                targets = d.targets;
                journal = d.journal;
                skipped_logsources = d.skipped;
                for note in &d.notes {
                    warn_msg(no_color, note);
                    log_warn(note);
                }
            }
            Err(e) => {
                error_msg(no_color, &e);
                return 1;
            }
        }
        for t in &mut targets {
            t.format = t.format.or(opts.input.log_format);
        }
        if !skipped_logsources.is_empty() {
            let names: Vec<String> = skipped_logsources
                .iter()
                .map(|s| format!("{{{s}}}"))
                .collect();
            warn_msg(
                no_color,
                &format!(
                    "No log files were found for {} log source(s); the rules that need them were skipped: {}",
                    skipped_logsources.len(),
                    names.join(", ")
                ),
            );
        }
    } else if let Some(f) = &opts.input.filepath {
        targets = input::enumerate(f, opts.input.log_format);
    } else if let Some(d) = &opts.input.directory {
        targets = input::enumerate(d, opts.input.log_format);
    }
    if targets.is_empty() && journal.is_none() {
        error_msg(no_color, "No log files to scan.");
        return 1;
    }

    // --- writers -------------------------------------------------------------------------------
    let writers = match Writers::new(
        opts.output.output.as_deref(),
        &opts.output.output_types,
        &stdout_profile,
        &file_profile,
        no_color,
        opts.output.sort,
    ) {
        Ok(w) => w,
        Err(e) => fatal_error(no_color, &e),
    };
    let render_profile = if writers.writes_stdout() {
        stdout_profile.clone()
    } else {
        file_profile.clone()
    };
    let render_opts = RenderOptions {
        utc: opts.output.utc,
    };

    // Only the live rules that have a log to run against matter for the summary of needs.
    let ruleset = if skipped_logsources.is_empty() {
        ruleset
    } else {
        drop_rules_for(ruleset, &skipped_logsources)
    };

    p_label(
        no_color,
        "Total log files: ",
        &util::fmt_num(targets.len() + usize::from(journal.is_some())),
    );
    println!();

    // --- scan ------------------------------------------------------------------------------------
    let scan_opts = ScanOptions {
        tz,
        hostname_hint,
        time_filter,
    };
    let state = Arc::new(Mutex::new(ScanState {
        writers,
        summary: Summary::default(),
        base_hits: Vec::new(),
        mixed_zone_files: 0,
    }));
    let verbose = opts.general.verbose;
    let ruleset_ref = &ruleset;
    let profile_ref = &render_profile;
    let opts_ref = &render_opts;
    let bar = progress_bar(targets.len(), no_color || opts.common.quiet);
    targets.par_iter().for_each(|target| {
        let result = scan_target(target, ruleset_ref, &scan_opts);
        report_file(target, &result, verbose, no_color);
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        consume_result(&mut st, result, ruleset_ref, profile_ref, opts_ref);
        if let Some(b) = &bar {
            b.inc(1);
        }
    });
    if let Some(mut child) = journal.take() {
        let target = ScanTarget {
            path: std::path::PathBuf::from("journalctl"),
            display_name: "journalctl".to_string(),
            extra_tags: Vec::new(),
            format: Some(LogFormat::Syslog),
        };
        // Drain stderr on its own thread: a journalctl that writes more than the pipe buffer
        // would otherwise block, and the "not seeing messages" hint is how a partial (non-root)
        // read of the journal shows up.
        let stderr_reader = child.stderr.take().map(|stderr| {
            std::thread::spawn(move || {
                std::io::BufReader::new(stderr)
                    .lines()
                    .map_while(Result::ok)
                    .collect::<Vec<String>>()
            })
        });
        if let Some(stdout) = child.stdout.take() {
            let mut ctx = ParseContext::new(Path::new("."), tz);
            ctx.display_name = "journalctl".to_string();
            ctx.hostname_hint = scan_opts.hostname_hint.clone();
            ctx.year_hint = Utc::now().format("%Y").to_string().parse().unwrap_or(2000);
            let reader = std::io::BufReader::new(stdout);
            let mut result = ScanResult {
                format: Some(LogFormat::Syslog),
                ..Default::default()
            };
            scan_lines(
                reader.lines().map_while(Result::ok),
                LogFormat::Syslog,
                ctx,
                &target,
                ruleset_ref,
                &scan_opts,
                &mut result,
            );
            report_file(&target, &result, verbose, no_color);
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            consume_result(&mut st, result, ruleset_ref, profile_ref, opts_ref);
        }
        let stderr_lines = stderr_reader
            .and_then(|t| t.join().ok())
            .unwrap_or_default();
        let mut partial = false;
        for line in &stderr_lines {
            log_warn(&format!("journalctl: {line}"));
            if line.contains("not seeing messages") || line.contains("insufficient permissions") {
                partial = true;
            }
        }
        if partial {
            let msg = "journalctl could not read the system journal completely (run as root or as a member of systemd-journal); results may be incomplete";
            log_warn(msg);
            warn_msg(no_color, msg);
        }
        match child.wait() {
            Ok(status) if !status.success() => {
                let msg = format!("journalctl exited with {status}; the journal may be incomplete");
                log_warn(&msg);
                warn_msg(no_color, &msg);
            }
            Err(e) => log_warn(&format!("journalctl: {e}")),
            _ => {}
        }
    }
    if let Some(b) = &bar {
        b.finish_and_clear();
    }

    let mut st = match Arc::try_unwrap(state) {
        Ok(m) => m.into_inner().unwrap_or_else(|e| e.into_inner()),
        Err(arc) => {
            let mut g = arc.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *g, ScanState::empty())
        }
    };

    // --- correlation -----------------------------------------------------------------------------
    if !ruleset.correlations.is_empty() && !st.base_hits.is_empty() {
        let outcome = correlate::evaluate(&ruleset.correlations, &st.base_hits);
        st.summary.correlation_hits_skipped = outcome.skipped_missing_group_by;
        for hit in &outcome.hits {
            let corr = &ruleset.correlations[hit.correlation_index];
            if rules::level_rank(&corr.meta.level) < rules::level_rank(&filters.min_level) {
                continue;
            }
            let members: Vec<&BaseHit> = hit.members.iter().map(|i| &st.base_hits[*i]).collect();
            let row = render_correlation(hit, &members, &corr.meta, &render_profile, &render_opts);
            let date = output::format_timestamp(&hit.timestamp, render_opts.utc);
            st.summary.record(
                &corr.meta.level,
                &corr.meta.title,
                corr.meta.author.as_deref(),
                Some(&date[..10.min(date.len())]),
            );
            st.summary.see_time(hit.timestamp);
            st.writers.write(row);
            if corr.spec.correlation.generate.unwrap_or(false) {
                // Member events are reported through the correlation only unless `generate: true`;
                // the members' own rows are their summaries.
                for m in &members {
                    log_warn(&format!("correlation member: {}", m.summary));
                }
            }
        }
    }
    if let Err(e) = st.writers.finish() {
        fatal_error(no_color, &e);
    }
    if st.mixed_zone_files > 0 && opts.general.timezone.is_none() {
        let msg = "Some logs carry a timezone and others do not; timestamps without one were read as local time. Use -z (ex: -z UTC) if those logs come from another timezone.";
        warn_msg(no_color, msg);
        log_warn(msg);
    }

    // --- summary --------------------------------------------------------------------------------
    println!();
    if !opts.output.no_summary {
        summary::print_summary(&st.summary, no_color, opts.output.utc);
    }
    if !st.writers.paths.is_empty() {
        p(IwatobiColor::Green.rdg(no_color), "Results saved: ", false);
        let parts: Vec<String> = st
            .writers
            .paths
            .iter()
            .map(|pth| format!("{} ({})", pth.display(), util::file_size_display(pth)))
            .collect();
        p(None, &parts.join(" and "), true);
    }
    0
}

struct ScanState {
    writers: Writers,
    summary: Summary,
    base_hits: Vec<BaseHit>,
    mixed_zone_files: usize,
}

impl ScanState {
    fn empty() -> Self {
        Self {
            writers: Writers::empty(),
            summary: Summary::default(),
            base_hits: Vec::new(),
            mixed_zone_files: 0,
        }
    }
}

fn consume_result(
    st: &mut ScanState,
    mut result: ScanResult,
    ruleset: &RuleSet,
    profile: &Profile,
    opts: &RenderOptions,
) {
    for det in result.detections.drain(..) {
        let meta = &ruleset.rules[det.rule_index].meta;
        let row = render_detection(&det, meta, profile, opts);
        let date = det
            .event
            .timestamp
            .map(|t| output::format_timestamp(&t.with_timezone(&Utc), opts.utc))
            .map(|s| s[..10.min(s.len())].to_string());
        result.summary.record(
            &meta.level,
            &meta.title,
            meta.author.as_deref(),
            date.as_deref(),
        );
        st.writers.write(row);
    }
    st.base_hits.append(&mut result.base_hits);
    if result.mixed_zone_sources {
        st.mixed_zone_files += 1;
    }
    st.summary.merge(result.summary);
}

fn report_file(target: &ScanTarget, result: &ScanResult, verbose: bool, no_color: bool) {
    if let Some(reason) = &result.skipped {
        let msg = format!("Skipped {}: {reason}", target.display_name);
        log_warn(&msg);
        if verbose {
            warn_msg(no_color, &msg);
        }
    } else if verbose {
        let fmt = result.format.map(|f| f.name()).unwrap_or("-");
        p(
            None,
            &format!(
                "Scanned {} ({fmt}, {} events, {} detections)",
                target.display_name,
                result.events,
                result.detections.len()
            ),
            true,
        );
    }
}

fn progress_bar(len: usize, hidden: bool) -> Option<indicatif::ProgressBar> {
    if hidden || len < 2 || !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        return None;
    }
    let bar = indicatif::ProgressBar::new(len as u64);
    bar.set_style(
        indicatif::ProgressStyle::with_template("[{elapsed_precise}] {wide_bar} {pos}/{len} files")
            .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar()),
    );
    Some(bar)
}

fn lower(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn build_time_filter(opts: &TimelineOptions) -> Result<TimeFilter, String> {
    let mut f = TimeFilter::default();
    if let Some(s) = &opts.filter.timeline_start {
        f.start = Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| e.to_string())?
                .with_timezone(&Utc),
        );
    }
    if let Some(e) = &opts.filter.timeline_end {
        f.end = Some(
            DateTime::parse_from_rfc3339(e)
                .map_err(|e| e.to_string())?
                .with_timezone(&Utc),
        );
    }
    if let Some(off) = &opts.filter.time_offset {
        let secs = offset_to_seconds(off).ok_or_else(|| format!("invalid time offset {off}"))?;
        f.start = Some(Utc::now() - chrono::Duration::seconds(secs));
    }
    if let (Some(s), Some(e)) = (f.start, f.end)
        && s > e
    {
        return Err("--timeline-start is after --timeline-end".to_string());
    }
    Ok(f)
}

/// The distinct logsources of every loaded rule (detection and correlation base rules).
pub fn needed_logsources(ruleset: &RuleSet) -> Vec<LogSourceSpec> {
    let mut seen = BTreeMap::new();
    for r in &ruleset.rules {
        seen.entry(r.logsource.to_string())
            .or_insert_with(|| r.logsource.clone());
    }
    for c in &ruleset.correlations {
        for b in &c.base_rules {
            seen.entry(b.logsource.to_string())
                .or_insert_with(|| b.logsource.clone());
        }
    }
    seen.into_values().collect()
}

/// Drop the rules whose logsource the user chose to skip in live analysis.
fn drop_rules_for(ruleset: RuleSet, skipped: &[LogSourceSpec]) -> RuleSet {
    let RuleSet {
        rules,
        correlations,
        stats,
    } = ruleset;
    let rules = rules
        .into_iter()
        .filter(|r| !skipped.contains(&r.logsource))
        .collect();
    let correlations = correlations
        .into_iter()
        .filter(|c| !c.base_rules.iter().any(|b| skipped.contains(&b.logsource)))
        .collect();
    RuleSet {
        rules,
        correlations,
        stats,
    }
}

fn print_rule_stats(ruleset: &RuleSet, no_color: bool) {
    let s = &ruleset.stats;
    p_label(
        no_color,
        "Total detection rules: ",
        &util::fmt_num(ruleset.rules.len()),
    );
    p_label(
        no_color,
        "Total correlation rules: ",
        &util::fmt_num(ruleset.correlations.len()),
    );
    if s.skipped_unsupported_logsource > 0 {
        p_label(
            no_color,
            "Rules skipped (unsupported log source): ",
            &util::fmt_num(s.skipped_unsupported_logsource),
        );
    }
    if s.skipped_status > 0 {
        p_label(
            no_color,
            "Rules skipped (status): ",
            &util::fmt_num(s.skipped_status),
        );
    }
    if s.skipped_level > 0 {
        p_label(
            no_color,
            "Rules skipped (below minimum level): ",
            &util::fmt_num(s.skipped_level),
        );
    }
    if s.skipped_tag > 0 {
        p_label(
            no_color,
            "Rules skipped (tags): ",
            &util::fmt_num(s.skipped_tag),
        );
    }
    if s.failed > 0 {
        p_label(
            no_color,
            "Rules failed to load (see the error log): ",
            &util::fmt_num(s.failed),
        );
    }
}
