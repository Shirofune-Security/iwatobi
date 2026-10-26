//! Iwatobi: native Sigma scanner and DFIR timeline generator for Linux logs.

// TODO(skeleton): remove once every module is implemented; the stubs leave fields unused.
#![allow(dead_code)]

mod app;
mod cli;
mod color;
mod correlate;
mod detect;
mod errorlog;
mod event;
mod input;
mod live;
mod logsource;
mod output;
mod parsers;
mod rules;
mod summary;
mod util;

use chrono::Local;
use clap::{CommandFactory, Parser};
use cli::{Cli, Commands, RELEASE_NAME, VERSION};
use color::IwatobiColor::Green;
use std::env;
use std::time::Instant;
use util::p;

const LOGO: &str = include_str!("../art/logo.txt");

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 || (args.len() == 2 && (args[1] == "-h" || args[1] == "--help")) {
        display_logo(false, false, false, true);
        Cli::command().print_help().ok();
        return;
    }

    let start = Instant::now();
    let cli = Cli::parse();
    let code = match &cli.cmd {
        Commands::DfirTimeline(opts) => {
            display_logo(opts.common.quiet, opts.common.no_color, true, false);
            let code = app::run(opts);
            print_error_log_info(opts.common.no_color);
            print_elapsed(start, opts.common.no_color);
            code
        }
        Commands::ListProfiles { common } => {
            display_logo(common.quiet, common.no_color, false, false);
            list_profiles(common.no_color)
        }
    };
    std::process::exit(code);
}

fn list_profiles(no_color: bool) -> i32 {
    let yaml = util::asset("config/profiles.yaml", output::DEFAULT_PROFILES);
    match output::parse_profiles(&yaml) {
        Ok(profiles) => {
            for (name, profile) in &profiles {
                p(Green.rdg(no_color), &format!("{name}:"), true);
                let cols: Vec<&str> = profile.columns.iter().map(|(c, _)| c.as_str()).collect();
                p(None, &format!("    {}", cols.join(", ")), true);
                println!();
            }
            0
        }
        Err(e) => {
            util::error_msg(
                no_color,
                &format!("Could not read config/profiles.yaml: {e}"),
            );
            1
        }
    }
}

fn print_error_log_info(no_color: bool) {
    let count = errorlog::entry_count();
    if count == 0 {
        return;
    }
    let Some(path) = errorlog::log_path() else {
        return;
    };
    let noun = if count == 1 { "message" } else { "messages" };
    p(
        color::IwatobiColor::Orange.rdg(no_color),
        "Warnings and errors: ",
        false,
    );
    p(
        None,
        &format!("{count} {noun} saved to {}", path.display()),
        true,
    );
}

fn print_elapsed(start: Instant, no_color: bool) {
    let duration = start.elapsed();
    let hours = duration.as_secs() / 3600;
    let minutes = (duration.as_secs() % 3600) / 60;
    let seconds = duration.as_secs() % 60;
    p(Green.rdg(no_color), "Elapsed time: ", false);
    p(
        None,
        &format!("{hours:02}:{minutes:02}:{seconds:02}\n"),
        true,
    );
}

fn display_logo(quiet: bool, no_color: bool, time: bool, help: bool) {
    if !quiet {
        let logo = util::asset("art/logo.txt", LOGO);
        p(Green.rdg(no_color), &logo, true);
        println!();
    }
    if time {
        let msg = Local::now().format("%Y/%m/%d %H:%M").to_string();
        p(Green.rdg(no_color), "Start time: ", false);
        p(None, &msg, true);
    }
    if help {
        p(None, &format!("Version: {VERSION} ({RELEASE_NAME})"), true);
    } else {
        p(Green.rdg(no_color), "Version: ", false);
        p(None, &format!("{VERSION} ({RELEASE_NAME})"), true);
    }
    println!();
}
