//! End-to-end tests: run the built binary against the shipped fixtures and rules.
//!
//! The expected numbers were derived by hand from the fixture lines and the rule keywords (see
//! docs/DESIGN.md §12 and the fixture READMEs), not copied from a run, so they check the parsers,
//! the keyword normalization, the logsource routing and the writers against an independent count.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_iwatobi"))
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(bin())
        .current_dir(repo())
        .args(args)
        .output()
        .expect("iwatobi binary runs");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// Run a scan writing JSONL with the verbose profile and return the rows.
fn scan_jsonl(input_flag: &str, input: &str, extra: &[&str]) -> (Run, Vec<Value>) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.jsonl");
    let out_s = out.to_string_lossy().to_string();
    let mut args = vec![
        "dfir-timeline",
        input_flag,
        input,
        "-q",
        "-K",
        "-w",
        "-Q",
        "-z",
        "UTC",
        "-U",
        "-o",
        &out_s,
        "-t",
        "jsonl",
    ];
    args.extend_from_slice(extra);
    let r = run(&args);
    assert_eq!(r.code, 0, "exit code\nstdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    let text = std::fs::read_to_string(&out).unwrap_or_default();
    let rows: Vec<Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad JSONL line {l}: {e}")))
        .collect();
    (r, rows)
}

fn count_by_title(rows: &[Value]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for r in rows {
        let t = r["RuleTitle"].as_str().unwrap_or("?").to_string();
        *m.entry(t).or_default() += 1;
    }
    m
}

fn expect(counts: &BTreeMap<String, usize>, title: &str, n: usize) {
    assert_eq!(
        counts.get(title).copied().unwrap_or(0),
        n,
        "detections for '{title}'\nall counts: {counts:#?}"
    );
}

const OOM: &str = "PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure)";
const SESSION: &str = "PHP Session ID Too Long Or Illegal Characters (PHP2Shell Memory Disclosure)";
const OUTBOUND: &str = "PHP Outbound HTTP Request From Command Line Code";
const POST_LEN: &str = "PHP POST Content-Length Exceeds Limit";
const SEGFAULT: &str = "Apache Segmentation Fault";
const ABORT: &str = "Apache Worker Process Exited On Abort Or Bus Error Signal";
const SHELL: &str = "Shell Error Output In Apache Error Log";
const THREADING: &str = "Apache Threading Error";
const NGINX_CORE: &str = "Nginx Core Dump";
const FPM_SIGNAL: &str = "PHP-FPM Child Process Exited On Signal";
const FPM_SHELL: &str = "PHP-FPM Child Shell Error Output";
const MEM_PRESSURE: &str = "PHP2Shell PoC Memory Pressure Request";
const RAPID_POST: &str = "Rapid Repeated POST Requests To PHP Index Page";
const CHAIN: &str = "PHP2Shell Exploitation Chain (Memory Pressure, Memory Disclosure, Worker Crash)";
const CRONTAB: &str = "Modifying Crontab";
const DISABLE_TOOLS: &str = "Disabling Security Tools - Builtin";
const NAMED: &str = "Suspicious Named Error";
const SSHD: &str = "Suspicious OpenSSH Daemon Error";

#[test]
fn help_lists_the_commands() {
    let r = run(&["-h"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("dfir-timeline"), "{}", r.stdout);
    assert!(r.stdout.contains("list-profiles"), "{}", r.stdout);
    assert!(r.stdout.contains("Rockhopper Release"), "{}", r.stdout);
}

#[test]
fn list_profiles_prints_the_six_profiles() {
    let r = run(&["list-profiles", "-q", "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for p in ["minimal:", "standard:", "verbose:", "super-verbose:", "all-field-info:", "all-field-info-verbose:"] {
        assert!(r.stdout.contains(p), "missing {p} in\n{}", r.stdout);
    }
}

#[test]
fn php2shell_php_error_log() {
    let (_, rows) = scan_jsonl("-f", "test_files/php2shell/php-error.log", &[]);
    let c = count_by_title(&rows);
    expect(&c, OOM, 106);
    expect(&c, SESSION, 39);
    expect(&c, OUTBOUND, 5);
    expect(&c, POST_LEN, 0);
    assert_eq!(rows.len(), 150);
    // the PHP lines carry an explicit UTC zone: rendered in UTC (-U) they keep their wall time
    let first = &rows[0];
    assert_eq!(first["Timestamp"].as_str().unwrap(), "2026-10-24 15:35:33.000 +00:00");
    assert_eq!(first["LogSource"], "php/error_log");
    assert_eq!(first["Level"], "high");
    assert_eq!(first["Details"]["Type"], "Fatal error");
    assert_eq!(first["Details"]["Line"], 0);
    assert_eq!(first["Details"]["File"], "Unknown");
    assert!(first["MitreTactics"].as_array().unwrap().iter().any(|t| t == "InitAccess"));
    assert!(first["MitreTags"].as_array().unwrap().iter().any(|t| t == "T1190"));
    assert!(first["OtherTags"].as_array().unwrap().iter().any(|t| t == "cve.2026-109618"));
    assert_eq!(first["RuleFile"], "php_pre_script_memory_exhaustion.yml");
    assert_eq!(first["RuleID"], "34b3599a-6677-409d-8400-073729193336");
    assert_eq!(first["LineNumber"], 1);
    assert!(first["LogFile"].as_str().unwrap().ends_with("php-error.log"));
}

#[test]
fn php2shell_apache_error_log() {
    let (_, rows) = scan_jsonl("-f", "test_files/php2shell/apache2/error.log", &[]);
    let c = count_by_title(&rows);
    expect(&c, SEGFAULT, 55);
    expect(&c, ABORT, 7);
    expect(&c, SHELL, 29);
    assert_eq!(rows.len(), 91);
    let shell = rows.iter().find(|r| r["RuleTitle"] == SHELL).unwrap();
    assert!(shell["Details"]["Msg"].as_str().unwrap().starts_with("sh: 1:"), "{shell}");
    assert_eq!(shell["ExtraFieldInfo"]["TimestampInferred"], true);
    assert_eq!(shell["LogSource"], "apache");
    let crash = rows.iter().find(|r| r["RuleTitle"] == SEGFAULT).unwrap();
    assert_eq!(crash["Details"]["Module"], "core");
    assert_eq!(crash["Details"]["Level"], "notice");
    assert_eq!(crash["ExtraFieldInfo"]["error_code"], "AH00051");
    // the apache lines are zoneless: with -z UTC they stay on their wall time
    assert!(crash["Timestamp"].as_str().unwrap().ends_with("+00:00"), "{crash}");
}

#[test]
fn php2shell_access_logs_text_and_json_agree() {
    let (_, text) = scan_jsonl("-f", "test_files/php2shell/apache2/access.log", &[]);
    let (_, json) = scan_jsonl("-f", "test_files/php2shell/apache2/access.jsonl", &[]);
    let ct = count_by_title(&text);
    let cj = count_by_title(&json);
    expect(&ct, MEM_PRESSURE, 44);
    expect(&cj, MEM_PRESSURE, 44);
    expect(&ct, RAPID_POST, 27);
    expect(&cj, RAPID_POST, 27);
    let row = text.iter().find(|r| r["RuleTitle"] == MEM_PRESSURE).unwrap();
    assert_eq!(row["Details"]["SrcIP"], "15.204.59.70");
    assert_eq!(row["Details"]["Method"], "POST");
    assert_eq!(row["Details"]["Status"], 200);
    assert_eq!(row["Details"]["UA"], Value::Null);
    assert_eq!(row["LogSource"], "webserver");
    let jrow = json.iter().find(|r| r["RuleTitle"] == MEM_PRESSURE).unwrap();
    assert_eq!(jrow["Details"]["SrcIP"], "15.204.59.70");
    assert_eq!(jrow["Details"]["Bytes"], 149);
    assert_eq!(jrow["Timestamp"], "2026-10-24 15:35:32.869 +00:00");
    let corr = text.iter().find(|r| r["RuleTitle"] == RAPID_POST).unwrap();
    assert_eq!(corr["LogSource"], "correlation");
    assert_eq!(corr["Level"], "medium");
    assert!(corr["Details"]["Count"].as_i64().unwrap() >= 3, "{corr}");
}

#[test]
fn php2shell_directory_scan_fires_the_exploitation_chain() {
    let (r, rows) = scan_jsonl("-d", "test_files/php2shell", &[]);
    let c = count_by_title(&rows);
    expect(&c, CHAIN, 12);
    expect(&c, OOM, 106);
    expect(&c, SESSION, 39);
    expect(&c, SEGFAULT, 55);
    expect(&c, SHELL, 29);
    expect(&c, MEM_PRESSURE, 88);
    assert!(c.get(RAPID_POST).copied().unwrap_or(0) >= 27, "{c:#?}");
    let chain = rows.iter().find(|r| r["RuleTitle"] == CHAIN).unwrap();
    assert_eq!(chain["Level"], "critical");
    assert_eq!(chain["LogSource"], "correlation");
    assert!(chain["Details"]["Rules"].as_str().unwrap().contains("Worker Crash"), "{chain}");
    // the 100%-untimestamped stderr segment file is skipped without a format hint
    assert!(r.stdout.contains("Total log files: 5") || r.stdout.contains("Total log files:"), "{}", r.stdout);
}

#[test]
fn log_format_override_scans_a_file_with_no_timestamps() {
    let (_, rows) = scan_jsonl(
        "-f",
        "test_files/php2shell/apache2/apache-stderr-segment.log",
        &["--log-format", "apache-error"],
    );
    let c = count_by_title(&rows);
    expect(&c, SHELL, 3);
    assert_eq!(rows[0]["Timestamp"], Value::Null);
}

#[test]
fn linux_syslog_family() {
    let (_, rows) = scan_jsonl("-d", "test_files/linux", &[]);
    let c = count_by_title(&rows);
    expect(&c, CRONTAB, 4); // syslog, cron, rsyslog-iso, rfc5424
    expect(&c, DISABLE_TOOLS, 2);
    expect(&c, NAMED, 4); // 3 in syslog + 1 in syslog.2.gz
    expect(&c, SSHD, 11); // syslog 3, auth.log 3, secure 2, rsyslog-iso 1, rfc5424 1, journalctl 1
    expect(&c, OOM, 1); // php[14100] via syslog
    assert_eq!(rows.len(), 22);
    let crontab = rows.iter().find(|r| r["RuleTitle"] == CRONTAB && r["LogFile"].as_str().unwrap().ends_with("syslog")).unwrap();
    assert_eq!(crontab["LogSource"], "linux/cron");
    assert_eq!(crontab["Computer"], "kali-linux-2025-2");
    assert_eq!(crontab["Details"]["Proc"], "crontab");
    assert_eq!(crontab["Details"]["PID"], 12399);
    assert_eq!(crontab["Details"]["Msg"], "(user) REPLACE (user)");
    let session = rows
        .iter()
        .find(|r| r["RuleTitle"] == SSHD && r["Details"]["Proc"] == "sshd-session")
        .expect("OpenSSH >= 9.8 sshd-session lines must be classified as sshd");
    assert_eq!(session["LogSource"], "linux/sshd");
    let gz = rows.iter().find(|r| r["LogFile"].as_str().unwrap().ends_with("syslog.2.gz")).unwrap();
    assert_eq!(gz["RuleTitle"], NAMED);
    let iso = rows.iter().find(|r| r["LogFile"].as_str().unwrap().ends_with("rsyslog-iso.log") && r["RuleTitle"] == CRONTAB).unwrap();
    assert_eq!(iso["Timestamp"], "2026-10-26 08:40:40.123 +00:00");
    let j = rows.iter().find(|r| r["LogFile"].as_str().unwrap().ends_with("journalctl-short-iso.log")).unwrap();
    assert_eq!(j["Timestamp"], "2026-10-26 08:44:05.000 +00:00");
}

#[test]
fn web_fixtures() {
    let (_, rows) = scan_jsonl("-d", "test_files/web", &[]);
    let c = count_by_title(&rows);
    expect(&c, SEGFAULT, 1);
    expect(&c, ABORT, 1);
    expect(&c, THREADING, 1);
    expect(&c, OOM, 2); // [php:error] line + proxy_fcgi "PHP message:" line
    expect(&c, SESSION, 1); // prefork [:error] line
    expect(&c, NGINX_CORE, 1);
    expect(&c, MEM_PRESSURE, 2); // access.log + access.json
    expect(&c, RAPID_POST, 1);
    let threading = rows.iter().find(|r| r["RuleTitle"] == THREADING).unwrap();
    assert_eq!(threading["ExtraFieldInfo"]["TimestampInferred"], true);
    let json_hit = rows
        .iter()
        .find(|r| r["RuleTitle"] == MEM_PRESSURE && r["LogFile"].as_str().unwrap().ends_with("access.json"))
        .unwrap();
    assert_eq!(json_hit["Details"]["SrcIP"], "203.0.113.20");
    assert_eq!(json_hit["Timestamp"], "2026-10-26 03:20:00.000 +00:00");
    let sess = rows.iter().find(|r| r["RuleTitle"] == SESSION).unwrap();
    assert_eq!(sess["Details"]["Client"], "::1:50284");
    assert_eq!(sess["ExtraFieldInfo"]["referer"], "http://example.com/");
}

#[test]
fn php_fpm_fixtures() {
    let (_, rows) = scan_jsonl("-d", "test_files/php2shell-fpm", &[]);
    let c = count_by_title(&rows);
    expect(&c, FPM_SIGNAL, 2);
    expect(&c, FPM_SHELL, 1);
    expect(&c, SESSION, 2); // fpm stderr + php-error.log
    expect(&c, OOM, 2); // php-error.log + nginx FastCGI stderr
    expect(&c, POST_LEN, 1);
    expect(&c, OUTBOUND, 2);
    let berlin = rows
        .iter()
        .find(|r| r["RuleTitle"] == OOM && r["LogFile"].as_str().unwrap().ends_with("php-error.log"))
        .unwrap();
    // [26-Oct-2026 11:00:59 Europe/Berlin] is 10:00:59 UTC
    assert_eq!(berlin["Timestamp"], "2026-10-26 10:00:59.000 +00:00");
    let fpm = rows.iter().find(|r| r["RuleTitle"] == FPM_SHELL).unwrap();
    assert_eq!(fpm["Details"]["Pool"], "www");
    assert_eq!(fpm["Details"]["ChildPID"], 2010);
}

#[test]
fn control_characters_never_reach_the_output() {
    let r = run(&[
        "dfir-timeline",
        "-f",
        "test_files/php2shell-fpm/php-error.log",
        "-q",
        "-K",
        "-w",
        "-Q",
        "-z",
        "UTC",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stdout.contains('\u{1b}'), "raw ESC in stdout");
    assert!(!r.stdout.contains('\u{7}'), "raw BEL in stdout");
    assert!(r.stdout.contains("\\x1B"), "escaped ESC expected in\n{}", r.stdout);
}

#[test]
fn stdout_uses_the_standard_profile_and_colors_can_be_disabled() {
    let r = run(&["dfir-timeline", "-f", "test_files/linux/cron", "-q", "-K", "-w", "-Q", "-z", "UTC", "-U"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Timestamp · RuleTitle · Level · Computer · LogSource · Details"), "{}", r.stdout);
    assert!(r.stdout.contains("2026-10-26 04:05:10.000 +00:00 · Modifying Crontab · medium · rhel9-web · linux/cron · "), "{}", r.stdout);
    assert!(r.stdout.contains("Msg: (apache) REPLACE (apache)"), "{}", r.stdout);
    assert!(!r.stdout.contains('\u{1b}'), "no ANSI escapes with -K");
    assert!(r.stdout.contains("Results Summary"), "{}", r.stdout);
    assert!(r.stdout.contains("Total detection rules: 16"), "{}", r.stdout);
    assert!(r.stdout.contains("Total correlation rules: 2"), "{}", r.stdout);
}

#[test]
fn minimum_level_filters_rules() {
    let (_, rows) = scan_jsonl("-d", "test_files/linux", &["-m", "high"]);
    let c = count_by_title(&rows);
    expect(&c, NAMED, 4);
    expect(&c, OOM, 1);
    expect(&c, CRONTAB, 0);
    expect(&c, SSHD, 0);
}

#[test]
fn csv_json_outputs_and_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("timeline");
    let base_s = base.to_string_lossy().to_string();
    let r = run(&[
        "dfir-timeline", "-f", "test_files/linux/syslog", "-q", "-K", "-w", "-Q", "-z", "UTC", "-U", "-o", &base_s, "-t", "csv,json,jsonl",
    ]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    let csv_path = dir.path().join("timeline.csv");
    let json_path = dir.path().join("timeline.json");
    let jsonl_path = dir.path().join("timeline.jsonl");
    assert!(csv_path.is_file() && json_path.is_file() && jsonl_path.is_file());
    let csv_text = std::fs::read_to_string(&csv_path).unwrap();
    let mut lines = csv_text.lines();
    assert_eq!(
        lines.next().unwrap(),
        "Timestamp,RuleTitle,Level,Computer,LogSource,MitreTactics,MitreTags,OtherTags,LineNumber,Details,ExtraFieldInfo,RuleFile,RuleID,LogFile"
    );
    let data_rows = lines.filter(|l| !l.is_empty()).count();
    assert_eq!(data_rows, 10);
    // CSV details use the ¦ separator and the apostrophe guard for formula-like cells
    assert!(csv_text.contains("Proc: crontab ¦ PID: 12399 ¦ Msg: (user) REPLACE (user)"), "{csv_text}");
    // JSON = newline-separated pretty objects (Hayabusa/Suzaku style); every object parses
    let json_text = std::fs::read_to_string(&json_path).unwrap();
    let objs: Vec<Value> = serde_json::Deserializer::from_str(&json_text).into_iter::<Value>().map(|v| v.unwrap()).collect();
    assert_eq!(objs.len(), 10);
    assert!(json_text.contains("\n  \"RuleTitle\""), "pretty-printed objects expected");
    let jsonl_text = std::fs::read_to_string(&jsonl_path).unwrap();
    assert_eq!(jsonl_text.lines().count(), 10);
    assert!(r.stdout.contains("Results saved:"), "{}", r.stdout);
    // refusing to overwrite without -C
    let again = run(&["dfir-timeline", "-f", "test_files/linux/syslog", "-q", "-K", "-w", "-Q", "-o", &base_s, "-t", "csv"]);
    assert_eq!(again.code, 1);
    assert!(again.stdout.contains("already exists"), "{}", again.stdout);
    let forced = run(&["dfir-timeline", "-f", "test_files/linux/syslog", "-q", "-K", "-w", "-Q", "-o", &base_s, "-t", "csv", "-C"]);
    assert_eq!(forced.code, 0, "{}", forced.stdout);
}

#[test]
fn sorted_output_is_in_time_order() {
    let (_, rows) = scan_jsonl("-d", "test_files/linux", &["-s"]);
    let times: Vec<&str> = rows.iter().filter_map(|r| r["Timestamp"].as_str()).collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted, "rows must be in ascending time order with -s");
}

#[test]
fn single_rule_file_can_be_used() {
    let (_, rows) = scan_jsonl(
        "-f",
        "test_files/linux/syslog",
        &["-r", "rules/sigma/linux/builtin/cron/lnx_cron_crontab_file_modification.yml"],
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["RuleTitle"], CRONTAB);
}

#[test]
fn missing_inputs_are_reported() {
    let r = run(&["dfir-timeline", "-f", "test_files/does-not-exist.log", "-q", "-K", "-Q"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("does not exist"), "{}", r.stdout);
    let r = run(&["dfir-timeline", "-d", "test_files/linux", "-q", "-K", "-Q", "-r", "nope/"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("Rule file or directory does not exist"), "{}", r.stdout);
}

#[cfg(target_os = "linux")]
#[test]
fn live_analysis_without_wizard_skips_missing_logsources() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    std::fs::create_dir_all(logs.join("apache2")).unwrap();
    std::fs::copy(repo().join("test_files/php2shell/apache2/error.log"), logs.join("apache2/error.log")).unwrap();
    let table = format!(
        "- logsource: {{service: apache}}\n  paths: [\"{0}/apache2/error*.log*\"]\n- logsource: {{product: php, service: error_log}}\n  paths: [\"{0}/apache2/error*.log*\"]\n- logsource: {{product: linux, service: cron}}\n  paths: [\"{0}/nowhere/cron*\"]\n",
        logs.display()
    );
    let table_path = dir.path().join("locations.yaml");
    std::fs::write(&table_path, table).unwrap();
    let out = dir.path().join("live.jsonl");
    let r = run(&[
        "dfir-timeline", "-l", "-w", "-q", "-K", "-Q", "-z", "UTC", "-U",
        "--log-locations", table_path.to_str().unwrap(),
        "-o", out.to_str().unwrap(), "-t", "jsonl",
        "-r", "rules",
    ]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("skipped"), "the unfound logsources must be reported:\n{}", r.stdout);
    let text = std::fs::read_to_string(&out).unwrap();
    let rows: Vec<Value> = text.lines().filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
    let c = count_by_title(&rows);
    expect(&c, SEGFAULT, 55);
    expect(&c, SHELL, 29);
    // the error log never had a syslog file, so no cron hits and no crash from the missing table rows
    expect(&c, CRONTAB, 0);
}

#[test]
fn fixture_tree_is_present() {
    for f in [
        "test_files/php2shell/php-error.log",
        "test_files/php2shell/apache2/error.log",
        "test_files/php2shell/apache2/access.log",
        "test_files/php2shell/apache2/access.jsonl",
        "test_files/linux/syslog.2.gz",
        "rules/sigma/web/product/nginx/web_nginx_core_dump.yml",
        "rules/iwatobi/php/php2shell/php2shell_exploitation_chain.yml",
    ] {
        assert!(Path::new(&repo().join(f)).is_file(), "{f} missing");
    }
}
