# Changes

## 0.1.0 [2026/10/27] - Rockhopper Release

**New Features:**

- First release of Iwatobi, a native Sigma scanner and DFIR timeline generator for Linux text logs, built on the same [sigma-rust](https://github.com/Yamato-Security/sigma-rust) engine as Suzaku. (@YamatoSecurity)
- `dfir-timeline` command: scan one file (`-f`), a directory (`-d`, recursively, rotated `.1`/`.2.gz` files included) or the live system (`-l, --live-analysis`). Live analysis works out which log files the loaded rules need from `config/log_locations.yaml`, asks for a directory (or skips the rules) when a log source is not found, and reads the systemd journal through `journalctl` when a host has no syslog files.
- Log formats: syslog (RFC 3164, RFC 5424, rsyslog ISO, `journalctl -o short-iso`), date-first daemon logs (vsftpd, clamd), Apache/nginx access logs (common, combined, vhost_combined and JSON lines, exposed with the Sigma web server field names), Apache and nginx error logs, PHP error logs and php-fpm logs. PHP engine messages are recognised inside Apache, nginx, php-fpm and syslog lines too.
- Sigma rules: `rules/sigma/` holds SigmaHQ rules verbatim (syslog, sshd, cron, Apache, nginx); `rules/iwatobi/` holds new rules, including a PHP2Shell (CVE-2026-109618 / CVE-2026-109619) set validated against the published honeypot evidence, with Sigma correlation rules (`event_count`, `temporal`) evaluated with sliding windows.
- Output: terminal timeline by default (`standard` profile); `-o` with `-t csv,json,jsonl` saves the `verbose` profile with MITRE ATT&CK tags, all parsed fields, rule file/ID and log file/line. Profiles live in `config/profiles.yaml` (`list-profiles`).
- Release packages for Linux (x64/ARM64, glibc and static musl), macOS and Windows, built by the `Iwatobi Release Automation` workflow.
- `-z, --timezone` for logs whose timestamps carry no zone, `-U, --utc` output, `--timeline-start/--timeline-end/--time-offset`, `--min-level`, status and tag filters, `-s, --sort`, `-C, --clobber`, error log under `logs/`.
