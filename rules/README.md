# Iwatobi rules

Iwatobi loads every `*.yml` / `*.yaml` file under this directory (recursively) with `-r, --rules`
(default `./rules`).

| Directory | Content |
| --- | --- |
| `sigma/` | Rules taken verbatim from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), keeping the upstream directory layout (`linux/builtin/<service>/`, `web/product/<server>/`, ...). |
| `iwatobi/` | Rules written for Iwatobi: `php/php2shell/` (PHP2Shell, CVE-2026-109618 / CVE-2026-109619), `php/fpm/` (php-fpm), `web/apache/` (Apache error log), `web/webserver/` (access logs). |

## Supported log sources

A rule is loaded when its `logsource` can be satisfied by one of the log formats Iwatobi parses:

| `logsource` | Log |
| --- | --- |
| `product: linux` (+ `service: syslog`, `auth`, `sshd`, `cron`, `sudo`, `vsftpd`, `clamav`, `guacamole`) | syslog-format files (`/var/log/syslog`, `messages`, `auth.log`, `secure`, `cron`, ...), `journalctl -o short-iso` output |
| `category: webserver` | Apache / nginx access logs (common, combined, vhost_combined, JSON lines) with the Sigma web server field names (`c-ip`, `cs-method`, `cs-uri-query`, `sc-status`, `cs-user-agent`, ...) |
| `service: apache` | Apache error log |
| `service: nginx` | nginx error log |
| `product: php`, `service: error_log` | PHP error log, and PHP messages inside the Apache error log |
| `product: php`, `service: fpm` | php-fpm log |

Rules for other sources (auditd, Sysmon for Linux, `category: process_creation`, web proxies, ...)
are skipped at load time and counted in the start-up summary.

## Keywords match anywhere in the line

Sigma keyword lists (`keywords:` or any search identifier that is a list of strings) match
anywhere in the log message, as the specification requires. Iwatobi guarantees this by
surrounding each keyword with `*` wildcards before handing the rule to the sigma-rust engine
(whose own keyword matching is whole-value), so `- 'REPLACE'` matches
`crontab[12399]: (user) REPLACE (user)`. Keywords that already start or end with `*` are left as
they are; field-based selections (`field: value`) are not changed.

## Correlation rules

Sigma correlation rules (`event_count`, `value_count`, `temporal`, `temporal_ordered`) are
supported. Put the correlation and its base rules in one file separated by `---`; the
`rules:` list may reference base rules by `name`, `id` or `title`. Base rules of a correlation
file are only reported through the correlation (unless `generate: true`).

## Writing rules

- Use the SigmaHQ field names for access logs (`cs-uri-query` holds the full request target,
  `cs-uri-stem` the path only).
- Syslog events expose `hostname`, `process`, `pid` and `message`; Apache error log events
  `module`, `level`, `pid`, `client`, `error_code` and `message`; PHP error log events
  `php_type`, `message`, `file` and `line`; php-fpm events `level`, `pool`, `child_pid` and
  `message`. Every event also has `raw` (the whole line).
- Test a rule with `iwatobi dfir-timeline -f <log> -r <rule.yml>`.
