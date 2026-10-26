# PHP2Shell test files

These files are derived from the PHP2Shell (CVE-2026-109618 / CVE-2026-109619) confirmed-RCE
evidence published by Adel "0x4D31" Karimi in
[0x4D31/honeypot-data](https://github.com/0x4D31/honeypot-data/tree/main/reports/php2shell/2026-10-24-rce-evidence)
(35 confirmed Apache-parent shell events on PHP 8.4.26 / Apache `mod_php` honeypots, 24 October
2026), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Changes made here: the per-case files were merged, de-duplicated and sorted by time; the
untimestamped Apache child `stderr` lines of each case were placed just before that case's first
worker crash line in `apache2/error.log` (which is where Apache writes them); two benign Apache
start-up notices were added; and `apache2/access.log` is a rendering of the original JSON access
records (`apache2/access.jsonl`) in Apache "combined" format (the requests carried no `User-Agent`
or `Referer`, so both are `-`). Honeypot addresses were already replaced with TEST-NET aliases
and the leaked `PHPSESSID` values redacted in the source data; attacker source addresses are
unchanged.

| File | Content | Lines |
| --- | --- | --- |
| `php-error.log` | PHP error log: pre-script memory exhaustion, session ID too long, `php -r` callback failures | 228 |
| `apache2/error.log` | Apache 2.4 error log: `AH00051` worker crashes and child shell `stderr` | 93 |
| `apache2/access.jsonl` | JSON access records (custom Apache `LogFormat`) | 144 |
| `apache2/access.log` | the same requests in combined log format | 144 |
