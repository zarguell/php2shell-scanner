# php2shell-scanner

Non-destructive network scanner for **php2shell** — CVE-2026-109618 /
CVE-2026-109619, critical unauthenticated PHP-core RCEs (CVSS v4.0 9.2,
fixed 2026-10-21 in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

**Scanner, not exploiter.** It sends only small benign requests (a version
check plus one ~300-byte error-oracle POST) and never attempts code execution,
heap shaping, OOM triggers, or worker crashes. Run only against hosts you own
or are explicitly authorized to test.

## How it detects

1. **Version fingerprint** (passive): `X-Powered-By` / `Server` / `phpinfo()`
   compared to the official fixed-release table. Below-fix → LIKELY_VULNERABLE;
   ≤ 8.1 → EOL_VULNERABLE; at/above fix → PATCHED. Header values must name PHP
   (Tomcat/WordPress/ASP.NET numbers never count).
2. **Session-write oracle** (active, benign): one tiny multipart POST with an
   invalid session id, sent to `/` plus any discovered PHP-executing path.
   Unpatched builds echo 3 warnings; patched builds echo only 2 (fix removed
   the write-warning path). 3/3 → VULNERABLE, high confidence.
3. **Safe GET probes for vague/hardened boxes** (no POST, no state change):
   PHP easter-egg GUIDs (`?=PHP…`, answered inside the PHP binary only),
   well-known PHP-app endpoints (`wp-login.php`, `xmlrpc.php`, phpMyAdmin,
   Nextcloud `status.php`, … — 200 + content match required), and PHP path
   discovery (`/app.php`, `/search.php`, … proven dynamic via query-reflection
   GETs, then oracle-tested). A WordPress/phpMyAdmin/Drupal behind stripped
   headers still resolves to PHP_NO_VERSION (medium) instead of silence.
   See [docs/RESEARCH.md](docs/RESEARCH.md) for the full write-up and sources.
## Quick start

```sh
python3 php2shell_scanner.py 192.0.2.10
python3 php2shell_scanner.py example.com -p 80,443,8080
python3 php2shell_scanner.py -f targets.txt --json -o results.json
python3 php2shell_scanner.py -s 192.168.1.0/24 --discover-ports
python3 php2shell_scanner.py 192.0.2.10 --reverse-dns --phpinfo
python3 php2shell_scanner.py 192.0.2.10 --no-oracle   # version check only
```

Defaults: checks ports 80+443; exit code 2 when VULNERABLE/LIKELY_VULNERABLE
found, 0 when clean, 1 on usage errors. Stdlib only — no dependencies.

| Flag | Purpose |
|---|---|
| `target` / `-f FILE` / `-s CIDR` | single host, file list, or subnet |
| `-p PORTS` / `--discover-ports` | explicit ports (`80,8080,9000-9010`) or probe common web ports |
| `--reverse-dns` | PTR lookup per target |
| `--local` | on-box enumeration: php binaries/versions/SAPIs/processes (run ON the host) |
| `--spider-pages N` (default 10) / `--spider-depth D` (default 2) | site-crawl budget per endpoint. `0/0` = single-page harvest only (quietest); aggressive: `--spider-pages 50 --spider-depth 4` |
| `--prove-rce` | AUTHORIZED ONLY: auto-discover LFI sink (inert) + contained Chain-A marker-write with cleanup. Double confirmation: `P2S_RCE_ARM=1` + typed target echo on TTY. Honest tiers: `RCE-PROVEN` or read-primitive-only |
| `-v` / `-vv` | trace to stderr: `-v` per-phase lines (fingerprint/spider/discover/oracle/verdict), `-vv` adds every request (method+path+status+ms) |
| `--trace-file FILE` | append the same trace lines to FILE (pairs with `-v`/`-vv` for debugging runs) |
| `--insecure` | skip TLS verification (self-signed labs) |
`PATCHED` · `PHP_NO_VERSION` (PHP proven, version hidden) ·
`PHP_CANNOT_RULE_OUT` (dynamic PHP path, zero identity — run `--local`) ·
`PHP_UNKNOWN` · `NO_PHP_SIGNAL` · `UNREACHABLE`.

## Test lab (transparency)

`tests/lab/docker-compose.yml` spins 20 local scenarios (18 lab services + TLS/downgrade); `tests/test_scanner.py`
asserts every verdict live. Last verified 2026-10-22 — 71/71 green (live):

| Service | Image | Result |
|---|---|---|
| vuln-error-on (`:19081`) | php:8.5.11, errors on | VULNERABLE (oracle 3/3) |
| eol-old (`:19084`) | php:8.3.6 | VULNERABLE (oracle 3/3) |
| vague-hardened (`:19088`) | php:8.5.11, headers stripped, static front | VULNERABLE (oracle 3/3 via discovered `/search.php`) |
| fpm-vuln (`:19092`) | nginx → php-fpm 8.5.11 | VULNERABLE (oracle 3/3 through proxy) |
| upload-disabled (`:19087`) | php:8.5.11, progress off | LIKELY_VULNERABLE (version; oracle 0/3 — mitigation signal) |
| patched (`:19083`) | php:8.5.12 | PATCHED (oracle 2/3 — no false positive) |
| pma (`:19090`) | phpMyAdmin on PHP 8.3.36 | PATCHED (app + version agree) |
| wordpress-vuln (`:19089`) | WordPress, headers silent | PHP_NO_VERSION (WP assets prove PHP app) |
| appliance-vuln (`:19095`) | locked-down panel UI, no PHP headers | PHP_NO_VERSION (Plesk panel + build 18.0.70 → vendor advisory) |
| appliance-fixed (`:19096`) | locked-down panel UI, no PHP headers | PHP_NO_VERSION (Plesk panel + build 18.0.81 → vendor advisory) |
| deep-surface (`:19097`) | static front, PHP 2 clicks down | VULNERABLE (spider → `/portal/home.php` → oracle 3/3) |
| js-spa (`:19100`) | SPA, endpoints only in JS bundle | VULNERABLE (bundle → `/api/v2/endpoint.php` → oracle 3/3, no browser) |
| tls-appliance (`:19098`) | nginx TLS (self-signed) → FPM 8.5.11 | TLS_UNTRUSTED strict (“retry --insecure”); VULNERABLE 3/3 insecure |
| downgrade-stub (`:19099`) | HTTP 301 → https://:19098 | PHP 8.5.11 found BEHIND the stub (insecure) |
| silent-errors-off (`:19091`) | php:8.5.11, zero disclosure | PHP_CANNOT_RULE_OUT (dynamic path, points at `--local`) |

```sh
docker compose -f tests/lab/docker-compose.yml up -d
python3 tests/test_scanner.py          # unit tests (no network)
python3 tests/test_scanner.py --live   # unit + live lab (71 tests)
# on the box itself (answers "what runs PHP here" authoritatively):
python3 php2shell_scanner.py --local
# trace what the spider saw (stderr; -vv adds every request):
python3 php2shell_scanner.py -p 19097 127.0.0.1 -v
# TLDR recap prints automatically after findings (counts + top action +
# per-host one-liners) — pipe -v trace to stderr, read the recap on stdout
# limits demo (lab only — megabyte probes, expect worker impact):
python3 tests/lab/unsafe_probe_demo.py && python3 tests/lab/unsafe_413_demo.py
# contained RCE demo (marker-write, cleanup enforced — authorized testing):
# docker compose -f tests/lab/docker-compose.rce.yml up -d && python3 tests/lab/rce_demo.py
# retarget to YOUR authorized box (double confirmation: typed echo + P2S_RCE_ARM=1):
# P2S_RCE_ARM=1 python3 tests/lab/rce_demo.py --target 10.0.0.5:8080 --lfi-path /vuln.php --session-path /tmp
```

## Timeout rules

Scanning a subnet used to hang: every dead host ate full HTTP+TLS timeouts
per scheme with no output until the end. Now:

1. **TCP pre-check always runs** (default + subnet paths): `connect-timeout`
   (default 3s) decides open vs closed/filtered. Closed ports become instant
   `UNREACHABLE` (`TCP pre-check: port N closed/filtered`) without HTTP.
   A /24 with one live host scans in ~17s instead of hanging.
2. **Per-request `--timeout`** (default 8s) caps each connect+read.
3. **Per-host `--host-budget`** (default 120s) caps wall-clock per host:port
   across all phases (spider, discovery, oracle, probes). Exhaustion skips
   remaining phases and records `budget:exhausted` — partial findings, never
   a stuck thread.
4. **`--progress`** streams `[*]` lines to stderr (stdout stays pipe-clean
   JSON). `-v`/`-vv` add phase/request tracing on top.

Tune down for speed (`--connect-timeout 1 --host-budget 30`), up for
far/slow networks (`--timeout 20 --host-budget 300`).

## Affected-product fleet (pressure test)

Real projects from [docs/affected-products.md](docs/affected-products.md),
scanned live 2026-10-21. Vendor images ship patched PHP (all PATCHED, oracle
negative — zero false positives on real apps); the same app code rebuilt on
PHP 8.5.11 via `tests/lab/build-vuln-fleet.sh` fires the oracle (all
VULNERABLE). Run both fleet composes up, then
`python3 tests/test_scanner.py --fleet`.

| App | Vendor PHP | Verdict | Same app on PHP 8.5.11 | Verdict |
|---|---|---|---|---|
| Drupal 11 | 8.5.12 | PATCHED | Drupal 11 | VULNERABLE (3/3) |
| MediaWiki 1.46.2 | 8.3.36 | PATCHED | — (500M src, on-demand) | — |
| Roundcube 1.7 | 8.4.27 | PATCHED | Roundcube 1.7 | VULNERABLE (3/3) |
| Nextcloud | 8.5.12 | PATCHED | — (800M src, on-demand) | — |
| Matomo | 8.4.27 | PATCHED | Matomo | VULNERABLE (3/3) |
| WordPress | 8.3.x (patched) | PHP_NO_VERSION* | WordPress | VULNERABLE (3/3) |
| phpMyAdmin 5.2 | 8.3.36 | PATCHED | — (covered by WP/RC/MT) | — |
| Joomla 6.1 | 8.4.27 | not bootable w/o MySQL | — | — |

*DB-less WP answers 500 on `/` but its static assets attribute the PHP app.

### Genuine pre-patch vendor images (pushed before 2026-10-21)

Old tags, the PHP of their era, scanned live via
`tests/lab/docker-compose.prepatch.yml` (`--fleet`). Every one flagged —
none silent, none PATCHED:

| Image (pushed) | Bundled PHP | Verdict |
|---|---|---|
| `drupal:11.2-apache` (2026-07) | 8.4.23 | VULNERABLE (oracle 3/3) |
| `mediawiki:1.44.0` (2025-10) | 8.1.33 (EOL) | VULNERABLE (oracle 3/3) |
| `matomo:5.2.2-apache` (2025-03) | 8.3.17 | LIKELY_VULNERABLE (version; app errors off) |
| `phpmyadmin:5.2.1-apache` (2025-01) | 8.2.27 | LIKELY_VULNERABLE (version; app errors off) |
| `roundcube/roundcubemail:1.6.1-apache` (2023-04) | 8.1.17 (EOL) | LIKELY_VULNERABLE (EOL version; app errors off) |
| `joomla:5.3-apache` (2025-10) | 8.3.26 | not bootable w/o MySQL (tag data recorded, no live row) |

Note the honest split: apps whose PHP layer leaks warnings go oracle-positive;
apps with `display_errors=Off` fall back to the version verdict — still
flagged, lower confidence. That is the documented errors-off blind spot, and
the version layer covers it whenever headers disclose.
Known limitation: with `display_errors=Off` and version hidden, remote
black-box detection is impossible without exploitation — the scanner reports
`NO_PHP_SIGNAL`/`PHP_NO_VERSION` instead of guessing. Version-only findings
without the oracle are medium confidence: confirm with the oracle or locally.

## Remediation (if flagged)

Upgrade to PHP **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (or vendor backport for
EOL branches), restart all PHP workers, re-scan. Until then: disable
`session.upload_progress` if unused, block `PHP_SESSION_UPLOAD_PROGRESS`
multipart fields at the gateway, and treat `display_errors=Off` as camouflage,
not a fix.

## References

PHP advisories GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp · NCSC-NL/php2shell ·
CERT-EU 2026-018 · PortSwigger php2shell BChecks (oracle design) · Sansec
research · murrez/php2shell · dinosn lab · 0x4148 lab. Full citations in
[docs/RESEARCH.md](docs/RESEARCH.md).
