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
| `--no-oracle` | skip active probe (passive fingerprint only) |
| `--phpinfo` | also check common phpinfo paths for version disclosure |
| `--reverse-dns` | PTR lookup per target |
| `--insecure` | skip TLS verification (self-signed labs) |
| `--json` / `-o FILE` | JSON stdout / write JSON report |
| `--timeout`, `--threads` | per-request seconds (default 8), concurrency (default 16) |

Verdicts: `VULNERABLE` (oracle 3/3) · `LIKELY_VULNERABLE` (old/EOL version) ·
`PATCHED` · `PHP_NO_VERSION` (PHP seen, version hidden — review manually) ·
`PHP_UNKNOWN` · `NO_PHP_SIGNAL` · `UNREACHABLE`.

## Test lab (transparency)

`tests/lab/docker-compose.yml` spins 10 local scenarios; `tests/test_scanner.py`
asserts every verdict live. Last verified 2026-10-21 — 33/33 green:

| Service | Image | Result |
|---|---|---|
| vuln-error-on (`:19081`) | php:8.5.11, errors on | VULNERABLE (oracle 3/3) |
| eol-old (`:19084`) | php:8.3.6 | VULNERABLE (oracle 3/3) |
| vague-hardened (`:19088`) | php:8.5.11, headers stripped, static front | VULNERABLE (oracle 3/3 via discovered `/search.php`) |
| upload-disabled (`:19087`) | php:8.5.11, progress off | LIKELY_VULNERABLE (version; oracle 0/3 — mitigation signal) |
| patched (`:19083`) | php:8.5.12 | PATCHED (oracle 2/3 — no false positive) |
| pma (`:19090`) | phpMyAdmin on PHP 8.3.36 | PATCHED (app + version agree) |
| wordpress-vuln (`:19089`) | WordPress, headers silent | PHP_NO_VERSION (WP assets prove PHP app) |
| vuln-error-off (`:19082`) | php:8.5.11, errors off/hidden | NO_PHP_SIGNAL (known blind spot, documented) |
| notphp (`:19085`) | nginx | NO_PHP_SIGNAL |
| static-only (`:19086`) | no PHP handler at `/` | NO_PHP_SIGNAL |

```sh
docker compose -f tests/lab/docker-compose.yml up -d
python3 tests/test_scanner.py          # unit tests (no network)
python3 tests/test_scanner.py --live   # unit + live lab (33 tests)
```

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
