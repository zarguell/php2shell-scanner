# php2shell — Research Notes (CVE-2026-109618 / CVE-2026-109619)

> Scanner, not exploiter. This document explains the vulnerability class and
> why the scanner's signals are reliable. All facts verified against the
> primary sources listed at the bottom on 2026-10-21.

## 1. What happened

On 20–21 Oct 2026 the PHP project shipped an out-of-band security release for
two critical PHP-core RCEs (CVSS v4.0 **9.2** each), fix releases **8.5.12,
8.4.27, 8.3.36, 8.2.35**. Details leaked early and a PoC tool circulated as
"php2shell". PHP 8.1 and older are EOL — no upstream fix; distros/LTS vendors
may backport, and the PHP team published minimal source backports for
7.4/8.0/8.1.

- CVE-2026-109618 (GHSA-w8hw-w9fx-j79w): OOM handling can interrupt PHP while
  internal request data is only partly initialised; request cleanup then treats
  the invalid data as valid → RCE. CWE-755 + CWE-416.
- CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp): request-owned global state can survive
  after its memory is freed; a later request on the same (persistent) worker
  reuses the stale state → RCE. CWE-416 (use-after-free).

Both are **unauthenticated**, pre-application-code in the worst case (mod_php:
trigger fires before app code runs). Every web SAPI at risk: PHP-FPM, mod_php,
php-cgi, FrankenPHP, LiteSpeed. Risk highest on persistent workers (FPM,
mod_php); plain per-request CGI is far less exposed to 619's cross-request
stale state.

## 2. Root mechanism (one paragraph each)

**618 — OOM teardown confusion.** PHP uses `longjmp` to bail out of the current
context on out-of-memory. If the OOM lands mid-request-startup, partially
initialised request structures are left published; the shutdown path consumes
them as if valid. Attackers shape the heap first (notably via
`session.upload_progress` + multipart parsing, which allocates predictably),
then trigger the OOM at the right moment. Independent lab work measured ~52x
memory amplification from duplicate 6-byte multipart headers (fixed 256-byte
`SMART_STR_START_SIZE` per saved header), so small bodies defeat
`post_max_size`-style size thinking; chunked framing additionally bypassed the
Content-Length pre-check on unpatched builds. Both closed in the patch.

**619 — stale worker state.** Request-owned globals are freed at request end
but a pointer survives; the *next* request on the same worker dereferences it.
Reliable pairing needs a persistent worker (FPM `pm.static max_children=1` in
labs; prefork single-worker for mod_php) plus attacker-influenced session
decoding in the window. Lab-verified as a crash primitive on FPM; full RCE
chains demonstrated on stock `php:8.5.11-apache` with in-band disclosure
(`PS(id)`→cookie leak) across repeated ASLR layouts.

## 3. Why `session.upload_progress` keeps appearing

It is the heap-shaping primitive, not the bug itself: attacker-controlled
multipart field names/values are stored into session data pre-RINIT, giving a
remote party predictable allocations + a readable/writable session file. The
upload-progress *injection* (attacker key stored verbatim) survives even the
8.5.12 patch per lab analysis — but without the OOM/stale-state bugs behind it
it is not RCE by itself. Defense-in-depth still says disable it if unused
(`session.upload_progress.enabled=0`) — it shrinks the primitive surface, but
**it is not a fix**.

## 4. How detection works (what this scanner uses)

Three layers; either can fire, agreement = highest confidence.

### Layer A — version fingerprint (passive, zero-risk)
`X-Powered-By: PHP/x.y.z` / `Server: ... PHP/x.y.z` / exposed `phpinfo()`.
Compare against the advisory table:

| Branch | Fixed in | Verdict if below |
|---|---|---|
| 8.5 | 8.5.12 | LIKELY_VULNERABLE |
| 8.4 | 8.4.27 | LIKELY_VULNERABLE |
| 8.3 | 8.3.36 | LIKELY_VULNERABLE |
| 8.2 | 8.2.35 | LIKELY_VULNERABLE |
| ≤ 8.1 | EOL, no upstream fix | EOL_VULNERABLE (check distro backport) |

Caveats handled: branch-only disclosure (`PHP/8.1`, no patch) → downgrade to
EOL/UNKNOWN, never hard-vulnerable; distro suffix (`+deb12u1`, `Ubuntu`,
`.el9`) → keep PATCHED verdict but medium confidence + changelog advice;
future branches (> 8.5) → UNKNOWN, not vulnerable.

### Layer B — session-write warning oracle (active, benign)
Single ~300-byte multipart POST with `Cookie: PHPSESSID=_` (invalid id) plus a
`PHP_SESSION_UPLOAD_PROGRESS` field. Unpatched builds print **all three**
warnings (needs `display_errors=On` and the request reaching the PHP handler):

1. `Session ID is too long or contains illegal characters`
2. `Failed to read session data`
3. `Failed to write session data (`

The 2026-10-21 fix removed the session-write warning path, so **patched builds
print only #1–#2** (verified live: 8.5.11 → 3/3, 8.5.12 → 2/3). Requiring all
three (not a substring of one) is what makes false positives ~zero: the exact
triple is emitted only by the unpatched session startup path. No OOM, no UAF,
no code execution — it only observes error output. Credit: PortSwigger
BCheck/active check by Tom SL; behavior confirmed against live Docker
`php:8.5.11-apache` vs `php:8.5-apache` (8.5.12) in this repo's test lab.

### Layer C — safe GET probes for vague/hardened boxes (no POST, no state)

Headers lie by omission: `expose_php=Off` strips `X-Powered-By`, front pages go
static, and the oracle needs a PHP-executing path. Three GET-only follow-ups
(~11 requests, the traffic of a casual crawler) close the gap:

- **PHP path discovery.** GET candidates (`/app.php`, `/search.php`,
  `/wp-login.php`, …); a path proves PHP execution via `X-Powered-By: PHP`,
  `PHPSESSID` cookie, `.php` redirect, or *dynamic* query handling (output
  changes with `?q=<random>` → server-side code ran). The oracle POST then
  goes to discovered paths, not just `/`. Lab proof: a header-stripped
  8.5.11 box with a static front page fires 3/3 via `/search.php`.
- **Easter-egg GUIDs** (`/?=PHPE9568F36-…`, `?=PHPB8B5F2A0-…`). Compiled into
  every PHP binary, answered without app code — but only when `expose_php=On`
  AND the request reaches PHP. Positive requires `image/*` content-type
  (never status/body alone).
- **PHP-only app endpoints.** WordPress (`wp-login.php`, `xmlrpc.php`, static
  `wp-includes` assets + `readme.html`), phpMyAdmin, Nextcloud `status.php`,
  MediaWiki, Drupal — each runs *exclusively* on PHP, so 200 + content match
  proves a PHP runtime with zero version disclosure → `PHP_NO_VERSION`
  (medium) instead of silence. Lab proof: DB-less WordPress with silent
  headers still attributes via static assets.

### What the scanner deliberately does NOT do

No stalled-multipart triggers, no heap spray, no session-injection canaries,
no worker-crash observation, no payload execution. Those are exploitation
primitives (see murrez/dinosn/0x4148 PoCs) — out of scope by design.

### Layer D — the silent box: CGI/FPM with zero disclosure

A fully hardened PHP (errors off, headers stripped, no app paths — typical of
php-cgi / FPM behind a quiet proxy) leaks nothing the oracle or fingerprint
can name. Three things still work, and one authoritative fallback exists:

- **404-differential.** `GET /p2s-<rand>.php` vs `.txt` vs extensionless. If
  `.php` 404s differently (status/length/content-type class), *something*
  parses `.php` — a handler exists. Verified: FPM-through-nginx differs,
  plain nginx does not.
- **Deployment droppings.** `composer.json/.lock`, `.env` (APP_KEY),
  `server.php`, `artisan` — 200 + content match proves a PHP deployment
  beside the web root.
- **Discovered-path surfacing.** Every dynamically-proven PHP path is now
  recorded on the finding, even when the oracle stays blind.
- **New verdict `PHP_CANNOT_RULE_OUT`.** Dynamic PHP execution proven, zero
  identity leaked: the scanner names the paths and says "remotely
  unconfirmable — run `--local` on the box". This replaces silent
  `NO_PHP_SIGNAL` for that case; honest uncertainty instead of a false
  negative.
- **`--local` on-box enumerator.** Run ON the host: every `php*` binary with
  `php -v` version + advisory verdict, `php -i` SAPI/ini flags
  (`expose_php`, `display_errors`, `upload_progress`, `memory_limit`), and
  the live process table filtered to php/httpd/apache/fpm/cgi workers.
  For the "I can see php-cgi in ps but the network is silent" case this is
  the authoritative answer remote scanning can never give.

### Layer E — locked-down appliances: panels over PHP version

The attacker's order of operations is panels and appliances first: no
`--local`, no patch window you control, management UIs facing the network,
and the vendor advisories in `docs/affected-products.md` (Plesk rebuilds,
cPanel EA4 25.91, PAN-OS fix-pending) confirm the exposure. The scanner meets
that with panel-first attribution instead of PHP-version-first:

- **Panel/appliance fingerprints** (13 new body signals, 8 endpoint probes):
  Plesk, cPanel/WHM, WHMCS, Passbolt, Coolify, PAN-OS/Panorama, pfSense,
  OPNsense, Synology, QNAP, TrueNAS — login pages, static assets, status
  endpoints, all 200 + content match.
- **Panel-build extraction** (`panel-version:*` signals): the panel build
  string (e.g. Plesk 18.0.70 vs 18.0.81) drives the *vendor* advisory lookup,
  because for appliances the panel build dates the bundled PHP rebuild. The
  finding names the advisory (Plesk 44397729587351, cPanel EA4 25.91,
  PAN-OS ETA-TBD) so triage doesn't stall on "PHP version unknown".
- **Assume-vulnerable posture.** A PHP-backed panel with undisclosed runtime
  resolves to `PHP_NO_VERSION` (medium) with "assume vulnerable until patched
  version proven" — the correct default for an appliance you can't open,
  where the attacker tries the aggressive probes first and you must get
  ahead. Lab proof: twin locked-down panel UIs (headers stripped, errors
  off) both attribute with build strings extracted.

### Layer F — behavioral proofs: fan-out without per-app hardcodes

Hand-listed login pages don't scale: every new appliance means another row.
Three mechanisms ask questions ANY PHP stack answers by construction,
regardless of vendor — plus a harvester that learns the site's own surface:

- **Method differential** (OPTIONS + PROPFIND vs GET). Lab matrix:
  Apache+mod_php and FPM-proxy answer 200 to exotic methods (the handler
  executes for any method); static nginx answers 405. PROPFIND-200 (or
  OPTIONS-200 with `Allow: POST`) separates dynamic handlers from file
  servers. Corroboration — a Java app server also 200s — never standalone
  PHP proof. Live: fires on mod_php/FPM/silent-Apache/appliance, silent on
  nginx. (Tomcat-class servers are the known confounder; the PHP-token gate
  on version parsing still blocks the false-positive path.)
- **Cookie grooming v2** (session rotation, cookieless opener). First visit
  mints, second fresh visit mints a DIFFERENT id → server-side session
  minter (Roundcube-class apps rotate per visit). Static servers never
  Set-Cookie. The scanner uses a dedicated cookieless opener — the shared
  jar was swallowing the second mint (caught live). Silent on session-less
  endpoints (most hardened fronts): corroboration, never proof.
- **Self-naming harvester.** Every fetched page is scanned for
  href/src/action `*.php` links; discovered targets feed the dynamic
  query-reflection test, then the oracle. The scanner probes the SITE'S OWN
  php surface instead of guessing ours — N unseen apps fan out through
  their own links. Live: appliance twin's own `/login.php` harvested;
  vague box's `/search.php` validated dynamic. (Static `.php` files that
  don't execute — like the lab's Plesk facade — correctly stay oracle-silent;
  harvest feeds *candidates*, the dynamic test decides.)
- **Bounded spider (multi-page).** Single-page harvest is blind when the
  front page links only to static pages and PHP lives clicks down. BFS crawl
  (same host, HTML only, depth ≤ 2, ≤ 10 pages, logout/asset links skipped,
  missing-ctype HTML followed) harvests `.php` targets AND JS `fetch()` ajax
  endpoints from every visited page; all feed discovery's dynamic test.
  Live proof (`deep-surface` lab): static front → `/about`, `/docs` →
  `/portal/` → `/portal/home.php` (dynamic `?q` handler); single-page
  harvest `[]`, spider `['/portal/home.php']`, oracle 3/3 there. Budget ~11
  GETs worst case; plain GETs only, no state change.
- **JS bundles instead of a browser.** JS-rendered apps (Vue/Angular/React)
  ship their API map as string literals in bundle source — the spider fetches
  up to 3 same-origin `.js` files per site and parses endpoint literals
  (measured on Matomo's 1MB installation bundle: endpoint names present in
  source text). A headless browser would re-derive what regex already reads
  at 10-50x the cost plus a 300MB dependency, sandbox risk, and GPU-less
  flakiness — deliberately not taken. Live proof (`js-spa` lab): index.html
  has ZERO `.php` refs, all routes in `/static/app.js`; bundle fetch finds
  `/api/v2/endpoint.php` + `/portal/deep.php`, `?action` dynamic test proves,
  oracle 3/3. Runtime-joined scripts (`"jsAd/StringTable_" + lang + ".js"`): the literal has
  no extension, so static `.js` harvesting misses it. The spider matches
  `getScript(`/`loadScript(` calls, reconstructs `prefix + var + ext` joins,
  completes statically-visible defaults (`|| "en"` → `StringTable_en.js`),
  resolves page-relative (jQuery semantics), and recurses into fetched bundles
  (loader loads the table). The fetched StringTable is PARSED for PHP
  artifacts — your exact shape (`this.php_*`, `$this->`, `$_SESSION`) — which
  become evidence without any `.php` URL existing. Live proof (`js-dyn` lab).
  Known-param probing (`?q/?s/?id/?action/?page/?p`) covers
  endpoints that ignore unknown params but consume named ones.
  2+ on an otherwise silent box is recorded for the operator. Deliberately
  NOT a verdict escalator: generic dynamic-handler evidence is not PHP
  evidence, and the obscure-pair test pins that NO_PHP_SIGNAL stands.

Debugging any of the above: `-v` traces every phase to stderr
(fingerprint → spider page visits with `+Nphp` finds → discover candidate
counts → oracle markers per path → verdict), `-vv` adds every request
(method+path+status+ms+bytes), `--trace-file` mirrors it to disk. Findings
stay on stdout — trace never pollutes piped JSON. Line shapes are pinned in
`TestVerbose`.

### Layer H — prove-rce: LFI auto-discovery + contained proof in one device

`--prove-rce` merges the lab demo into the scanner for single-device work:
the scanner discovers the LFI sink itself (crawled form inputs + `?param=`
links + conventional include-ish names, inert benign-vs-traversal validation
reading `/etc/hostname` — never executing), then runs the fixed marker-write
through the validated sink with cleanup. Same double confirmation as the demo
(typed target echo + `P2S_RCE_ARM=1`, TTY-required). New `RCE-PROVEN` verdict
outranks the oracle.

Honest tiering, proven live on the RCE twins: the lab sink is a suffix-less
session `include()`, which PRINTS the serialized row without parsing `<?php`
— so remote echo proves the READ primitive (attacker session content reaches
the sink) but NOT execution. `--prove-rce` reports exactly that
(`RCE unproven through this sink; needs parsing include`) instead of
claiming RCE. Full execution proof needs a parsing sink (.php-suffixed
include, auto_prepend_file, LFI wrapper) — demonstrated with docker-exec
ground truth in `tests/lab/rce_demo.py`. The scanner never upgrades a read
primitive into an RCE verdict.

### Layer G2 — optional CDP browser (bring your own Chromium)

No Playwright, no bundled download, no new dependency. You launch any
Chromium/Chrome (`--headless=new --remote-debugging-port=9222`), pass
`--cdp 127.0.0.1:9222`, and the scanner speaks CDP over a hand-rolled stdlib
websocket (`Page.navigate` + `Runtime.evaluate`): rendered
`documentElement.outerHTML` plus `performance` resource URLs per crawled page.
That catches what static parsing cannot — e.g. the js-dyn StringTable, which
the browser loads (`StringTable_en.js` in resources) even though no static
or dynamic ref names the final URL. Resource URLs are now FETCHED through the
same artifact parser (not just listed): browser-observed bundles join the
evidence channel like spider-fetched ones.
`--crawl-full` (requires `--cdp`) upgrades this to Burp/ZAP-class discovery:
rendered DOM + network-observed XHR/API urls + clickable hrefs + benign
GET-form submissions (fixed safe values; POST forms reported, never sent) +
`--cookie` session passthrough + content-hash dedupe (session-token noise
normalized away). Extensionless form actions (`/query` → 301 `/query/`) are
followed as same-resource redirects and admitted to the dynamic test. Live
proof (`form-crawl` lab): unconventional `/finder.php`, then extensionless
`/query`, found via submitted GET forms and fired 3/3 — where static guesses
and single-page harvest are blind. If your Chromium gates `/json/*`
with 401/403, relaunch with `--remote-debugging-token=...` and pass
`--cdp-token`. CDP failures log the inner error
(`unavailable (ConnectionError: …)`), not just the type name.
Downstream (extract, artifacts, oracle) is unchanged: the browser is a richer
body supplier. Disabled by default; per-page CDP failure falls back to plain
HTTP. Verified live against a real Chromium (Comet 155): `TestCdpBridge`
(skipped without `P2S_CDP`/`--cdp-test`).
Static-side twin fix in the same pass: JOIN/lang-default candidates are now
priority-ordered (completed `StringTable_en.js` before bare `StringTable_`
stubs that 404 as `+php total=0` noise), and resource-URL fetching covers
browser-observed bundles the static pass never names.

### Layer G — scheme negotiation: both protocols, upgrades, TLS honesty

The old logic (HTTP-only on :80, HTTPS-only on :443, stop after HTTP answers)
missed appliance TLS on :8443-style ports and fingerprinted redirect stubs
instead of the app behind them. Now: every port is probed with BOTH schemes;
`http→https` same-port upgrade stubs are followed and scanned behind (the
finding records `redirect-upgrade:`); findings dedupe to one per service
(https preferred on identical verdicts). TLS with an untrusted cert
(self-signed appliance) is its own verdict — `TLS_UNTRUSTED`, "retry with
`--insecure`" — instead of silent `UNREACHABLE`. Lab proof: vuln 8.5.11
FPM behind nginx TLS on :19098 → `TLS_UNTRUSTED` strict, `VULNERABLE` 3/3
with `--insecure`; `:19099` 301-stub → PHP 8.5.11 found behind it.

### Layer D, worked example — the silent-obscure limits demo

The repo ships a deployment where safe probes genuinely go blind, so the
limitation is demonstrated, not asserted (`tests/lab/docker-compose.yml`:
`obscure-*`; nginx config `tests/lab/obscure-nginx*.conf`):
- **Shape.** PHP-FPM behind nginx, `display_errors=Off`, `expose_php=Off`,
  no `Server` header, static `/`, PHP reachable ONLY at `/api/submit` (no
  `.php` location block — every candidate/app/deploy guess 404s at nginx;
  404-differential negative). Twin builds: **8.5.11 vuln** (`:19093`) and
- **Safe-probe result (pinned in tests).** Both return `NO_PHP_SIGNAL`,
  oracle negative on both. Indistinguishable — honestly reported.
- **Unsafe demos (lab only, never shipped).**
  `tests/lab/unsafe_probe_demo.py` (OOM size sweep): small bodies → both 200,
  identical, no signal — impact is not an oracle. `tests/lab/unsafe_413_demo.py`
  records a CAUTIONARY TALE: a 200-vs-413 split observed 3/3 once turned out to
  be our own nginx misconfiguration; same payload now 200/200 across bisection,
  repeats, fresh-worker restarts. Boundary behavior is environmental — a line
  drawn on one afternoon's observation misfires on another's. Divergence is
  observation, never a version oracle. Four no-ship reasons in that file.
- **Contained RCE demo (authorized lab only, `tests/lab/rce_demo.py`).**
  Public Chain-A primitive (session-injection + intentional LFI sink in
  `vuln.php`): fixed marker-write payload (`file_put_contents` to
  `/tmp/p2s-demo-*`, no shell, asserts pin the shape), execution proven by
  marker FILE in the container (not HTTP echo — echo alone lies, observed
  live), cleanup enforced and verified. Lab twins `:19110` (8.5.11) and
  `:19111` (8.5.12): BOTH RCE-positive, as documented — the patch removes the
  session-write warning path, NOT session injection or an app-layer LFI sink.
  Scanner agrees per-twin (VULNERABLE oracle vs PATCHED oracle-negative).
  Guardrails: hardcoded 127.0.0.1:19110/:19111 allowlist (no --target flag),
  NOT imported by the scanner or default suite, `TestRceDemo` opt-in only
  (`--rcedemo`). Run: compose up rce twins, `python3 tests/lab/rce_demo.py`.
## 5. Hardening / mitigation notes (not fixes)

- Real fix: upgrade to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or vendor backport),
  then **restart all PHP workers** (FPM pools, Apache).
- Stopgaps until patched: `session.upload_progress.enabled=0`; gateway/WAF
  rules blocking `PHP_SESSION_UPLOAD_PROGRESS` multipart fields — note the
  comma-separator bypass (`Content-Type: multipart/form-data, boundary=X` is
  accepted by PHP's SAPI parser, so anchor signatures carefully); request-size
  limits (weak alone given 52x amplification); `display_errors=Off` (hides the
  oracle, not the bug).
- Detection: this scanner (external), plus server-side log watches for
  multipart `upload_progress` bursts and worker crashes.

## 6. Sources

- PHP security advisories: GHSA-w8hw-w9fx-j79w (618), GHSA-6wmf-4rv5-p3rp (619);
  PHP 2026 archive #2026-10-21-5 (fixed releases + `memory_limit` /
  `post_max_size` / `fatal_error_backtraces` guidance).
- NCSC-NL/php2shell — operational info repo (status, SAPI coverage, actions).
- CERT-EU Security Advisory 2026-018.
- PortSwigger BChecks `CVE-2026-109618_CVE-2026-109619-PHP2Shell-active.bcheck`
  + passive version bcheck + bambda scan check (oracle design).
- Sansec php2shell research (disclosure timeline, impact).
- murrez/php2shell (`php2shell_core.py` — fingerprint/trigger/619-spray shapes).
- dinosn/php-cve-2026-10961x-lab-poc (end-to-end RCE receipt, 52x amplification,
  patch-gap analysis, FPM stale-state, WAF bypass).
- 0x4148/CVE-2026-109618-php2shell-lab (Docker lab + PoC runner).
- JoasASantos/php2shell-scanner (version-strategy reference).
- ENISA CNW-2026-04 (EU CSIRT advisory list).
