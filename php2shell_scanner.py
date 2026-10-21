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


def say(msg: str) -> None:
    with print_lock:
        print(msg, flush=True)


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


def make_opener(timeout: float, insecure: bool) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(),
        NoRedirect(),
    )


def http_request(opener, url: str, timeout: float, method="GET",
                 data: bytes | None = None, headers: dict | None = None,
                 max_bytes: int = 300_000) -> dict:
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": UA, "Accept": "*/*", "Connection": "close",
        **(headers or {}),
    }, method=method)
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(max_bytes)
        return {"status": resp.status, "headers": dict(resp.headers.items()),
                "body": body.decode("utf-8", "replace"), "url": resp.geturl()}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(60_000)
        except Exception:
            body = b""
        return {"status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": body.decode("utf-8", "replace"), "url": url}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}", "url": url}


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
        if re.search(r"wp-content|wp-includes|/wp-json/|wordpress", body, re.I):
            signals.append("body:wordpress")
        if re.search(r"laravel|__laravel|csrf-token", body, re.I):
            signals.append("body:laravel")
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


ORACLE_PATHS = ("/", "/index.php")

def build_oracle_body(boundary: str, token: str, fname: str) -> bytes:
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n{token}\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{fname}\"\r\nContent-Type: text/plain\r\n\r\n1\r\n",
        f"--{boundary}--\r\n",
    ]
    return "".join(parts).encode()


def run_oracle(opener, url: str, timeout: float) -> tuple[bool, str]:
    """Return (positive, evidence). Tries ORACLE_PATHS; positive requires
    ALL THREE markers on any path (matches PortSwigger check)."""
    base = url.rstrip("/")
    last_ev = "not run"
    for p in ORACLE_PATHS:
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
        if len(hits) == len(ORACLE_MARKERS):
            return True, last_ev
    return False, last_ev


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
    signals: list[str] = field(default_factory=list)
    reverse_dns: str | None = None
    verdict: str = "UNREACHABLE"
    confidence: str = "none"
    detail: str = ""


def decide(f: Finding) -> Finding:
    if not f.reachable:
        f.verdict, f.confidence, f.detail = "UNREACHABLE", "none", "no HTTP response"
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
        f.verdict = "PHP_NO_VERSION"
        f.confidence = "low"
        f.detail = ("PHP signals present but version undisclosed "
                    f"({', '.join(f.signals[:4])}); manual review needed")
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
                  opener: urllib.request.OpenerDirector) -> list[Finding]:
    schemes = ["https"] if port == 443 else ["http"] if port == 80 else ["http", "https"]
    out: list[Finding] = []
    for scheme in schemes:
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
            out.append(decide(f))
            continue
        f.reachable = True
        f.http_status = res["status"]
        ver, src, sigs, branch_only = fingerprint_response(res)
        f.signals.extend(sigs)
        if ver:
            f.php_detected = True
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
            f.php_detected = True
        if phpinfo and not ver:
            for p in COMMON_PHPINFO_PATHS:
                r2 = http_request(opener, url.rstrip("/") + p, timeout)
                if r2.get("status") == 200 and r2.get("body"):
                    m = PHPINFO_VER_RE.search(r2["body"])
                    if m:
                        f.php_detected = True
                        f.php_version = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
                        f.version_source = f"phpinfo:{p}"
                        f.version_verdict, f.version_detail = classify_version(
                            parse_strict_version(f.php_version))
                        f.signals.append(f"phpinfo:{p}")
                        break
        if do_oracle:
            try:
                pos, ev = run_oracle(opener, url, timeout)
                f.oracle_ran, f.oracle_positive, f.oracle_evidence = True, pos, ev
            except Exception as e:
                f.oracle_evidence = f"oracle error: {e}"
        out.append(decide(f))
        if scheme == "http" and f.reachable:
            break  # plain-HTTP answered; skip https guess on non-standard ports
    return out


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
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (labs/self-signed)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("-o", "--output", help="write results (JSON) to file")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    args = ap.parse_args(argv)
    if args.version:
        print(f"php2shell-scanner {TOOL_VERSION}")
        return 0

    hosts = expand_targets(args)
    if not hosts:
        ap.error("no target: give TARGET, --targets-file, or --subnet")
    ports = expand_ports(args)
    do_oracle = not args.no_oracle
    opener = make_opener(args.timeout, args.insecure)

    jobs: list[tuple[str, int]] = []
    if args.discover_ports:
        def probe(hp):
            h, pt = hp
            return (h, pt) if tcp_open(h, pt, min(args.timeout, 3.0)) else None
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for r in ex.map(probe, [(h, p) for h in hosts for p in ports]):
                if r:
                    jobs.append(r)
        if not jobs:
            say("port discovery: no open web ports found")
    else:
        jobs = [(h, p) for h in hosts for p in ports]

    findings: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_endpoint, h, p, args.timeout, args.insecure,
                          do_oracle, args.phpinfo, args.reverse_dns, opener): (h, p)
                for h, p in jobs}
        for fut in concurrent.futures.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception as e:
                h, p = futs[fut]
                f = Finding(target=f"{h}:{p}", host=h, port=p, scheme="?", url="")
                f.detail = f"scan error: {e}"
                findings.append(f)

    data = [asdict(f) for f in findings]
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"tool": f"php2shell-scanner/{TOOL_VERSION}", "cves": list(CVES),
                       "results": data}, fh, indent=2)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        order = {"VULNERABLE": 0, "LIKELY_VULNERABLE": 1, "PHP_NO_VERSION": 2,
                 "PHP_UNKNOWN": 3, "PATCHED": 4, "NO_PHP_SIGNAL": 5, "UNREACHABLE": 6}
        for f in sorted(findings, key=lambda x: (order.get(x.verdict, 9), x.host, x.port)):
            extra = f" PHP {f.php_version} ({f.version_source})" if f.php_version else ""
            ptr = f" [{f.reverse_dns}]" if f.reverse_dns else ""
            say(f"[{f.verdict}] {f.scheme}://{f.host}:{f.port}{extra}{ptr} :: {f.detail}")
        n_v = sum(1 for f in findings if f.verdict == "VULNERABLE")
        n_l = sum(1 for f in findings if f.verdict == "LIKELY_VULNERABLE")
        say(f"--- {len(findings)} endpoint(s): {n_v} VULNERABLE(oracle), {n_l} LIKELY_VULNERABLE(version) ---")
    return 0 if not any(f.verdict in ("VULNERABLE", "LIKELY_VULNERABLE") for f in findings) else 2


if __name__ == "__main__":
    sys.exit(main())
