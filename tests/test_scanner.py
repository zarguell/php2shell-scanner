#!/usr/bin/env python3
"""php2shell-scanner test suite — unit + live Docker lab tests.

Unit tests run anywhere (no network). Live tests need the lab:
    docker compose -f tests/lab/docker-compose.yml up -d
    python3 tests/test_scanner.py --live
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import php2shell_scanner as S

LAB = {  # service -> (port, expected_verdict)
    "vuln-error-on": (19081, "VULNERABLE"),
    "vuln-error-off": (19082, "NO_PHP_SIGNAL"),  # hardened: no version, oracle blind
    "patched": (19083, "PATCHED"),
    "eol-old": (19084, "VULNERABLE"),
    "notphp": (19085, "NO_PHP_SIGNAL"),
    "static-only": (19086, "NO_PHP_SIGNAL"),
    "upload-disabled": (19087, "LIKELY_VULNERABLE"),  # oracle neg, version vuln
    "vague-hardened": (19088, "VULNERABLE"),  # no headers; oracle via discovered /search.php
    "wordpress-vuln": (19089, "PHP_NO_VERSION"),  # WP assets prove PHP app, version silent
    "pma": (19090, "PATCHED"),  # phpMyAdmin on PHP 8.3.36
    "silent-errors-off": (19091, "PHP_CANNOT_RULE_OUT"),  # dynamic path, zero disclosure
    "fpm-vuln": (19092, "VULNERABLE"),  # nginx->php-fpm 8.5.11, oracle through proxy
    "obscure-vuln": (19093, "NO_PHP_SIGNAL"),  # PHP only at /api/submit; safe probes blind BY DESIGN
    "obscure-fixed": (19094, "NO_PHP_SIGNAL"),  # patched twin: identical silence (control)
    "appliance-vuln": (19095, "PHP_NO_VERSION"),  # panel UI attributed, build 18.0.70 extracted
    "appliance-fixed": (19096, "PHP_NO_VERSION"),  # panel UI attributed, build 18.0.81 extracted
    "deep-surface": (19097, "VULNERABLE"),  # spider-only find: PHP 2 clicks down, oracle via /portal/home.php
    "js-dyn": (19101, "PHP_NO_VERSION"),  # StringTable via runtime JOIN: PHP artifacts proven, no .php surface
    "js-spa": (19100, "VULNERABLE"),  # JS-bundle-only endpoints (?action handler), oracle via /api/v2/endpoint.php
}

LIVE = os.environ.get("P2S_LIVE") == "1" or "--live" in sys.argv
FLEET_LIVE = os.environ.get("P2S_FLEET") == "1" or "--fleet" in sys.argv

# Real affected-product apps on KNOWN-VULNERABLE PHP 8.5.11
# (docker-compose.vulnfleet.yml). All must be oracle-VULNERABLE.
VULN_FLEET = {
    "vDrupal/11": 19201,
    "vMatomo": 19203,
    "vRoundcube/1.7": 19204,
    "vWordpress": 19206,
}

# Real affected-product apps on PATCHED vendor PHP (docker-compose.fleet.yml).
# All must be PATCHED with oracle negative (no false positives on real apps).
PATCHED_FLEET = {
    "drupal:apache/8.5.12": 19101,
    "mediawiki:stable/8.3.36": 19103,
    "roundcube/8.4.27": 19104,
    "nextcloud:apache/8.5.12": 19105,
    "matomo/8.4.27": 19106,
}

# GENUINE pre-patch vendor images (docker-compose.prepatch.yml), pushed before
# 2026-10-21 with the PHP of their era. Expectation per row pinned from
# observed behavior (see README fleet table): oracle-positive where the app's
# PHP layer leaks warnings, version-verdict where errors are off.
PREPATCH_FLEET = {
    # name: (port, expected_verdict, expected_php)
    "drupal:11.2-apache": (19301, "VULNERABLE", "8.4.23"),
    "mediawiki:1.44.0": (19303, "VULNERABLE", "8.1.33"),
    "roundcube:1.6.1-apache": (19304, "LIKELY_VULNERABLE", "8.1.17"),  # EOL + errors off
    "matomo:5.2.2-apache": (19305, "LIKELY_VULNERABLE", "8.3.17"),  # errors off
    "phpmyadmin:5.2.1-apache": (19306, "LIKELY_VULNERABLE", "8.2.27"),  # errors off
}

class TestVersions(unittest.TestCase):
    def test_parse_full(self):
        self.assertEqual(S.parse_version("PHP/8.5.11"), (8, 5, 11))
        self.assertEqual(S.parse_version("PHP 8.3.6"), (8, 3, 6))
        # strict parser is for OUR normalized strings only (PHP context proven)
        self.assertEqual(S.parse_strict_version("8.5.12"), (8, 5, 12))

    def test_parse_branch_only(self):
        self.assertEqual(S.parse_version("PHP/8.1"), (8, 1, 0))
        self.assertTrue(S.version_has_patch("PHP/8.1.34"))
        self.assertFalse(S.version_has_patch("PHP/8.1"))

    def test_parse_rejects_junk(self):
        self.assertIsNone(S.parse_version("Apache/2.4.69 (Debian)"))
        self.assertIsNone(S.parse_version(""))
        self.assertIsNone(S.parse_version("PHP/9.9.9"))
        # token gate: bare numbers are NOT php versions at parse layer
        self.assertIsNone(S.parse_version("8.5.12"))
        self.assertIsNone(S.parse_version("Apache Tomcat/8.5.98"))
        self.assertIsNone(S.parse_version("WordPress 6.8.3"))

    def test_classify_boundaries(self):
        for branch, fixed in S.FIXED.items():
            fs = f"{fixed[0]}.{fixed[1]}.{fixed[2]}"
            self.assertEqual(S.classify_version(fixed, fs)[0], "PATCHED", fs)
            below = (fixed[0], fixed[1], fixed[2] - 1)
            bs = f"{below[0]}.{below[1]}.{below[2]}"
            self.assertEqual(S.classify_version(below, bs)[0], "LIKELY_VULNERABLE", bs)

    def test_classify_eol(self):
        self.assertEqual(S.classify_version((8, 1, 34), "8.1.34")[0], "EOL_VULNERABLE")
        self.assertEqual(S.classify_version((7, 4, 33), "7.4.33")[0], "EOL_VULNERABLE")
        self.assertEqual(S.classify_version(None, "")[0], "UNKNOWN")

    def test_distro_regex_scoped(self):
        self.assertFalse(S.DISTRO_RE.search("PHP/8.5.12"))
        self.assertTrue(S.DISTRO_RE.search("PHP/8.5.12 Ubuntu"))
        self.assertTrue(S.DISTRO_RE.search("8.5.11-1+deb12u1"))


class TestBehavioral(unittest.TestCase):
    """Generic proofs: no per-app knowledge. Harvester + grooming + method
    matrix are pure functions of response behavior, tested offline."""
    def test_harvest_php_links(self):
        bodies = ['<a href="/admin/login.php">x</a> <form action="search.php?q=1">',
                  "<script src='/js/app.js'></script>"]
        # dead base: fetch fails, extra_bodies still parsed
        got = S.harvest_php_links(S.make_opener(1, False),
                                  "http://127.0.0.1:1/", 1,
                                  extra_bodies=bodies)
        self.assertIn("/admin/login.php", got)
        self.assertIn("/search.php", got)
        self.assertNotIn("/js/app.js", got)

    def test_link_rx_ignores_non_php(self):
        self.assertIsNone(S.LINK_RX.search('<a href="/about">x</a>'))
        self.assertIsNotNone(S.LINK_RX.search('<a href="/a.php">x</a>'))

    def test_extract_links_js_fetch(self):
        got = S.extract_links('<script>fetch("/api/go.php")</script>')
        self.assertIn("/api/go.php", got)
        self.assertEqual(S.extract_links(None), set())
        self.assertEqual(S.extract_links("<html>no links</html>"), set())

    def test_relative_js_resolves_against_page(self):
        # regression: src="js/x.js" on https://h/ must fetch https://h/js/x.js,
        # NEVER https://hjs/x.js (missing slash). urljoin against page URL.
        from urllib.parse import urljoin
        page_url = "https://192.168.1.1/"
        self.assertEqual(urljoin(page_url, "js/query.mind.js"),
                         "https://192.168.1.1/js/query.mind.js")
        self.assertEqual(urljoin("https://192.168.1.1/docs/", "js/query.mind.js"),
                         "https://192.168.1.1/docs/js/query.mind.js")
        self.assertEqual(urljoin(page_url, "/static/app.js"),
                         "https://192.168.1.1/static/app.js")
        import inspect
        self.assertIn("urljoin(page_url", inspect.getsource(S.spider_site))

    def test_grooming_needs_bare_opener(self):
        # contract: grooming builds its own cookieless opener internally
        import inspect
        src = inspect.getsource(S.run_cookie_grooming)
        self.assertIn("make_bare_opener", src)


class TestRecap(unittest.TestCase):
    """TLDR recap: counts, headline action, per-host lines."""
    def _mk(self, host, port, verdict, version=None):
        return S.Finding(target=f"{host}:{port}", host=host, port=port,
                         scheme="http", url=f"http://{host}:{port}/",
                         reachable=True, php_version=version, verdict=verdict)

    def test_counts_and_action(self):
        import io
        fs = [self._mk("a", 80, "VULNERABLE", "8.5.11"),
              self._mk("b", 80, "PATCHED", "8.5.12"),
              self._mk("c", 80, "NO_PHP_SIGNAL")]
        old = sys.stdout
        try:
            sys.stdout = buf = io.StringIO()
            S.say_recap(fs)
            out = buf.getvalue()
        finally:
            sys.stdout = old
        self.assertIn("endpoints=3", out)
        self.assertIn("VULNERABLE=1", out)
        self.assertIn("action: patch PHP", out)
        self.assertIn("a:80 -> VULNERABLE PHP 8.5.11", out)
        self.assertIn("c:80 -> NO_PHP_SIGNAL", out)

    def test_rce_headline_wins(self):
        import io
        fs = [self._mk("a", 80, "PATCHED", "8.5.12"),
              self._mk("b", 80, "RCE-PROVEN")]
        old = sys.stdout
        try:
            sys.stdout = buf = io.StringIO()
            S.say_recap(fs)
            out = buf.getvalue()
        finally:
            sys.stdout = old
        self.assertIn("CONFIRMED RCE", out)

    def test_quiet_headline(self):
        import io
        fs = [self._mk("a", 80, "PATCHED", "8.5.12")]
        old = sys.stdout
        try:
            sys.stdout = buf = io.StringIO()
            S.say_recap(fs)
            out = buf.getvalue()
        finally:
            sys.stdout = old
        self.assertIn("none required", out)


class TestEvidence(unittest.TestCase):
    """Provenance: detail cites positives only; negatives labeled (-)."""
    def test_detail_never_cites_negatives(self):
        f = S.Finding(target="h:80", host="h", port=80, scheme="http",
                      url="http://h/", reachable=True, http_status=200)
        S.mark(f, "body:app-plesk")
        f.signals.append("cookie-grooming(-):no Set-Cookie minted")
        f.signals.append("404-differential(-):identical")
        out = S.decide(f)
        self.assertEqual(out.verdict, "PHP_NO_VERSION")
        self.assertIn("body:app-plesk", out.detail)
        self.assertNotIn("cookie-grooming", out.detail)
        self.assertNotIn("404-differential", out.detail)

    def test_empty_evidence_is_flagged(self):
        f = S.Finding(target="h:80", host="h", port=80, scheme="http",
                      url="http://h/", reachable=True, http_status=200)
        f.php_detected = True  # simulate a setter that forgot mark()
        out = S.decide(f)
        self.assertIn("PROVENANCE BUG", out.detail)

    def test_audit_no_detail_cites_signals_slice(self):
        import inspect
        src = inspect.getsource(S.decide)
        self.assertNotIn("signals[:", src)

    def test_audit_lfi_sink_is_evidence(self):
        f = S.Finding(target="h:80", host="h", port=80, scheme="http",
                      url="http://h/", reachable=True, http_status=200)
        S.mark(f, "lfi-sink:/vuln.php?page=")
        out = S.decide(f)
        self.assertEqual(out.verdict, "PHP_NO_VERSION")
        self.assertIn("lfi-sink:/vuln.php?page=", out.detail)

    def test_audit_method_diff_never_proves(self):
        import inspect
        src = inspect.getsource(S.scan_endpoint)
        # method-differential must never call mark() (corroboration only)
        seg = src.split("run_method_differential")[1].split("run_easter_eggs")[0]
        self.assertNotIn("mark(f", seg)

    def test_short_tokens_need_boundaries(self):
        # user's case: javascript noise / WHMCS must not fire cpanel;
        # real cPanel login must. matched= names the alternative that fired.
        self.assertEqual(S.fingerprint_response(
            {'headers': {}, 'body': '<script>var e="x" type="text/javascript"</script>'})[2], [])
        sigs = S.fingerprint_response(
            {'headers': {}, 'body': 'WHMCS billing portal'})[2]
        self.assertFalse(any(x.startswith("body:app-cpanel") for x in sigs), sigs)
        self.assertTrue(any(x.startswith("body:app-whmcs") for x in sigs), sigs)
        sigs2 = S.fingerprint_response(
            {'headers': {}, 'body': '<title>cPanel Login</title>'})[2]
        hit = [x for x in sigs2 if x.startswith("body:app-cpanel")]
        self.assertTrue(hit, sigs2)
        self.assertIn("matched='cPanel'", hit[0])

    def test_snippets_attached(self):
        # sanity check: signal carries matched text + endpoint
        _, _, sigs, _ = S.fingerprint_response(
            {"headers": {}, "body": '<form action="login.php">cPanel login</form>'})
        app = [x for x in sigs if x.startswith("body:app-cpanel")]
        self.assertTrue(app, sigs)
        self.assertIn("cPanel login", app[0])

    def test_mark_sets_detected(self):
        f = S.Finding(target="h:80", host="h", port=80, scheme="http",
                      url="http://h/", reachable=True, http_status=200)
        S.mark(f, "deploy:composer.json")
        self.assertTrue(f.php_detected)
        self.assertIn("deploy:composer.json", f.evidence)


class TestTimeouts(unittest.TestCase):
    """Timeout rules: pre-check, budgets, progress routing."""
    def test_precheck_closed_port_fast(self):
        import time
        t0 = time.monotonic()
        self.assertFalse(S.tcp_open("127.0.0.1", 19991, 1.0))
        self.assertLess(time.monotonic() - t0, 5.0)

    def test_host_budget_param(self):
        import inspect
        sig = inspect.signature(S.scan_endpoint)
        self.assertIn("host_budget", sig.parameters)

    def test_progress_goes_to_stderr(self):
        import inspect
        src = inspect.getsource(S.main)
        self.assertNotIn('say(f"[*]', src)

    def test_closed_findings_shape(self):
        f = S.Finding(target="h:1", host="h", port=1, scheme="?", url="")
        f.detail = "TCP pre-check: port 1 closed/filtered (connect-timeout=1s)"
        out = S.decide(f)
        self.assertEqual(out.verdict, "UNREACHABLE")


class TestVerbose(unittest.TestCase):
    """Verbose tracing: exact line shapes, stderr routing, level gating."""
    def test_level_gating_off_by_default(self):
        self.assertEqual(S._TRACE_LEVEL, 0)

    def test_trace_lines_exact_shape(self):
        import io
        old_level, old_err = S._TRACE_LEVEL, sys.stderr
        try:
            S._TRACE_LEVEL = 1
            sys.stderr = buf = io.StringIO()
            S.trace(1, "spider http://x/ d=0 200 (10B) +0php ")
            S.trace(2, "req GET http://x/ -> 200 (1ms, 10B)")
            out = buf.getvalue()
            self.assertIn("spider http://x/ d=0 200 (10B) +0php", out)
            self.assertNotIn("req GET", out)  # level 2 hidden at -v
            S._TRACE_LEVEL = 2
            S.trace(2, "req GET http://x/ -> 200 (1ms, 10B)")
            self.assertIn("req GET http://x/ -> 200 (1ms, 10B)", buf.getvalue())
        finally:
            S._TRACE_LEVEL, sys.stderr = old_level, old_err

    def test_trace_file_mirror(self):
        import tempfile
        old_level = S._TRACE_LEVEL
        try:
            with tempfile.NamedTemporaryFile("r+", suffix=".log", delete=True) as fh:
                S._TRACE_LEVEL = 1
                S._trace_fh = open(fh.name, "a", encoding="utf-8")
                S.trace(1, "verdict http://x:80 -> VULNERABLE (high) :: detail")
                S._trace_fh.close()
                S._trace_fh = None
                fh.seek(0)
                self.assertIn("verdict http://x:80", fh.read())
        finally:
            S._TRACE_LEVEL = old_level
            S._trace_fh = None

class TestFingerprint(unittest.TestCase):
    """Pressure battery: every fingerprint the server may leak."""
    def fp(self, headers=None, body=""):
        return S.fingerprint_response({"headers": headers or {}, "body": body})

    def test_redirect_to_surfaced(self):
        import urllib.error
        # unit: 301 with Location must surface redirect_to (no network)
        self.assertIn("redirect_to", str(S.http_request.__code__.co_consts))

    def test_tls_untrusted_flagged(self):
        import inspect
        src = inspect.getsource(S.http_request)
        self.assertIn("tls_untrusted", src)
        src2 = inspect.getsource(S.decide)
        self.assertIn("TLS_UNTRUSTED", src2)

    def test_x_powered_by_full(self):
        ver, src, _, bo = self.fp({"X-Powered-By": "PHP/8.5.11"})
        self.assertEqual((ver, src, bo), ("8.5.11", "header:x-powered-by", False))

    def test_server_header_embedded(self):
        ver, src, _, _ = self.fp({"Server": "Apache/2.4.58 (Unix) PHP/8.2.20"})
        self.assertEqual((ver, src), ("8.2.20", "header:server"))

    def test_branch_only_flagged(self):
        ver, _, _, bo = self.fp({"X-Powered-By": "PHP/8.1"})
        self.assertEqual(ver, "8.1.0")
        self.assertTrue(bo)

    def test_tomcat_not_php(self):
        ver, _, sigs, _ = self.fp({"Server": "Apache Tomcat/8.5.98"})
        self.assertIsNone(ver)
        self.assertEqual(sigs, [])

    def test_servlet_generator_ignored(self):
        self.assertIsNone(self.fp({"X-Powered-By": "Servlet/5.0"})[0])
        self.assertIsNone(self.fp({"X-Generator": "WordPress 6.8.3"})[0])

    def test_aspnet_ignored(self):
        self.assertIsNone(self.fp({"X-Powered-By": "ASP.NET", "X-AspNet-Version": "4.0.30319"})[0])

    def test_body_powered_by(self):
        ver, src, _, _ = self.fp(body="<html>Powered by PHP 8.2.12</html>")
        self.assertEqual((ver, src), ("8.2.12", "body:powered-by"))

    def test_body_bare_number_ignored(self):
        self.assertIsNone(self.fp(body="Tomcat 8.5.98 status page")[0])

    def test_framework_signals(self):
        _, _, sigs, _ = self.fp({"Server": "nginx"}, '<a href="i.php">x</a>')
        self.assertTrue(any(x.startswith("body:.php-link") for x in sigs), sigs)
        _, _, sigs, _ = self.fp(body='<script src="/wp-includes/x.js">')
        self.assertTrue(any(x.startswith("body:app-wordpress") for x in sigs), sigs)
        _, _, sigs, _ = self.fp(body='<input name="_token" data-csrf-token>')
        self.assertTrue(any(x.startswith("body:app-laravel") for x in sigs), sigs)


class TestOracleBody(unittest.TestCase):
    def test_body_shape(self):
        body = S.build_oracle_body("----BOUND", "TOKEN123", "f.txt")
        self.assertIn(b"PHP_SESSION_UPLOAD_PROGRESS", body)
        self.assertIn(b"TOKEN123", body)
        self.assertIn(b'filename="f.txt"', body)
        self.assertIn(b"PHPSESSID", b"PHPSESSID=_")  # cookie goes in header
        self.assertLess(len(body), 1024, "oracle must stay tiny/non-destructive")

    def test_all_markers_required(self):
        # decide() only trusts oracle_positive, which requires 3/3 markers
        f = S.Finding(target="t", host="h", port=80, scheme="http", url="http://h/",
                      reachable=True, http_status=200, oracle_ran=True,
                      oracle_positive=False, oracle_evidence="oracle markers 2/3")
        S.decide(f)
        self.assertNotEqual(f.verdict, "VULNERABLE")


class TestDecide(unittest.TestCase):
    def _base(self, **kw):
        f = S.Finding(target="t", host="h", port=80, scheme="http", url="http://h/",
                      reachable=True, http_status=200)
        for k, v in kw.items():
            setattr(f, k, v)
        return S.decide(f)

    def test_oracle_positive_wins(self):
        f = self._base(php_version="8.5.12", version_verdict="PATCHED",
                       oracle_ran=True, oracle_positive=True, oracle_evidence="3/3")
        self.assertEqual(f.verdict, "VULNERABLE")
        self.assertEqual(f.confidence, "high")

    def test_patched_stays_patched_on_oracle_negative(self):
        f = self._base(php_version="8.5.12", version_verdict="PATCHED",
                       version_detail="fixed", oracle_ran=True, oracle_positive=False)
        self.assertEqual(f.verdict, "PATCHED")

    def test_vuln_version_no_oracle(self):
        f = self._base(php_version="8.5.11", version_verdict="LIKELY_VULNERABLE",
                       version_detail="old", oracle_ran=False)
        self.assertEqual(f.verdict, "LIKELY_VULNERABLE")

    def test_unreachable(self):
        f = S.Finding(target="t", host="h", port=1, scheme="http", url="http://h:1/")
        self.assertEqual(S.decide(f).verdict, "UNREACHABLE")

    def test_no_php(self):
        self.assertEqual(self._base().verdict, "NO_PHP_SIGNAL")


class TestTargetExpansion(unittest.TestCase):
    def _args(self, **kw):
        d = dict(target=None, targets_file=None, subnet=None)
        d.update(kw)
        return type("A", (), d)()

    def test_subnet(self):
        hosts = S.expand_targets(self._args(subnet="127.0.0.0/30"))
        self.assertEqual(hosts, ["127.0.0.1", "127.0.0.2"])

    def test_url_strip(self):
        hosts = S.expand_targets(self._args(target="https://example.com/app.php?x=1"))
        self.assertEqual(hosts, ["example.com"])

    def test_ports(self):
        a = type("A", (), {"ports": "80,8080,9000-9002", "discover_ports": False})()
        self.assertEqual(S.expand_ports(a), [80, 8080, 9000, 9001, 9002])


@unittest.skipUnless(LIVE, "needs live lab (P2S_LIVE=1 or --live)")
class TestLiveLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.opener = S.make_opener(10, False)

    def _scan(self, port):
        res = S.scan_endpoint("127.0.0.1", port, 10, False, True, False, False, self.opener)
        self.assertTrue(res, f"no findings for port {port}")
        # both schemes probed: prefer reachable (http first), fall back to [0]
        return next((f for f in res if f.reachable), res[0])

    def test_all_scenarios(self):
        for name, (port, want) in LAB.items():
            with self.subTest(service=name):
                f = self._scan(port)
                self.assertEqual(f.verdict, want,
                                 f"{name}:{port} got {f.verdict} ({f.detail})")

    def test_oracle_no_false_positive_on_patched(self):
        f = self._scan(19083)
        self.assertFalse(f.oracle_positive, f.oracle_evidence)
        self.assertIn("8.5.12", f.php_version or "")

    def test_oracle_positive_on_vuln(self):
        f = self._scan(19081)
        self.assertTrue(f.oracle_positive, f.oracle_evidence)

    def test_vague_hardened_found_via_path_discovery(self):
        # no X-Powered-By, static front page — oracle fires on /search.php
        f = self._scan(19088)
        self.assertEqual(f.verdict, "VULNERABLE", f.detail)
        self.assertIsNone(f.php_version)
        self.assertIn("/search.php", f.oracle_evidence)

    def test_silent_errors_off_cannot_rule_out(self):
        # zero disclosure: oracle blind, no version — but dynamic path found.
        # Must NOT be silent; must name the path and point at --local.
        f = self._scan(19091)
        self.assertEqual(f.verdict, "PHP_CANNOT_RULE_OUT", f.detail)
        self.assertTrue(f.discovered_paths, "discovered PHP paths must surface")
        self.assertIn("/search.php", f.discovered_paths)
        self.assertIn("--local", f.detail)

    def test_fpm_vulnerable_through_proxy(self):
        f = self._scan(19092)
        self.assertEqual(f.verdict, "VULNERABLE", f.detail)
        self.assertTrue(f.oracle_positive, f.oracle_evidence)
        self.assertIn("8.5.11", f.php_version or "")

    def test_stringtable_dyn_chain(self):
        # loader.js -> getScript + JOIN with lang default -> StringTable_en.js
        # whose $this->/$_SESSION content proves server-side PHP. No .php URL
        # anywhere: verdict rides the artifact evidence, not a path.
        op = self.opener
        base = "http://127.0.0.1:19101/"
        tgts, visited, arts = S.spider_site(op, base, 10)
        self.assertTrue(any("StringTable_en.js" in a for a in arts), arts)
        self.assertTrue(any("$this->" in a for a in arts), arts)
        f = self._scan(19101)
        self.assertEqual(f.verdict, "PHP_NO_VERSION", f.detail)
        self.assertTrue(any("dynjs-artifact" in e for e in f.evidence), f.evidence)

    def test_js_spa_bundle_only_endpoints(self):
        # index.html has ZERO .php refs; endpoints live in /static/app.js.
        # Bundle fetching must find them, ?action dynamic test must prove,
        # oracle must fire — without any browser.
        op = self.opener
        base = "http://127.0.0.1:19100/"
        self.assertEqual(S.harvest_php_links(op, base, 10), [])
        tgts, visited, _arts = S.spider_site(op, base, 10)
        self.assertIn("/api/v2/endpoint.php", tgts)
        self.assertIn("/portal/deep.php", tgts)
        self.assertIn("/static/app.js", visited)
        f = self._scan(19100)
        self.assertEqual(f.verdict, "VULNERABLE", f.detail)
        self.assertIn("/api/v2/endpoint.php", f.oracle_evidence)

    def test_404_differential(self):
        # FPM proxy parses .php differently from static 404s; nginx alone doesn't
        pos_fpm, _ = S.run_404_differential(self.opener, "http://127.0.0.1:19092/", 10)
        self.assertTrue(pos_fpm)
        pos_nginx, _ = S.run_404_differential(self.opener, "http://127.0.0.1:19085/", 10)
        self.assertFalse(pos_nginx)
        # obscure pair: nginx 404s everything identically -> negative on BOTH
        # (this is the documented limits-demo: safe probes blind by design)
        pos_ov, _ = S.run_404_differential(self.opener, "http://127.0.0.1:19093/", 10)
        pos_of, _ = S.run_404_differential(self.opener, "http://127.0.0.1:19094/", 10)
        self.assertFalse(pos_ov)
        self.assertFalse(pos_of)

    def test_obscure_pair_identical_silence(self):
        # The limits demo, pinned: vuln 8.5.11 and patched 8.5.12 behind
        # obscure routing are INDISTINGUISHABLE to safe probes. Both must be
        # NO_PHP_SIGNAL (honest), never a fabricated verdict. See
        # tests/lab/unsafe_413_demo.py for why the boundary probe must not ship.
        fv = self._scan(19093)
        ff = self._scan(19094)
        self.assertEqual(fv.verdict, "NO_PHP_SIGNAL", fv.detail)
        self.assertEqual(ff.verdict, "NO_PHP_SIGNAL", ff.detail)
        self.assertFalse(fv.oracle_positive)
        self.assertFalse(ff.oracle_positive)

    def test_local_enumerator(self):
        data = S.run_local_enum()
        self.assertIn("binaries", data)
        self.assertIn("processes", data)

    def test_spider_finds_deep_surface(self):
        # PHP two clicks down a static front: single-page harvest is blind,
        # the bounded spider must find /portal/home.php and fire the oracle.
        op = self.opener
        base = "http://127.0.0.1:19097/"
        self.assertEqual(S.harvest_php_links(op, base, 10), [])
        tgts, visited, _arts = S.spider_site(op, base, 10)
        self.assertIn("/portal/home.php", tgts)
        self.assertIn("/portal/", visited)
        f = self._scan(19097)
        self.assertEqual(f.verdict, "VULNERABLE", f.detail)
        self.assertIn("/portal/home.php", f.oracle_evidence)

    def test_spider_budget_flags(self):
        # --spider-pages 0 --spider-depth 0 disables the crawl: the deep
        # surface (2 clicks down, no static guesses hit) must go silent.
        # Default and aggressive budgets must both find it.
        op = self.opener
        base = "http://127.0.0.1:19097/"
        tgts_off, _, _ = S.spider_site(op, base, 10, max_pages=0, max_depth=0)
        self.assertEqual(tgts_off, set())
        paths_off, _ = S.discover_php_paths(op, base, 10, 0, 0)
        self.assertEqual(paths_off, ["/"])
        paths_on, _ = S.discover_php_paths(op, base, 10)
        self.assertIn("/portal/home.php", paths_on)
        r = S.scan_endpoint("127.0.0.1", 19097, 10, False, True, False, False,
                            op, 50, 4)
        self.assertTrue(r, "aggressive scan returned no findings")
        self.assertEqual(r[0].verdict, "VULNERABLE", r[0].detail)

    def test_appliance_twins_attributed_with_build(self):
        # Locked-down panel UIs, no PHP headers: scanner must attribute the
        # PHP-backed panel + extract the panel build for advisory lookup.
        # Vuln twin ships build 18.0.70 (pre-fix era), fixed twin 18.0.81.
        fv = self._scan(19095)
        self.assertEqual(fv.verdict, "PHP_NO_VERSION", fv.detail)
        self.assertTrue(any("plesk" in h for h in fv.app_hits), fv.app_hits)
        self.assertIn("18.0.70", fv.detail)
        self.assertIn("44397729587351", fv.detail)  # vendor advisory pointer
        ff = self._scan(19096)
        self.assertEqual(ff.verdict, "PHP_NO_VERSION", ff.detail)
        self.assertIn("18.0.81", ff.detail)

    def test_tls_appliance_both_schemes(self):
        # TLS on non-standard port: strict sees TLS_UNTRUSTED on https
        # (self-signed) and scans behind it with insecure opener.
        op = self.opener
        strict = S.scan_endpoint("127.0.0.1", 19098, 10, False, True, False, False, op)
        by_scheme = {f.scheme: f for f in strict}
        self.assertIn("https", by_scheme)
        self.assertEqual(by_scheme["https"].verdict, "TLS_UNTRUSTED", by_scheme["https"].detail)
        self.assertIn("--insecure", by_scheme["https"].detail)
        op2 = S.make_opener(10, True)
        vuln = S.scan_endpoint("127.0.0.1", 19098, 10, True, True, False, False, op2)
        best = [f for f in vuln if f.verdict == "VULNERABLE"]
        self.assertTrue(best, [(f.scheme, f.verdict) for f in vuln])
        self.assertTrue(best[0].oracle_positive)
        self.assertIn("8.5.11", best[0].php_version or "")

    def test_downgrade_stub_scanned_behind(self):
        # :19099 http 301 -> https://:19098: with insecure opener the scanner
        # follows the upgrade and reports the PHP behind the stub.
        op2 = S.make_opener(10, True)
        res = S.scan_endpoint("127.0.0.1", 19099, 10, True, True, False, False, op2)
        self.assertTrue(res)
        joined = " ".join(f.verdict + (f.php_version or "") for f in res)
        self.assertIn("8.5.11", joined, [(f.scheme, f.verdict) for f in res])

    def test_panel_fingerprints_unit(self):
        # unit-level: panel bodies attribute without network
        ver, _, sigs, _ = S.fingerprint_response(
            {"headers": {"Server": "Apache"},
             "body": "<title>Plesk Obsidian 18.0.70</title><div class=psa-page>"})
        self.assertIsNone(ver)
        self.assertTrue(any(x.startswith("body:app-plesk") for x in sigs), sigs)

    def test_wordpress_proves_php_app(self):
        f = self._scan(19089)
        self.assertEqual(f.verdict, "PHP_NO_VERSION", f.detail)
        self.assertTrue(any("wordpress" in h for h in f.app_hits), f.app_hits)

    def test_pma_patched(self):
        f = self._scan(19090)
        self.assertEqual(f.verdict, "PATCHED", f.detail)
        self.assertEqual(f.php_version, "8.3.36")

    def test_oracle_tiny_request(self):
        # regression: scanner must never send exploit-sized bodies
        body = S.build_oracle_body("----x" + "a" * 24, "t" * 20, "f.txt")
        self.assertLess(len(body), 2048)

    def test_cli_json_targets_file_subnet(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("127.0.0.1\n# comment\n\n")
            tf = fh.name
        try:
            r = subprocess.run(
                [sys.executable, "php2shell_scanner.py", "-f", tf,
                 "-p", "19081,19083", "--json"],
                capture_output=True, text=True, timeout=90,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.assertEqual(r.returncode, 2, r.stdout[:500])  # vuln found -> rc 2
            data = json.loads(r.stdout)
            by_port: dict = {}
            for d in data:
                # both schemes probed: keep the most severe verdict per port
                sev = {"VULNERABLE": 0, "LIKELY_VULNERABLE": 1, "PHP_NO_VERSION": 2,
                       "PHP_CANNOT_RULE_OUT": 2, "PHP_UNKNOWN": 3, "PATCHED": 4,
                       "TLS_UNTRUSTED": 5, "NO_PHP_SIGNAL": 6, "UNREACHABLE": 7}
                if d["port"] not in by_port or sev.get(d["verdict"], 9) < sev.get(by_port[d["port"]], 9):
                    by_port[d["port"]] = d["verdict"]
            self.assertEqual(by_port[19081], "VULNERABLE")
            self.assertEqual(by_port[19083], "PATCHED")
        finally:
            os.unlink(tf)
        r = subprocess.run(
            [sys.executable, "php2shell_scanner.py", "-s", "127.0.0.0/31",
             "-p", "19085", "--no-oracle"],
            capture_output=True, text=True, timeout=90,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.assertIn("NO_PHP_SIGNAL", r.stdout)


@unittest.skipUnless(FLEET_LIVE, "needs app fleets (P2S_FLEET=1 or --fleet)")
class TestAffectedFleet(unittest.TestCase):
    """Pressure test on REAL affected products from docs/affected-products.md:
    vendor images (patched PHP -> PATCHED, oracle negative) and rebuilt
    vuln-fleet images (real app code on PHP 8.5.11 -> oracle VULNERABLE)."""
    @classmethod
    def setUpClass(cls):
        cls.opener = S.make_opener(12, False)

    def _scan(self, port):
        res = S.scan_endpoint("127.0.0.1", port, 12, False, True, False, False, self.opener)
        self.assertTrue(res, f"no findings for port {port}")
        return next((f for f in res if f.reachable), res[0])

    def test_vuln_apps_fire_oracle(self):
        for name, port in VULN_FLEET.items():
            with self.subTest(app=name):
                f = self._scan(port)
                self.assertEqual(f.verdict, "VULNERABLE",
                                 f"{name}:{port} got {f.verdict} ({f.detail})")
                self.assertTrue(f.oracle_positive, f.oracle_evidence)
                self.assertIn("8.5.11", f.php_version or "")

    def test_patched_apps_no_false_positive(self):
        for name, port in PATCHED_FLEET.items():
            with self.subTest(app=name):
                f = self._scan(port)
                self.assertEqual(f.verdict, "PATCHED",
                                 f"{name}:{port} got {f.verdict} ({f.detail})")
                self.assertFalse(f.oracle_positive, f.oracle_evidence)

    def test_prepatch_apps_detected(self):
        # Genuine old vendor images: every one must be flagged (oracle or
        # version verdict — never PATCHED, never silent).
        for name, (port, want, want_php) in PREPATCH_FLEET.items():
            with self.subTest(app=name):
                f = self._scan(port)
                self.assertEqual(f.verdict, want,
                                 f"{name}:{port} got {f.verdict} ({f.detail})")
                self.assertIn(want_php, f.php_version or "", f.detail)
                self.assertNotIn(f.verdict, ("PATCHED", "NO_PHP_SIGNAL"))


RCEDEMO = os.environ.get("P2S_RCEDEMO") == "1" or "--rcedemo" in sys.argv


class TestProveRce(unittest.TestCase):
    """--prove-rce integration: LFI auto-discovery + contained proof wiring.
    Runs against the RCE twins only (19110/19111); no confirmation needed
    below the CLI layer (direct function calls, same as the CLI path after
    double confirmation)."""
    def _rce_up(self):
        import urllib.request
        try:
            urllib.request.urlopen("http://127.0.0.1:19110/", timeout=5).read(16)
            return True
        except Exception:
            return False

    def test_lfi_sink_autodiscovered(self):
        if not LIVE:
            self.skipTest("needs live rce twins")
        if not self._rce_up():
            self.skipTest("rce twins down (docker-compose.rce.yml)")
        op = S.make_opener(10, False)
        sinks = S.discover_lfi_sinks(op, "http://127.0.0.1:19110/", 10)
        self.assertIn(("/vuln.php", "page"), sinks)

    def test_prove_reports_honest_tier(self):
        if not LIVE:
            self.skipTest("needs live rce twins")
        if not self._rce_up():
            self.skipTest("rce twins down (docker-compose.rce.yml)")
        op = S.make_opener(10, False)
        # suffix-less session include: read primitive proven, RCE unproven
        # through echo — the scanner must say exactly that, never RCE-PROVEN.
        ok, ev = S.prove_chain_a(op, "http://127.0.0.1:19110/", 10, ("/vuln.php", "page"))
        self.assertFalse(ok)
        self.assertIn("reads attacker session content", ev)
        self.assertIn("RCE unproven", ev)

    def test_prove_refusal_contract(self):
        import inspect
        src = inspect.getsource(S.main)
        self.assertIn("P2S_RCE_ARM", src)
        self.assertIn("isatty", src)
        self.assertIn("--prove-rce", src)



@unittest.skipUnless(RCEDEMO, "contained RCE demo, opt-in only (P2S_RCEDEMO=1 or --rcedemo)")
class TestRceDemo(unittest.TestCase):
    def test_retarget_refusals(self):
        import subprocess as _sp
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # no arm -> refuse, exit nonzero-equivalent message, rc 1
        r = _sp.run([sys.executable, "tests/lab/rce_demo.py", "--target", "10.0.0.5:8080"],
                    capture_output=True, text=True, timeout=60, cwd=root, stdin=_sp.DEVNULL)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("P2S_RCE_ARM", r.stdout)
        # arm + non-tty stdin -> refuse (no script-driven retargeting)
        import os as _os
        env = dict(_os.environ, P2S_RCE_ARM="1")
        r2 = _sp.run([sys.executable, "tests/lab/rce_demo.py", "--target", "10.0.0.5:8080"],
                     capture_output=True, text=True, timeout=60, cwd=root, stdin=_sp.DEVNULL, env=env)
        self.assertEqual(r2.returncode, 1, r2.stdout)
        self.assertIn("not a TTY", r2.stdout)
        # lab default still works with no flags
        r3 = _sp.run([sys.executable, "tests/lab/rce_demo.py", "--help"],
                     capture_output=True, text=True, timeout=30, cwd=root)
        self.assertIn("--target", r3.stdout)


    """AUTHORIZED LAB ONLY. Runs tests/lab/rce_demo.py (Chain-A marker write)
    against the rce twins and asserts the documented outcome: BOTH twins
    RCE-positive (the fix does not remove app-layer session injection or the
    intentional LFI sink), markers cleaned, scanner agrees per-twin
    (VULNERABLE oracle on 8.5.11, PATCHED oracle-negative on 8.5.12).
    Never runs by default; never touches non-lab targets (script allowlists)."""
    def test_contained_rce_both_twins(self):
        import subprocess as _sp
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        r = _sp.run([sys.executable, "tests/lab/rce_demo.py"],
                    capture_output=True, text=True, timeout=120, cwd=root)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-500:])
        self.assertIn("RCE-POSITIVE", r.stdout)
        self.assertIn("markers cleaned", r.stdout)

    def test_scanner_agrees_per_twin(self):
        op = S.make_opener(10, False)
        fv = S.scan_endpoint("127.0.0.1", 19110, 10, False, True, False, False, op)
        fv = next((f for f in fv if f.reachable), fv[0])
        self.assertEqual(fv.verdict, "VULNERABLE", fv.detail)
        ff = S.scan_endpoint("127.0.0.1", 19111, 10, False, True, False, False, op)
        ff = next((f for f in ff if f.reachable), ff[0])
        self.assertEqual(ff.verdict, "PATCHED", ff.detail)


if __name__ == "__main__":
    if "--live" in sys.argv:
        sys.argv.remove("--live")
        os.environ["P2S_LIVE"] = "1"
    if "--fleet" in sys.argv:
        sys.argv.remove("--fleet")
        os.environ["P2S_FLEET"] = "1"
    if "--rcedemo" in sys.argv:
        sys.argv.remove("--rcedemo")
        os.environ["P2S_RCEDEMO"] = "1"
    unittest.main(verbosity=2)
