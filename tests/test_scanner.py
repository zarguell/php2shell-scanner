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


class TestFingerprint(unittest.TestCase):
    """Pressure battery: every fingerprint the server may leak."""
    def fp(self, headers=None, body=""):
        return S.fingerprint_response({"headers": headers or {}, "body": body})

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
        self.assertIn("body:.php-link", sigs)
        _, _, sigs, _ = self.fp(body='<script src="/wp-includes/x.js">')
        self.assertIn("body:app-wordpress", sigs)
        _, _, sigs, _ = self.fp(body='<input name="_token" data-csrf-token>')
        self.assertIn("body:app-laravel", sigs)


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
        return res[0]

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
            by_port = {d["port"]: d["verdict"] for d in data}
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
        return res[0]

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


if __name__ == "__main__":
    if "--live" in sys.argv:
        sys.argv.remove("--live")
        os.environ["P2S_LIVE"] = "1"
    if "--fleet" in sys.argv:
        sys.argv.remove("--fleet")
        os.environ["P2S_FLEET"] = "1"
    unittest.main(verbosity=2)
