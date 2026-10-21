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
}

LIVE = os.environ.get("P2S_LIVE") == "1" or "--live" in sys.argv


class TestVersions(unittest.TestCase):
    def test_parse_full(self):
        self.assertEqual(S.parse_version("PHP/8.5.11"), (8, 5, 11))
        self.assertEqual(S.parse_version("PHP 8.3.6"), (8, 3, 6))
        self.assertEqual(S.parse_version("8.5.12"), (8, 5, 12))  # bare re-parse

    def test_parse_branch_only(self):
        self.assertEqual(S.parse_version("PHP/8.1"), (8, 1, 0))
        self.assertTrue(S.version_has_patch("PHP/8.1.34"))
        self.assertFalse(S.version_has_patch("PHP/8.1"))

    def test_parse_rejects_junk(self):
        self.assertIsNone(S.parse_version("Apache/2.4.69 (Debian)"))
        self.assertIsNone(S.parse_version(""))
        self.assertIsNone(S.parse_version("PHP/9.9.9"))

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
        # DISTRO_RE matches distro tokens; scan_endpoint scopes it to
        # PHP-bearing header values only, so plain "Apache (Debian)" is
        # excluded at the call site. Live test below proves end state.
        self.assertFalse(S.DISTRO_RE.search("PHP/8.5.12"))
        self.assertTrue(S.DISTRO_RE.search("PHP/8.5.12 Ubuntu"))
        self.assertTrue(S.DISTRO_RE.search("8.5.11-1+deb12u1"))

    def test_distro_not_set_for_stock_docker(self):
        if not LIVE:
            self.skipTest("needs live lab")
        op = S.make_opener(10, False)
        res = S.http_request(op, "http://127.0.0.1:19083/", 10)
        ver, _, _ = S.fingerprint_response(res)
        self.assertEqual(ver, "8.5.12")
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


if __name__ == "__main__":
    if "--live" in sys.argv:
        sys.argv.remove("--live")
        os.environ["P2S_LIVE"] = "1"
    unittest.main(verbosity=2)
