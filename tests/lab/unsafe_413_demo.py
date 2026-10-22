#!/usr/bin/env python3
"""Limits demo, part 2 — the 413-divergence boundary probe (LAB ONLY).

Observed (2026-10-22, obscure pair, identical nginx/post_max_size=8M):
  ~1.3 MB duplicate-header multipart POST, NO upload-progress field:
    vuln 8.5.11   -> HTTP 200 (3/3 runs)
    patched 8.5.12 -> HTTP 413 (3/3 runs)
  At 360KB and 720KB both answer 200.

Hypothesis (consistent with dinosn's patch-gap analysis): the 8.5.12 patch's
streaming post_max_size enforcement + unknown-header filtering rejects the
inflated body where unpatched PHP parses it. This LOOKS like a version
oracle for silent boxes — and this script exists to show why it is NOT one
you should trust or ship:

  1. It is a single lab observation (one build pair, one SAPI, one config).
     post_max_size, memory_limit, SAPI buffering, proxy limits, and request
     sizing all move the threshold. A 200-vs-413 line drawn here will misfire
     elsewhere — in BOTH directions.
  2. It requires sending megabytes to production workers. That is a DoS
     probe wearing a lab coat: on small memory_limit / single-worker pools it
     degrades or kills workers. The demo pair has memory_limit=64M and
     throwaway containers; your targets do not.
  3. A 413-vs-200 split is not identity. Proxies, WAFs, rate limiters, and
     per-location limits all mint 413s for their own reasons. Treating any
     413 as "patched" (or any 200 as "vuln") manufactures false negatives
     and false positives at once.
  4. CGI has no persistent worker, so half the CVE class (619 stale state)
     does not apply there — yet this probe cannot tell CGI from FPM.

Verdict policy: the scanner MUST NOT implement this. If YOU run it against a
box you own, treat any divergence as "interesting, investigate locally with
--local" — never as a version verdict.

Usage (lab only, obscure pair must be up):
    python3 tests/lab/unsafe_413_demo.py [--wire-kb 1289 --trials 3]
"""
import argparse
import socket
import sys
import time

HDR = b"X: a\r\n"
TAIL = (b"------demo\r\n"
        b'Content-Disposition: form-data; name="t"\r\n\r\nv\r\n'
        b"------demo--\r\n")


def fire(port: int, body: bytes, timeout: float = 60.0) -> str:
    head = (f"POST /api/submit HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Cookie: PHPSESSID=demoprobe\r\n"
            f"Content-Type: multipart/form-data; boundary=--demo\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(head + body)
        raw = b""
        try:
            while True:
                c = s.recv(4096)
                if not c:
                    break
                raw += c
                if len(raw) > 4096:
                    break
        except Exception as e:
            s.close()
            return f"mid-read:{type(e).__name__}"
        s.close()
        if not raw:
            return "empty"
        return raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    except Exception as e:
        return f"conn:{type(e).__name__}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Lab-only 413-divergence demo (do not ship).")
    ap.add_argument("--wire-kb", type=int, default=1289)
    ap.add_argument("--trials", type=int, default=3)
    args = ap.parse_args()
    n = max(1000, (args.wire_kb * 1024) // len(HDR))
    body = HDR * n + TAIL
    print(f"LAB-ONLY 413-divergence demo: wire={len(body)//1024}KB, trials={args.trials}")
    print("vuln=:19093 (8.5.11)  patched=:19094 (8.5.12)  post_max_size=8M both")
    for t in range(args.trials):
        row = [f"trial{t}"]
        for port, label in ((19093, "vuln"), (19094, "patched")):
            st = fire(port, body)
            code = st.split(" ", 2)[1] if " " in st else st
            row.append(f"{label}={code}")
            time.sleep(1)
        print("  " + "  ".join(row))
    print("\nRead the module docstring before drawing conclusions: divergence "
          "here is a lab observation, not a version oracle. Do not ship this.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
