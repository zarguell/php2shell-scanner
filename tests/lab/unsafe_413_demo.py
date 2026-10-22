#!/usr/bin/env python3
"""Limits demo, part 2 — the 413-divergence that WASN'T (LAB ONLY).

History: on 2026-10-22 this script once showed, 3/3 runs, ~1.3 MB
duplicate-header multipart POST with NO upload-progress field:
  vuln 8.5.11 -> HTTP 200, patched 8.5.12 -> HTTP 413.
On revisit the SAME pair, SAME payload returns 200/200 across 6+ runs,
bisection 703–1289 KB, and fresh-worker restarts. Root cause of the original
split: the fixed-front container was briefly mounted with the WRONG nginx
config (upstream pointed at the vuln backend / stale 1m client_max), i.e.
lab-operator error, not a PHP behavior difference. The "divergence" was an
artifact — kept in git history as a cautionary tale.

That failed replication IS the finding, and it strengthens the no-ship case:
  1. Boundary behavior is stateful and environmental (worker memory state,
     proxy config drift, SAPI buffering). A 200-vs-413 line drawn on one
     afternoon's observation misfires on another afternoon's — in BOTH
     directions, on IDENTICAL containers.
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

Verdict policy: the scanner MUST NOT implement this. If YOU observe a 413
split against a box you own, check YOUR proxy config first (we failed this
ourselves), then investigate locally with --local — never as a version verdict.

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
