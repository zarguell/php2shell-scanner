import json as _js
import os as _os
import socket as _sock
import struct as _st
import sys as _sys
import threading as _th
import time as _t
import unittest
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import php2shell_scanner as S



def _frame(payload: bytes) -> bytes:
    assert len(payload) < 126, "drill replies are small by construction"
    return bytes([0x81, len(payload)]) + payload


def _read_http(conn) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("drill peer closed mid-handshake")
        buf += chunk
    return buf


def _read_frame(conn2, fbuf: bytes):
    """Read one masked client frame; return (payload_bytes, remaining_buf)."""
    while len(fbuf) < 2:
        chunk = conn2.recv(65536)
        if not chunk:
            raise ConnectionError("drill peer closed")
        fbuf += chunk
    b1, b2 = fbuf[0], fbuf[1]
    ln = b2 & 0x7F
    need = 2 + (2 if ln == 126 else 8 if ln == 127 else 0)
    while len(fbuf) < need:
        chunk = conn2.recv(65536)
        if not chunk:
            raise ConnectionError("drill peer closed")
        fbuf += chunk
    off = 2
    if ln == 126:
        ln = _st.unpack("!H", fbuf[2:4])[0]
        off = 4
    elif ln == 127:
        ln = _st.unpack("!Q", fbuf[2:10])[0]
        off = 10
    want = off + (4 + ln if b2 & 0x80 else ln)
    while len(fbuf) < want:
        chunk = conn2.recv(65536)
        if not chunk:
            raise ConnectionError("drill peer closed")
        fbuf += chunk
    # RFC 6455 5.2: payload length EXCLUDES the 4-byte mask key — the key
    # rides between the header and the masked payload.
    if b2 & 0x80:
        key = fbuf[off:off + 4]
        masked = fbuf[off + 4:off + 4 + ln]
        payload = bytes(x ^ key[i % 4] for i, x in enumerate(masked))
        rest = off + 4 + ln
    else:
        payload = fbuf[off:off + ln]
        rest = off + ln
    return payload, fbuf[rest:]


class TestCdpHang(unittest.TestCase):
    def test_attach_hang_falls_back_sessionless(self):
        # The strict-build symptom: attachToTarget hangs, everything else
        # answers. cdp_session must return "" in ~5s (not the full timeout)
        # and getTargets must then succeed sessionless.
        started = _th.Event()

        def run():
            srv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 19298))
            srv.listen(1)
            srv.settimeout(30)
            started.set()
            try:
                conn, _ = srv.accept()
            except Exception:
                return
            conn.settimeout(30)
            try:
                _read_http(conn)
            except Exception:
                return
            body = (b'{"id":"T9","webSocketDebuggerUrl":'
                    b'"ws://127.0.0.1:19298/devtools/page/T9"}')
            # one-shot: read exactly one request, answer, close. (The client
            # tries PUT first; it never retries on success — no keep-alive loop.)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Content-Length: " + str(len(body)).encode() +
                         b"\r\nConnection: close\r\n\r\n" + body)
            try:
                conn.shutdown(_sock.SHUT_RDWR)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            try:
                conn2, _ = srv.accept()
            except Exception:
                return
            conn2.settimeout(30)
            try:
                _read_http(conn2)
            except Exception:
                return
            conn2.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                          b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                          b"Sec-WebSocket-Accept: xxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n\r\n")
            fbuf = b""
            while True:
                try:
                    payload, fbuf = _read_frame(conn2, fbuf)
                    msg = _js.loads(payload.decode())
                except Exception:
                    return
                if "attachToTarget" in _js.dumps(msg):
                    continue  # HANG like the strict build
                reply = _js.dumps({"id": msg.get("id"), "result": {
                    "targetInfos": [{"targetId": "T9"}]}}).encode()
                conn2.sendall(_frame(reply))

        _th.Thread(target=run, daemon=True).start()
        self.assertTrue(started.wait(timeout=10))
        _t.sleep(0.3)
        t0 = _t.monotonic()
        sock, tid = S.cdp_ws_connect("127.0.0.1", 19298, 12)
        sid, call = S.cdp_session(sock, tid, 12)
        dt = _t.monotonic() - t0
        try:
            self.assertEqual(sid, "")
            self.assertLess(dt, 9.0,
                            f"attach hang took {dt:.1f}s, must fall back ~5s")
            r = call("Target.getTargets")
            self.assertIn("targetInfos", r.get("result", {}))
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def test_stall_names_method_not_bare_timeout(self):
        # A socket that accepts but never replies must surface TimeoutError
        # naming the method (not socket.timeout / bare "timed out").
        srv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 19297))
        srv.listen(1)
        srv.settimeout(20)

        def _hold():
            try:
                c, _ = srv.accept()
                c.settimeout(20)
                try:
                    c.recv(65536)
                except Exception:
                    pass
                _t.sleep(15)  # hold silent past the call deadline
            except Exception:
                pass

        _th.Thread(target=_hold, daemon=True).start()
        _t.sleep(0.3)
        s2 = _sock.create_connection(("127.0.0.1", 19297), timeout=5)
        try:
            with self.assertRaises(TimeoutError) as cm:
                S.cdp_send(s2, {"id": 1, "method": "Page.navigate",
                                "params": {"url": "http://x/"}}, 30,
                           call_timeout=2.0)
            self.assertIn("Page.navigate", str(cm.exception))
        finally:
            try:
                s2.close()
            except Exception:
                pass
            srv.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
