"""Minimal local SMTP server for TESTING ONLY — no dependencies, no real mail.

Use it to verify the app's "Test connection" and "Send test email" buttons
without a real mail server. It accepts connections, speaks just enough SMTP
(EHLO / AUTH / MAIL / RCPT / DATA / QUIT), and discards every message.

  python tools/local_smtp_server.py            # listens on 127.0.0.1:1025

Then in the app (Settings -> Email server): SMTP host 127.0.0.1, port 1025,
Use STARTTLS unchecked, username/password blank -> Test connection -> success.
Do NOT use this for anything real; it has no TLS and stores nothing.
"""
from __future__ import annotations

import argparse
import socketserver


class _Handler(socketserver.StreamRequestHandler):
    def _send(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode("utf-8"))

    def handle(self) -> None:
        self._send("220 local-smtp-test ESMTP (test only)")
        while True:
            raw = self.rfile.readline()
            if not raw:
                break
            up = raw.decode("utf-8", "replace").strip().upper()
            if up.startswith(("EHLO", "HELO")):
                self._send("250-local-smtp-test")
                self._send("250-AUTH LOGIN PLAIN")
                self._send("250 OK")
            elif up.startswith("AUTH LOGIN"):
                self._send("334 VXNlcm5hbWU6")   # base64("Username:")
                self.rfile.readline()
                self._send("334 UGFzc3dvcmQ6")   # base64("Password:")
                self.rfile.readline()
                self._send("235 2.7.0 Authentication successful")
            elif up.startswith("AUTH PLAIN"):
                if len(up.split()) > 2:
                    self._send("235 2.7.0 Authentication successful")
                else:
                    self._send("334 ")
                    self.rfile.readline()
                    self._send("235 2.7.0 Authentication successful")
            elif up.startswith(("MAIL FROM", "RCPT TO", "NOOP", "RSET")):
                self._send("250 OK")
            elif up == "DATA":
                self._send("354 End data with <CR><LF>.<CR><LF>")
                while True:
                    line = self.rfile.readline()
                    if not line or line.strip() == b".":
                        break
                self._send("250 OK: queued (discarded)")
            elif up.startswith("QUIT"):
                self._send("221 Bye")
                break
            else:
                self._send("250 OK")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    ap = argparse.ArgumentParser(description="Local test-only SMTP server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1025)
    args = ap.parse_args()
    print(f"Local TEST SMTP listening on {args.host}:{args.port} (no TLS). Ctrl+C to stop.")
    with _Server((args.host, args.port), _Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")


if __name__ == "__main__":
    main()
