#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - live_server.py
#  A small, dependency-free HTTP server that publishes the live state.
#
#  STDLIB ONLY, ON PURPOSE. This runs on the same Windows workstation as the
#  Arduino IDE. Adding a web framework or a WebSocket library to a bench that
#  currently needs nothing but Python (and optionally `cryptography`) would be a
#  poor trade for a page that refreshes once a second.
#
#  ROUTES
#      GET  /            the map page (live_map.html, read from disk each time
#                        so the page can be edited without a restart)
#      GET  /state.json  the current snapshot from live_state.LiveState
#      POST /set-time    TEST ONLY - set or clear the verification clock
#                        override. See live_state.time_override for why this
#                        exists and why any run using it is a bench exercise
#                        rather than evidence.
#
#  BINDS TO LOCALHOST BY DEFAULT. The snapshot contains aircraft positions and
#  identities; it is not something to expose on a shared network by accident.
#  --host is available for the deliberate case.
# =============================================================================

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "live_map.html")


class _Handler(BaseHTTPRequestHandler):
    # Injected by serve()
    state = None

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_page()
        elif path == "/state.json":
            self._send_state()
        else:
            self.send_error(404, "no such path")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/set-time":
            self.send_error(404, "no such path")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:
            self._respond(json.dumps({"ok": False, "error": f"bad request: {e}"})
                          .encode(), "application/json")
            return

        # unix=null clears the override and returns to the real host clock.
        try:
            unix = payload.get("unix", None)
            self.state.set_time_override(None if unix is None else float(unix))
        except (TypeError, ValueError) as e:
            self._respond(json.dumps({"ok": False, "error": f"bad time: {e}"})
                          .encode(), "application/json")
            return

        # Announce it on the terminal too. A doctored clock must never be
        # something only the browser knows about.
        if self.state.time_override is None:
            print("\n[TIME OVERRIDE CLEARED] verification is back on the real "
                  "host clock.")
        else:
            print(f"\n[TIME OVERRIDE SET] verification time is now "
                  f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.state.time_override))} "
                  f"- TEST ONLY, this run is not evidence.")
        self._respond(json.dumps({"ok": True}).encode(), "application/json")

    def _send_page(self):
        try:
            with open(PAGE, "rb") as fh:
                body = fh.read()
        except OSError as e:
            self.send_error(500, f"cannot read live_map.html: {e}")
            return
        self._respond(body, "text/html; charset=utf-8")

    def _send_state(self):
        try:
            body = json.dumps(self.state.snapshot()).encode("utf-8")
        except Exception as e:                       # never take the server down
            body = json.dumps({"error": str(e)}).encode("utf-8")
        self._respond(body, "application/json")

    def _respond(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # The page polls; a cached snapshot would freeze the map.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass            # browser navigated away mid-write; not an error

    def log_message(self, fmt, *args):
        # Silence per-request logging: at 1 Hz it would bury the observer's own
        # status line, which is the thing the operator actually needs to see.
        pass


def serve(state, host="127.0.0.1", port=8080):
    """Start the server on a daemon thread. Returns the ThreadingHTTPServer."""
    handler = type("BoundHandler", (_Handler,), {"state": state})
    httpd = ThreadingHTTPServer((host, port), handler)
    t = threading.Thread(target=httpd.serve_forever, name="live-http",
                         daemon=True)
    t.start()
    return httpd
