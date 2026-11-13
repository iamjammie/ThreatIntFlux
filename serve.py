#!/usr/bin/env python3
"""Local companion for the ThreatIntFlux console.

The console works fully offline from its saved dataset. When this server is running, the
console can also sync live intel: it asks this server to run the collector, and the server
returns the feed. The browser never contacts the intel sources itself.

Security:
  * Binds to 127.0.0.1 only.
  * Serves a fixed list of files, nothing else (no .git, no source files).
  * Rejects requests whose Host header is not localhost (DNS-rebinding defence).
  * Sync needs the custom header X-TIF: 1, which a cross-site page cannot send without a CORS preflight
    that this server never grants.
  * API keys are read from environment variables here. Their values are never sent to the browser;
    /api/status reports only whether each key is set.

Usage:
    pip install requests
    export THREATFOX_KEY=... OTX_KEY=... MALWAREBAZAAR_KEY=... GITHUB_TOKEN=... CERTIN_FEED_URL=...
    python3 serve.py            # then open http://127.0.0.1:8787/
"""
import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
PAGES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/collector.html": ("collector.html", "text/html; charset=utf-8"),
    "/threatintflux_feed.json": ("threatintflux_feed.json", "application/json; charset=utf-8"),
}
KEY_VARS = ["THREATFOX_KEY", "OTX_KEY", "MALWAREBAZAAR_KEY", "NVD_KEY", "GITHUB_TOKEN", "CERTIN_FEED_URL"]
MAX_BODY = 4096
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")


def status_payload():
    return {"ok": True, "app": "ThreatIntFlux", "version": "4",
            "keys": {name: bool(os.environ.get(name)) for name in KEY_VARS}}


def run_sync(days, mitre=False):
    """Run the collector and return the feed. Imported lazily so the page still loads without requests."""
    import threatintflux_collector as tc
    return tc.build_feed(days=days, mitre=mitre)


def make_handler(get_port):
    """get_port() returns the bound port, so port 0 (OS-chosen) works for tests."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "ThreatIntFluxCompanion/4"

        def log_message(self, fmt, *args):
            sys.stderr.write("[serve] " + (fmt % args) + "\n")

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

        def _host_ok(self):
            port = get_port()
            if self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"}:
                return True
            self._json(421, {"error": "host not allowed"})
            return False

        def do_GET(self):
            if not self._host_ok():
                return
            path = self.path.split("?", 1)[0]
            if path == "/api/status":
                return self._json(200, status_payload())
            if path in PAGES:
                name, ctype = PAGES[path]
                fp = os.path.join(ROOT, name)
                if not os.path.isfile(fp):
                    return self._json(404, {"error": f"{name} not found"})
                with open(fp, "rb") as f:
                    return self._send(200, f.read(), ctype)
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return
            if self.path.split("?", 1)[0] != "/api/sync":
                return self._json(404, {"error": "not found"})
            if self.headers.get("X-TIF") != "1":
                return self._json(403, {"error": "missing X-TIF header"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "body too large"})
            try:
                opts = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._json(400, {"error": "invalid JSON"})
            try:
                days = min(max(int(opts.get("days", 7)), 1), 30)
            except (TypeError, ValueError):
                return self._json(400, {"error": "days must be a number"})
            feed = run_sync(days, mitre=bool(opts.get("mitre")))
            return self._json(200, feed)

    return Handler


def make_server(port=8787):
    """Bind to localhost only. Pass port=0 to let the OS choose (used by tests)."""
    holder = {}
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(lambda: holder["port"]))
    holder["port"] = server.server_address[1]
    return server


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    server = make_server(args.port)
    print(f"ThreatIntFlux companion on http://127.0.0.1:{args.port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
