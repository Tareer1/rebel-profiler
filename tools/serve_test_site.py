#!/usr/bin/env python3
"""Tiny static server with CORS enabled — lets the extension's fetch-fallback
read the test pages when Firefox withholds host permissions."""
import functools
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
ROOT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/rp_test_site"


class CorsHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()


handler = functools.partial(CorsHandler, directory=ROOT)
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), handler).serve_forever()
