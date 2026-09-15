"""Shared fixtures for Rebel Profiler tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database


@pytest.fixture()
def db(tmp_path):
    database = Database(tmp_path / "case.db")
    database.migrate()
    yield database
    database.close()


@pytest.fixture()
def scoped_engine():
    """A scope engine with one active case authorizing *.lab.example.test."""
    scope = Scope(case_id="case1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test", note="authorized lab range")
    scope.add("*.lab.example.test:5555.excluded.example.test", excluded=True)
    engine = ScopeEngine()
    engine.register(scope)
    return engine


class _BareHandler(BaseHTTPRequestHandler):
    """A real HTTP/1.1 endpoint that sends no security headers at all."""

    def do_GET(self):
        body = b"<html><body>hello</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def local_site():
    """A loopback site on an ephemeral port (no fixtures, no external network)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BareHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
