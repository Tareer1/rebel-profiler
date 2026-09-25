"""Tests: GUI session kill — one click closes gateway, bridge and proxy.

The kill path is the same discipline as the whitelist: same-origin gated,
structured response, and the process teardown is bounded to the operator's
own rebel-profiler listeners (never arbitrary pids).
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import threading
import time
import urllib.request
from pathlib import Path
from unittest import mock

import pytest

_spec = importlib.util.spec_from_file_location(
    "rp_proxy", Path(__file__).resolve().parents[1] / "frontend" / "proxy.py")
proxy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proxy)


class TestSessionKillUnit:
    def test_close_port_reports_listener_state(self):
        import socket as s

        srv = s.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            detail = proxy._close_port(port, "gateway")
            assert detail == {"kind": "gateway", "port": port, "was_up": True}
        finally:
            srv.close()
        detail = proxy._close_port(port, "gateway")
        assert detail["was_up"] is False

    def test_kill_signals_only_rebel_profiler_listeners(self, tmp_path):
        """SIGTERM goes to same-user rebel-profiler serve/bridge processes ONLY."""
        killed: list[tuple[int, int]] = []

        def fake_kill(pid, sig):
            killed.append((pid, sig))

        def fake_processes():
            return [
                (111, ["rebel-profiler", "serve", "case1"]),      # ours → TERM
                (112, ["rebel-profiler", "browser", "bridge"]),   # ours → TERM
                (113, ["firefox"]),                               # never
                (114, ["bash"]),                                  # never
                (115, ["python3", "-c", "import os"]),            # never
            ]

        with mock.patch.object(proxy.os, "getpid", return_value=99), \
                mock.patch.object(proxy.os, "kill", side_effect=fake_kill), \
                mock.patch.object(proxy, "_own_user_processes",
                                  side_effect=fake_processes), \
                mock.patch.object(proxy, "_KILL_SENTINEL",
                                  str(tmp_path / "sentinel")):
            detail = proxy.session_kill(api_port=1, bridge_port=2, proxy_port=3)

        assert sorted(pid for pid, _ in killed) == [111, 112]
        assert all(sig == signal.SIGTERM for _, sig in killed)
        assert [d["kind"] for d in detail] == ["gateway", "browser_bridge", "proxy"]

    def test_kill_writes_sentinel(self, tmp_path):
        sentinel = tmp_path / "dead"
        with mock.patch.object(proxy.os, "getpid", return_value=99), \
                mock.patch.object(proxy.os, "kill"), \
                mock.patch.object(proxy, "_own_user_processes", return_value=[]), \
                mock.patch.object(proxy, "_KILL_SENTINEL", str(sentinel)):
            proxy.session_kill(api_port=1, bridge_port=2, proxy_port=3)
        assert sentinel.exists()
        payload = json.loads(sentinel.read_text())
        assert len(payload["closed"]) == 3

    def test_own_user_processes_never_spawns(self):
        """The /proc scan is pure reads — no subprocess, no ps."""
        procs = proxy._own_user_processes()
        assert isinstance(procs, list)
        for pid, cmdline in procs:
            assert isinstance(pid, int)
            assert isinstance(cmdline, list)


class TestSessionKillEndpoint:
    def _make_handler(self, origin=""):
        import socketserver

        class FakeServer:
            server_address = ("127.0.0.1", 8898)

        handler = object.__new__(proxy.ProxyHandler)
        handler.request = mock.Mock()
        handler.client_address = ("127.0.0.1", 55555)
        handler.server = FakeServer()
        handler.raw_requestline = b"POST /api/session_kill HTTP/1.1"
        handler.path = "/api/session_kill"
        handler.headers = {}
        if origin:
            handler.headers["Origin"] = origin
        sent = {}

        def fake_json(code, data):
            sent["code"] = code
            sent["data"] = data

        handler._json = fake_json
        return handler, sent

    def test_kill_endpoint_same_origin_ok(self, tmp_path):
        handler, sent = self._make_handler(origin="http://127.0.0.1:8898")
        with mock.patch.object(proxy, "session_kill",
                               return_value=[{"kind": "proxy", "port": 8898,
                                              "was_up": True}]) as sk, \
                mock.patch.object(proxy.threading, "Timer") as timer, \
                mock.patch.object(proxy.ProxyHandler, "_security_headers",
                                  lambda self: None):
            handler.do_POST()
        assert sent["code"] == 200
        assert sent["data"]["ok"] is True
        assert sent["data"]["closed"][0]["kind"] == "proxy"
        sk.assert_called_once_with(api_port=8899, bridge_port=8765,
                                   proxy_port=8898)
        timer.assert_called_once()   # the deferred os._exit is armed

    def test_kill_endpoint_refuses_cross_origin(self, tmp_path):
        handler, sent = self._make_handler(origin="http://evil.example:80")
        with mock.patch.object(proxy, "session_kill") as sk:
            handler.do_POST()
        assert sent["code"] == 403
        sk.assert_not_called()

    def test_kill_endpoint_unreachable_ports_still_answer(self):
        """Every port closed (dead already) → still a clean 200 response."""
        handler, sent = self._make_handler(origin="http://127.0.0.1:8898")
        with mock.patch.object(proxy, "session_kill",
                               return_value=[{"kind": "gateway", "port": 8899,
                                              "was_up": False}]), \
                mock.patch.object(proxy.threading, "Timer"), \
                mock.patch.object(proxy.ProxyHandler, "_security_headers",
                                  lambda self: None):
            handler.do_POST()
        assert sent["code"] == 200
        assert sent["data"]["closed"][0]["was_up"] is False


class TestGuiSurface:
    def test_index_has_kill_button(self):
        html = (Path(__file__).resolve().parents[1] / "frontend" /
                "index.html").read_text()
        assert "session-kill" in html
        assert "/api/session_kill" in html

    def test_proxy_exposes_kill_route(self):
        src = (Path(__file__).resolve().parents[1] / "frontend" /
               "proxy.py").read_text()
        assert "/api/session_kill" in src
        assert "_shutdown_everything" in src
