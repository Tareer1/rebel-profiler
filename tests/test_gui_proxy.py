"""Tests for the GUI proxy (frontend/proxy.py): whitelist discipline,
gateway proxying, static GUI serving and the hermes SSE surface.

The proxy is stdlib-only and lives outside the package (frontend/), so it is
loaded here by file path — exactly how the operator runs it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY_PATH = os.path.join(REPO_ROOT, "frontend", "proxy.py")


@pytest.fixture(scope="module")
def proxy_module():
    spec = importlib.util.spec_from_file_location("rp_gui_proxy", PROXY_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestWhitelist:
    """The whitelist is the only write surface — it must fail closed."""

    def test_unknown_command_is_none(self, proxy_module):
        assert proxy_module.build_argv("rm -rf /", {}) is None
        assert proxy_module.build_argv("", {}) is None
        assert proxy_module.build_argv("case_list; touch /tmp/pwn", {}) is None

    def test_case_list_argv(self, proxy_module):
        argv = proxy_module.build_argv("case_list", {})
        assert argv == ["case", "list"]

    def test_output_mode_is_enforced_last(self, proxy_module):
        argv = proxy_module.build_argv("case_list", {})
        assert proxy_module.run_cli.__doc__  # sanity
        # run_cli appends -o json itself; build_argv never emits flags.
        assert all(not a.startswith("-") or a in {"--exclude"} for a in argv)

    def test_case_id_validation(self, proxy_module):
        assert proxy_module.build_argv("case_show", {"case": "abc123"}) == [
            "case", "show", "abc123"]
        # spaces, separators, empty → rejected
        assert proxy_module.build_argv("case_show", {"case": "a b"}) is None
        assert proxy_module.build_argv("case_show", {"case": "x/y"}) is None
        assert proxy_module.build_argv("case_show", {"case": ""}) is None
        assert proxy_module.build_argv("case_show", {"case": "x" * 65}) is None

    def test_target_token_validation(self, proxy_module):
        assert proxy_module.build_argv(
            "scope_add", {"case": "c1", "target": "*.lab.test"}) is not None
        assert proxy_module.build_argv(
            "scope_add", {"case": "c1", "target": "two words"}) is None
        assert proxy_module.build_argv(
            "scope_add", {"case": "c1", "target": ""}) is None

    def test_text_slots_are_positional(self, proxy_module):
        argv = proxy_module.build_argv(
            "case_create", {"text": "Alpha", "text2": "desc"})
        assert argv == ["case", "create", "Alpha", "desc"]
        # missing text slot → rejected, never an empty argv token
        assert proxy_module.build_argv("case_create", {"text": "Alpha"}) is None

    def test_dork_template_shapes_full_command(self, proxy_module):
        argv = proxy_module.build_argv("dork_search", {
            "case": "c1", "target": "example.test",
            "text": "google", "text2": "login-portals"})
        assert argv == ["intel", "collect", "c1", "dork-search", "example.test",
                        "-p", "engine", "google", "-p", "dork",
                        "login-portals", "-y"]

    def test_tor_template_pins_ahmia_and_onion(self, proxy_module):
        argv = proxy_module.build_argv("dork_search_tor", {
            "case": "c1", "target": "example", "text": "open-directories"})
        assert "ahmia" in argv and "onion" in argv

    def test_approval_decide_template_carries_the_decision(self, proxy_module):
        argv = proxy_module.build_argv("approval_decide", {
            "case": "c1", "target": "apr_5ed7154c09d7", "text": "approve"})
        assert argv == ["approval", "decide", "c1", "apr_5ed7154c09d7", "approve"]
        # a smuggled decision word is still one validated single token
        bad = proxy_module.build_argv("approval_decide", {
            "case": "c1", "target": "apr_x; rm -rf /", "text": "approve"})
        assert bad is None

    def test_approval_run_and_list_templates(self, proxy_module):
        assert proxy_module.build_argv(
            "approvals_list", {"case": "c1"}) == ["approval", "list", "c1"]
        assert proxy_module.build_argv(
            "approval_run", {"case": "c1", "target": "apr_x"}) == \
            ["approval", "run", "c1", "apr_x"]

    def test_audit_and_surface_read_templates(self, proxy_module):
        assert proxy_module.build_argv("audit_show", {"case": "c1"}) == \
            ["audit", "show", "c1"]
        assert proxy_module.build_argv("surface_show", {"case": "c1"}) == \
            ["surface", "show", "c1"]
        assert proxy_module.build_argv("surface_build", {"case": "c1"}) == \
            ["surface", "build", "c1"]
        assert proxy_module.build_argv("evidence_verify", {"case": "c1"}) == \
            ["evidence", "verify", "c1"]


@pytest.fixture()
def proxy_server(tmp_path, monkeypatch):
    """A live proxy bound to an ephemeral port, with a stub `rp` binary."""
    proxy_module = proxy_module_global
    # stub CLI: a tiny script that prints a JSON payload for any command
    stub = tmp_path / "fake-rp"
    stub.write_text(
        "#!/bin/sh\n"
        'printf \'{"data": {"stub": true, "argv_count": %d}}\\n\' "$#"\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    proxy_module.ProxyHandler.rp_binary = str(stub)
    proxy_module.ProxyHandler.api_port = 1  # gateway unreachable on purpose
    proxy_module.ProxyHandler.api_token = ""
    proxy_module.ProxyHandler.frontend_dir = os.path.join(REPO_ROOT, "frontend")

    server = ThreadingHTTPServer(("127.0.0.1", 0), proxy_module.ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


proxy_module_global = None  # set in the module fixture below


@pytest.fixture(scope="module", autouse=True)
def _bind_module(proxy_module):
    global proxy_module_global
    proxy_module_global = proxy_module


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def _post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


class TestProxyHTTP:
    def test_serves_the_gui_at_root(self, proxy_server):
        with urllib.request.urlopen(proxy_server + "/", timeout=5) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read().decode()
        assert status == 200
        assert "text/html" in ctype
        assert "REBEL PROFILER" in body

    def test_healthz_reports_backend_down(self, proxy_server):
        status, payload = _get(proxy_server + "/healthz")
        assert status == 200
        assert payload["ok"] is True
        assert payload["backend"]["reachable"] is False
        assert "serve" in payload["backend"]["detail"]["action"]

    def test_unknown_path_404(self, proxy_server):
        try:
            urllib.request.urlopen(proxy_server + "/nope", timeout=5)
            status = 200
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 404

    def test_cli_stub_roundtrip(self, proxy_server):
        status, payload = _post(proxy_server + "/api/cli", {"cmd": "case_list"})
        assert status == 200
        assert payload["result"]["data"]["stub"] is True

    def test_cli_rejects_unknown_command(self, proxy_server):
        status, payload = _post(proxy_server + "/api/cli", {"cmd": "shell"})
        assert status == 400
        assert "unknown command" in payload["error"]
        assert "whitelisted" in payload["action"]

    def test_cli_rejects_bad_params(self, proxy_server):
        status, payload = _post(
            proxy_server + "/api/cli",
            {"cmd": "case_show", "params": {"case": "bad id"}})
        assert status == 400

    def test_cli_enforces_json_output(self, proxy_server, tmp_path, monkeypatch):
        # the stub must be called with -o json appended after the template
        calls = []

        class FakeProc:
            returncode = 0
            stdout = '{"data": 1}'
            stderr = ""

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return FakeProc()

        monkeypatch.setattr("subprocess.run", fake_run)
        proxy_module = proxy_module_global
        code, data, stderr = proxy_module.run_cli(
            "rp", "case_list", {}, output_mode="human")
        assert code == 200
        assert calls[0][-2:] == ["-o", "json"]

    def test_hermes_stream_requires_goal(self, proxy_server):
        try:
            urllib.request.urlopen(proxy_server + "/api/hermes/stream", timeout=5)
            status = 200
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode()
        else:
            body = ""
        assert status == 400
        assert "goal" in body

    def test_hermes_stream_rejects_bad_case(self, proxy_server):
        url = proxy_server + "/api/hermes/stream?goal=x&case=bad%20id"
        try:
            urllib.request.urlopen(url, timeout=5)
            status = 200
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 400

    def test_hermes_stream_rejects_bad_tier(self, proxy_server):
        url = proxy_server + "/api/hermes/stream?goal=x&tier=ultra"
        try:
            urllib.request.urlopen(url, timeout=5)
            status = 200
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 400


class TestProxyHardening:
    """CSRF/origin discipline + baseline security headers."""

    def test_post_from_foreign_origin_is_refused(self, proxy_server):
        req = urllib.request.Request(
            proxy_server + "/api/cli",
            data=json.dumps({"cmd": "case_list"}).encode(),
            headers={"Content-Type": "application/json",
                     "Origin": "http://evil.example"},
            method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            status = 200
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode()
        else:
            body = ""
        assert status == 403
        assert "cross-origin" in body

    def test_post_with_same_origin_is_allowed(self, proxy_server):
        port = proxy_server.rsplit(":", 1)[1]
        req = urllib.request.Request(
            proxy_server + "/api/cli",
            data=json.dumps({"cmd": "case_list"}).encode(),
            headers={"Content-Type": "application/json",
                     "Origin": f"http://127.0.0.1:{port}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200

    def test_post_without_origin_is_allowed(self, proxy_server):
        status, payload = _post(proxy_server + "/api/cli", {"cmd": "case_list"})
        assert status == 200

    def test_security_headers_on_static_gui(self, proxy_server):
        with urllib.request.urlopen(proxy_server + "/", timeout=5) as resp:
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("X-Frame-Options") == "DENY"
            csp = resp.headers.get("Content-Security-Policy", "")
            assert "frame-ancestors 'none'" in csp
            assert resp.headers.get("Referrer-Policy") == "no-referrer"

    def test_security_headers_on_json_api(self, proxy_server):
        with urllib.request.urlopen(proxy_server + "/healthz", timeout=5) as resp:
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("X-Frame-Options") == "DENY"
