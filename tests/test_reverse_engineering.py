"""Tests: reverse-engineering plane — static, offline, analysis-only.

The RE adapters dissect a file the operator ALREADY possesses. Contracts
under test: no execution of the sample, no network, strict path
validation, honest parsers (unknown input → no claims), and knowledge
consistency (guides + coverage rows vs the live registry).
"""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution.broker import AdapterRegistry, ActionRequest
from rebel_profiler.execution.re import (
    BinaryInfoAdapter,
    ChecksecAdapter,
    DisasmAdapter,
    StringDumpAdapter,
    SymbolDumpAdapter,
)
from rebel_profiler.intel.collection import (
    _parse_binary_info,
    _parse_checksec,
    _parse_disasm,
    _parse_strings,
    _parse_symbols,
)


def make_request(action: str, target: str, **params) -> ActionRequest:
    return ActionRequest(case_id="c1", capability="binary_analysis",
                         action=action, target=target, params=params)


SAMPLE = "/srv/samples/app.bin"


class TestRegistryAndRisk:
    def test_re_actions_registered(self):
        names = set(AdapterRegistry().names())
        assert {"checksec", "binary-info", "string-dump",
                "symbol-dump", "disasm"} <= names

    def test_binary_analysis_is_low_risk(self):
        from rebel_profiler.security.risk import classify_risk

        assert classify_risk("binary_analysis").level == "low"

    def test_all_re_binaries_are_readers(self):
        """No interpreter/compiler ever enters the RE plane."""
        binaries = {a.binary for a in AdapterRegistry().list()
                    if a.capability_class == "binary_analysis"}
        assert binaries <= {"checksec", "readelf", "strings", "nm", "objdump"}


class TestPathValidation:
    @pytest.mark.parametrize("adapter_cls", [
        ChecksecAdapter, BinaryInfoAdapter, StringDumpAdapter,
        SymbolDumpAdapter, DisasmAdapter,
    ])
    def test_rejects_metacharacters(self, adapter_cls):
        with pytest.raises(UsageError):
            adapter_cls().build_argv(make_request(
                adapter_cls.name, "/srv/samples/app; rm -rf /"))

    @pytest.mark.parametrize("bad", ["/proc/self/exe", "/sys/firmware/abc",
                                     "/dev/sda"])
    def test_rejects_kernel_pseudo_fs(self, bad):
        with pytest.raises(UsageError):
            ChecksecAdapter().build_argv(make_request("checksec", bad))

    def test_relative_paths_are_fine(self):
        argv = ChecksecAdapter().build_argv(
            make_request("checksec", "samples/app.bin"))
        assert "--file=samples/app.bin" in argv


class TestArgvContracts:
    def test_checksec_argv(self):
        argv = ChecksecAdapter().build_argv(make_request("checksec", SAMPLE))
        assert argv == ["checksec", "--file=" + SAMPLE]

    def test_binary_info_argv(self):
        argv = BinaryInfoAdapter().build_argv(make_request("binary-info", SAMPLE))
        assert argv[0] == "readelf"
        assert "-h" in argv and "-d" in argv and SAMPLE in argv

    def test_string_dump_bounded_param(self):
        argv = StringDumpAdapter().build_argv(
            make_request("string-dump", SAMPLE, max_lines="400"))
        assert argv[0] == "strings" and "-n" in argv
        with pytest.raises(UsageError):
            StringDumpAdapter().build_argv(
                make_request("string-dump", SAMPLE, max_lines="99999"))

    def test_symbol_dump_defined_only(self):
        argv = SymbolDumpAdapter().build_argv(
            make_request("symbol-dump", SAMPLE, defined_only="1"))
        assert "--defined-only" in argv

    def test_disasm_section_whitelisted(self):
        argv = DisasmAdapter().build_argv(
            make_request("disasm", SAMPLE, section=".text"))
        assert "-j" in argv and ".text" in argv
        with pytest.raises(UsageError):
            DisasmAdapter().build_argv(
                make_request("disasm", SAMPLE, section=".text; reboot"))


class TestREParsers:
    def test_checksec_states(self):
        text = "CANARY\tenabled\nNX\tenabled\nPIE\tdisabled\nRELRO\tfull\n"
        pairs = _parse_checksec(text)
        values = {v for _, v in pairs}
        assert "canary=enabled" in values
        assert "pie=disabled" in values

    def test_checksec_garbage_yields_nothing(self):
        assert _parse_checksec("random noise\n\n") == []

    def test_binary_info_identity(self):
        text = ("Class:                              ELF64\n"
                "Machine:                           AMD X86-64\n"
                "Type:                              EXEC\n"
                "  NEEDED               Shared library: [libc.so.6]\n")
        pairs = _parse_binary_info(text)
        assert ("binary_class", "ELF64") in pairs
        assert ("binary_library", "libc.so.6") in pairs

    def test_strings_classify_and_cap(self):
        text = ("visit https://evil.example/payload now\n"
                "connect to 10.0.0.9:4444\n"
                "plain noise without artifacts\n")
        for _ in range(2000):
            text += "more noise line\n"
        pairs = _parse_strings(text, max_claims=50)
        kinds = {k for k, _ in pairs}
        assert "string_url" in kinds or "string_ip" in kinds
        assert len(pairs) <= 50
        assert all("plain noise" not in v for _, v in pairs)

    def test_symbols_only_interesting_imports(self):
        text = ("                 U socket\n"
                "                 U getchar\n"
                "0000000000401100 T main\n")
        pairs = _parse_symbols(text)
        values = [v for _, v in pairs]
        assert "socket" in values
        assert "getchar" not in values

    def test_disasm_summary_and_calls(self):
        text = ("  401133:\tcall   401050 <system@plt>\n"
                "  401138:\tpop    %rbp\n"
                "  401139:\tret\n")
        pairs = _parse_disasm(text)
        assert any(k == "disasm_call" and "system@plt" in v for k, v in pairs)
        assert any(k == "disasm_summary" for k, v in pairs)


class TestKnowledgeConsistency:
    def test_re_domain_present(self):
        from rebel_profiler.knowledge import find_domain

        d = find_domain("reverse_engineering")
        assert d is not None and d.number == 16
        assert len(d.topics) >= 5

    def test_coverage_matrix_has_re_rows(self):
        from rebel_profiler.intel.claims import ClaimLedger
        from rebel_profiler.intel.sources import SourceRegistry
        from rebel_profiler.intel.vulncov import coverage_for_case

        ledger = ClaimLedger(SourceRegistry())
        report = coverage_for_case(ledger, "c1")
        keys = {r["class"] for r in report["classes"]}
        assert {"binary_mitigation_gap", "sample_ioc"} <= keys
        assert report["no_adapter"] == 0

    def test_guide_coverage_complete(self):
        from rebel_profiler.knowledge.action_guides import coverage_report

        report = coverage_report()
        assert report["complete"] is True

    def test_hunter_playbook_binary_triage(self):
        from rebel_profiler.intel.playbooks import get_playbook

        pb = get_playbook("binary-triage", None)
        assert pb.name == "binary-triage"
        actions = [e["action"] for e in
                   __import__("rebel_profiler.intel.playbooks",
                              fromlist=["expand_playbook"]
                              ).expand_playbook(pb, SAMPLE)["entries"]]
        assert actions == ["binary-info", "checksec", "string-dump",
                           "symbol-dump", "disasm"]
