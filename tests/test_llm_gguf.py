"""Tests for the GGUF engine, setup planning and LLM script authoring."""

from __future__ import annotations

import json
import sys
import types

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.core.errors import DependencyUnavailableError, UsageError
from rebel_profiler.llm.budget import DEFAULT_LIMITS, Limits, ModelBudgetError
from rebel_profiler.llm.gguf import (
    GgufEngine,
    discover_local_gguf,
    gguf_params_b,
    parse_quant,
    resolve_local_gguf,
    strip_quant,
)
from rebel_profiler.llm.inference import ModelPlane


# ---------------------------------------------------------------- quant parsing

class TestQuantParsing:
    @pytest.mark.parametrize("name,expect", [
        ("m-8B-Q4_K_S.gguf", ("Q4_K_S", 4, True)),
        ("m-Q5_K_M.gguf", ("Q5_K_M", 5, True)),
        ("m.Q8_0.gguf", ("Q8_0", 8, True)),
        ("m-IQ3_XS.gguf", ("IQ3_XS", 3, True)),
        ("m-Q2_K.gguf", ("Q2_K", 2, True)),
        ("m-f16.gguf", ("F16", 16, False)),
        ("m-F32.gguf", ("F32", 32, False)),
        ("model.gguf", ("unknown", 16, False)),
    ])
    def test_quant_tag(self, name, expect):
        assert parse_quant(name) == expect

    def test_unknown_quant_is_conservative(self):
        # no tag => report f16-class uncompressed so a compression-demanding
        # tier refuses instead of under-reporting memory
        tag, bits, compressed = parse_quant("plain.gguf")
        assert compressed is False and bits >= 16

    def test_strip_quant(self):
        assert strip_quant("Dolphin3.0-Llama3.1-8B-Q4_K_S") == "Dolphin3.0-Llama3.1-8B"
        assert strip_quant("qwen2.5-7b-instruct") == "qwen2.5-7b-instruct"

    def test_params_from_name(self, tmp_path):
        p = tmp_path / "Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf"
        p.write_bytes(b"\0" * 1024)
        assert gguf_params_b(p) == 70.0

    def test_params_size_fallback(self, tmp_path):
        # no size in the name -> estimate from bytes and quant bits
        p = tmp_path / "mystery-model-Q4_K_M.gguf"
        p.write_bytes(b"\0" * (4 * 1024 ** 3 // 4))    # ~1GB names no param count
        assert gguf_params_b(p) == pytest.approx(2.0, abs=0.3)


# ---------------------------------------------------------------- discovery

class TestDiscovery:
    def _make(self, root, name, size=1024):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\0" * size)
        return path

    def test_discover_and_resolve_by_path(self, tmp_path):
        gguf = self._make(tmp_path / "models", "Tiny-3B-Q4_K_M.gguf")
        assert resolve_local_gguf(gguf) == gguf
        rows = discover_local_gguf(roots=[tmp_path / "models"])
        assert [r["name"] for r in rows] == ["Tiny-3B-Q4_K_M.gguf"]
        assert rows[0]["quant"] == "Q4_K_M" and rows[0]["compressed"] is True
        assert rows[0]["params_b"] == 3.0

    def test_resolve_directory(self, tmp_path):
        gguf = self._make(tmp_path / "lib", "A-7B-Q8_0.gguf")
        assert resolve_local_gguf(tmp_path / "lib") == gguf

    def test_resolve_by_model_name(self, tmp_path):
        self._make(tmp_path / "lib", "Dolphin3.0-Llama3.1-8B-Q4_K_S.gguf")
        found = resolve_local_gguf("dphn/Dolphin3.0-Llama3.1-8B-GGUF",
                                   roots=[tmp_path / "lib"])
        assert found is not None and found.name.startswith("Dolphin3.0")

    def test_unrelated_name_does_not_match(self, tmp_path):
        self._make(tmp_path / "lib", "Dolphin3.0-Llama3.1-8B-Q4_K_S.gguf")
        # a different model request must NOT silently grab the local file
        assert resolve_local_gguf("Qwen/Qwen3-4B", roots=[tmp_path / "lib"]) is None

    def test_empty_root_is_safe(self, tmp_path):
        assert discover_local_gguf(roots=[tmp_path / "nope"]) == []

    def test_missing_path_returns_none(self):
        assert resolve_local_gguf("/nope/does-not-exist.gguf") is None

    def test_configured_gguf_dirs_are_searched(self, monkeypatch, tmp_path):
        """`[llm] gguf_dirs` makes a model library durable, not cwd-bound.

        Regression: discovery only ever looked at RP_LLM__GGUF_DIRS and the
        current directory, so a checkpoint registered in the user config was
        invisible to every command run from elsewhere.
        """
        from rebel_profiler.core import config as config_mod

        self._make(tmp_path, "Configured-3B-Q4_K_M.gguf")
        monkeypatch.setattr(
            config_mod, "load_config",
            lambda **kw: {"llm": {"gguf_dirs": [str(tmp_path)]}})
        names = {r["name"] for r in discover_local_gguf()}
        assert "Configured-3B-Q4_K_M.gguf" in names

    def test_configured_gguf_dirs_accept_pathsep_string(self, monkeypatch, tmp_path):
        from rebel_profiler.core import config as config_mod

        self._make(tmp_path, "Configured-3B-Q4_K_M.gguf")
        monkeypatch.setattr(
            config_mod, "load_config",
            lambda **kw: {"llm": {"gguf_dirs": str(tmp_path)}})
        names = {r["name"] for r in discover_local_gguf()}
        assert "Configured-3B-Q4_K_M.gguf" in names

    def test_broken_config_never_breaks_discovery(self, monkeypatch, tmp_path):
        from rebel_profiler.core import config as config_mod

        self._make(tmp_path, "Safe-3B-Q4_K_M.gguf")

        def _explode(**kw):
            raise RuntimeError("unreadable config")

        monkeypatch.setattr(config_mod, "load_config", _explode)
        monkeypatch.setenv("RP_LLM__GGUF_DIRS", str(tmp_path))
        # an unreadable config contributes no roots; the env pin still applies
        names = {r["name"] for r in discover_local_gguf()}
        assert "Safe-3B-Q4_K_M.gguf" in names


# ---------------------------------------------------------------- engine

class _FakeLlama:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def tokenize(self, data, add_bos=False):
        return list(range(min(12, max(1, len(data) // 4))))

    def detokenize(self, ids):
        return b"fitted prompt"

    def create_completion(self, prompt, **kwargs):
        self.last_prompt = prompt
        self.last_kwargs = kwargs
        return {"choices": [{"text": "SCRIPT-OUTPUT"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2}}


@pytest.fixture()
def fake_llama(monkeypatch):
    module = types.ModuleType("llama_cpp")
    module.Llama = _FakeLlama
    inner = types.SimpleNamespace(llama_supports_gpu_offload=lambda: False)
    module.llama_cpp = inner
    monkeypatch.setitem(sys.modules, "llama_cpp", module)
    return module


@pytest.fixture()
def model_file(tmp_path):
    path = tmp_path / "lib" / "Test-8B-Q4_K_M.gguf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\0" * 2048)
    return path


class TestGgufEngine:
    def test_missing_binding_is_structured_error(self, monkeypatch, model_file):
        monkeypatch.setitem(sys.modules, "llama_cpp", None)
        with pytest.raises(DependencyUnavailableError) as excinfo:
            GgufEngine(str(model_file), limits=DEFAULT_LIMITS["mid"])
        assert "llm setup" in excinfo.value.action

    def test_unknown_model_is_structured_error(self, fake_llama):
        with pytest.raises(DependencyUnavailableError) as excinfo:
            GgufEngine("/nope/absent.gguf", limits=DEFAULT_LIMITS["mid"])
        assert "RP_LLM__GGUF_DIRS" in excinfo.value.action

    def test_generate_end_to_end(self, fake_llama, model_file):
        engine = GgufEngine(str(model_file), limits=DEFAULT_LIMITS["mid"])
        assert engine.compressed is True
        assert engine.params_b == 8.0
        engine.load()
        result = engine.generate("hello", max_new_tokens=4)
        assert result.engine == "gguf"
        assert result.text == "SCRIPT-OUTPUT"
        assert result.compressed is True
        assert result.device == "cpu"
        assert engine.profiling_summary()["steps"] == 1
        engine.unload()
        assert engine.loaded is False

    def test_cpu_placement_when_gpu_disallowed(self, fake_llama, model_file):
        limits = Limits(max_rss_mb=8192, max_context_tokens=2048,
                        max_new_tokens=128, max_model_b=70.0,
                        allow_gpu=False, require_compression=False, tier="mid")
        engine = GgufEngine(str(model_file), limits=limits)
        engine.load()
        assert "n_gpu_layers" not in engine._llm.kwargs
        engine.unload()

    def test_oversize_refused_on_tiny_tier(self, fake_llama, model_file):
        with pytest.raises(ModelBudgetError) as excinfo:
            GgufEngine(str(model_file), limits=DEFAULT_LIMITS["tiny"])
        assert "exceeds tier cap" in excinfo.value.message

    def test_generation_request_is_clamped_to_tier_cap(self, fake_llama, model_file):
        limits = Limits(max_rss_mb=8192, max_context_tokens=1024,
                        max_new_tokens=8, max_model_b=70.0,
                        allow_gpu=False, require_compression=False, tier="mid")
        engine = GgufEngine(str(model_file), limits=limits)
        engine.load()
        engine.generate("x", max_new_tokens=99)
        assert engine._llm.last_kwargs["max_tokens"] == 8
        engine.unload()

    def test_dolphin_uses_chatml(self, fake_llama, tmp_path):
        path = tmp_path / "Dolphin3.0-Llama3.1-8B-Q4_K_S.gguf"
        path.write_bytes(b"\0" * 1024)
        engine = GgufEngine(str(path), limits=DEFAULT_LIMITS["mid"])
        prompt = engine.chat_prompt("be brief", "hi")
        assert "<|im_start|>system" in prompt and "<|im_start|>assistant" in prompt

    def test_llama_name_uses_header_template(self, fake_llama, tmp_path):
        path = tmp_path / "Llama-3.1-8B-Instruct-Q4_K_M.gguf"
        path.write_bytes(b"\0" * 1024)
        engine = GgufEngine(str(path), limits=DEFAULT_LIMITS["mid"])
        assert "<|start_header_id|>" in engine.chat_prompt("s", "u")

    def test_info_reports_format(self, fake_llama, model_file):
        engine = GgufEngine(str(model_file), limits=DEFAULT_LIMITS["mid"])
        info = engine.info()
        assert info["quant"] == "Q4_K_M" and info["engine"] == "gguf"

    def test_refusal_after_load_releases_the_weights(self, monkeypatch, fake_llama,
                                                     model_file):
        """A budget refusal must not leave the checkpoint resident.

        Regression: the guard checks RSS *after* llama.cpp mapped the file,
        so the refusal raised while ~4GB of weights stayed loaded and the
        plane fell back to another engine holding them.
        """
        from rebel_profiler.llm.budget import BudgetGuard

        calls = {"n": 0}

        def flaky_check_rss(self):
            calls["n"] += 1
            if calls["n"] >= 2:      # 1st = start-of-load, 2nd = post-load
                raise ModelBudgetError(
                    "LLM plane RSS 8889MB exceeds ceiling 8192MB")

        monkeypatch.setattr(BudgetGuard, "check_rss", flaky_check_rss)
        engine = GgufEngine(str(model_file), limits=DEFAULT_LIMITS["mid"])
        with pytest.raises(ModelBudgetError) as excinfo:
            engine.load()
        # the honest budget message survives (not wrapped as a dep error)
        assert "exceeds ceiling" in excinfo.value.message
        assert engine.loaded is False       # the mapped weights were released


class TestPlaneSelection:
    def test_explicit_gguf_pin_raises_without_binding(self, monkeypatch, model_file):
        monkeypatch.setitem(sys.modules, "llama_cpp", None)
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="gguf")
        # an explicit pin never silently degrades to another engine
        with pytest.raises(DependencyUnavailableError):
            plane.select_engine(str(model_file))

    def test_explicit_gguf_pin_selects_engine(self, fake_llama, model_file):
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="gguf")
        engine = plane.select_engine(str(model_file))
        assert plane.engine_kind == "gguf"
        assert engine.model_id.endswith("Test-8B-Q4_K_M.gguf")
        plane.unload()

    def test_unrelated_model_still_falls_back_to_tiny(self, monkeypatch, model_file):
        # a local gguf must never hijack an explicit request for another model
        monkeypatch.setitem(sys.modules, "llama_cpp", None)
        # also stub airllm when installed: without the stub select_engine
        # would start a REAL model download for the Qwen repo id here
        try:
            import airllm  # noqa: F401
        except ImportError:
            pass
        else:
            import types

            fake = types.ModuleType("airllm")

            class _FakeAutoModel:
                @staticmethod
                def from_pretrained(*_a, **_kw):
                    raise RuntimeError("stubbed: no downloads in tests")

            fake.AutoModel = _FakeAutoModel
            monkeypatch.setitem(sys.modules, "airllm", fake)
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        plane.select_engine("Qwen/Qwen3-4B")
        assert plane.engine_kind == "tiny"
        plane.unload()

    def test_failure_detail_keeps_the_taxonomy_reason(self):
        """str(RPError) is only the message; the reason is the diagnosis."""
        from rebel_profiler.llm.inference import _failure_detail

        exc = DependencyUnavailableError(
            "llama.cpp could not load 'x.gguf'",
            reason="ValueError: model is corrupted or incomplete")
        note = _failure_detail(exc)
        assert "could not load 'x.gguf'" in note
        assert "model is corrupted or incomplete" in note

    def test_failure_detail_never_repeats_itself(self):
        from rebel_profiler.llm.inference import _failure_detail

        exc = DependencyUnavailableError(
            "boom", reason="boom")
        assert _failure_detail(exc) == "boom"

    def test_fallback_note_reports_why_the_gguf_failed(self, monkeypatch, tmp_path):
        """A corrupt checkpoint's real error must reach the operator.

        Regression: the fallback note said only "llama.cpp could not load",
        so a truncated download ("model is corrupted or incomplete") looked
        like an unexplained engine failure.
        """
        path = tmp_path / "Corrupt-8B-Q4_K_M.gguf"
        path.write_bytes(b"\0" * 2048)
        monkeypatch.setenv("RP_LLM__GGUF_DIRS", str(tmp_path))

        def _ragged_init(self, **kwargs):
            raise ValueError(
                "tensor 'blk.14.ffn_up.weight' data is not within the file "
                "bounds, model is corrupted or incomplete")

        module = types.ModuleType("llama_cpp")
        module.Llama = type("Llama", (), {"__init__": _ragged_init})
        module.llama_cpp = types.SimpleNamespace(
            llama_supports_gpu_offload=lambda: False)
        monkeypatch.setitem(sys.modules, "llama_cpp", module)
        # stub airllm too: without the stub an installed airllm would start a
        # real (network) load of the path
        fake = types.ModuleType("airllm")

        class _FakeAutoModel:
            @staticmethod
            def from_pretrained(*_a, **_kw):
                raise RuntimeError("stubbed: no downloads in tests")

        fake.AutoModel = _FakeAutoModel
        monkeypatch.setitem(sys.modules, "airllm", fake)

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        plane.select_engine(str(path))
        assert plane.engine_kind == "tiny"
        assert "corrupted or incomplete" in plane.fallback_reason
        plane.unload()

    def test_empty_pin_auto_selects_fitting_local_gguf(self, fake_llama,
                                                      monkeypatch, tmp_path):
        """Empty pin + a fitting local GGUF + no other engine = that GGUF.

        Regression: `rebel-profiler hermes` with no model pin and no airllm
        fell back to tiny while a perfectly good local checkpoint sat on
        disk — the plane volunteered nothing local before reaching for the
        network.
        """
        _isolate_gguf_roots(monkeypatch, tmp_path)
        (tmp_path / "Local-7B-Instruct-Q4_K_M.gguf").write_bytes(b"\0" * 2048)
        plane = ModelPlane(limits=DEFAULT_LIMITS["high"])
        engine = plane.select_engine("")
        assert plane.engine_kind == "gguf"
        assert engine.model_id.endswith("Local-7B-Instruct-Q4_K_M.gguf")
        assert plane.fallback_reason == ""
        plane.unload()

    def test_empty_pin_names_the_unfitting_checkpoint_in_reason(self,
                                                               fake_llama,
                                                               monkeypatch,
                                                               tmp_path):
        """A checkpoint that does NOT fit is named in the fallback reason.

        Regression: on the reporting box a 7B Q4 (~8.9GB peak RSS) was told
        "airllm unavailable" while the real blocker was the tier's 8192MB
        ceiling. The reason must carry the size class and the tier escape.
        """
        _with_fat_gguf(tmp_path, monkeypatch, "Local-7B-Instruct-Q4_K_M.gguf")
        _stub_airllm(monkeypatch)
        _isolate_gguf_roots(monkeypatch, tmp_path)
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        engine = plane.select_engine("")
        assert plane.engine_kind == "tiny"
        assert "Local-7B-Instruct-Q4_K_M.gguf" in plane.fallback_reason
        assert "RP_LLM__TIER" in plane.fallback_reason
        plane.unload()

    def test_empty_pin_never_grabs_a_checkpoint_that_does_not_fit(self,
                                                                 fake_llama,
                                                                 monkeypatch,
                                                                 tmp_path):
        """Discovery is fit-gated: a too-big GGUF is never volunteered."""
        _isolate_gguf_roots(monkeypatch, tmp_path)
        (tmp_path / "Huge-70B-Q4_K_M.gguf").write_bytes(b"\0" * 2048)
        _stub_airllm(monkeypatch)
        plane = ModelPlane(limits=DEFAULT_LIMITS["tiny"])
        engine = plane.select_engine("")
        assert plane.engine_kind == "tiny"
        # not selected — and honestly named as the reason nothing local ran
        assert "Huge-70B" in plane.fallback_reason
        assert "does not fit tier 'tiny'" in plane.fallback_reason
        plane.unload()

    def test_explicit_pin_still_beats_auto_discovery(self, fake_llama,
                                                     monkeypatch, tmp_path):
        """An explicit --model pin is never swapped for another local file."""
        _isolate_gguf_roots(monkeypatch, tmp_path)
        (tmp_path / "Auto-8B-Q4_K_M.gguf").write_bytes(b"\0" * 2048)
        wanted = tmp_path / "Wanted-3B-Q4_K_M.gguf"
        wanted.write_bytes(b"\0" * 2048)
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        engine = plane.select_engine(str(wanted))
        assert plane.engine_kind == "gguf"
        assert engine.model_id.endswith("Wanted-3B-Q4_K_M.gguf")
        plane.unload()

    def test_empty_pin_tiny_prefer_never_scans_disk(self, monkeypatch,
                                                    tmp_path):
        """prefer_engine='tiny' keeps its old semantics: no discovery."""
        from rebel_profiler.llm import inference as inference_mod

        def _boom(*_a, **_kw):
            raise AssertionError("discovery must not run for prefer=tiny")

        monkeypatch.setattr(inference_mod.ModelPlane, "_best_local_model",
                            _boom)
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="tiny")
        engine = plane.select_engine("")
        assert plane.engine_kind == "tiny"
        plane.unload()

    def test_failed_load_releases_that_engine(self):
        """One engine at a time is the law, failed attempts included."""

        class _Engine:
            loaded = False
            unloads = 0

            def load(self):
                self.loaded = True       # holds weights, then refuses
                raise ModelBudgetError("ceiling reached")

            def unload(self):
                self.loaded = False
                self.unloads += 1

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        engine = _Engine()
        with pytest.raises(ModelBudgetError):
            plane._load_or_release(engine)
        assert engine.loaded is False and engine.unloads == 1

    def test_successful_load_is_returned_untouched(self):
        class _Engine:
            loaded = False
            unloads = 0

            def load(self):
                self.loaded = True

            def unload(self):
                self.unloads += 1

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        engine = _Engine()
        assert plane._load_or_release(engine) is engine
        assert engine.loaded is True and engine.unloads == 0


# ---------------------------------------------------------------- setup

class TestGgufFits:
    """The public fit verdict used by the engine selector and `llm models`."""

    def test_alias_matches_public_name(self):
        from rebel_profiler.llm import setup as setup_mod

        assert setup_mod.gguf_fits is setup_mod._gguf_fits

    def test_fits_by_size_compression_and_ram(self, tmp_path):
        from rebel_profiler.llm.setup import gguf_fits

        p = tmp_path / "Tiny-1B-Q4_K_M.gguf"
        p.write_bytes(b"\0" * 2048)
        row = {
            "path": str(p), "params_b": 1.0, "size_gb": 0.5,
            "compressed": True, "integrity_ok": None,
        }
        assert gguf_fits(row, DEFAULT_LIMITS["tiny"]) is True

    def test_integrity_failure_excludes_even_when_size_fits(self, tmp_path):
        from rebel_profiler.llm.setup import gguf_fits

        p = tmp_path / "Broken-1B-Q4_K_M.gguf"
        p.write_bytes(b"\0" * 2048)
        row = {
            "path": str(p), "params_b": 1.0, "size_gb": 0.5,
            "compressed": True, "integrity_ok": False,
        }
        assert gguf_fits(row, DEFAULT_LIMITS["tiny"]) is False


class TestSetup:
    def test_plan_lists_every_engine_with_install(self):
        from rebel_profiler.llm.setup import setup_plan

        plan = setup_plan(limits=DEFAULT_LIMITS["mid"])
        engines = {e["engine"] for e in plan["engines"]}
        assert engines == {"tiny", "gguf", "native", "airllm", "external"}
        gguf = next(e for e in plan["engines"] if e["engine"] == "gguf")
        assert "llama-cpp-python" in gguf["install"]
        assert "abetlen.github.io" in gguf["install"]

    def test_tiny_always_ready(self):
        from rebel_profiler.llm.setup import setup_plan

        plan = setup_plan(limits=DEFAULT_LIMITS["mid"])
        tiny = next(e for e in plan["engines"] if e["engine"] == "tiny")
        assert tiny["installed"] is True

    def test_local_models_reports_fit(self, tmp_path):
        from rebel_profiler.llm.setup import local_models

        big = tmp_path / "Big-70B-Q4_K_M.gguf"
        big.write_bytes(b"\0" * 1024)
        small = tmp_path / "Small-2B-Q4_K_M.gguf"
        small.write_bytes(b"\0" * 1024)
        payload = local_models(limits=DEFAULT_LIMITS["tiny"], roots=[tmp_path])
        rows = {r["name"]: r["fits"] for r in payload["gguf"]}
        assert rows["Small-2B-Q4_K_M.gguf"] is True
        assert rows["Big-70B-Q4_K_M.gguf"] is False
        assert "--model" in payload["gguf"][0]["run"]

    def test_fit_verdict_accounts_for_resident_ram(self, tmp_path, monkeypatch):
        """The fit verdict must include peak RSS, not just the size class.

        Regression: an 8B Q4 file (4.4GB on disk) was announced as fitting the
        mid tier, then refused at load when its real RSS (~2× file size)
        crossed that tier's ceiling. A model whose *load* would exceed the
        plane's memory must not be called fitting.
        """
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.setup import (
            gguf_rss_need_mb,
            local_models,
        )

        assert gguf_rss_need_mb(5.5) == 5.5 * 1024 * 2
        mid, high = _with_fat_gguf(tmp_path, monkeypatch, "Midsized-8B-Q4_K_S.gguf")

        row = next(r for r in mid["gguf"] if r["name"] == "Midsized-8B-Q4_K_S.gguf")
        # 5.5GB file → ~11GB peak RSS > the mid tier's 8GB ceiling: must NOT fit
        assert row["size_gb"] == 5.5
        assert row["fits"] is False
        assert row["needs_tier"] == "high"      # 16GB ceiling carries it

        row_high = next(
            r for r in high["gguf"] if r["name"] == "Midsized-8B-Q4_K_S.gguf")
        assert row_high["fits"] is True

    def test_render_local_names_the_tier_that_fits(self, tmp_path, monkeypatch):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.setup import local_models, render_local

        mid, _high = _with_fat_gguf(tmp_path, monkeypatch, "Midsized-8B-Q4_K_S.gguf")
        text = render_local(mid)
        assert "needs tier 'high'" in text

    def test_render_setup_mentions_hardware(self):
        from rebel_profiler.llm.setup import render_setup, setup_plan

        text = render_setup(setup_plan(limits=DEFAULT_LIMITS["mid"]))
        assert "LLM plane setup" in text and "Engines:" in text

    def test_run_command_pins_the_tier_that_actually_runs(self, tmp_path, monkeypatch):
        """A hint the tool's own guard refuses is worse than no hint.

        Regression: `llm local` printed a run command with no --tier for a
        checkpoint that does not fit the current tier, so the copy-pasted
        command was refused by the very guard that printed it.
        """
        from rebel_profiler.llm.setup import local_models

        mid, high = _with_fat_gguf(tmp_path, monkeypatch, "Midsized-8B-Q4_K_S.gguf")
        row = next(r for r in mid["gguf"] if r["name"] == "Midsized-8B-Q4_K_S.gguf")
        assert row["fits"] is False
        assert row["run"].endswith("--tier high")
        # at a tier that carries it there is nothing to pin
        row_high = next(
            r for r in high["gguf"] if r["name"] == "Midsized-8B-Q4_K_S.gguf")
        assert row_high["fits"] is True
        assert "--tier" not in row_high["run"]

    def test_setup_next_step_is_a_command_that_runs(self, tmp_path, monkeypatch):
        from rebel_profiler.llm.setup import setup_plan
        from rebel_profiler.llm import gguf as gguf_mod

        # hermetic: only the fat checkpoint exists, wherever this runs from
        monkeypatch.setattr(gguf_mod, "default_gguf_roots", lambda: [tmp_path])
        _with_fat_gguf(tmp_path, monkeypatch, "Midsized-8B-Q4_K_S.gguf")
        plan = setup_plan(limits=DEFAULT_LIMITS["mid"])
        step = next(s for s in plan["next_steps"] if "local checkpoint" in s)
        assert "--tier high" in step
        assert "Midsized-8B-Q4_K_S.gguf" in step


# ---------------------------------------------------------------- integrity


def _make_gguf(path, tensors, *, truncate: int = 0):
    """Write a minimal but genuinely *valid* GGUF.

    ``tensors`` is a list of ``(name, dims, ggml_type, data_bytes)``. The
    header layout (magic, version, counts, tensor infos, 32-byte-aligned data
    section) is what the integrity reader walks, so the fixture has to be real
    rather than a stand-in blob of zeroes.
    """
    import struct as _s

    def _string(text):
        raw = text.encode()
        return _s.pack("<Q", len(raw)) + raw

    infos, blob, offset = b"", b"", 0
    for name, dims, ttype, nbytes in tensors:
        infos += _string(name) + _s.pack("<I", len(dims))
        infos += _s.pack(f"<{len(dims)}Q", *dims)
        infos += _s.pack("<IQ", ttype, offset)
        blob += b"\0" * nbytes
        offset += nbytes
    body = (b"GGUF" + _s.pack("<I", 3)               # magic + version
            + _s.pack("<Q", len(tensors)) + _s.pack("<Q", 0)   # counts
            + infos)
    raw = body + b"\0" * ((-len(body)) % 32) + blob     # aligned data start
    path.write_bytes(raw[:-truncate] if truncate else raw)
    return path


class TestGgufIntegrity:
    def test_valid_checkpoint_is_verified(self, tmp_path):
        from rebel_profiler.llm.gguf import gguf_integrity

        path = _make_gguf(tmp_path / "Good-2B-Q8_0.gguf",
                          [("blk.0.weight", (32,), 8, 34)])
        assert gguf_integrity(path) == {"ok": True, "tensors": 1}

    def test_truncated_checkpoint_is_refused(self, tmp_path):
        """A truncated download keeps a valid header and loses the tail.

        Regression: such a file was listed as fitting and only failed at load,
        with the reason printed by the C library where Python never sees it.
        """
        from rebel_profiler.llm.gguf import gguf_integrity

        path = _make_gguf(tmp_path / "Cut-2B-Q8_0.gguf",
                          [("blk.0.weight", (32,), 8, 34)], truncate=8)
        verdict = gguf_integrity(path)
        assert verdict["ok"] is False
        assert "truncated" in verdict["reason"]

    def test_unknown_format_is_unverified_not_broken(self, tmp_path):
        """A wrong accusation is worse than no verdict."""
        from rebel_profiler.llm.gguf import gguf_integrity

        path = tmp_path / "opaque.gguf"
        path.write_bytes(b"nope" * 8)
        assert gguf_integrity(path)["ok"] is None

    def test_empty_file_is_refused(self, tmp_path):
        from rebel_profiler.llm.gguf import gguf_integrity

        path = tmp_path / "empty.gguf"
        path.write_bytes(b"")
        assert gguf_integrity(path)["ok"] is False

    def test_truncated_checkpoint_never_reads_as_fitting(self, tmp_path):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.setup import local_models, render_local

        _make_gguf(tmp_path / "Cut-2B-Q8_0.gguf",
                   [("blk.0.weight", (32,), 8, 34)], truncate=8)
        # even the widest tier cannot run a file that lost its own weights
        payload = local_models(limits=DEFAULT_LIMITS["high"], roots=[tmp_path])
        row = payload["gguf"][0]
        assert row["integrity_ok"] is False
        assert row["fits"] is False
        text = render_local(payload)
        assert "UNUSABLE" in text and "truncated" in text
        assert "re-download" in text

    def test_unverified_checkpoint_is_not_punished(self, tmp_path):
        # a file this reader cannot parse keeps its budget verdict untouched
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.setup import local_models

        (tmp_path / "Opaque-2B-Q4_K_M.gguf").write_bytes(b"\0" * 2048)
        row = local_models(
            limits=DEFAULT_LIMITS["high"], roots=[tmp_path])["gguf"][0]
        assert row["integrity_ok"] is None
        assert row["fits"] is True


# ---------------------------------------------------------------- helpers

def _stub_airllm(monkeypatch):
    """Neutralize an installed airllm: selection must never reach network."""
    fake = types.ModuleType("airllm")

    class _FakeAutoModel:
        @staticmethod
        def from_pretrained(*_a, **_kw):
            raise RuntimeError("stubbed: no downloads in tests")

    fake.AutoModel = _FakeAutoModel
    monkeypatch.setitem(sys.modules, "airllm", fake)


def _isolate_gguf_roots(monkeypatch, tmp_path):
    """Discovery sees ONLY tmp_path.

    A real repo-local model (``dphn/*.gguf`` on a developer box) must never
    leak into engine-selection tests: on a big tier it genuinely fits and
    would win auto-selection over the test fixture.
    """
    from rebel_profiler.llm import gguf as gguf_mod

    real = gguf_mod.discover_local_gguf
    monkeypatch.setattr(gguf_mod, "discover_local_gguf",
                        lambda **kw: real(roots=[tmp_path]))


def _with_fat_gguf(tmp_path, monkeypatch, name):
    """Discover a checkpoint that *reports* 5.5GB without writing 5.5GB.

    Multi-GB test artifacts would fill tmpfs; the size comes from stat(), so
    that is what gets patched (st_size sits at positional index 6 in
    ``os.stat_result``). Returns ``(payload_at_mid, payload_at_high)``.
    """
    import os as _os

    path = tmp_path / name
    path.write_bytes(b"\0" * 2048)
    real_stat = type(path).stat
    fat = int(5.5 * 1024 ** 3)

    def _patched_stat(path_self, *, follow_symlinks=True):
        st = real_stat(path_self, follow_symlinks=follow_symlinks)
        if str(path_self).endswith(".gguf") and st.st_size < 1_000_000:
            fields = list(st)
            fields[6] = fat
            return _os.stat_result(tuple(fields))
        return st

    monkeypatch.setattr(type(path), "stat", _patched_stat)

    from rebel_profiler.llm.budget import DEFAULT_LIMITS
    from rebel_profiler.llm.setup import local_models

    return (local_models(limits=DEFAULT_LIMITS["mid"], roots=[tmp_path]),
            local_models(limits=DEFAULT_LIMITS["high"], roots=[tmp_path]))


# ---------------------------------------------------------------- CLI

@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


class TestLlmCli:
    def test_setup_command(self, workspace, capsys):
        assert main([*workspace, "llm", "setup", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["recommended_engine"] in {"tiny", "gguf", "native", "airllm"}
        assert payload["limits"]["max_new_tokens"] > 0

    def test_local_command(self, workspace, capsys, monkeypatch, tmp_path):
        monkeypatch.setenv("RP_LLM__GGUF_DIRS", str(tmp_path))
        (tmp_path / "Local-3B-Q4_K_M.gguf").write_bytes(b"\0" * 512)
        assert main([*workspace, "llm", "local", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        names = [r["name"] for r in payload["gguf"]]
        assert "Local-3B-Q4_K_M.gguf" in names

    def test_models_command_includes_local_gguf(self, workspace, capsys,
                                                monkeypatch, tmp_path):
        monkeypatch.setenv("RP_LLM__GGUF_DIRS", str(tmp_path))
        (tmp_path / "Local-3B-Q4_K_M.gguf").write_bytes(b"\0" * 512)
        assert main([*workspace, "llm", "models", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        quants = {r["quant"] for r in payload["local_gguf"]}
        assert "Q4_K_M" in quants

    def test_status_reports_engine_availability(self, workspace, capsys):
        assert main([*workspace, "llm", "status", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert "llama_cpp_installed" in payload
        assert "torch_installed" in payload
        assert set(payload["local_models"]) == {"gguf", "hf"}

    def test_generate_local_uses_the_on_disk_checkpoint(self, workspace, capsys,
                                                        monkeypatch, fake_llama,
                                                        tmp_path):
        # Pin a small fake checkpoint: the project tree may hold a real
        # multi-GB model that (correctly) does not fit the default tier.
        monkeypatch.setenv("RP_LLM__GGUF_DIRS", str(tmp_path))
        (tmp_path / "Tiny-1B-Q4_K_M.gguf").write_bytes(b"\0" * 2048)
        # --local picks the checkpoint that is already on disk and runs it
        rc = main([*workspace, "llm", "generate", "hi", "--local",
                   "--max-tokens", "8", "-o", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["engine_kind"] == "gguf"
        assert payload["text"] == "SCRIPT-OUTPUT"

    def test_generate_local_naming_a_wider_tier_when_none_fit(
            self, workspace, capsys, monkeypatch, tmp_path):
        # A big file (≈5.5GB → ≈11GB peak RSS) is right-sized for the high
        # tier, not the default mid tier — the error must say so. The size is
        # faked via stat (nothing multi-GB is written; tmpfs is small).
        monkeypatch.setenv("RP_LLM__GGUF_DIRS", str(tmp_path))
        _mid, _high = _with_fat_gguf(tmp_path, monkeypatch, "Big-8B-Q4_K_S.gguf")
        rc = main([*workspace, "llm", "generate", "hi", "--local", "-o", "json"])
        assert rc == 2
        err = json.loads(capsys.readouterr().err)["error"]
        assert "needs tier 'high'" in err["action"]

    def test_generate_local_without_any_checkpoint_is_structured_error(
            self, workspace, capsys, monkeypatch):
        import rebel_profiler.llm.setup as setup_mod

        monkeypatch.setattr(setup_mod, "local_models",
                            lambda **kw: {"gguf": [], "hf": [], "total": 0})
        rc = main([*workspace, "llm", "generate", "hi", "--local", "-o", "json"])
        assert rc == 2
        err = json.loads(capsys.readouterr().err)["error"]
        assert "llm local" in err["action"]

    def test_hermes_repl_uses_fitting_local_checkpoint(self, workspace, capsys,
                                                       monkeypatch, fake_llama,
                                                       tmp_path):
        """End-to-end regression for the reported failure.

        `rebel-profiler hermes` on a box with a local 7B Q4 and no airllm:
        the REPL must open with the gguf engine (not the tiny refusal).
        """
        from rebel_profiler.llm import gguf as gguf_mod

        real = gguf_mod.discover_local_gguf
        monkeypatch.setattr(gguf_mod, "discover_local_gguf",
                            lambda **kw: real(roots=[tmp_path]))
        (tmp_path / "Coder-7B-Instruct-Q4_K_M.gguf").write_bytes(b"\0" * 2048)
        _stub_airllm(monkeypatch)
        # No RP_LLM__MODEL, no --llm, no config pin: the empty-pin path.
        monkeypatch.delenv("RP_LLM__MODEL", raising=False)
        rc = main([*workspace, "hermes", "--oneshot", "-o", "json",
                   "--max-turns", "2", "hello"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["engine"] == "gguf"
        assert payload["model"].endswith(
            "Coder-7B-Instruct-Q4_K_M.gguf")

    def test_hermes_tier_pin_widens_the_budget(self, workspace, capsys,
                                               monkeypatch, fake_llama,
                                               tmp_path):
        """hermes --tier high carries a checkpoint the auto tier refuses."""
        from rebel_profiler.llm import gguf as gguf_mod

        real = gguf_mod.discover_local_gguf
        monkeypatch.setattr(gguf_mod, "discover_local_gguf",
                            lambda **kw: real(roots=[tmp_path]))
        _with_fat_gguf(tmp_path, monkeypatch, "Coder-7B-Q4_K_M.gguf")
        _stub_airllm(monkeypatch)
        monkeypatch.delenv("RP_LLM__MODEL", raising=False)
        rc = main([*workspace, "hermes", "--oneshot", "-o", "json",
                   "--tier", "high", "--max-turns", "2", "hello"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["engine"] == "gguf"
        assert payload["model"].endswith("Coder-7B-Q4_K_M.gguf")

    def test_hermes_unfitting_checkpoint_reports_the_tier_escape(
            self, workspace, capsys, monkeypatch, fake_llama, tmp_path):
        """Without the tier pin the structured error names the escape."""
        from rebel_profiler.llm import gguf as gguf_mod

        real = gguf_mod.discover_local_gguf
        monkeypatch.setattr(gguf_mod, "discover_local_gguf",
                            lambda **kw: real(roots=[tmp_path]))
        _with_fat_gguf(tmp_path, monkeypatch, "Coder-7B-Q4_K_M.gguf")
        _stub_airllm(monkeypatch)
        monkeypatch.delenv("RP_LLM__MODEL", raising=False)
        rc = main([*workspace, "hermes", "--oneshot", "-o", "json", "hello"])
        assert rc == 7   # EXIT_DEPENDENCY
        err = json.loads(capsys.readouterr().err)["error"]
        assert "needs real weights" in err["message"]
        assert "--tier high" in err["action"]
        assert "Coder-7B-Q4_K_M.gguf" in err["reason"]


# ---------------------------------------------------------------- codegen

class TestCodegen:
    def test_extract_fenced_python(self):
        from rebel_profiler.llm.codegen import extract_python

        reply = "Sure!\n```python\ndef run(payload):\n    return {}\n```\nDone."
        assert extract_python(reply).strip() == "def run(payload):\n    return {}"

    def test_extract_bare_source(self):
        from rebel_profiler.llm.codegen import extract_python

        assert "def run(" in extract_python("def run(payload):\n    return 1\n")

    def test_extract_without_code_raises(self):
        from rebel_profiler.llm.codegen import extract_python

        with pytest.raises(UsageError):
            extract_python("I cannot help with that.")

    def test_extract_empty_reply_raises(self):
        from rebel_profiler.llm.codegen import extract_python

        with pytest.raises(UsageError):
            extract_python("   ")

    def test_syntax_check_rejects_broken_code(self):
        from rebel_profiler.llm.codegen import syntax_check

        with pytest.raises(UsageError) as excinfo:
            syntax_check("def run(payload)\n    return 1\n")
        assert "syntax error" in excinfo.value.message

    def test_syntax_check_accepts_valid_code(self):
        from rebel_profiler.llm.codegen import syntax_check

        syntax_check("def run(payload):\n    return {'ok': True}\n")

    def test_prompts_state_the_contract(self):
        from rebel_profiler.llm.codegen import (
            build_author_prompt,
            build_repair_prompt,
        )

        prompt = build_author_prompt("sum a list", payload_keys=["nums"])
        assert "def run(payload):" in prompt
        assert "nums" in prompt
        assert "subprocess" in prompt        # forbidden list is stated
        repair = build_repair_prompt("g", "def run(p):\n    pass",
                                     error="NameError: x", fix="define x")
        assert "NameError: x" in repair and "define x" in repair

    def test_author_requires_real_engine(self, monkeypatch, tmp_path):
        from rebel_profiler.llm.codegen import author_script
        from rebel_profiler.llm.inference import ModelPlane

        monkeypatch.setitem(sys.modules, "airllm", None)
        monkeypatch.setitem(sys.modules, "torch", None)
        monkeypatch.setitem(sys.modules, "llama_cpp", None)
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        with pytest.raises(DependencyUnavailableError) as excinfo:
            author_script("compute something", script_dir=tmp_path,
                          plane=plane)
        assert "tiny engine" in excinfo.value.message

    def test_load_failure_reports_missing_result(self, tmp_path):
        from rebel_profiler.llm.codegen import load_failure

        with pytest.raises(UsageError) as excinfo:
            load_failure("rps_none", script_dir=tmp_path)
        assert "no result yet" in excinfo.value.message

    def test_retry_rejects_already_done(self, tmp_path):
        from rebel_profiler.llm.codescript import submit_script, ScriptRunner
        from rebel_profiler.llm.codegen import retry_script

        sdir = tmp_path / "scripts"
        env = submit_script("def run(payload):\n    return 1\n", script_dir=sdir)
        ScriptRunner(sdir).poll_once()
        with pytest.raises(UsageError) as excinfo:
            retry_script(env["script_id"], script_dir=sdir)
        assert "already succeeded" in excinfo.value.message

    def test_retry_builds_prompt_from_rejection(self, tmp_path, monkeypatch):
        from rebel_profiler.llm.codescript import submit_script, ScriptRunner
        from rebel_profiler.llm import codegen

        sdir = tmp_path / "scripts"
        env = submit_script("import os\ndef run(payload):\n    return os.getcwd()\n",
                            script_dir=sdir)
        ScriptRunner(sdir).poll_once()
        captured = {}

        def fake_generate(prompt, *, model, plane, max_new_tokens=None):
            captured["prompt"] = prompt
            class R:
                text = "```python\ndef run(payload):\n    return {}\n```"
                engine = "fake"
                model = "fake"
            return R()

        monkeypatch.setattr(codegen, "_generate", fake_generate)
        out = codegen.retry_script(env["script_id"], script_dir=sdir)
        assert out["parent_script_id"] == env["script_id"]
        assert out["fixed_from"]["state"] == "rejected"
        assert "forbidden_import" in captured["prompt"]


# ---------------------------------------------------------------- real binding

class TestGgufRealBinding:
    """Integration with the real llama-cpp-python (only runs when installed).

    The stub-based tests above prove the logic; these prove the integration.
    They skip on a machine without the binding — which is exactly why the
    `engines` CI job installs it and then fails if they skipped anyway.
    """

    @pytest.fixture(autouse=True)
    def require_binding(self):
        pytest.importorskip("llama_cpp")

    def test_api_surface_our_engine_calls(self):
        import llama_cpp

        assert callable(llama_cpp.Llama)
        # Regression guard: if upstream renames any of these, our engine breaks.
        for method in ("create_completion", "tokenize", "detokenize"):
            assert callable(getattr(llama_cpp.Llama, method, None)), method

    def test_gpu_probe_tolerates_any_binding_version(self, model_file):
        # `_gpu_layers` reads the internal offload probe through getattr with a
        # fallback, so it must return a placement decision and never raise.
        engine = GgufEngine(str(model_file), limits=DEFAULT_LIMITS["mid"])
        layers = engine._gpu_layers()
        assert layers in {0, -1}

    def test_gpu_offload_disabled_under_budget(self, model_file):
        limits = Limits(max_rss_mb=8192, max_context_tokens=2048,
                        max_new_tokens=128, max_model_b=70.0,
                        allow_gpu=False, require_compression=False, tier="mid")
        engine = GgufEngine(str(model_file), limits=limits)
        assert engine._gpu_layers() == 0

    def test_construction_never_opens_weights(self, model_file):
        # Building the engine must be pure Python: nothing reads the file until
        # load(), so a status/plan command never pulls a 4GB checkpoint in.
        engine = GgufEngine(str(model_file), limits=DEFAULT_LIMITS["mid"])
        assert engine.loaded is False
        assert engine.quant == "Q4_K_M"
        assert engine.params_b == 8.0
        assert engine.info()["path"].endswith("Test-8B-Q4_K_M.gguf")


class TestGgufOperatorRun:
    """End-to-end generation against a real model — opt-in, not run in CI.

    CI cannot carry a multi-GB checkpoint, so this is the operator's harness:

        RP_TEST_GGUF=/path/to/model.gguf python -m pytest \
            tests/test_llm_gguf.py -q -k GgufOperatorRun -rs
    """

    def test_real_generation(self):
        import os

        pytest.importorskip("llama_cpp")
        path = os.environ.get("RP_TEST_GGUF", "").strip()
        if not path:
            pytest.skip("set RP_TEST_GGUF=<path.gguf> to run a real generation")
        limits = Limits(max_rss_mb=16_384, max_context_tokens=2048,
                        max_new_tokens=16, max_model_b=200.0,
                        allow_gpu=False, require_compression=False, tier="high")
        engine = GgufEngine(path, limits=limits)
        try:
            assert engine.loaded is False       # lazy until generate()
            result = engine.generate("The capital of France is", max_new_tokens=8)
            assert result.engine == "gguf"
            assert result.output_tokens > 0
            assert result.text.strip()
            assert result.device == "cpu"
            assert engine.profiling_summary()["steps"] == 1
        finally:
            engine.unload()
        assert engine.loaded is False
