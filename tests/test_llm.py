"""Tests for the LLM plane: budget tiers, engines, planner, daemon and CLI."""

from __future__ import annotations

import json

import pytest


def _cuda_present() -> bool:
    try:
        import torch

        return bool(torch.cuda.is_available())
    except Exception:
        return False

from rebel_profiler.cli.main import main
from rebel_profiler.core.errors import (
    DependencyUnavailableError,
    RPError,
    UsageError,
)
from rebel_profiler.llm.budget import (
    DEFAULT_LIMITS,
    Limits,
    BudgetGuard,
    ModelBudgetError,
    read_budget,
    recommend,
    resolve_limits,
)
from rebel_profiler.llm.catalog import model_params_b, suggest_models
from rebel_profiler.llm.inference import ModelPlane, TinyLlmEngine
from rebel_profiler.llm.planner import build_plan_prompt, parse_proposals


@pytest.fixture(autouse=True)
def _no_real_airllm(monkeypatch):
    """Keep engine-selection tests offline and fast.

    When the airllm package IS installed, select_engine('Qwen/…') would
    start a real model download + layer split inside these unit tests.
    Stub AutoModel so 'airllm importable' still drives the selection path
    without ever touching the network.
    """
    try:
        import airllm  # noqa: F401
    except ImportError:
        yield
        return
    import sys
    import types

    fake = types.ModuleType("airllm")

    class _FakeAutoModel:
        @staticmethod
        def from_pretrained(*_a, **_kw):
            raise RuntimeError("stubbed: tests must not download models")

    fake.AutoModel = _FakeAutoModel
    monkeypatch.setitem(sys.modules, "airllm", fake)
    yield
    return
from rebel_profiler.llm.daemon import (
    JobValidationError,
    LlmDaemon,
    default_queue_dir,
    load_result,
    submit_job,
)


# ---------------------------------------------------------------- budget

class TestBudget:
    def test_recommend_tiers_by_ram(self):
        assert recommend({"total_ram_mb": 2_000, "cpu_only": True}) == "tiny"
        assert recommend({"total_ram_mb": 8_000, "cpu_only": False}) == "low"
        assert recommend({"total_ram_mb": 16_000, "cpu_only": False}) == "mid"
        assert recommend({"total_ram_mb": 64_000, "cpu_only": False}) == "high"

    def test_resolve_limits_env_tighten_only(self, monkeypatch):
        monkeypatch.setenv("RP_LLM__TIER", "mid")
        monkeypatch.setenv("RP_LLM__MAX_RSS_MB", "1024")
        limits = resolve_limits(environ=dict(__import__("os").environ))
        assert limits.max_rss_mb == 1024   # tightened below tier default

    def test_env_cannot_loosen(self, monkeypatch):
        monkeypatch.setenv("RP_LLM__TIER", "tiny")
        monkeypatch.setenv("RP_LLM__MAX_MODEL_B", "999")
        limits = resolve_limits(environ=dict(__import__("os").environ))
        assert limits.max_model_b == DEFAULT_LIMITS["tiny"].max_model_b

    def test_cpu_only_does_not_force_compression(self, monkeypatch):
        # AirLLM's block-wise compression quantizes on CUDA (bnb .cuda()); a
        # CPU-only box must run UNCOMPRESSED (layer streaming keeps RAM tiny).
        monkeypatch.setenv("RP_LLM__TIER", "high")
        monkeypatch.setenv("RP_LLM__ALLOW_GPU", "false")
        limits = resolve_limits(environ=dict(__import__("os").environ))
        assert limits.allow_gpu is False
        assert limits.require_compression is False

    def test_guard_refuses_oversized_model(self):
        guard = BudgetGuard(DEFAULT_LIMITS["tiny"])
        with pytest.raises(ModelBudgetError):
            guard.check_model(70.0, compressed=False)

    def test_guard_refuses_compression_without_cuda(self):
        # No CUDA in CI: compressed loads are refused with an honest fix hint.
        if _cuda_present():
            return
        guard = BudgetGuard(DEFAULT_LIMITS["mid"])
        with pytest.raises(ModelBudgetError) as excinfo:
            guard.check_model(4.0, compressed=True)
        assert "CUDA" in excinfo.value.message

    def test_guard_requires_compression_on_tiny(self):
        guard = BudgetGuard(DEFAULT_LIMITS["tiny"])
        with pytest.raises(ModelBudgetError):
            guard.check_model(0.5, compressed=False)

    def test_guard_context_and_generate_caps(self):
        guard = BudgetGuard(DEFAULT_LIMITS["tiny"])
        with pytest.raises(ModelBudgetError):
            guard.check_context(10_000)
        with pytest.raises(ModelBudgetError):
            guard.check_generate(999)

    def test_read_budget_is_dict(self):
        budget = read_budget(meminfo_path="/nonexistent/meminfo")
        assert budget["total_ram_mb"] > 0
        assert isinstance(budget["cpu_only"], bool)


# ---------------------------------------------------------------- catalog

class TestCatalog:
    def test_known_model_size(self):
        assert model_params_b("meta-llama/Llama-3.3-70B-Instruct") == 70.0

    def test_unknown_repo_id_is_conservative(self):
        assert model_params_b("org/WeirdModel-X") == 32.0

    def test_size_pattern_in_name(self):
        assert model_params_b("org/foo-13b") == 13.0

    def test_suggest_models_flags_fits(self):
        models = suggest_models(2_000)
        small = [m for m in models if m["params_b"] <= 4]
        assert any(m["fits"] for m in small)
        big = [m for m in models if m["params_b"] >= 47]
        assert not any(m["fits"] for m in big)


# ---------------------------------------------------------------- engines

class TestEngines:
    def test_tiny_engine_generate_is_bounded_and_labeled(self):
        engine = TinyLlmEngine(limits=DEFAULT_LIMITS["tiny"])
        result = engine.generate("hello world " * 100, max_new_tokens=16)
        assert result.engine == "tiny"
        assert result.text.startswith("[tiny-engine deterministic output]")
        assert result.output_tokens <= DEFAULT_LIMITS["tiny"].max_new_tokens

    def test_plane_falls_back_to_tiny_with_reason(self):
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        engine = plane.select_engine("Qwen/Qwen3-4B")
        assert plane.engine_kind == "tiny"
        assert "airllm unavailable" in plane.fallback_reason
        assert engine.kind == "tiny"
        plane.unload()

    def test_plane_prefer_tiny(self):
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="tiny")
        plane.load_tiny()
        result = plane.generate("ping")
        assert result.engine == "tiny"
        plane.unload()

    def test_generate_without_engine_is_structured_error(self):
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        with pytest.raises(ModelBudgetError):
            plane.generate("x")

    def test_airllm_engine_construction_refuses_oversize_on_tiny(self):
        from rebel_profiler.llm.inference import AirLlmEngine

        with pytest.raises(ModelBudgetError):
            AirLlmEngine("meta-llama/Llama-3.3-70B-Instruct",
                         limits=DEFAULT_LIMITS["tiny"])

    def test_compression_without_cuda_refused_early(self, monkeypatch):
        from rebel_profiler.llm.inference import AirLlmEngine

        limits = Limits(max_rss_mb=2048, max_context_tokens=1024,
                        max_new_tokens=128, max_model_b=70.0,
                        allow_gpu=False, require_compression=False, tier="mid")
        # This box has no CUDA (CI/CPU): compression must be refused up front.
        with pytest.raises(ModelBudgetError) as excinfo:
            AirLlmEngine("Qwen/Qwen3-4B", limits=limits, compression="8bit")
        assert "CUDA" in excinfo.value.message

    def test_uncompressed_engine_passes_construction_without_cuda(self):
        from rebel_profiler.llm.inference import AirLlmEngine

        limits = Limits(max_rss_mb=2048, max_context_tokens=1024,
                        max_new_tokens=128, max_model_b=70.0,
                        allow_gpu=False, require_compression=False, tier="mid")
        # Construction succeeds; only load() touches weights/network.
        engine = AirLlmEngine("Qwen/Qwen3-4B", limits=limits)
        assert engine.compressed is False


# ---------------------------------------------------------------- planner

class _Adapter:
    def __init__(self, name, allowed):
        self.name = name
        self.allowed_params = allowed
        self.capability_class = "discovery"
        self.binary = "dig"


class _Registry:
    def __init__(self, adapters):
        self._adapters = adapters

    def get(self, name):
        return self._adapters.get(name)


class TestPlanner:
    def _view(self):
        class View:
            goal = "map lab.example.test passive footprint"
            def available_actions(self):
                return [{"action": "passive-dns", "binary": "dig",
                         "capability_class": "passive_recon",
                         "allowed_params": ["record_type"]}]
        return View()

    def test_prompt_contains_goal_and_contract(self):
        prompt = build_plan_prompt(self._view())
        assert "lab.example.test" in prompt
        assert "passive-dns" in prompt
        assert "available_actions" in prompt or "AVAILABLE ACTIONS" in prompt

    def test_parse_simple_array(self):
        regs = _Registry({"passive-dns": _Adapter("passive-dns", ["record_type"])})
        proposals = parse_proposals(
            '[{"action": "passive-dns", "target": "lab.example.test", '
            '"params": {"record_type": "A"}, "reason": "resolve"}]', regs)
        assert len(proposals) == 1
        assert proposals[0].action == "passive-dns"
        assert proposals[0].params == {"record_type": "A"}

    def test_parse_fenced_json(self):
        regs = _Registry({"passive-dns": _Adapter("passive-dns", ["record_type"])})
        reply = 'Here you go:\n```json\n[{"action": "passive-dns", "target": "x"}]\n```'
        proposals = parse_proposals(reply, regs)
        assert proposals[0].target == "x"

    def test_parse_single_object(self):
        regs = _Registry({"passive-dns": _Adapter("passive-dns", [])})
        proposals = parse_proposals('{"action": "passive-dns", "target": "x"}', regs)
        assert len(proposals) == 1

    def test_unknown_action_rejected(self):
        regs = _Registry({})
        with pytest.raises(UsageError):
            parse_proposals('[{"action": "run-shell", "target": "x"}]', regs)

    def test_undeclared_param_rejected(self):
        regs = _Registry({"passive-dns": _Adapter("passive-dns", ["record_type"])})
        with pytest.raises(UsageError):
            parse_proposals(
                '[{"action": "passive-dns", "target": "x", "params": {"evil": "1"}}]',
                regs)

    def test_garbage_reply_rejected(self):
        with pytest.raises(UsageError):
            parse_proposals("I cannot do that, sorry.")

    def test_empty_array_rejected(self):
        with pytest.raises(UsageError):
            parse_proposals("[]")

    def test_missing_target_rejected(self):
        with pytest.raises(UsageError):
            parse_proposals('[{"action": "passive-dns"}]')

    def test_secrets_redacted_in_reason(self):
        regs = _Registry({"passive-dns": _Adapter("passive-dns", [])})
        proposals = parse_proposals(
            '[{"action": "passive-dns", "target": "x", '
            '"reason": "token: sk-abcdefghijklmnopqrst"}]', regs)
        assert "sk-abcdefghijklmnopqrst" not in proposals[0].reason
        assert "[REDACTED]" in proposals[0].reason

    def test_llm_planner_needs_weights(self):
        from rebel_profiler.llm.planner import LlmPlanner

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="tiny")
        plane.load_tiny()
        planner = LlmPlanner(plane)
        with pytest.raises(DependencyUnavailableError):
            planner(self._view())

    def test_llm_planner_uses_engine_chat_template(self):
        """Instruct checkpoints must receive their chat template, not raw text.

        Regression: the planner sent the raw instruction prompt to the engine,
        so a Qwen2.5/Llama instruct checkpoint degenerated (repeated single
        characters) and every agent run failed to parse proposals.
        """
        import types

        from rebel_profiler.llm.planner import LlmPlanner

        captured = {}

        class _ChatEngine:
            loaded = True
            model_id = "fake-instruct"

            def chat_prompt(self, system, user):
                captured["system"] = system
                captured["user"] = user
                return f"<|im_start|>system\n{system}<|im_end|>\n"

            def generate(self, prompt, **kw):
                captured["prompt"] = prompt
                result = types.SimpleNamespace(
                    text='[{"action": "passive-dns", '
                         '"target": "lab.example.test", '
                         '"params": {"record_type": "A"}, '
                         '"reason": "resolve"}]')
                return result

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        plane._engine = _ChatEngine()
        plane._engine_kind = "gguf"
        plane.select_engine = lambda model, **kw: plane._engine   # already loaded
        planner = LlmPlanner(plane,
                             registry=_Registry({
                                 "passive-dns": _Adapter("passive-dns",
                                                         ["record_type"])}))
        proposals = planner(self._view())
        assert proposals and proposals[0].action == "passive-dns"
        # the chat template was applied to the plan prompt
        assert "<|im_start|>system" in captured["prompt"]
        assert "lab.example.test" in captured["user"]

    def test_plane_chat_generate_routes_through_template(self):
        """ModelPlane.chat_generate applies the engine's chat_prompt."""
        import types

        captured = {}

        class _ChatEngine:
            loaded = True
            model_id = "fake-instruct"

            def chat_prompt(self, system, user):
                return f"SYS[{system}] USER[{user}]"

            def generate(self, prompt, **kw):
                captured["prompt"] = prompt
                return types.SimpleNamespace(text="ok")

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        plane._engine = _ChatEngine()
        plane._engine_kind = "gguf"
        result = plane.chat_generate("be brief", "do the thing")
        assert result.text == "ok"
        assert captured["prompt"] == "SYS[be brief] USER[do the thing]"


# ---------------------------------------------------------------- daemon

class TestDaemon:
    def test_submit_and_load_result_roundtrip(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job("hello", queue_dir=q, model="m", max_new_tokens=8)
        assert load_result(env["job_id"], queue_dir=q) is None  # not done yet
        assert (q / f"{env['job_id']}.llmjob.json").exists()

    def test_submit_redacts_prompt(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job("key: sk-abcdefghijklmnopqrst", queue_dir=q)
        stored = json.loads((q / f"{env['job_id']}.llmjob.json").read_text())
        assert "sk-abcdefghijklmnopqrst" not in stored["prompt"]

    def test_oversized_prompt_refused(self, tmp_path):
        with pytest.raises(RPError):
            submit_job("x" * 70_000, queue_dir=tmp_path)

    def test_daemon_processes_job_with_tiny_engine(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job("say hi", queue_dir=q, max_new_tokens=16)
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        result = load_result(env["job_id"], queue_dir=q)
        assert result is not None and result["state"] == "done"
        assert result["generation"]["engine"] == "tiny"

    def test_daemon_unloads_after_pass(self, tmp_path):
        q = tmp_path / "q"
        submit_job("hi", queue_dir=q)
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        assert daemon.plane.engine_kind is None   # the LLM went quiet

    def test_tampered_job_is_rejected(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job("hi", queue_dir=q)
        path = q / f"{env['job_id']}.llmjob.json"
        envelope = json.loads(path.read_text())
        envelope["prompt"] = "tampered"
        path.write_text(json.dumps(envelope))
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        reject = q / f"{env['job_id']}.llmreject.json"
        assert reject.exists()
        assert load_result(env["job_id"], queue_dir=q) is None

    def test_empty_prompt_job_rejected(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job("hi", queue_dir=q)
        path = q / f"{env['job_id']}.llmjob.json"
        envelope = json.loads(path.read_text())
        envelope["prompt"] = ""
        body = {k: v for k, v in envelope.items() if k != "checksum"}
        from rebel_profiler.llm.daemon import _sha256_canonical
        envelope["checksum"] = _sha256_canonical(body)
        path.write_text(json.dumps(envelope))
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        assert (q / f"{env['job_id']}.llmreject.json").exists()

    def test_untrusted_requester_rejected(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job("hi", queue_dir=q)
        path = q / f"{env['job_id']}.llmjob.json"
        envelope = json.loads(path.read_text())
        envelope["requested_by"] = "attacker"
        body = {k: v for k, v in envelope.items() if k != "checksum"}
        from rebel_profiler.llm.daemon import _sha256_canonical
        envelope["checksum"] = _sha256_canonical(body)
        path.write_text(json.dumps(envelope))
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        assert (q / f"{env['job_id']}.llmreject.json").exists()

    def test_result_is_idempotent(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job("hi", queue_dir=q)
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        first = load_result(env["job_id"], queue_dir=q)
        daemon.run_forever(once=True)
        second = load_result(env["job_id"], queue_dir=q)
        assert first == second

    def test_default_queue_dir_under_data_dir(self):
        assert default_queue_dir("/tmp/x").name == "llm_queue"


# ---------------------------------------------------------------- CLI

@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


# ---------------------------------------------------------------- native engine


class TestNativeEngine:
    @pytest.fixture()
    def tiny_checkpoint(self, tmp_path):
        """Build a REAL runnable 1-layer checkpoint on disk (no download)."""
        torch = pytest.importorskip("torch")
        import struct

        d = tmp_path / "m"
        d.mkdir()
        (d / "config.json").write_text(json.dumps({
            "model_type": "qwen2", "hidden_size": 16, "num_hidden_layers": 1,
            "num_attention_heads": 2, "num_key_value_heads": 1,
            "intermediate_size": 32, "vocab_size": 64,
            "tie_word_embeddings": True, "rms_norm_eps": 1e-6,
            "rope_theta": 10000.0,
        }))
        H, V, I = 16, 64, 32
        tensors = {
            "model.embed_tokens.weight": (V, H),
            "model.layers.0.input_layernorm.weight": (H,),
            "model.layers.0.post_attention_layernorm.weight": (H,),
            "model.layers.0.self_attn.q_proj.weight": (H, H),
            "model.layers.0.self_attn.k_proj.weight": (H // 2, H),
            "model.layers.0.self_attn.v_proj.weight": (H // 2, H),
            "model.layers.0.self_attn.o_proj.weight": (H, H),
            "model.layers.0.mlp.gate_proj.weight": (I, H),
            "model.layers.0.mlp.up_proj.weight": (I, H),
            "model.layers.0.mlp.down_proj.weight": (H, I),
            "model.norm.weight": (H,),
        }
        header, blob = {}, bytearray()
        for name, shape in tensors.items():
            n = 1
            for s in shape:
                n *= s
            header[name] = {"dtype": "F32", "shape": list(shape),
                            "data_offsets": [len(blob), len(blob) + 4 * n]}
            blob += torch.randn(*shape).float().view(-1).numpy().tobytes()
        hb = json.dumps(header).encode()
        with open(d / "model.safetensors", "wb") as fh:
            fh.write(struct.pack("<Q", len(hb)) + hb + bytes(blob))
        return d

    def test_safetensors_reader(self, tiny_checkpoint):
        from rebel_profiler.llm.native import SafeTensorFile

        sf = SafeTensorFile(tiny_checkpoint / "model.safetensors")
        assert "model.embed_tokens.weight" in sf.tensor_names()
        w = sf.load("model.embed_tokens.weight")
        assert w.shape == (64, 16)
        sf.close()

    def test_discovery_and_resolution(self, tiny_checkpoint, monkeypatch):
        from rebel_profiler.llm import native

        monkeypatch.setenv("HF_HOME", str(tmp_path_hf(tiny_checkpoint)))
        models = native.discover_local_models(
            hf_cache=tmp_path_hf(tiny_checkpoint))
        assert models and models[0]["source"] == "hf-cache"
        snap = native.resolve_local_model(
            models[0]["model"], hf_cache=tmp_path_hf(tiny_checkpoint))
        assert snap is not None and (snap / "config.json").exists()

    def test_generate_offline_from_local_checkpoint(self, tiny_checkpoint,
                                                    monkeypatch):
        monkeypatch.setenv("HF_HOME", str(tmp_path_hf(tiny_checkpoint)))
        from rebel_profiler.llm import native

        engine = native.NativeStreamingEngine(
            "local/tiny", limits=DEFAULT_LIMITS["mid"],
            hf_cache=tmp_path_hf(tiny_checkpoint))
        engine.load()
        result = engine.generate("hello world", max_new_tokens=4)
        assert result.engine == "native"
        assert result.output_tokens <= 4
        assert result.device == "cpu"
        engine.unload()
        assert engine.loaded is False

    def test_missing_local_model_is_structured_error(self):
        from rebel_profiler.llm import native

        with pytest.raises(DependencyUnavailableError):
            native.NativeStreamingEngine(
                "org/never-downloaded", limits=DEFAULT_LIMITS["mid"],
                hf_cache="/tmp/definitely-not-a-hf-cache")

    def test_plane_prefers_native_for_local_models(self, tiny_checkpoint,
                                                   monkeypatch):
        monkeypatch.setenv("HF_HOME", str(tmp_path_hf(tiny_checkpoint)))
        from rebel_profiler.llm import native
        from rebel_profiler.llm.inference import ModelPlane

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        model_id = native.discover_local_models(
            hf_cache=tmp_path_hf(tiny_checkpoint))[0]["model"]
        engine = plane.select_engine(model_id)
        assert plane.engine_kind == "native"
        engine.unload()


def tmp_path_hf(checkpoint_dir):
    """Wrap a checkpoint dir as models--local--tiny/snapshots/x layout."""
    import shutil
    from pathlib import Path

    hf = Path(checkpoint_dir).parent / "hf"
    snap = hf / "hub" / "models--local--tiny" / "snapshots" / "s1"
    if not snap.exists():
        snap.mkdir(parents=True)
        for f in checkpoint_dir.iterdir():
            shutil.copy2(f, snap / f.name)
    return hf


class TestLlmCli:
    def test_status_json(self, workspace, capsys):
        assert main([*workspace, "llm", "status", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["recommended_tier"] in {"tiny", "low", "mid", "high"}
        assert payload["data"]["budget"]["total_ram_mb"] > 0

    def test_models_table(self, workspace, capsys):
        assert main([*workspace, "llm", "models"]) == 0
        out = capsys.readouterr().out
        assert "Qwen" in out or "model" in out.lower()

    def test_generate_with_tiny_engine(self, workspace, capsys):
        assert main([*workspace, "llm", "generate", "hello world",
                     "--engine", "tiny", "--max-tokens", "24", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["engine"] == "tiny"
        assert "tiny-engine deterministic output" in payload["data"]["text"]

    def test_submit_and_result_flow(self, workspace, capsys, tmp_path):
        qdir = str(tmp_path / "llmq")
        assert main([*workspace, "llm", "submit", "summarize this",
                     "--queue-dir", qdir, "-o", "json"]) == 0
        job_id = json.loads(capsys.readouterr().out)["data"]["job_id"]
        # run the daemon pass directly against the same queue
        from rebel_profiler.llm.daemon import LlmDaemon
        LlmDaemon(__import__("pathlib").Path(qdir),
                  prefer_engine="tiny").run_forever(once=True)
        assert main([*workspace, "llm", "result", job_id,
                     "--queue-dir", qdir, "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["state"] == "done"

    def test_daemon_once(self, workspace, capsys, tmp_path):
        qdir = tmp_path / "q2"
        submit_job("hi", queue_dir=qdir)
        assert main([*workspace, "llm", "daemon", "--once",
                     "--queue-dir", str(qdir), "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"][0]["state"] == "done"

    def test_plan_requires_case(self, workspace, capsys):
        rc = main([*workspace, "llm", "plan", "ghost", "goal", "-o", "json"])
        assert rc != 0
        err = json.loads(capsys.readouterr().err)
        assert err["error"]["exit_code"] != 0


class TestExternalEngine:
    def test_missing_key_is_structured_error(self, monkeypatch):
        from rebel_profiler.llm.external import ExternalEngine

        monkeypatch.delenv("RP_LLM__API_KEY", raising=False)
        monkeypatch.delenv("RP_LLM__API_KEY_FILE", raising=False)
        engine = ExternalEngine("gpt-x", limits=DEFAULT_LIMITS["mid"])
        with pytest.raises(ModelBudgetError):
            engine.load()

    def test_key_file_roundtrip(self, tmp_path, monkeypatch):
        import os

        from rebel_profiler.llm.external import ExternalEngine, resolve_api_key

        key_file = tmp_path / "k.txt"
        key_file.write_text("sk-test-123\n")
        monkeypatch.setenv("RP_LLM__API_KEY_FILE", str(key_file))
        monkeypatch.delenv("RP_LLM__API_KEY", raising=False)
        assert resolve_api_key(dict(os.environ)) == "sk-test-123"
        engine = ExternalEngine("gpt-x", limits=DEFAULT_LIMITS["mid"])
        engine.load()
        assert engine.loaded is True
        engine.unload()
        assert engine.loaded is False   # key dropped when idle

    def test_payload_is_redacted(self, monkeypatch):
        import json as _json

        from rebel_profiler.llm import external

        captured = {}

        class FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return _json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

        def fake_urlopen(request, timeout):
            captured["payload"] = _json.loads(request.data.decode())
            return FakeResp()

        monkeypatch.setattr(external.urllib.request, "urlopen", fake_urlopen)
        engine = external.ExternalEngine(
            "gpt-x", limits=DEFAULT_LIMITS["mid"], api_key="k")
        result = engine.generate("use key: sk-abcdefghijklmnopqrst")
        sent = captured["payload"]["messages"][0]["content"]
        assert "sk-abcdefghijklmnopqrst" not in sent
        assert result.engine == "external" and result.device == "remote"


class TestDataHandshake:
    def test_data_job_requires_case_and_question(self, tmp_path):
        from rebel_profiler.llm.daemon import RPError

        with pytest.raises(RPError):
            submit_job(queue_dir=tmp_path, kind="data")

    def test_data_pack_is_bounded_and_redacted(self, tmp_path, monkeypatch):
        from rebel_profiler.storage.database import Database
        from rebel_profiler.llm.datapack import build_data_pack
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        built = build_data_pack(db, "c1")
        assert built["truncated"] is False
        assert built["pack"]["case_id"] == "c1"
        assert "stats" in built["pack"]
        db.close()

    def test_datapack_prompt_wraps_as_data(self):
        from rebel_profiler.llm.datapack import wrap_pack_as_prompt

        prompt = wrap_pack_as_prompt("{}", "what is exposed?")
        assert "CASE_DATA" in prompt and "what is exposed?" in prompt

    def test_data_job_end_to_end_pack_only(self, tmp_path, monkeypatch):
        import os

        from rebel_profiler.llm.daemon import LlmDaemon
        from rebel_profiler.storage.database import Database

        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        q = tmp_path / "q"
        env = submit_job(queue_dir=q, kind="data", case_id="c1",
                         question="what is exposed?", generate=False)
        daemon = LlmDaemon(q, prefer_engine="tiny",
                           db_factory=lambda _cid: db)
        daemon.run_forever(once=True)
        result = load_result(env["job_id"], queue_dir=q)
        assert result is not None and result["state"] == "done"
        assert result["datapack"]["truncated"] is False
        assert "CASE_DATA" not in result.get("pack_text", "")  # raw pack, wrapped separately
        db.close()

    def test_data_job_without_db_factory_fails_cleanly(self, tmp_path):
        q = tmp_path / "q"
        env = submit_job(queue_dir=q, kind="data", case_id="ghost",
                         question="?", generate=False)
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        result = load_result(env["job_id"], queue_dir=q)
        assert result is not None and result["state"] == "failed"
        assert "db factory" in (result.get("error", "") + result.get("reason", "")).lower()
