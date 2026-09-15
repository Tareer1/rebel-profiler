"""Tests for the extended AirLLM feature set: quantization, tokenizer, script
plane, native engine upgrades (chat template, profiling, shards) and CLI."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.core.errors import UsageError


# ---------------------------------------------------------------- quantization

class TestQuant:
    def _torch(self):
        return pytest.importorskip("torch")

    def test_roundtrip_8bit_close(self):
        torch = self._torch()
        from rebel_profiler.llm.quant import quantize_tensor

        t = torch.randn(32, 64)
        q = quantize_tensor(t, bits=8)
        d = q.dequantize()
        err = (d - t).abs().max().item()
        scale = t.abs().max().item() / 2 ** 7
        assert err < scale * 1.5   # within one quantization step-ish

    def test_roundtrip_4bit_reasonable(self):
        torch = self._torch()
        from rebel_profiler.llm.quant import quantize_tensor

        t = torch.randn(16, 128)
        q = quantize_tensor(t, bits=4)
        d = q.dequantize()
        # 4-bit absmax over 128-value blocks: coarse but correlated
        assert q.packed.shape[1] == 64   # two values per byte
        corr = torch.corrcoef(torch.stack([d.flatten(), t.flatten()]))[0, 1]
        assert corr > 0.85

    def test_packed_size_is_quarter(self):
        torch = self._torch()
        from rebel_profiler.llm.quant import quantize_tensor

        t = torch.randn(64, 256)
        q4 = quantize_tensor(t, bits=4)
        q8 = quantize_tensor(t, bits=8)
        assert q4.packed.numel() == 64 * 128          # 4bit: half bytes of 8bit
        assert q8.packed.numel() == 64 * 256
        assert q4.nbytes() < t.numel() * 4 / 3        # packed + scales < fp32

    def test_non_2d_rejected(self):
        torch = self._torch()
        from rebel_profiler.llm.quant import QuantError, quantize_tensor

        with pytest.raises(QuantError):
            quantize_tensor(torch.randn(4, 4, 4), bits=8)

    def test_shard_bake_and_manifest(self, tmp_path):
        torch = self._torch()
        from rebel_profiler.llm.quant import prepare_model_shards

        snap = _mini_checkpoint(tmp_path, torch)
        out = tmp_path / "shards"
        manifest = prepare_model_shards(snap, out, bits=0)
        assert manifest["bits"] == 0
        assert len(manifest["shards"]) == 2   # shard 0 embed+norm, shard 1 layer 0
        for shard in manifest["shards"]:
            path = out / shard["file"]
            assert path.exists()
        assert (out / "manifest.json").exists()

    def test_shard_bake_quantized(self, tmp_path):
        torch = self._torch()
        from rebel_profiler.llm.quant import prepare_model_shards

        snap = _mini_checkpoint(tmp_path, torch)
        out = tmp_path / "shards4"
        manifest = prepare_model_shards(snap, out, bits=4)
        assert manifest["bits"] == 4
        # quantized shards must be smaller than the fp32 originals
        total = sum(s["bytes"] for s in manifest["shards"])
        original = (snap / "model.safetensors").stat().st_size
        assert total < original

    def test_delete_original_only_after_verification(self, tmp_path):
        torch = self._torch()
        from rebel_profiler.llm.quant import prepare_model_shards

        snap = _mini_checkpoint(tmp_path, torch)
        out = tmp_path / "shards_del"
        manifest = prepare_model_shards(snap, out, bits=0, delete_original=True)
        assert manifest.get("deleted_originals") == ["model.safetensors"]
        assert not (snap / "model.safetensors").exists()
        assert (out / "DELETED_ORIGINALS.txt").exists()


def _mini_checkpoint(tmp_path, torch, *, layers=1, hidden=16, vocab=64):
    """A real, loadable 1-layer checkpoint on disk (safetensors), at *tmp_path*."""
    d = Path(tmp_path)
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.json").write_text(json.dumps({
        "model_type": "qwen2", "hidden_size": hidden,
        "num_hidden_layers": layers, "num_attention_heads": 2,
        "num_key_value_heads": 2, "intermediate_size": 32,
        "vocab_size": vocab, "tie_word_embeddings": True,
        "rms_norm_eps": 1e-6, "rope_theta": 10000.0,
    }))
    H, V, I = hidden, vocab, 32
    tensors = {
        "model.embed_tokens.weight": (V, H),
        "model.norm.weight": (H,),
    }
    for i in range(layers):
        tensors.update({
            f"model.layers.{i}.input_layernorm.weight": (H,),
            f"model.layers.{i}.post_attention_layernorm.weight": (H,),
            f"model.layers.{i}.self_attn.q_proj.weight": (H, H),
            f"model.layers.{i}.self_attn.k_proj.weight": (H, H),
            f"model.layers.{i}.self_attn.v_proj.weight": (H, H),
            f"model.layers.{i}.self_attn.o_proj.weight": (H, H),
            f"model.layers.{i}.mlp.gate_proj.weight": (I, H),
            f"model.layers.{i}.mlp.up_proj.weight": (I, H),
            f"model.layers.{i}.mlp.down_proj.weight": (H, I),
        })
    header, blob = {}, bytearray()
    for name, shape in tensors.items():
        n = 1
        for s in shape:
            n *= s
        header[name] = {"dtype": "F32", "shape": list(shape),
                        "data_offsets": [len(blob), len(blob) + 4 * n]}
        blob += torch.randn(*shape).view(-1).numpy().tobytes()
    hb = json.dumps(header).encode()
    with open(d / "model.safetensors", "wb") as fh:
        fh.write(struct.pack("<Q", len(hb)) + hb + bytes(blob))
    return d


# ---------------------------------------------------------------- tokenizer

class TestTokenizer:
    def test_roundtrip_full_byte_vocab(self):
        from rebel_profiler.llm.tokenizer import _BYTE_ENCODER, BpeTokenizer

        # full byte alphabet in vocab → every encode is representable
        vocab = {_BYTE_ENCODER[b]: 256 - b if False else i
                 for i, b in enumerate(sorted(_BYTE_ENCODER))}
        tok = BpeTokenizer(vocab, [], [])
        ids = tok.encode("hello world")
        assert ids and all(isinstance(i, int) for i in ids)
        assert tok.decode(ids) == "hello world"

    def test_merge_rule_applies(self):
        from rebel_profiler.llm.tokenizer import _BYTE_ENCODER, BpeTokenizer

        # "h"+"e" merge exists → 'he' encodes to ONE token
        vocab = {_BYTE_ENCODER[b]: i for i, b in enumerate(sorted(_BYTE_ENCODER))}
        vocab["he"] = 300
        tok = BpeTokenizer(vocab, [("h", "e")], [])
        ids = tok.encode("he")
        assert ids == [300]

    def test_split_words_family_rules(self):
        from rebel_profiler.llm.tokenizer import split_words

        assert split_words("hello world") == ["hello", " world"]
        assert split_words("don't") == ["don", "'t"]
        assert split_words("abc123def") == ["abc", "123", "def"]
        assert split_words("a,b") == ["a", ",", "b"]
        assert split_words("x  y") == ["x", " ", " y"]

    def test_special_tokens_roundtrip(self):
        from rebel_profiler.llm.tokenizer import BpeTokenizer

        vocab = {"a": 1, "<|im_end|>": 5, "b": 2}
        tok = BpeTokenizer(vocab, [], ["<|im_end|>"])
        ids = tok.encode("a<|im_end|>b")
        assert 5 in ids
        assert tok.decode(ids) == "a<|im_end|>b"
        assert 5 in tok.eos_ids({})

    def test_sentencepiece_decode_marker(self):
        from rebel_profiler.llm.tokenizer import BpeTokenizer

        # SP-style vocab: raw bytes not in the byte-decoder path, ▁ marker
        vocab = {"▁hello": 1, "▁world": 2}
        tok = BpeTokenizer(vocab, [], [])
        assert tok.decode([1, 2]) == " hello world"

    def test_approx_fallback_labeled(self):
        from rebel_profiler.llm.tokenizer import ApproxTokenizer

        tok = ApproxTokenizer()
        # encode caps at ~len/3.5 even without max_tokens (conservative estimate)
        ids = tok.encode("x" * 700)
        assert 1 <= len(ids) <= 208   # (700/3.5)+8 = 208
        capped = tok.encode("x" * 700, max_tokens=50)
        assert len(capped) == 50
        assert "approx tokenizer" in tok.decode(ids)

    def test_from_snapshot_missing_is_unavailable(self, tmp_path):
        from rebel_profiler.llm.tokenizer import TokenizerUnavailable, BpeTokenizer

        with pytest.raises(TokenizerUnavailable):
            BpeTokenizer.from_snapshot(tmp_path)

    def test_load_tokenizer_never_raises(self, tmp_path):
        from rebel_profiler.llm.tokenizer import ApproxTokenizer, load_tokenizer

        assert isinstance(load_tokenizer(tmp_path), ApproxTokenizer)


# ---------------------------------------------------------------- script plane

SAFE_SCRIPT = (
    "import json\n"
    "def run(payload):\n"
    "    nums = payload.get('nums', [])\n"
    "    return {'sum': sum(nums), 'count': len(nums)}\n"
)

UNSAFE_SCRIPT = (
    "import os\n"
    "def run(payload):\n"
    "    return os.listdir('/')\n"
)

EVIL_SCRIPT = (
    "def run(payload):\n"
    "    return eval(payload['expr'])\n"
)


class TestScriptPlane:
    def test_submit_and_run_real_result(self, tmp_path):
        from rebel_profiler.llm.codescript import (
            load_script_result,
            submit_script,
            ScriptRunner,
        )

        sdir = tmp_path / "scripts"
        env = submit_script(SAFE_SCRIPT, script_dir=sdir,
                            payload={"nums": [1, 2, 3, 4]}, name="summer")
        assert load_script_result(env["script_id"], script_dir=sdir) is None
        runner = ScriptRunner(sdir)
        handled = runner.poll_once()
        assert handled and handled[0]["state"] == "done"
        result = load_script_result(env["script_id"], script_dir=sdir)
        assert result["state"] == "done"
        assert result["result"] == {"sum": 10, "count": 4}   # the ACTUAL result

    def test_no_execution_at_submit(self, tmp_path):
        from rebel_profiler.llm.codescript import submit_script

        sdir = tmp_path / "scripts"
        submit_script(SAFE_SCRIPT, script_dir=sdir)
        files = list(sdir.iterdir())
        # only the script file + sidecar exist — nothing ran
        assert len(files) == 2
        assert not any(f.name.endswith(".rpsresult.json") for f in files)

    def test_unsafe_import_rejected(self, tmp_path):
        from rebel_profiler.llm.codescript import (
            submit_script,
            ScriptRunner,
        )

        sdir = tmp_path / "scripts"
        env = submit_script(UNSAFE_SCRIPT, script_dir=sdir)
        ScriptRunner(sdir).poll_once()
        reject = sdir / f"{env['script_id']}.rpsreject.json"
        assert reject.exists()
        assert "forbidden_import" in reject.read_text()

    def test_eval_rejected(self, tmp_path):
        from rebel_profiler.llm.codescript import submit_script, ScriptRunner

        sdir = tmp_path / "scripts"
        env = submit_script(EVIL_SCRIPT, script_dir=sdir)
        ScriptRunner(sdir).poll_once()
        reject = sdir / f"{env['script_id']}.rpsreject.json"
        assert reject.exists()
        assert "forbidden_builtin" in reject.read_text()

    def test_runtime_error_is_structured(self, tmp_path):
        from rebel_profiler.llm.codescript import load_script_result, submit_script, ScriptRunner

        sdir = tmp_path / "scripts"
        env = submit_script("def run(payload):\n    return 1/0\n",
                            script_dir=sdir)
        ScriptRunner(sdir).poll_once()
        result = load_script_result(env["script_id"], script_dir=sdir)
        assert result["state"] == "failed"
        assert "ZeroDivisionError" in result["error"]

    def test_timeout_killed(self, tmp_path):
        from rebel_profiler.llm.codescript import load_script_result, submit_script, ScriptRunner

        sdir = tmp_path / "scripts"
        env = submit_script("def run(payload):\n    while True: pass\n",
                            script_dir=sdir, timeout_s=2.0)
        ScriptRunner(sdir).poll_once()
        result = load_script_result(env["script_id"], script_dir=sdir)
        assert result["state"] == "failed"
        assert "exceeded" in result["error"]

    def test_missing_run_fn_fails_cleanly(self, tmp_path):
        from rebel_profiler.llm.codescript import load_script_result, submit_script, ScriptRunner

        sdir = tmp_path / "scripts"
        env = submit_script("x = 1\n", script_dir=sdir)
        ScriptRunner(sdir).poll_once()
        result = load_script_result(env["script_id"], script_dir=sdir)
        assert result["state"] == "failed"
        assert "run(payload)" in result["error"]

    def test_idempotent_no_double_execution(self, tmp_path):
        from rebel_profiler.llm.codescript import load_script_result, submit_script, ScriptRunner

        sdir = tmp_path / "scripts"
        env = submit_script(
            "def run(payload):\n"
            "    import json, os\n"
            "    marker = os.path.join(os.path.dirname(__file__) if False else '', '')\n"
            "    return {'n': payload.get('n', 0)}\n",
            script_dir=sdir, payload={"n": 41})
        runner = ScriptRunner(sdir)
        runner.poll_once()
        first = load_script_result(env["script_id"], script_dir=sdir)
        runner.poll_once()   # second pass must skip (result already final)
        second = load_script_result(env["script_id"], script_dir=sdir)
        assert first == second

    def test_empty_source_refused(self, tmp_path):
        from rebel_profiler.llm.codescript import submit_script

        with pytest.raises(UsageError):
            submit_script("  ", script_dir=tmp_path)

    def test_oversized_script_refused(self, tmp_path):
        from rebel_profiler.llm.codescript import MAX_SCRIPT_BYTES, submit_script

        with pytest.raises(UsageError):
            submit_script("x = 1\n" * (MAX_SCRIPT_BYTES // 6 + 100),
                          script_dir=tmp_path)

    def test_list_scripts_states(self, tmp_path):
        from rebel_profiler.llm.codescript import list_scripts, submit_script, ScriptRunner

        sdir = tmp_path / "scripts"
        submit_script(SAFE_SCRIPT, script_dir=sdir, name="pending-one")
        submit_script(UNSAFE_SCRIPT, script_dir=sdir, name="will-reject")
        ScriptRunner(sdir).poll_once()
        rows = {r["name"]: r["state"] for r in list_scripts(sdir)}
        assert rows["pending-one"] == "done"
        assert rows["will-reject"] == "rejected"

    def test_daemon_run_forever_once(self, tmp_path):
        from rebel_profiler.llm.codescript import (
            load_script_result,
            submit_script,
            ScriptDaemon,
        )

        sdir = tmp_path / "scripts"
        env = submit_script(SAFE_SCRIPT, script_dir=sdir,
                            payload={"nums": [7, 7]})
        daemon = ScriptDaemon(sdir)
        daemon.run_forever(once=True)
        result = load_script_result(env["script_id"], script_dir=sdir)
        assert result["result"] == {"sum": 14, "count": 2}


# ---------------------------------------------------------------- script CLI

@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


class TestScriptCli:
    def test_submit_run_result_flow(self, workspace, capsys, tmp_path):
        script_file = tmp_path / "s.py"
        script_file.write_text(SAFE_SCRIPT)
        sdir = str(tmp_path / "sdir")
        assert main([*workspace, "llm", "script", "submit", "--file", str(script_file),
                     "--payload", '{"nums": [2, 3]}', "--name", "cli-sum",
                     "--script-dir", sdir, "-o", "json"]) == 0
        sid = json.loads(capsys.readouterr().out)["data"]["script_id"]
        assert main([*workspace, "llm", "script", "run", "--once",
                     "--script-dir", sdir, "-o", "json"]) == 0
        capsys.readouterr()
        assert main([*workspace, "llm", "script", "result", sid,
                     "--script-dir", sdir, "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["state"] == "done"
        assert payload["data"]["result"] == {"sum": 5, "count": 2}

    def test_script_list(self, workspace, capsys, tmp_path):
        sdir = str(tmp_path / "sdir2")
        assert main([*workspace, "llm", "script", "submit",
                     "--source", SAFE_SCRIPT, "--name", "x",
                     "--script-dir", sdir, "-o", "json"]) == 0
        capsys.readouterr()
        assert main([*workspace, "llm", "script", "list",
                     "--script-dir", sdir, "-o", "json"]) == 0
        rows = json.loads(capsys.readouterr().out)["data"]
        assert rows and rows[0]["state"] == "pending"

    def test_unsafe_script_cli_rejected(self, workspace, capsys, tmp_path):
        sdir = str(tmp_path / "sdir3")
        assert main([*workspace, "llm", "script", "submit",
                     "--source", UNSAFE_SCRIPT, "--script-dir", sdir,
                     "-o", "json"]) == 0
        sid = json.loads(capsys.readouterr().out)["data"]["script_id"]
        assert main([*workspace, "llm", "script", "run", "--once",
                     "--script-dir", sdir, "-o", "json"]) == 0
        capsys.readouterr()
        assert main([*workspace, "llm", "script", "result", sid,
                     "--script-dir", sdir, "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["state"] != "done"   # nothing executed


# ---------------------------------------------------------------- script jobs via daemon

class TestScriptJobs:
    def test_script_job_end_to_end(self, tmp_path):
        from rebel_profiler.llm.codescript import submit_script
        from rebel_profiler.llm.daemon import LlmDaemon, load_result, submit_job

        sdir = tmp_path / "scripts"
        env_s = submit_script(SAFE_SCRIPT, script_dir=sdir,
                              payload={"nums": [10, 20]})
        q = tmp_path / "q"
        env = submit_job(queue_dir=q, kind="script", case_id="",
                         question="", generate=False,
                         requested_by="llm")
        # patch the envelope to point at the script
        path = q / f"{env['job_id']}.llmjob.json"
        envelope = json.loads(path.read_text())
        envelope["script_id"] = env_s["script_id"]
        envelope["script_dir"] = str(sdir)
        body = {k: v for k, v in envelope.items() if k != "checksum"}
        from rebel_profiler.llm.daemon import _sha256_canonical
        envelope["checksum"] = _sha256_canonical(body)
        path.write_text(json.dumps(envelope))
        daemon = LlmDaemon(q, prefer_engine="tiny")
        daemon.run_forever(once=True)
        result = load_result(env["job_id"], queue_dir=q)
        assert result is not None and result["state"] == "done"
        assert result["script"]["result"] == {"sum": 30, "count": 2}


# ---------------------------------------------------------------- native engine upgrades

class TestNativeUpgrades:
    @pytest.fixture()
    def checkpoint(self, tmp_path):
        torch = pytest.importorskip("torch")
        return _mini_checkpoint(tmp_path, torch)

    def test_generate_produces_decoded_text_or_honest_label(self, checkpoint):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine

        engine = NativeStreamingEngine(str(checkpoint),
                                       limits=DEFAULT_LIMITS["mid"],
                                       hf_cache=checkpoint.parent)
        engine.load()
        result = engine.generate("test prompt", max_new_tokens=3)
        assert result.engine == "native"
        assert result.output_tokens <= 3
        assert isinstance(result.text, str) and result.text
        engine.unload()

    def test_incremental_decode_is_bounded(self, checkpoint):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine

        engine = NativeStreamingEngine(str(checkpoint),
                                       limits=DEFAULT_LIMITS["mid"],
                                       hf_cache=checkpoint.parent)
        engine.load()
        result = engine.generate("a b c", max_new_tokens=5)
        assert result.input_tokens > 0
        engine.unload()

    def test_profiling_summary_populates(self, checkpoint):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine

        engine = NativeStreamingEngine(str(checkpoint),
                                       limits=DEFAULT_LIMITS["mid"],
                                       hf_cache=checkpoint.parent)
        engine.load()
        engine.generate("prof", max_new_tokens=2)
        summary = engine.profiling_summary()
        assert summary["steps"] == 2
        assert summary["avg_ms"] >= 0
        engine.unload()

    def test_chat_template_qwen(self, tmp_path):
        torch = pytest.importorskip("torch")
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine

        # name the snapshot dir like a qwen model so the template matches
        qdir = tmp_path / "qwen2.5-0.5b"
        _mini_checkpoint(qdir, torch)
        engine = NativeStreamingEngine(str(qdir), limits=DEFAULT_LIMITS["mid"])
        engine.load()
        prompt = engine.chat_prompt("be brief", "hello")
        assert "<|im_start|>" in prompt
        engine.unload()

    def test_quantized_shards_end_to_end(self, checkpoint):
        pytest.importorskip("torch")
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine
        from rebel_profiler.llm.quant import prepare_model_shards

        out = checkpoint.parent / "shards_e2e"
        prepare_model_shards(checkpoint, out, bits=8)
        engine = NativeStreamingEngine(
            str(checkpoint), limits=DEFAULT_LIMITS["mid"],
            hf_cache=checkpoint.parent,
            layer_shards_saving_path=str(out), compression="8bit")
        engine.load()
        result = engine.generate("quant", max_new_tokens=2)
        assert result.engine == "native"
        assert result.compressed is True
        engine.unload()

    def test_shard_source_preferred_when_present(self, checkpoint):
        pytest.importorskip("torch")
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine
        from rebel_profiler.llm.quant import prepare_model_shards

        out = checkpoint / "rp_shards"
        prepare_model_shards(checkpoint, out, bits=0)
        engine = NativeStreamingEngine(str(checkpoint),
                                       limits=DEFAULT_LIMITS["mid"],
                                       hf_cache=checkpoint.parent)
        engine.load()
        assert engine.source.kind == "shards"
        engine.unload()

    def test_temperature_sampling_deterministic_at_zero(self, checkpoint):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine

        engine = NativeStreamingEngine(str(checkpoint),
                                       limits=DEFAULT_LIMITS["mid"],
                                       hf_cache=checkpoint.parent)
        engine.load()
        r1 = engine.generate("temp", max_new_tokens=2, temperature=0.0)
        r2 = engine.generate("temp", max_new_tokens=2, temperature=0.0)
        assert r1.text == r2.text
        engine.unload()


class TestPrepareCli:
    def test_prepare_requires_local_model(self, workspace, capsys, tmp_path):
        rc = main([*workspace, "llm", "prepare", "org/never-downloaded",
                   str(tmp_path / "sh"), "-o", "json"])
        assert rc != 0   # structured error: no download, ever


# ---------------------------------------------------------------- real torch

class TestNativeRealTorch:
    """Integration with real torch (only runs when it is installed).

    The miniature checkpoint is a genuine safetensors file, so these execute the
    real forward pass, the real block-wise quantizer/dequantizer and the real
    incremental KV-cache decode. A stub cannot prove any of that, and without
    the `engines` CI job these tests skip and the engine ships untested.
    """

    @pytest.fixture(autouse=True)
    def require_torch(self):
        pytest.importorskip("torch")

    @pytest.fixture()
    def checkpoint(self, tmp_path):
        torch = pytest.importorskip("torch")
        return _mini_checkpoint(tmp_path, torch)

    def test_real_forward_pass_produces_tokens(self, checkpoint):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine

        engine = NativeStreamingEngine(str(checkpoint),
                                       limits=DEFAULT_LIMITS["mid"],
                                       hf_cache=checkpoint.parent)
        engine.load()
        assert engine.loaded is True
        result = engine.generate("hello world", max_new_tokens=4, temperature=0.0)
        assert result.engine == "native"
        assert result.input_tokens > 0
        assert 1 <= result.output_tokens <= 4
        assert isinstance(result.text, str)
        engine.unload()
        assert engine.loaded is False

    def test_reload_after_unload_reclaims_state(self, checkpoint):
        # The machine must go quiet between jobs: load, run, unload, repeat.
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine

        engine = NativeStreamingEngine(str(checkpoint),
                                       limits=DEFAULT_LIMITS["mid"],
                                       hf_cache=checkpoint.parent)
        for _ in range(3):
            engine.load()
            engine.generate("x", max_new_tokens=1, temperature=0.0)
            engine.unload()
            assert engine.loaded is False

    def test_quantized_shards_run_through_the_real_dequantizer(self, checkpoint):
        pytest.importorskip("torch")
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.native import NativeStreamingEngine
        from rebel_profiler.llm.quant import prepare_model_shards

        out = checkpoint.parent / "real_shards4"
        manifest = prepare_model_shards(checkpoint, out, bits=4)
        assert manifest["bits"] == 4
        engine = NativeStreamingEngine(
            str(checkpoint), limits=DEFAULT_LIMITS["mid"],
            hf_cache=checkpoint.parent,
            layer_shards_saving_path=str(out), compression="4bit")
        engine.load()
        assert engine.source.kind == "shards"
        result = engine.generate("quantized", max_new_tokens=2, temperature=0.0)
        assert result.compressed is True
        engine.unload()

    def test_plane_selects_native_for_an_on_disk_checkpoint(self, checkpoint):
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.inference import ModelPlane

        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"])
        plane.select_engine(str(checkpoint))
        assert plane.engine_kind == "native"
        plane.unload()
