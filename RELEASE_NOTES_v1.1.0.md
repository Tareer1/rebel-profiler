# Release Notes — v1.1.0

**Milestone: the LLM plane.** Heavy LLMs on low-end hardware, an LLM that
plans, repairs and extends the tool itself — and data that never leaves the
gated transport. Core remains stdlib-only; AirLLM stays an optional extra.

## Highlights

### AirLLM-mode: 70B-class models on low-end hardware

- Layer-wise streaming (one transformer layer resident at a time), 4/8-bit
  block-wise compression (CUDA-only — refused early with a fix hint on CPU
  boxes), AutoModel across Llama/Qwen/DeepSeek/Mistral/Phi/Gemma, prefetching,
  profiling, layer-shards path, `delete_original`, `hf_token`.
- GPU-optional placement: explicit `device=` pass-through (cpu / cuda / mps —
  never AirLLM's hardcoded `cuda:0` default).
- **Live-verified end to end on CPU**: Qwen2.5-0.5B — coherent generation,
  ~816 MB peak RSS, clean unload.
- Hardware budget guard: tiers (tiny/low/mid/high) with tighten-only env caps
  (`RP_LLM__TIER`, `RP_LLM__MAX_RSS_MB`, `RP_LLM__MAX_CONTEXT_TOKENS`,
  `RP_LLM__MAX_NEW_TOKENS`, `RP_LLM__MAX_MODEL_B`, `RP_LLM__ALLOW_GPU`,
  `RP_LLM__REQUIRE_COMPRESSION`). Structured errors, never swap-death.
- Deterministic tiny fallback — no weights, no RAM spike, no hallucination;
  the fallback reason is always recorded, never silent.

### The Autonomous Engineer (`agent auto`)

One command; the LLM does the rest — including repairing and extending the
tool itself:

```
rebel-profiler agent auto <case-id> "<goal>" --llm Qwen/Qwen3-4B
```

1. **PLAN** — LLM planner emits validated proposals (unknown action/param =
   structured rejection; the no-fake-adapter rule applies to LLM output).
2. **EXECUTE** — the work list runs through the six gates; failures become
   structured error-log entries with deterministic fix hints.
3. **REPAIR** — the LLM reviser reads error + fix hint and returns a corrected
   proposal. Bounded retries; scope/policy blocks are NEVER auto-retried;
   without weights it gives up honestly instead of inventing fixes.
4. **EXTEND** — when the error log reveals a missing capability ("no
   adapter"), the LLM writes its own adapter module and Feature Forge's
   deterministic gates decide: static AST gate → subprocess sandbox test →
   HMAC signature → live registration, with bounded rewrite rounds against
   gate findings.

### Data through the handshake only

- `llm data <case-id> "<question>"` — case data reaches any model exclusively
  as a bounded, redacted data pack (findings + surface graph + exposure)
  delivered over the checksummed 3-way job-file handshake (SYN → SYN-ACK →
  ACK). The LLM never opens the database; packs are delimited DATA, never
  instructions.
- Resident daemon (`llm daemon`) unloads the model after every job — the
  machine goes quiet.

### Local-first, remote opt-in

- Default engine is on-device AirLLM; tiny fallback keeps every contract
  alive where weights cannot load.
- The only remote path is an explicit pin: `RP_LLM__ENGINE=external` +
  `RP_LLM__API_KEY`/`_FILE` + optional `RP_LLM__API_BASE` (any
  OpenAI-compatible endpoint). Outbound payloads and responses are redacted;
  without the pin nothing leaves the machine.

### New CLI surface

```
llm status | models | generate | plan | submit | data | result | daemon
agent run --llm <model>        # LLM planner in a normal session
agent auto <case-id> "<goal>"  # the Autonomous Engineer
```

## Also in this release

- GitHub Actions CI: full pytest suite on push/PR (Python 3.11/3.12) plus the
  tiny-engine fallback smoke check.
- Browser extension hardening: fetch timeout guard (a hung bridge can no
  longer wedge the polling loop); MV3 alarm-clamp documented.
- `CHEATSHEET.md` — every daily-use command, env var and exit code on one
  page, verified against the live CLI parser.
- 483 tests green (70 dedicated to the LLM plane), suite on Python 3.11+.

## Upgrade

```bash
git pull && pip install -e .
# optional heavy-inference extras:
pip install 'rebel-profiler[airllm]'            # local AirLLM (CPU fine)
pip install 'rebel-profiler[airllm-compression]' # + 4/8-bit (CUDA required)
```

No breaking changes: existing cases, evidence chains and workflows are
untouched; the LLM plane is additive.

## The one rule (unchanged)

> The LLM proposes; the system decides. Scope fails closed; nothing runs
> without authorization; nothing is claimed without evidence. Use only on
> targets you are explicitly authorized to assess.
