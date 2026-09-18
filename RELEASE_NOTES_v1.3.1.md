# Rebel Profiler v1.3.1 — chat-template fix + CI badge

A patch release: one real bug found on hardware, fixed and regression-tested.

## The bug: instruct checkpoints degenerated on raw planner prompts

Running the agent against a real local GGUF checkpoint (Qwen2.5-Coder-7B,
ChatML) exposed it live: `agent run --llm <model>` failed with *"LLM planner
reply is not parsable as proposals"* — the model's reply was pages of the
same repeated character.

**Root cause.** Every engine carries a `chat_prompt()` that renders a
system/user pair into its checkpoint family's trained template, but the
callers that compose *instructions* — the LLM planner, the script-authoring
path (`codegen`), the autonomous repair reviser and the daemon's data-pack
answering — never used it. They handed the raw instruction text to
`plane.generate()`. A base-style call against an *instruct* checkpoint is
out-of-distribution: Qwen2.5 fell into a degenerate loop, and every gated
proposal was unparsable. Hermes was never affected because it renders
ChatML client-side by design.

**The fix.** One new method, `ModelPlane.chat_generate(system, user)`:
it renders through the loaded engine's own `chat_prompt()` (engines without
a template fall back to the same plain concatenation they already applied)
and then generates. All four instruction paths now go through it, each with
a system message that restates the untrusted-data rule where external
content is involved. Regression tests pin the routing: the planner must
emit the template, and `chat_generate` must apply it.

```bash
# now works end to end with any instruct GGUF on disk:
rebel-profiler agent run <case-id> "map lab.example.test" \
    --llm dphn/Qwen2.5-Coder-7B-Instruct-abliterated-Q4_K_M.gguf
```

## Restoring a truncated checkpoint: `tools/fetch_dphn.py`

A 32-byte file whose entire content is `Auth failed: credentials expired`
is a failed download wearing a model's name — and it *listed* fine
(`llm local` estimated its size class from the filename) while the
integrity reader knew better. The new helper is the honest way to get the
real checkpoint: HTTP-range parts in parallel, each part resumable, size-
verified, then concatenated and re-checked (339 tensors, `ok`) before it is
called a model. HF's per-connection throttle makes single-stream downloads
of multi-GB checkpoints crawl; parallel ranges do not.

```bash
python3 tools/fetch_dphn.py     # resumable — re-run until it says DONE
```

## CI badge

The README now carries the CI status badge (pytest matrix on Python
3.11/3.12 + the engines job), so the green the project keeps claiming is
one glance away.

## Numbers

* 705 tests passing on a full install (airllm + torch + llama.cpp) — two
  more than v1.3.0, both regression tests for the chat-template routing;
* verified live on hardware: 7B Q4_K_M generation (75 tokens, ~7.9 GB peak
  RSS against the high tier's 16 GB ceiling), a 6-step gated agent session
  and a Hermes chat turn with a real `dns-lookup` tool call.
