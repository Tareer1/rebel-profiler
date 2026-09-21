# Rebel Profiler v1.4.0 — Hermes works on real hardware

A feature release born from a live debugging session: every finding below was
reproduced on an actual laptop (4-core CPU, no CUDA, 31.9 GB RAM) running a
real Qwen2.5-Coder-7B GGUF checkpoint, then fixed and regression-tested.

## The headline: `rebel-profiler hermes` actually answers now

Running the interactive Hermes shell against a real local model exposed a
stack of compounding problems that tests could not see.

### 1. Runaway generation past end-of-turn (gguf engine)

`GgufEngine.generate` called llama.cpp with **no stop sequences**. An
instruct-tuned ChatML checkpoint emits `<|im_end|>` when it is done; without
a stop list, llama.cpp kept sampling *through* the turn boundary — up to the
full 1024-token ceiling — so every agent turn paid for a wall of rambling
text instead of one reply. The engine now stops on the standard end-of-turn
markers (`<|im_end|>`, `<|im_start|>`, `<|eot_id|>`, `<|end_header_id|>`,
`<|end_of_text|>`).

### 2. First-turn freeze: a ~1,900-token tool contract at ~7 tok/s

The Hermes system prompt embedded the tool schemas as pretty-printed,
indent-2 JSON — about 1,900 tokens. On the target hardware llama.cpp
prefills at roughly 7 tokens/second, which measured **262 seconds before the
first reply token**. The prompt now renders as a compact signature list
(`- name(param!, typed_param) :: description`) — same names, params,
required-flags and descriptions, ~3x fewer tokens, verified live: the same
greeting that burned 8 turns of tool chaos now returns in **1 turn**.

### 3. Wrong thread count on hyper-threaded CPUs

`n_threads=os.cpu_count()` reports logical CPUs (8 on this box), but
llama.cpp saturates both SMT siblings of a core and loses throughput. The
engine now counts unique `(physical id, core id)` pairs from `/proc/cpuinfo`
and starts with the honest 4 — measured slightly faster, and leaves fewer
cycles for the rest of the machine.

### 4. Bare `exit` became an LLM goal (REPL)

Typing `exit` (no slash) in the hermes / agent-chat REPL fell through to the
agent loop: the model spent a multi-minute CPU turn interpreting the word
"exit". Bare `exit`, `quit`, `q`, `:q`, `bye` now quit the shell. A
regression test pins it.

### 5. Context truncation amputated the newest message (gguf engine)

When a long session outgrew the tier's context window, `_fit_input` kept the
*front* of the prompt — chopping off the current user turn and making the
model answer a question it never saw. Truncation is now head + tail (system
rules stay, the live exchange stays, the middle ages out), with a visible
`[older turns trimmed]` marker.

### 6. Honesty upgrades

- Bounded default replies (320 tokens) for hermes turns — cost proportional
  to what the model said, not to what it rambled.
- The shell prints a first-turn expectation note ("reads the whole tool
  contract — can take a few minutes on CPU") and a per-turn `(N turn(s),
  Xs)` footer, so a slow turn is a known cost, not a frozen screen.
- The goal message tells the model not to call tools for show: greetings and
  questions about itself get plain-prose answers.
- CHEATSHEET documents the CPU reality check.

## Also in this release

- Empty model pin volunteers the best-fitting **local** checkpoint (GGUF
  ranked by tier fit → params, then HF cache) before anything network-bound;
  when nothing fits, the fallback reason names the exact file, its size
  class and the `--tier` escape instead of a misleading "airllm unavailable".
- Source-tree model dirs (`models/`, `gguf/`, `weights/`, `dphn/`) are
  discovery roots, so a repo-local checkpoint is found from any cwd.
- `--tier` on `hermes` / `agent chat`; refusal messages carry concrete
  escape hatches (`--llm`, `--tier`).
- `gguf_fits()` is public API: the selector reuses the same fit verdict as
  `llm local` / `llm models`.
- Repo hygiene: stray workbench artifacts removed; 10 new tests.
- Full suite: **769 passed, 23 skipped** on Python 3.11/3.12 CI.
