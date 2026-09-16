# Rebel Profiler v1.3.0 — the Hermes agent: a chat-shaped operator

**Theme:** the LLM stops planning once and starts operating — one gated
`<tool_call>` at a time, in an interactive chat.

## The Hermes agent (`agent chat`)

The agentic pattern popularized by the Hermes fine-tunes, wired into the
same six-gate broker everything else runs through:

* **ChatML tool-calling loop** — the model sees its tools in a `<tools>`
  block inside a ChatML system message and answers with
  `<tool_call>{"name", "arguments"}</tool_call>`; the harness executes and
  returns the redacted result as a `tool`-role `<tool_response>`;
* **one call per turn, always gated** — every call becomes a validated
  proposal: scope, risk, policy, approval, evidence and audit behave exactly
  as in `agent run` — a Hermes session cannot touch anything a manual run
  cannot;
* **a forced final turn** — when the turn budget runs out the model is asked
  for a plain-text final answer, and a tool call emitted on that turn is
  *not* executed: the loop never acts on a result it cannot see;
* **structured refusal without weights** — no model installed means a
  precise install/pull hint, never a hallucinated session.

## Interactive REPL — no goal opens a chat

```bash
rebel-profiler agent chat <case-id>          # live REPL (engine loads once)
you> enumerate h1.lab.example.test
  → [ok ] dns-lookup h1.lab.example.test
hermes> The host resolves to …
/tools /help /exit            # and --llm to pin a model
```

The engine loads a single time; every line is one bounded loop; `/exit`
unloads the weights so the machine goes quiet.

## External-engine wiring fixes (found by a mock OpenAI server)

An end-to-end test against a local OpenAI-compatible mock exposed three
bugs, all fixed:

* a missing `os` import crashed `agent chat` on the external pin;
* `RP_LLM__MODEL` was ignored by `llm generate` and `agent chat`, so remote
  providers always received the hard-coded default model id;
* the model-id precedence is now `--model/--llm` > `RP_LLM__MODEL` >
  config profile > default, verified against the wire.

Verified live against the mock: payloads leave the machine redacted
(`password=…` arrives as `[REDACTED]`), a bad key is a structured HTTP 401
error, and a Hermes loop executed 7 gated, evidence-backed calls over the
remote brain.

## Shell completion (bash + zsh)

Tab completion ships in `completions/`: every subcommand, the live case ids
from the workspace index, per-subcommand flags and `-o` format choices. The
`rp` alias is one line away (see CHEATSHEET).

## Tests can no longer download models

With `airllm` installed, engine-selection tests started real multi-GB HF
downloads and hung the suite. They now stub `AutoModel` (the selection logic
is still exercised) and every airllm load is watchdog-bounded
(`AIRLLM_LOAD_TIMEOUT_S`): a wedged transfer fails structurally instead of
stalling the CLI forever.

## Numbers

* 705 tests passing on a full install (airllm + torch + llama.cpp),
* 679 on the stdlib-only core; CI green on Python 3.11/3.12 + engines job.
