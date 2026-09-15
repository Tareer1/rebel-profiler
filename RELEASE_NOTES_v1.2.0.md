# Rebel Profiler v1.2.0 — local models that just run, and a bug-bounty workflow

**Theme:** use the model and the authorization you already have.

## GGUF engine — the checkpoint you already own now runs

A new `gguf` engine joins `native`, `airllm`, `external` and `tiny` behind the
same interface, so a single-file quantized checkpoint (llama.cpp, Ollama,
LM Studio export) runs in place:

* **bounded, offline discovery** — `RP_LLM__GGUF_DIRS`, the project tree, and
  the usual llama.cpp / Ollama / LM Studio / HF roots; capped depth and file
  count, no network, no download;
* **the quant tag drives the budget** — `Q4_K_S` is reported as 4-bit
  *compressed*, `F16` as uncompressed, so a compression-demanding tier accepts
  a quantized file and refuses an uncompressed one;
* **conservative matching** — a local checkpoint is never silently substituted
  for a different model you asked for by name;
* **the same guard** — tier model-size caps, the RSS ceiling and the
  context/new-token caps wrap construction, load and every call;
* **honest failure** — a missing `llama-cpp-python` is a structured
  `DependencyUnavailableError` with the exact install command.

## Easy setup

```bash
rebel-profiler llm setup        # hardware, tier, caps, per-engine install commands
rebel-profiler llm local        # checkpoints on disk + fit verdict + run command
rebel-profiler llm generate "…" --local    # best local model that fits the tier
```

`llm setup` includes the prebuilt wheel indexes for `llama-cpp-python` (CPU and
CUDA) so a machine without a C++ toolchain still works. Full walkthrough in
[docs/SETUP.md](docs/SETUP.md).

## The LLM writes its own scripts — and repairs them

The script plane already gated and sandbox-executed model-written code; now the
model can author it and fix it:

```bash
rebel-profiler llm script author "<goal>"    # model writes run(payload)
rebel-profiler llm script run --once         # static gate → sandbox → result
rebel-profiler llm script retry <script-id>  # failure + fix hint back to the model
```

`author` refuses honestly when only the tiny engine is loaded — a placeholder is
never submitted and called a script. Everything a model writes is stored (not
executed) at submit time, passes the same static AST gate and subprocess sandbox
as a human-written script, runs idempotently, and lands as hash-chained evidence.

## Bug-bounty workflow

```bash
rebel-profiler bounty import <case-id> scope.csv --program acme
rebel-profiler bounty run <case-id> --execute
rebel-profiler bounty assess <case-id>

# or state one goal and let the whole chain run, LLM authoring included
rebel-profiler bounty auto <case-id> "this scope came from HackerOne — find what \
you can, test it, and give me a report with real results, no demos" --verbose --save
```

* **`auto`** runs scope → recon → assess → author → execute → repair → report
  from one plain-language goal. The model decides which scripts the goal still
  needs and writes them (stored, never executed at submit time); the static AST
  gate and subprocess sandbox decide whether they run; a real failure or a gate
  rejection goes back to the model within a bounded number of rounds. The
  session refuses a non-active case *before* any stage runs, skips assets that
  do not survive live scope validation, and with no engine holding real weights
  it skips authoring, says why, and still delivers the deterministic audit and
  report — no placeholder script is ever submitted and called a result.

* **`import`** parses HackerOne-style CSV/JSON exports and plain target lists
  into *ordinary scope entries*, records the program as the authorization
  source, imports ineligible assets as exclusions, and skips non-host assets
  with a stated reason. Nothing is special-cased: the same fail-closed scope
  engine gates everything that follows.
* **`run`** audits every in-scope asset through the existing scope-enforced web
  auditor. Plan-only by default, `--execute` to dispatch, refuses a non-active
  case, and skips network ranges with a pointer to the right capability.
* **`assess`** triages the claim ledger into reportable findings with advisory
  severity, CWE, a reproduction command built from the URL the evidence came
  from, and remediation. Unclassifiable observations are listed as unmapped
  rather than inflated, and an empty case produces an honest empty report.

Every reported item traces to hash-chained evidence re-verifiable with
`evidence verify`.

## Knowledge depth

* **Networking internals** — TCP/IP state machine (and why `filtered` vs
  `closed` is the most common source of a wrong port finding), DNS resolution
  path, record semantics and the DNSSEC chain of trust, the TLS handshake and
  certificate validation, HTTP/2–3 framing and proxy normalisation,
  NAT/firewall/NGFW/WAF/load-balancer boundaries, IPv6/SLAAC/NDP and dual-stack
  asymmetry.
* **Vulnerability research** — the vulnerability lifecycle and the zero-day
  window (and that it is closed with compensating controls, not hope), severity
  scoring with CVSS/EPSS and reachability, coordinated disclosure and the CNA
  path, bug-bounty scope discipline and report quality, patch-diff research,
  and exploitability against the mitigation stack.
* Matching techniques and 15 new glossary terms, so the planner and the report
  speak the same language as a triager.

## Repo hygiene

Model weights are gitignored (`dphn/`, `models/`, `*.gguf`, `*.safetensors`). A
multi-GB checkpoint must never enter the repository, and this tree is now safe
to publish as-is.

---

**Boundaries unchanged.** No raw shell path exists anywhere, no adapter is
faked, claims require evidence, scope fails closed, and the LLM proposes while
the system decides. The malware domain remains analysis-only and the detection
lab emits benign artifacts; there is no exploit weaponization and no unattended
offensive action. Use only on systems you are explicitly authorized to assess —
for bounty work, the program's published scope and instructions are that
authorization, and its rate limits and exclusions are binding.
