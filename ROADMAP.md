# Roadmap

Every phase keeps Phase 1's invariants: no raw shell, no fake adapters, no
evidence-free claims, scope always fail-closed, LLM proposes but never decides.

## Phase 1 — Core foundation ✅

- [x] Error taxonomy + documented exit-code contract
- [x] Secret redaction pipeline
- [x] Scope engine (fail-closed, wildcards, exclusions, expiry windows)
- [x] Risk engine (deterministic, versioned, production escalation)
- [x] Policy engine (allow / confirm / approve / deny; tighten-only overrides)
- [x] Execution broker with six-gate sequence (no raw shell)
- [x] Adapter framework + reference adapters (echo, dns-lookup, host-discovery)
- [x] Evidence ledger: SHA-256 content addressing, chain linkage, verify
- [x] Tamper-evident audit chain (edit/delete detection)
- [x] SQLite storage: migrations, case lifecycle, targets, observations, tasks
- [x] Knowledge layer: 15 domains / topics + Kali tool matrix + planner context
- [x] Layered config with protected (tighten-only) security keys
- [x] CLI: case/scope-check/plan/run/adapters/knowledge/doctor
- [x] Output modes: human, JSON, JSONL, CSV; structured errors everywhere
- [x] Unit tests, all passing

## Phase 2 — OSINT & recon capabilities ✅

- [x] Source registry with reliability/freshness/independence scoring (PDF 5)
- [x] Claim vs fact model; confidence propagation into the profile
- [x] Prompt-injection defenses for all external content ingestion
- [x] Target normalization + entity resolution pipeline (PDF 4)
- [x] Evidence ledger + audit chain CLI surface (list/verify/show)
- [x] DNS/WHOIS/CT collection adapters with provenance on every observation
- [x] Agent harness (LLM-operator loop): planner proposals → six-gate broker →
  claims → report; deterministic passive-first planner shipped, LLM planner
  plugs in via the same Proposal interface
- [x] Findings/report generator: corroborated claims → findings + conflicts
  + low-confidence context, human + JSON

## Phase 3 — Recon, web & correlation ✅

- [x] Authorized discovery adapters (nmap port/service/OS modules) (PDF 6)
- [x] Exposure mapping + attack-surface graph
- [x] Web crawler with scope-enforced boundaries; TLS/auth/session checks (PDF 7)
- [x] Cross-domain fusion + contradiction engine (PDF 9)
- [x] Relationship graph store + graph queries (PDF 8, 10)

## Phase 4 — Case workspace & workflows ✅

- [x] Full case RBAC (owner/operator/viewer) + durable approvals queue (PDF 11)
- [x] Hypotheses engine: testable statements + deterministic criteria (PDF 4/11)
- [x] Workflow DSL + task DAG + approval gates + resumable checkpoints (PDF 14)
- [x] Scheduler with authorization windows (`interval=` cron, window expiry)
- [x] Self-repair agent loop (`agent work`): persisted work list → structured
  error log → bounded revise/retry → operator-facing suggestions

## Phase 5 — Platform & integrations ✅

- [x] Plugin SDK: manifests, HMAC signing, trust levels, permission grants (PDF 15)
- [x] Event bus + HMAC-signed webhooks + read-only token-gated API gateway
- [x] Search index (FTS5 with LIKE fallback) + CLI (`search query/rebuild`)
- [x] Credential broker: scrypt-derived keys, HMAC encrypt-then-MAC at rest,
  scoped audited access, metadata-only listing (PDF 17)
- [x] Operations: manifest-verified backup/restore, offline .pyz packaging,
  self-check with deterministic repair (PDF 18/20)
- [x] File-based worker plane: TCP-style three-way handshake job files
- [x] Browser bridge + MV3 extension: scope-checked browser automation
- [x] Privileged system job plane: whitelisted sudo job templates only
- [x] Feature Forge: the LLM extends the tool itself through a static safety
  gate, a subprocess sandbox test and HMAC signing before registration
- [x] Detection engineering lab: EICAR AV test file, canary tripwires,
  IoC bundles, deterministic YARA rulesets — benign artifacts only
- [x] Complaint package generator: FIA CCW / IC3 / CERT-ready bundles

## Phase 6 — QA to production acceptance ✅

- [x] E2E scenario coverage through the CLI contract (case → scope → collect
  → surface → report → approval → workflow → complaint)
- [x] Deterministic parser discipline: unknown input yields no claims,
  malformed job files are rejected with structured reasons
- [x] Bounded execution everywhere: session caps, crawl bounds, workflow
  step caps, sandbox timeouts
- [x] Release sign-off: full suite green on Python 3.11+

## Phase 7 — LLM plane: AirLLM-mode ✅

- [x] Hardware budget guard: tiers (tiny/low/mid/high), tighten-only env caps
  (`RP_LLM__TIER`, `RP_LLM__MAX_RSS_MB`, `RP_LLM__MAX_CONTEXT_TOKENS`,
  `RP_LLM__MAX_NEW_TOKENS`, `RP_LLM__MAX_MODEL_B`, `RP_LLM__ALLOW_GPU`,
  `RP_LLM__REQUIRE_COMPRESSION`) — RSS ceiling refuses allocation-heavy calls
  with structured errors instead of swap-death
- [x] AirLLM engine with the full low-memory feature set: layer-wise streaming,
  4/8-bit block-wise compression (CUDA-only, refused early on CPU-only boxes),
  AutoModel across Llama/Qwen/DeepSeek/Mistral/Phi/Gemma, prefetching,
  profiling, layer-shards path, `delete_original`, `hf_token`
- [x] GPU-optional placement: explicit `device=` pass-through (CPU/MPS/CUDA)
- [x] Deterministic tiny engine fallback — no weights, no RAM spike, no
  hallucination; fallback reason always recorded, never silent
- [x] Model catalog: parameter sizing for repo ids/local paths + tier-aware
  `llm models` shortlist
- [x] LLM planner (`llm plan`, `agent run --llm`): bounded redacted prompt →
  validated proposals through the same no-fake-adapter gate
- [x] Resident daemon (`llm daemon`): checksummed 3-way handshake job files,
  idempotent results, tamper rejection, model unloads after every pass
- [x] Case data via handshake only (`llm data`): bounded, redacted data packs
- [x] Opt-in external brain: OpenAI-compatible provider, pin with
  `RP_LLM__ENGINE=external` + key; payloads and responses redacted
- [x] CLI surface: `llm status/models/generate/plan/submit/data/result/daemon`
- [x] Autonomous Engineer (`agent auto`) — plan → execute → repair → extend
- [x] Native layer-streaming engine: stdlib safetensors reader, real byte-level
  BPE tokenizer, block-wise 4/8-bit quantization, layer shards, profiling,
  chat templates, incremental KV-cache decoding — torch is the only optional
  dependency, and nothing is ever downloaded
- [x] Script plane (`llm script submit/run/result/list`): the LLM writes a code
  file; a static AST gate plus a subprocess sandbox decides whether it runs;
  results are the real returned value, errors carry fix hints, runs are
  idempotent and hash-chained as evidence

## Phase 8 — GGUF engine, setup & bug-bounty workflow ✅

- [x] **GGUF / llama.cpp engine** — single-file quantized checkpoints run in
  place: bounded offline discovery (`RP_LLM__GGUF_DIRS`, project, HF-style and
  llama.cpp/Ollama/LM Studio roots), quant tag read from the filename for the
  budget decision, conservative name matching so an unrelated local model is
  never picked up for an explicit request, same `BudgetGuard` as every other
  engine, and a structured install hint when `llama-cpp-python` is absent
- [x] **Easy setup** — `llm setup` prints this machine's hardware, tier and
  caps, every engine with its exact install command (prebuilt CPU/CUDA wheel
  indexes included) and a recommended next step; `llm local` lists every
  checkpoint on disk with a fit verdict and a copy-paste run command
- [x] **`--local`** — `llm generate --local` picks the best checkpoint already
  on disk that fits the tier; it never downloads
- [x] **LLM script authoring** — `llm script author "<goal>"` has the model
  write the script, then submits it through the same static gate; `llm script
  retry <id>` feeds the failure and the tool's fix hint back to the model and
  re-submits the corrected source. Both refuse honestly when only the tiny
  engine is loaded — no placeholder is ever submitted as a script
- [x] **Bug-bounty scope import** — `bounty import` parses HackerOne-style CSV
  or JSON exports and plain target lists into ordinary scope entries, records
  the program as the authorization source, imports ineligible assets as
  exclusions, and skips non-host assets with a stated reason
- [x] **Authorized check chain** — `bounty run` audits every in-scope asset
  through the scope-enforced web auditor (headers, cookie flags, cleartext
  forms, TLS posture); plan-only by default, `--execute` to dispatch, refuses
  a non-active case, and skips network ranges with a pointer to the right
  capability
- [x] **Reportable-finding triage** — `bounty assess` maps collected claims to
  vulnerability classes with advisory severity, CWE, a reproduction command
  built from the URL the evidence actually came from, and remediation; it
  reads only the claim ledger, reports unproven observations as unmapped
  rather than inflating them, and produces an honest empty report
- [x] **Goal-driven session** — `bounty auto <case-id> "<goal>"` runs the whole
  chain from one stated goal: scope → recon → assess → author → execute →
  repair → report. The model decides which scripts the goal still needs and
  writes them; the static gate and sandbox decide whether they run; failures
  and gate rejections go back to the model within a bounded number of rounds.
  Refuses a non-active case before any stage runs, skips assets that do not
  survive live scope validation, and when no engine with real weights is loaded
  it skips authoring, says why, and still delivers the deterministic audit and
  report — it never substitutes a placeholder script and calls it a result
- [x] **Knowledge depth** — networking internals (TCP/IP state machine, DNS
  wire format & DNSSEC, TLS handshake, HTTP/2–3 framing and proxy
  normalisation, NAT/firewall boundaries, IPv6/NDP dual-stack risk) and a
  vulnerability-research block (zero-day window, CVSS/EPSS-based prioritisation,
  coordinated disclosure and CNA process, bounty scope discipline, patch
  diffing, exploitability and the mitigation stack) — plus the matching
  techniques and glossary terms
- [x] **Repo hygiene** — model weights are gitignored (a multi-GB checkpoint
  must never enter the repository), so the tree is always safe to publish
