# Roadmap

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
- [x] Knowledge layer: 15 domains / 50 topics + Kali tool matrix + planner context
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
  *(role engine enforced in the broker before gate 1; approvals queue with
  exact-argv storage, re-validation at decision time, `approval decide/run`)*
- [x] Hypotheses engine: testable statements + deterministic criteria
  evaluation against the claim ledger (PDF 4/11)
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
  (SYN → SYN-ACK → ACK), checksum-validated envelopes, idempotent results,
  5-second poll daemon — the LLM writes job files and goes quiet while the
  daemon works
- [x] Browser bridge + MV3 extension: scope-checked browser automation —
  read-only extraction AND user-like interaction (click/type/scroll/submit,
  approval-gated) with per-step action logs; the LLM uses the operator's
  browser the way the operator would
- [x] Privileged system job plane: whitelisted sudo job templates
  (pkg-install, service-*, monitor-mode, …), approval-queued, audited,
  evidence-captured — never a free-form shell
- [x] Feature Forge: the LLM extends the tool itself (vibe-coding style) —
  it writes adapter modules that pass a deterministic static safety gate
  (no subprocess/socket/os/eval/open), a subprocess sandbox test, and are
  HMAC-signed before registration
- [x] Detection engineering lab: EICAR AV test file, canary tripwires,
  IoC bundles, deterministic YARA rulesets — benign artifacts only, all
  evidence-chained
- [x] Complaint package generator: FIA CCW / IC3 / CERT-ready bundles with
  re-verified evidence chains, IoC sets, audit timeline and a verifiable
  bundle hash

## Phase 6 — QA to production acceptance ✅

- [x] E2E scenario coverage through the CLI contract (case → scope → collect
  → surface → report → approval → workflow → complaint, 413 tests)
- [x] Deterministic parser discipline: unknown input yields no claims,
  malformed job files are rejected with structured reasons
- [x] Bounded execution everywhere: session caps, crawl bounds, workflow
  step caps, sandbox timeouts
- [x] Release sign-off: full suite green on Python 3.11+

Each phase keeps Phase 1's invariants: no raw shell, no fake adapters, no
evidence-free claims, scope always fail-closed, LLM proposes but never
decides.

## Phase 7 — LLM plane: AirLLM-mode ✅

- [x] Hardware budget guard: tiers (tiny/low/mid/high), tighten-only env caps
  (`RP_LLM__TIER`, `RP_LLM__MAX_RSS_MB`, `RP_LLM__MAX_CONTEXT_TOKENS`,
  `RP_LLM__MAX_NEW_TOKENS`, `RP_LLM__MAX_MODEL_B`, `RP_LLM__ALLOW_GPU`,
  `RP_LLM__REQUIRE_COMPRESSION`) — RSS ceiling refuses allocation-heavy calls
  with structured errors instead of swap-death
- [x] AirLLM engine with the full low-memory feature set: layer-wise streaming
  (one layer resident at a time), 4/8-bit block-wise compression (CUDA-only —
  refused early with a fix hint on CPU-only boxes), AutoModel across
  Llama/Qwen/DeepSeek/Mistral/Phi/Gemma, prefetching, profiling,
  layer-shards path, `delete_original`, `hf_token`
- [x] GPU-optional placement: explicit `device=` pass-through (CPU/MPS on
  boxes without CUDA — never AirLLM's cuda:0 default), per-generation device
  reporting; **live-verified end to end** on CPU (Qwen2.5-0.5B: coherent
  generation, ~816MB peak RSS, clean unload)
- [x] Deterministic tiny engine fallback — no weights, no RAM spike, no
  hallucination; fallback reason always recorded, never silent
- [x] Model catalog: parameter sizing for repo ids/local paths + tier-aware
  `llm models` shortlist
- [x] LLM planner (`llm plan`, `agent run --llm`): bounded redacted prompt →
  validated proposals through the same no-fake-adapter gate as everything
  else; garbage/unknown-action/undeclared-param replies are structured
  rejections, never executions
- [x] Resident daemon (`llm daemon`): checksummed 3-way handshake job files
  (SYN → SYN-ACK → ACK), idempotent results, tamper rejection, **model
  unloads after every pass** — the machine goes quiet
- [x] Case data via handshake only (`llm data`): bounded, redacted data packs
  (findings + surface graph + exposure) built deterministically from the
  report engines; the LLM never opens the database; packs are delimited DATA,
  never instructions
- [x] Opt-in external brain: OpenAI-compatible provider, pin with
  `RP_LLM__ENGINE=external` + `RP_LLM__API_KEY`/`_FILE` + `RP_LLM__API_BASE`;
  payloads and responses redacted; local AirLLM stays the default — without
  the pin nothing leaves the machine
- [x] CLI surface: `llm status/models/generate/plan/submit/data/result/daemon`
- [x] Autonomous Engineer (`agent auto`) — the LLM repairs and extends the
  tool itself: plan → execute → repair (LLM reviser, bounded, scope/policy
  never auto-retried) → extend (missing capability ⇒ LLM-written adapter
  through the full Forge gate pipeline with bounded rewrite rounds)
- [x] 70 dedicated tests (suite total 483, green)

Each phase keeps Phase 1's invariants: no raw shell, no fake adapters, no
evidence-free claims, scope always fail-closed, LLM proposes but never
decides.

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
- [x] Knowledge layer: 15 domains / 50 topics + Kali tool matrix + planner context
- [x] Layered config with protected (tighten-only) security keys
- [x] CLI: case/scope-check/plan/run/adapters/knowledge/doctor
- [x] Output modes: human, JSON, JSONL, CSV; structured errors everywhere
- [x] Unit tests, all passing

## Phase 2 — OSINT & recon capabilities 🔄 (in progress)

- [x] Source registry with reliability/freshness/independence scoring (PDF 5)
- [x] Claim vs fact model; confidence propagation into the profile
- [x] Prompt-injection defenses for all external content ingestion
- [x] Target normalization + entity resolution pipeline (PDF 4)
- [x] Evidence ledger + audit chain CLI surface (list/verify/show)
- [x] DNS/WHOIS/CT collection adapters with provenance on every observation
  *(passive-dns multi-type dig adapter, record-type-aware parsing, crt.sh
  CT JSON parsing, batch dedupe, full provenance: source/method/task/evidence)*
- [x] Agent harness (LLM-operator loop): planner proposals → six-gate broker →
  claims → report; deterministic passive-first planner shipped, LLM planner
  plugs in via the same Proposal interface
- [x] Findings/report generator: corroborated claims → findings + conflicts
  + low-confidence context, human + JSON

## Phase 3 — Recon, web & correlation 🔄 (in progress)

- [x] Authorized discovery adapters (nmap port/service/OS modules) (PDF 6)
- [x] Exposure mapping + attack-surface graph
  *(typed SurfaceGraph + ExposureMapper over claims; `surface map` /
  `surface exposure` CLI; lateral-pivot hints via shared products)*
- [x] Web crawler with scope-enforced boundaries; TLS/auth/session checks (PDF 7)
  *(mechanical per-URL scope gate, bounded crawl, injectable fetch/TLS probe,
  headers + cookie flags + cleartext forms + TLS posture → evidence-backed claims)*
- [x] Cross-domain fusion + contradiction engine (PDF 9)
  *(subject profiles, noisy-OR corroboration, cross-domain conflicts kept live
  in the ledger and surfaced by fusion)*
- [x] Relationship graph store + graph queries (PDF 8, 10)
  *(migration v3 graph tables; deterministic rebuild from claims; neighbors,
  bounded paths, shared-neighbor related queries; CLI: surface build/show/paths/related)*

## Phase 4 — Case workspace & workflows

- [ ] Full case RBAC (owner/operator/viewer) + approvals queue (PDF 11)
- [ ] Hypotheses, findings and report generation (PDF 4, 11)
- [ ] Workflow DSL + task DAG + approval gates + checkpoints (PDF 14)
- [ ] Scheduler with authorization windows

## Phase 5 — Platform & integrations

- [ ] Plugin SDK: manifests, signing, trust levels, permission grants (PDF 15)
- [ ] API gateway + events/webhooks
- [ ] Search index (FTS5) + object store; graph index evaluation (PDF 16)
- [ ] Credential broker with secret-scoped access (PDF 17)
- [ ] Operations: backup/restore, offline packaging, upgrade hooks (PDF 18)

## Phase 6 — QA to production acceptance

- [ ] 20 scripted E2E scenarios from the acceptance spec (PDF 19)
- [ ] Fuzzing for every parser touching external content
- [ ] Performance benchmarks vs spec budgets
- [ ] Self-repair loop: inspect → implement → test → audit → repair (PDF 20)
- [ ] Release sign-off matrices

Each phase keeps Phase 1's invariants: no raw shell, no fake adapters, no
evidence-free claims, scope always fail-closed.
