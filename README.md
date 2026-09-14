# Rebel Profiler

**Kali Linux Cybersecurity Intelligence & Authorized Security Operations Framework**

Rebel Profiler turns natural-language investigation goals into *controlled,
authorized, evidence-backed* security operations. It is built for Kali Linux
and follows one non-negotiable design law:

> **The LLM reasons. The system decides. Nothing runs without authorization,
> and nothing is claimed without evidence.**

## Design laws (enforced in code, not by prompt)

| Law | Where it lives |
|-----|----------------|
| LLM proposes, never decides | `security/policy.py` — deterministic, versioned policy engine |
| Scope fails closed | `security/scope.py` — unknown target ⇒ blocked; exclusions win |
| No raw shell, ever | `execution/broker.py` — structured actions + whitelisted params only |
| LLM runs tools, not shells | `execution/tool_exec.py` — whitelisted binaries, validated argv, scope-checked args, approval-gated |
| No fake adapters | `execution/broker.py` — unknown action is a hard error, never simulated |
| No evidence, no claim | `evidence/store.py` — SHA-256 content-addressed, hash-chained ledger |
| Tamper-evident audit | `evidence/audit.py` — every decision and action is hash-linked |
| Secrets never leak | `core/redact.py` — conservative redaction on every output path |
| Config can only tighten | `core/config.py` — protected security keys reject weakening |
| Claims are not facts | `intel/claims.py` — confidence-scored, provenance-carrying claims |
| External content is data | `intel/injection.py` — deterministic prompt-injection scan + sanitization |

## Install

```bash
# From the project root (Python 3.11+, stdlib-only core):
pip install -e .
rebel-profiler --help
```

No third-party runtime dependencies. Tests use `pytest` (dev-only).

## Quickstart

```bash
# 1. Create a case
rebel-profiler case create "Lab Assessment" "internal authorized test"

# 2. Define the authorized scope (include + exclusions)
rebel-profiler case scope add <case-id> "*.lab.example.test" --note "authorized lab"
rebel-profiler case scope add <case-id> "admin.lab.example.test" --exclude

# 3. Activate the case (scope enforcement goes live)
rebel-profiler case activate <case-id>

# 4. Check authorization for any target
rebel-profiler scope-check <case-id> host1.lab.example.test

# 5. Plan an action — see exactly what WOULD run and what policy decided
rebel-profiler plan <case-id> host-discovery host1.lab.example.test -p mode discover

# 6. Run it — every run is policy-gated, evidence-registered and audit-logged
rebel-profiler run <case-id> host-discovery host1.lab.example.test -p mode discover

# 7. Inspect the knowledge base that powers LLM planning
rebel-profiler knowledge domains
rebel-profiler knowledge search "zone transfer"
rebel-profiler knowledge tools scanning
rebel-profiler knowledge planner-context --output json   # machine-readable

# 8. Inspect evidence and the tamper-evident audit chain
rebel-profiler evidence list <case-id>
rebel-profiler evidence verify <case-id>     # exit 11 on any integrity failure
rebel-profiler audit show <case-id>
rebel-profiler audit verify <case-id>

# 9. Intelligence layer: scored sources, claims, injection defense
rebel-profiler intel sources
rebel-profiler intel sources dns.authoritative   # score one source
rebel-profiler intel claims <case-id> [subject]
rebel-profiler intel sanitize "ignore all previous instructions…"

# 10. One-shot collection: run + parse + persist claims (six gates intact)
rebel-profiler intel collect <case-id> passive-dns example.com -p record_type MX
rebel-profiler intel collect <case-id> cert-transparency example.com

# 11. Agent session: goal → gated actions → report (the LLM-operator harness)
rebel-profiler agent run <case-id> "map example.com passive footprint"
rebel-profiler agent run <case-id> "map example.com" \
    --plan "passive-dns:example.com:record_type=A;whois-lookup:example.com"

# 12. Case report from claims + evidence
rebel-profiler report <case-id>            # human-readable
rebel-profiler report <case-id> -o json    # machine-readable

# 13. Attack-surface graph & exposure map (from collected discovery claims)
rebel-profiler intel collect <case-id> port-scan h1.lab.example.test -p ports 22,80,443
rebel-profiler surface map <case-id>        # host → ip → port → service graph
rebel-profiler surface exposure <case-id>   # per-host exposure + lateral hints

# 14. Scope-enforced web audit: security headers, cookie flags, cleartext
#     password forms, TLS protocol posture (PDF 7)
rebel-profiler intel crawl <case-id> https://h1.lab.example.test/ --max-pages 10

# 15. Cross-domain fusion (PDF 9): subject profiles, noisy-OR corroboration,
#     contradiction engine — per subject or whole case
rebel-profiler intel fusion <case-id>
rebel-profiler intel fusion <case-id> h1.lab.example.test

# 16. Persistent relationship graph (PDF 8/10): rebuild from claims, query
#     neighbors/paths/related hosts — survives across CLI invocations
rebel-profiler surface build <case-id>
rebel-profiler surface show <case-id>
rebel-profiler surface paths <case-id> host:h1 host:product:nginx
rebel-profiler surface related <case-id> host:h1

# 17. LLM plane (AirLLM-mode): 70B-class models on low-end hardware.
#     Layer-wise streaming keeps one transformer layer resident at a time;
#     4/8-bit block-wise compression, CPU-only + Apple-silicon (MPS)
#     placement, and a hardware budget guard that refuses to swap-die.
rebel-profiler llm status                 # hardware budget + tier + caps
rebel-profiler llm models                 # what fits THIS machine
rebel-profiler llm generate "summarize: …" --model Qwen/Qwen3-4B
rebel-profiler llm plan <case-id> "map example.com"   # LLM planner (dry)
rebel-profiler agent run <case-id> "map example.com" --llm Qwen/Qwen3-4B
rebel-profiler agent auto <case-id> "map example.com fully"   # Autonomous Engineer
rebel-profiler llm submit "long job"      # SYN → resident daemon → ACK
rebel-profiler llm data <case-id> "what is exposed?"   # case data via job file
rebel-profiler llm daemon                 # claim → generate → UNLOAD the model

# LLM uses the operator's browser (extension/, load unpacked in Chrome):
# poll (SYN) → claim (SYN-ACK) → result (ACK); scope re-checked client-side
rebel-profiler browser serve <case-id>    # localhost bridge for the extension

# 18. Health check
rebel-profiler doctor
```

### AirLLM-mode: heavy LLMs on low-end hardware

The LLM plane wraps the full AirLLM feature set behind the hardware budget
(`pip install 'rebel-profiler[airllm]'`): layer-wise streaming (one layer
resident at a time), 4/8-bit block-wise compression (CUDA only — on CPU-only
boxes the guard refuses compression up front because AirLLM's bitsandbytes
path quantizes on-device; uncompressed layer streaming already keeps RAM tiny
— verified live: Qwen2.5-0.5B, ~816MB peak RSS, coherent generation, clean
unload), AutoModel across Llama/Qwen/DeepSeek/Mistral/Phi/Gemma, prefetching,
profiling, layer-shards path, `delete_original`, `hf_token` — GPU optional,
CPU/MPS placement automatic (AirLLM's `device=` is set explicitly, never the
cuda:0 default). Tighten-only env caps (`RP_LLM__TIER`, `RP_LLM__MAX_RSS_MB`,
`RP_LLM__MAX_CONTEXT_TOKENS`, `RP_LLM__MAX_NEW_TOKENS`, `RP_LLM__MAX_MODEL_B`,
`RP_LLM__ALLOW_GPU`, `RP_LLM__REQUIRE_COMPRESSION`) can never loosen a tier.
Where weights cannot load at all, a deterministic tiny engine keeps every
downstream contract alive — no hallucinated output, ever. The planner only
emits proposals through the same no-fake-adapter gate as every other source,
and the resident daemon unloads the model after every job so the machine goes
quiet again.

**Local-first, remote opt-in.** AirLLM runs on-device and is the default;
the only remote path is an explicit pin — `RP_LLM__ENGINE=external` plus
`RP_LLM__API_KEY` (or `RP_LLM__API_KEY_FILE`) and optionally
`RP_LLM__API_BASE` for any OpenAI-compatible endpoint. Without the pin
nothing ever leaves the machine; with it, outbound payloads are redacted
first and responses are redacted on arrival.

**Data reaches the model through the same 3-way handshake.** The LLM never
opens the case database: `llm data <case-id> "question"` writes a checksummed
job file; the resident daemon deterministically builds a bounded, redacted
data pack (findings + surface graph + exposure, size-capped), optionally
analyzes it with the loaded engine, and writes the result file. The pack is
delimited DATA — never instructions — exactly like every other untrusted
input in the tool.

**The tool extends itself.** When a capability is missing, the LLM writes its
own adapter through Feature Forge (`forge propose/register`): a deterministic
static gate (no subprocess/socket/os/eval/open reach), a sandbox test of the
argv builder, HMAC signing before registration. The same loop serves the LLM
plane: missing planner capabilities become forged adapters instead of shell
escape hatches.

### The Autonomous Engineer (`agent auto`)

One command, the LLM does the rest — repair and extend the tool itself:

```
rebel-profiler agent auto <case-id> "map example.com fully" --llm Qwen/Qwen3-4B
```

  1. **PLAN** — the LLM planner reads the goal + the live action contract and
     emits validated proposals (unknown action/param = structured rejection).
  2. **EXECUTE** — the work list runs through the six gates; failures become
     structured error-log entries with deterministic fix hints.
  3. **REPAIR** — the LLM reviser reads the error + fix hint and returns a
     corrected proposal (bounded retries; scope/policy blocks are NEVER
     auto-retried; no weights → honest give-up, never invented fixes).
  4. **EXTEND** — when the error log says the capability itself is missing
     ("no adapter"), the LLM writes a new adapter and Feature Forge's gates
     decide: static AST gate → subprocess sandbox → HMAC signature → live
     registration, with bounded rewrite rounds against gate findings.

Every phase is gated, evidenced and audited. The operator reads the session
report and decides what's next — the tool grows, the law doesn't change.

## Output modes

Every command supports `--output human|json|jsonl|csv` (PDF 3 contract):

```bash
rebel-profiler case list -o json     # pretty JSON
rebel-profiler case list -o jsonl    # one JSON object per line
rebel-profiler case list -o csv      # flattened CSV
```

Errors are structured in every mode: `what happened / why / next action`,
with a documented exit code (`0` ok, `2` usage, `3` config, `5` scope,
`7` dependency, `11` evidence, `12` state, …).

## The six gate sequence

Every `run` passes through all gates, in order, before any tool executes:

```
structured request ─▶ 1. adapter exists? (no-fake-adapter)
                      2. params match declared contract?
                      3. target in ACTIVE scope? (fail closed)
                      4. risk classified (versioned rules, not opinions)
                      5. policy: allow ▸ confirm ▸ approve ▸ deny
                      6. execute ▸ evidence ▸ audit
```

A denial at **any** gate means nothing executes — and the denial itself is
audited.

## Knowledge layer

15 domains (foundations → networking → security → footprinting → scanning →
enumeration → system → malware → sniffing → social engineering → wireless →
attack/defense → cryptography → architecture → cloud/IoT), each with topics
wired to capability classes, authorization gates, Kali tooling and defensive
counterparts. This is the structured context the LLM planner consumes —
`rebel-profiler knowledge planner-context -o json` emits it machine-readably.
Content is original to this project; it mirrors standard curriculum coverage
without reproducing any external text.

## Intelligence layer (Phase 2, in progress)

The `intel/` plane turns executed, policy-gated collection into **claims with
provenance** — never bare facts:

* **Source registry** (`intel sources`) — every source carries a deterministic
  admiralty-style score: reliability grade (A–E), freshness decay
  (30-day half-life) and independence, combined by a versioned weighted mean.
* **Claim ledger** — confidence is *computed* from the source score, never an
  LLM opinion. Independent corroboration upgrades a claim to `corroborated`;
  contradictions demote the lower-confidence side to `contradicted` (kept,
  never deleted).
* **Entity resolution** — raw observations normalize into canonical
  hosts/domains/IPs and group into alias-linked entities.
* **Injection defense** — every external blob is pattern-scanned for
  instruction-style content and wrapped as clearly-delimited untrusted data
  before it can reach any planner context.
* **Collection pipeline** — broker results → hash-chained evidence → parsed
  claims (DNS answers record-type aware, WHOIS fields, crt.sh CT JSON) →
  persisted observations.
* **Agent harness** (`agent run`) — the LLM-operator loop: a planner proposes
  `ActionRequest`s (only declared actions/params), the broker gates and runs
  them, denials come back as feedback, successful runs become claims, and the
  session ends with a generated report. Ships today with a deterministic
  passive-first planner; any LLM can plug in by emitting the same Proposal
  objects. This is the 10x lever: the operator states a goal, the harness
  does the chained work in minutes with every step audited.
* **Report generator** (`report`) — findings from corroborated/live claims,
  conflicts surfaced explicitly, low-confidence context separated, stats and
  provenance in both human and JSON form.
* **Discovery & surface** (Phase 3) — `port-scan`, `service-detect` and
  `os-fingerprint` nmap adapters (whitelisted flag sets, polite timing only,
  T5 never offered); nmap output parsed record-style into port/service/product/
  version claims; `surface map` builds the typed graph
  (host → ip → port → service/product/version) and `surface exposure` sums up
  per-host exposure with lateral-pivot hints (hosts sharing the same product).
* **Controlled tool execution** (`exec-tool`, the LLM's hands) — the agent
  can run vetted Kali tools (nmap, dig, whois, enum4linux-ng, sslscan, …)
  through one adapter with four mechanical controls: a binary whitelist that
  excludes shells/interpreters/download-execute tools, a per-tool flag
  whitelist, strict safe-token argv validation (no shell interpreter exists
  anywhere in the path), and approval gating (risk=high). Host-like arguments
  are scope-checked at plan time and the exact argv is audit-logged before
  dispatch. This is how the LLM does the operator's actual work at 10x speed
  without a raw-shell escape hatch.
* **Cross-domain fusion** (`intel fusion`, PDF 9) — joins DNS, certificates,
  WHOIS, scanning and web views per subject: same (attribute, value) from
  independent sources fuses into one entry with noisy-OR confidence
  (0.6+0.6 → 0.84, never 1.2); cross-domain contradictions surface with every
  supporting source on each side, and both sides always stay in the ledger.
* **Persistent relationship graph** (`surface build/show/paths/related`,
  PDF 8/10) — the case's world model (host → ip → port → service/product/
  version, plus web findings) rebuilds deterministically from claims into
  SQLite (migration v3) and survives across invocations; queries cover
  neighbors (both directions), bounded BFS paths and shared-neighbor
  peers for lateral movement analysis.
* **Scope-enforced web audit** (`intel crawl`, Phase 3/PDF 7) — a bounded
  crawler whose scope gate is *mechanical*: every seed and discovered URL is
  validated against the live case scope before any fetch, out-of-scope links
  are never touched, non-HTML is never parsed, and fetched bytes are
  registered as hash-chained evidence. Four deterministic check families:
  security headers (CSP/HSTS/XFO/…), cookie flags (Secure/HttpOnly/SameSite),
  cleartext password forms, and TLS protocol posture — findings become
  provenance-carrying claims.

## Autonomous operations (Phases 4–6, shipped)

Beyond the six-gate broker and intel plane, the tool now ships the full
operations stack:

* **RBAC & approvals** — per-case owner/operator/viewer roles enforced in the
  broker before every other gate; headless approval-gated actions land in a
  durable queue (`approval list/decide/run`) whose stored argv is re-validated
  against live scope/policy at decision time.
* **Hypotheses** — state testable statements with deterministic criteria
  (`hypothesis add/evaluate`) checked against the claim ledger; supported /
  refuted / untestable verdicts with per-check provenance.
* **Workflows** — a human-writable DSL with a resumable DAG runner
  (`workflow create/run/approve/status`); human approval gates pause the run,
  every finished step is a checkpoint, nothing re-executes.
* **Scheduler** — authorization-windowed schedules (`schedule add/tick`);
  outside the window nothing fires, expired windows auto-expire.
* **Self-repair agent** (`agent work`) — the LLM keeps a persisted work list,
  every failure becomes a structured error-log entry with a fix hint, the
  planner revises and retries (bounded), scope/policy blocks are never
  auto-retried, and the session ends with concrete suggestions awaiting the
  operator's decision.
* **File-based worker plane** (`worker submit/run/list`) — TCP-style
  three-way handshake over job files: SYN (job envelope with checksum) →
  SYN-ACK (ack file, state=running) → ACK (result file). The LLM writes job
  files and goes quiet (freeing RAM/GPU) while the 5-second daemon executes
  everything through the same six gates; results are idempotent and
tamper-verified.
* **Browser bridge + extension** (`browser submit/serve/result`) — the LLM
  uses the operator's own browser: scope-checked, token-gated localhost
  bridge; read-only extraction AND user-like interaction (click/type/scroll/
  submit — form submission is approval-gated) with per-step action logs;
  failures produce structured error logs the LLM reads, fixes and re-submits.
* **Privileged system jobs** (`system submit/run/templates`) — whitelisted
  sudo job templates only (install a package, start/stop a service, monitor
  mode): validated params, approval-queued, audited, evidence-captured.
  There is no free-form shell path anywhere.
* **Feature Forge** (`forge propose/list/register`) — vibe-coding, inside
  the law: when the tool lacks a capability, the LLM *writes its own adapter
  module*; a deterministic static gate rejects shell/os/socket/eval/open
  reach, a subprocess sandbox test exercises the argv builder, and accepted
  modules are HMAC-signed and registerable. The LLM grows the tool itself;
  the system stays in control.
* **Detection engineering** (`detection generate/kinds/list`) — benign,
  industry-standard artifacts only: EICAR AV test files, canary tripwires,
  IoC bundles and deterministic YARA rulesets, all hash-chained as evidence.
  No functional malware is ever generated — the module is the blue-team
  counterpart of the malware-analysis domain.
* **Complaint packages** (`complaint build/list`) — FIA CCW / IC3 / CERT-ready
  bundles: re-verified evidence chain, IoC set, audit timeline, narrative and
  a verifiable bundle hash. Built for handing a case to the authorities.
* **Search, events, API, ops** — FTS5 search over claims/observations;
  structured events with HMAC-signed webhooks; a read-only token-gated API
  gateway (`serve`); manifest-verified backup/restore, offline `.pyz`
  packaging and self-check with deterministic repair (`ops`).
* **LLM plane, AirLLM-mode** (`llm status/models/generate/plan/submit/
  result/daemon`, `agent run --llm`) — the full AirLLM low-memory feature
  set behind a tighten-only hardware budget: layer-wise streaming, 4/8-bit
  compression, AutoModel, prefetching/profiling/layer-shards/`delete_original`,
  CPU + Apple-silicon placement, RSS guard with tier caps, a checksummed
  file-transport daemon that unloads the model after every job, and an LLM
  planner whose output passes the same validation gates as everything else
  (unknown action or undeclared param = structured rejection, never
  execution).

## Development

```bash
python3 -m pytest tests/ -q      # 483 tests
python3 -m rebel_profiler.cli.main doctor
```

## Status

Phases 1–6 complete: core foundation, OSINT/recon intelligence, surface &
fusion, case workflows/RBAC, platform integrations (worker plane, browser
bridge, Feature Forge, complaint packages) and QA acceptance. See
[ROADMAP.md](ROADMAP.md) for the shipped checklist and
[ARCHITECTURE.md](ARCHITECTURE.md) for the plane model and data flow.

**Use only on systems you are explicitly authorized to assess.** The tool
enforces scope and policy mechanically, but authorization documents, legal
review and operational competence remain the operator's responsibility.
