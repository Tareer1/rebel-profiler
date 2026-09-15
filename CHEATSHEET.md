# Rebel Profiler — Quickstart Cheat-Sheet

Every daily-use command in one page. Replace `<case-id>` with your case id
(`case list` shows them). All commands accept `-o json|jsonl|csv|human`.

---

## 0. One-time setup

```bash
pip install -e .                                # core (stdlib-only)
rebel-profiler doctor                           # health check

# Local LLM engines — pick what fits your checkpoints (see docs/SETUP.md)
pip install 'rebel-profiler[gguf]'              # GGUF files (llama.cpp/Ollama/LM Studio)
pip install 'rebel-profiler[native]'            # HF safetensors already on disk
pip install 'rebel-profiler[airllm]'            # airllm layer streaming

rebel-profiler llm setup                        # hardware-aware install guidance
rebel-profiler llm local                        # checkpoints on disk + run commands
rebel-profiler llm status                       # what can THIS machine run?
rebel-profiler llm models                       # which models fit?
```

## 1. Case lifecycle (every job starts here)

```bash
rebel-profiler case create "Job Name" "description"
rebel-profiler case scope add <case-id> "*.target.com" --note "authorized"
rebel-profiler case scope add <case-id> "admin.target.com" --exclude
rebel-profiler case activate <case-id>          # scope enforcement goes live
rebel-profiler scope-check <case-id> host.target.com
rebel-profiler case list                        # ids + status
rebel-profiler case show <case-id>
rebel-profiler case close <case-id>
```

## 2. The daily driver — Autonomous Engineer

State the goal. The LLM plans, runs (six gates), repairs failures, and
forges any missing adapter through the safety gates. You read the report.

```bash
rebel-profiler agent auto <case-id> "map target.com passive footprint" \
    --llm Qwen/Qwen3-4B
```

Variants:

```bash
rebel-profiler agent auto <case-id> "<goal>" \
    --llm Qwen/Qwen3-4B --max-actions 20 --max-repair-attempts 3
RP_LLM__ENGINE=external RP_LLM__API_KEY=sk-... \
    rebel-profiler agent auto <case-id> "<goal>"     # remote brain (opt-in)
```

Manual/surgical modes:

```bash
rebel-profiler agent run <case-id> "<goal>" --llm Qwen/Qwen3-4B   # LLM plans once
rebel-profiler agent run <case-id> "<goal>" \
    --plan "passive-dns:target.com:record_type=A;whois-lookup:target.com"
rebel-profiler agent work <case-id> "<goal>" --plan "..."          # + repair loop
```

## 3. LLM plane (AirLLM-mode)

```bash
rebel-profiler llm status                       # budget, tier, caps
rebel-profiler llm status --tier low            # pretend to be a smaller box
rebel-profiler llm models                       # fits-this-machine shortlist
rebel-profiler llm generate "summarize: ..." \
    --model Qwen/Qwen3-4B --max-tokens 200      # one shot; loads then unloads
rebel-profiler llm generate "…" --model /path/to/model.gguf   # a local GGUF file
rebel-profiler llm generate "…" --local         # best local model that fits
rebel-profiler llm plan <case-id> "find subdomains" --model Qwen/Qwen3-4B
```

### The LLM writes and repairs its own scripts

```bash
rebel-profiler llm script author "<goal>"       # model writes run(payload)
rebel-profiler llm script run --once            # static gate → sandbox → result
rebel-profiler llm script result <script-id>    # the ACTUAL returned value
rebel-profiler llm script retry <script-id>     # feed the failure back to the model
rebel-profiler llm script list
```

Stored, never executed at submit time; idempotent; a script gets exactly the
reach the static gate allows — no more than a human-written one.

Unattended (job files — the CLI stays tiny, the daemon gets heavy):

```bash
rebel-profiler llm submit "long analysis prompt" --model Qwen/Qwen3-4B
rebel-profiler llm daemon                       # resident; UNLOADS after every job
rebel-profiler llm result <job-id>              # read the ACK
rebel-profiler llm data <case-id> "what is exposed and why?"   # case analysis
rebel-profiler llm data <case-id> "question" --pack-only       # data pack, no model
```

Local-first rule: without `RP_LLM__ENGINE=external` **nothing leaves the
machine**. The engine order is always airllm → tiny (honest fallback, reason
recorded), never a silent substitution.

## 4. One-shot collection (each = run + evidence + claims)

```bash
rebel-profiler intel collect <case-id> passive-dns target.com -p record_type MX
rebel-profiler intel collect <case-id> whois-lookup target.com
rebel-profiler intel collect <case-id> cert-transparency target.com
rebel-profiler intel collect <case-id> port-scan h1.target.com -p ports 22,80,443
rebel-profiler intel crawl <case-id> https://h1.target.com/ --max-pages 20
rebel-profiler run <case-id> <action> <target> -p key value --dry-run  # preview
rebel-profiler intel claims <case-id> [subject]
rebel-profiler intel sources [source-key]
rebel-profiler intel sanitize "<untrusted text>"
rebel-profiler intel fusion <case-id> [subject]
```

## 5. Surface, graph & reports

```bash
rebel-profiler surface build <case-id>          # graph from claims (persisted)
rebel-profiler surface show <case-id>
rebel-profiler surface map <case-id>
rebel-profiler surface exposure <case-id>
rebel-profiler surface paths <case-id> host:h1 port:80/tcp
rebel-profiler surface related <case-id> host:h1
rebel-profiler report <case-id>                 # human; -o json for machine
rebel-profiler search query <case-id> terms...  # FTS over claims
rebel-profiler search rebuild <case-id>
```

## 6. Approvals, RBAC, workflows

```bash
rebel-profiler approval list <case-id>          # pending approval-gated actions
rebel-profiler approval decide <case-id> <approval-id> approve
rebel-profiler approval run <case-id> <approval-id>
rebel-profiler member add <case-id> alice owner
rebel-profiler workflow create <case-id> flow.dsl
rebel-profiler workflow run <case-id> [workflow-id]     # resumable DAG
rebel-profiler workflow approve <case-id> <wf-id> <step-key>
rebel-profiler schedule add <case-id> --action port-scan --target h1 \
    --cron "interval=60" --not-before <epoch> --not-after <epoch>
rebel-profiler schedule tick <case-id>
rebel-profiler hypothesis add <case-id> "statement" --criteria '[{"kind":"exists",...}]'
rebel-profiler hypothesis evaluate <hypothesis-id>
```

## 7. Transports: worker plane & browser bridge

```bash
# File-based jobs (3-way handshake): submit → daemon → result
rebel-profiler worker submit <case-id> <action> <target> -p k v
rebel-profiler worker run <case-id> --interval 5
rebel-profiler worker status <job-id>

# The operator's own browser (load extension/ unpacked in Chrome first)
rebel-profiler browser serve <case-id>          # 127.0.0.1:8765, token-gated
rebel-profiler browser submit <case-id> https://in.scope/ --extract title,links,forms
rebel-profiler browser submit <case-id> <url> --actions '[{"op":"click","selector":"#id"}]' --approved
rebel-profiler browser result <job-id>
```

## 8. Self-extension & privileged jobs

```bash
rebel-profiler forge propose adapter.py --test-cases '[{"target":"h1",...}]'
rebel-profiler forge list
rebel-profiler forge register                   # load accepted modules live
rebel-profiler system templates                 # whitelisted sudo jobs only
rebel-profiler system submit <case-id> pkg-install -p package nmap
rebel-profiler detection generate <case-id> canary --name tripwire1
rebel-profiler complaint build <case-id> --agency ic3 --targets h1.target.com
```

## 9. Integrity & maintenance (run before trusting anything)

```bash
rebel-profiler evidence list <case-id>
rebel-profiler evidence verify <case-id>        # exit 11 on ANY tamper
rebel-profiler audit show <case-id>
rebel-profiler audit verify <case-id>
rebel-profiler ops backup <case-id> out.zip
rebel-profiler ops restore out.zip dest/
rebel-profiler ops check <case-id> --repair
rebel-profiler ops package rebel-profiler.pyz   # offline zipapp
rebel-profiler doctor
```

## 9b. Authorized bug-bounty workflow

A published program scope is the authorization document — import it, review,
activate, then test strictly inside it.

```bash
rebel-profiler bounty import <case-id> scope.csv --program acme
rebel-profiler bounty import <case-id> scope.json --program acme --activate
rebel-profiler case scope show <case-id>          # what was imported
rebel-profiler bounty run <case-id>               # PLAN ONLY (default)
rebel-profiler bounty run <case-id> --execute     # scope-enforced web audit
rebel-profiler bounty assess <case-id>            # severity + CWE + repro + fix
rebel-profiler bounty report <case-id> -o json    # submission-ready
```

One stated goal runs the whole chain (scope → recon → assess → author →
execute → repair → report):

```bash
rebel-profiler bounty auto <case-id> "find what you can in this scope, test it, \
and give me a report with real results, no demos" --verbose --save
```

| Flag | Effect |
| --- | --- |
| `--no-author` | deterministic audit + report only (no LLM script authoring) |
| `--max-scripts N` | cap on model-written scripts (default 3; `0` disables) |
| `--max-repair-rounds N` | how many times a failing script goes back to the model |
| `--max-assets N` / `--max-pages N` | bounds on the audit |
| `--scheme http\|https` | scheme used to build seed URLs (default https) |
| `--model <id>` | model id for authoring |
| `--save` | write the full session JSON into the case's `reports/` |
| `--verbose` | stream each stage to stderr as it runs |

Exit `0` when there is at least one reportable finding, `1` when the report is
empty, `2` on a usage/authorization error (e.g. the case is not ACTIVE).

Accepted scope inputs: HackerOne-style JSON (`{"data": [{"attributes": …}]}`)
or CSV export, and a plain one-target-per-line list (`!target` or `-target` for
exclusions, `#` for comments). Non-host assets are skipped with a reason;
assets the program marks ineligible are imported as exclusions.

`bounty assess` reads only the claim ledger: advisory severity, CWE, a
reproduction command built from the URL the evidence came from, and a fix. No
demo data, no invented findings, and an honest empty report when nothing was
observed.

`bounty auto` authors scripts through the same gate as everything else: the
model's source is stored (not executed) at submit time, the static AST gate and
subprocess sandbox decide whether it runs, and the run lands as hash-chained
evidence. With no real engine loaded, authoring is skipped and said so — the
deterministic half still reports.

## 10. Job profiles (`--config-file`)

Pin model/tier/actor settings once, reuse for every recurring job (cron,
scheduler, CI):

```toml
# nightly.toml
[llm]
tier = "low"                 # tier pin (may be tightened by env, never loosened)
model = "Qwen/Qwen3-4B"      # default model for llm generate/plan/agent auto
max_new_tokens = 128         # tighten-only cap

[core]
actor = "nightly-agent"      # audit subject for the job
```

```bash
rebel-profiler --config-file nightly.toml agent auto <case-id> "<goal>"
rebel-profiler --config-file nightly.toml llm status
```

Precedence: built-in tier defaults < profile `[llm]` < `RP_LLM__*` env <
explicit `--tier` flag. Protected security keys stay tighten-only in
profiles too. Same file works for `llm generate`, `llm plan`, `agent
run/work/auto` and the daemon.

## 11. Environment variables

| Variable | Meaning | Default |
|---|---|---|
| `RP_LLM__TIER` | tiny / low / mid / high | auto from RAM |
| `RP_LLM__MAX_RSS_MB` | plane memory ceiling (tighten-only) | per tier |
| `RP_LLM__MAX_CONTEXT_TOKENS` | input cap | per tier |
| `RP_LLM__MAX_NEW_TOKENS` | output cap | per tier |
| `RP_LLM__MAX_MODEL_B` | model size cap (billions) | per tier |
| `RP_LLM__ALLOW_GPU` | `false` = CPU/MPS placement only | true |
| `RP_LLM__REQUIRE_COMPRESSION` | `true` = only compressed loads | per tier |
| `RP_LLM__ENGINE` | `tiny` / `gguf` / `native` / `airllm` / `external` pin | auto (best local → airllm → tiny) |
| `RP_LLM__MODEL` | default model id (or a local `.gguf` path) | — |
| `RP_LLM__GGUF_DIRS` | extra directories to search for GGUF files | project + usual roots |
| `RP_LLM__API_KEY` / `_FILE` | remote provider key (opt-in only) | — |
| `RP_LLM__API_BASE` | any OpenAI-compatible /v1 endpoint | api.openai.com |
| `RP_ACTOR` | acting subject in audit | operator |
| `RP_API_TOKEN` | token for `serve` gateway | — |

## 12. Exit codes worth memorizing

`0` ok · `2` usage · `3` config · `4` permission/policy · `5` scope ·
`7` dependency · `11` evidence tamper · `12` state · `15` model budget

## The one rule

> The LLM proposes; the system decides. Scope fails closed; nothing runs
> without authorization; nothing is claimed without evidence. Use only on
> targets you are explicitly authorized to assess.
