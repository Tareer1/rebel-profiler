# Rebel Profiler — Quickstart Cheat-Sheet

Every daily-use command in one page. Replace `<case-id>` with your case id
(`case list` shows them). All commands accept `-o json|jsonl|csv|human`.

---

## 0. One-time setup

```bash
pip install -e .                                # core (stdlib-only)
rebel-profiler doctor                           # health check (auto-detects WSL — docs/WSL.md)

# No pip, no git? The offline single-file route:
curl -LO https://github.com/Tareer1/rebel-profiler/releases/latest/download/rebel-profiler.pyz
sha256sum -c rebel-profiler.pyz.sha256          # verify, then run:
python3 rebel-profiler.pyz doctor               #  (or: ./scripts/install.sh --zipapp)

# Local LLM engines — pick what fits your checkpoints (see docs/SETUP.md)
pip install 'rebel-profiler[gguf]'              # GGUF files (llama.cpp/Ollama/LM Studio)
pip install 'rebel-profiler[native]'            # HF safetensors already on disk
pip install 'rebel-profiler[airllm]'            # airllm layer streaming

rebel-profiler llm setup                        # hardware-aware install guidance
rebel-profiler llm local                        # checkpoints on disk + run commands
rebel-profiler llm status                       # what can THIS machine run?
rebel-profiler llm models                       # which models fit?

# Shell completion + short alias (bash or zsh, once):
source <repo>/completions/rebel-profiler.bash    # bash
# zsh: copy completions/_rebel-profiler to a dir on your $fpath, or source it
# from ~/.zshrc — Tab then completes subcommands, case ids and flags.

# The friendly front door (recommended): install `rp` — see section 0b
ln -sf "<repo>/tools/rp" ~/.local/bin/rp && export PATH="$HOME/.local/bin:$PATH"
```

## 0b. `rp` — one command, everything by prompting (the daily driver)

`tools/rp` + `rebel-profiler hermes` is the whole CLI reduced to a
conversation. The session case is picked (or created) automatically, the
pinned Hermes model from `hermes.toml` loads, and the model holds the full
operator tool surface — case create/activate, scope add/show, claims,
report generation, evidence + audit verification, surface/fusion, search,
knowledge, glossary, the browser bridge and a status probe — next to the
gated adapter registry. You ask; it proposes tool calls; the same gates
decide; the answer comes from the model.

```bash
rp                        # status panel: case, hermes model, bridge
rp talk                   # chat REPL with Hermes — plain language, zero ceremony
rp talk "map example.com" # one bounded hermes loop for that goal
rp recon TARGET.com       # NOT a command — it is a prompt: hermes plans + runs it
rp add *.lab.test to scope "authorized"   # a prompt: hermes authorizes + activates
rp show me the report     # a prompt: hermes generates it from the claims
rp grab https://in.scope/ # a prompt: hermes grabs it through the browser bridge
rp verify the evidence    # a prompt: hermes re-verifies evidence + audit chains
rp bridge                 # start the browser bridge (extension ke liye)

# Direct, without rp:
rebel-profiler hermes                                   # interactive REPL
rebel-profiler hermes "collect DNS A for lab.example.test and explain it"
rebel-profiler --config-file hermes.toml hermes "..."   # pinned local GGUF
rebel-profiler hermes --case <case-id> "..."            # explicit case (optional)
```

## 0c. The GUI — browser console over the same gates

`frontend/` ships a local-only web console (dark Hermes aesthetic) over the
read-only gateway and the whitelisted JSON CLI. Two processes, both on
127.0.0.1:

```bash
rebel-profiler serve <case-id> --port 8899 --token SECRET   # read-only API
python3 frontend/proxy.py --port 8898 --api-port 8899 --api-token SECRET
# then open http://127.0.0.1:8898
```

Dashboard (live claims/evidence/audit-head + events feed) · case create →
scope add → activate · Hermes chat with an honest elapsed timer (no fake
progress bars — first turn on CPU takes minutes) · dork console · surface
map · browser-bridge grab. Writes go through `frontend/proxy.py`'s CLI
whitelist only — every command still passes the broker's six gates; the
browser never touches anything else. Tests: `tests/test_gui_proxy.py`.

In the shell (cloned from the Hermes agent CLI — banner, registry-owned
slash commands): `/help [filter]` `/status` `/model [name]` `/new [name]`
`/case` `/tools [filter]` `/scope` `/clear` `/exit`. Plain language runs
the agent loop; `hermes.toml` pins the default model.

Hermes-agent CLI semantics: a goal on a real TTY seeds the interactive
session (it answers, then keeps chatting); piped or `--oneshot` answers
once and exits — so scripts get one answer, terminals get a conversation.

Everything the chat does is the same gated machinery as the full CLI below
— six gates, scope engine, evidence chain, audit trail — it only hides the
ceremony. The raw `rebel-profiler` commands stay the source of truth for
scripting and CI.

## 0d. Wireless (authorized-site 802.11 posture — listen-only)

```bash
# One command runs the whole chain: monitor mode (approval-gated) →
# bounded RF survey → restore managed mode → offline posture audit:
rebel-profiler intel playbook run wifi-posture <case-id> office-floor-2

# Or step by step:
rebel-profiler run <case-id> wlan-monitor operator-laptop \
    -p interface wlan0                       # approval-gated (own machine)
rebel-profiler run <case-id> wlan-survey office-floor-2 \
    -p interface wlan0mon -p duration 300    # listen-only survey
rebel-profiler run <case-id> wlan-monitor operator-laptop \
    -p interface wlan0mon -p stop 1          # back to managed mode
rebel-profiler run <case-id> wlan-ap-audit office-floor-2  # offline summary
```

## 0e. Kali tool surface (40 gated actions)

```bash
# Web misconfiguration sweep (polite tuning, CSV to stdout):
rebel-profiler intel collect <case-id> nikto-scan h1.lab.example.test -p port 443 -p ssl 1

# WordPress exposure audit — NO brute force, NO aggressive enumeration:
rebel-profiler intel collect <case-id> wpscan-audit https://wp.lab.example.test

# Offline exploit-db correlation — ZERO target traffic:
rebel-profiler intel collect <case-id> exploit-lookup "nginx 1.18"

# Listen-only packet capture on the OWN interface (protocol aggregates only):
rebel-profiler intel collect <case-id> packet-capture office-floor-2 -p interface eth0 -p filter tcp -p count 300

# Local hardening baseline (lynis on the operator's own box — blue team):
rebel-profiler intel collect <case-id> host-audit operator-laptop

# Two more playbooks ship with these:
rebel-profiler intel playbook run web-deep-audit <case-id> h1.lab.example.test
rebel-profiler intel playbook run own-box-baseline <case-id> operator-laptop

# Coverage-driven planning: audit what you have NOT covered yet
rebel-profiler intel vuln-coverage <case-id> --plan        # blind spots → plan
rebel-profiler agent run <case-id> "audit the blind spots" --coverage
```

`nikto-scan`/`wpscan-audit` feed `nikto_finding`/`wp_finding` claims;
`exploit-lookup` produces advisory `exploit_candidate` claims (publication
≠ exploitability); `packet-capture` records protocol AGGREGATES only — no
addresses of bystanders, no payloads, named BPF filters only; `host-audit`
is the lynis blue-team baseline. All of it passes the same six gates, and
`hermes`/`rp-mcp` can drive every one through the `collect` operator tool.

APs become `ap` claims (BSSID, channel, ESSID), encryption posture becomes
`wifi_security` (WEP/TKIP/open = reportable), associated clients become
`wireless_sta` — association-only: probe SSIDs are NEVER recorded.
Deauth/evil-twin/injection actions do not exist in this tool by design:
detection, not disruption. RF surveys require written authorization for
the PHYSICAL site — the case scope gates hosts; the operator gates the
spectrum.

### Root on Kali: the `--privileged` flag (sudo, whitelisted binaries only)

`airmon-ng`/`airodump-ng` need root. Non-root boxes add `--privileged` so
ONLY these two whitelisted binaries are wrapped via `sudo -n` — the argv
whitelist is unchanged and no other action ever gains sudo:

```bash
rebel-profiler --privileged run <case-id> wlan-survey office-floor-2 \
    -p interface wlan0mon -p duration 60

# No passwordless sudo? Provide an askpass helper once:
RP_SUDO_ASKPASS=/path/to/askpass.sh rebel-profiler --privileged run \
    <case-id> wlan-monitor operator-laptop -p interface wlan0
```

Or run the whole command under `sudo -i` yourself — then no flag is needed.
A sudo password failure returns the exact sudoers/askpass hint in stderr.

## 0f. Reverse engineering & binary analysis (offline, analysis-only)

```bash
# Static triage of a possessed sample — the whole chain in one run:
rebel-profiler intel playbook run binary-triage <case-id> /srv/samples/app.bin

# Or step by step (the sample is DATA — nothing ever executes it):
rebel-profiler intel collect <case-id> binary-info  /srv/samples/app.bin  # ELF header, arch, libs
rebel-profiler intel collect <case-id> checksec     /srv/samples/app.bin  # NX/PIE/canary/RELRO posture
rebel-profiler intel collect <case-id> string-dump  /srv/samples/app.bin  # IOC candidates (URLs, IPs, domains)
rebel-profiler intel collect <case-id> symbol-dump  /srv/samples/app.bin  # imports/exports (socket, execve…)
rebel-profiler intel collect <case-id> disasm       /srv/samples/app.bin -p section .text
```

New capability class `binary_analysis` (risk: low, offline reads) and the
new knowledge domain **16 — Reverse Engineering & Binary Analysis** (static
lifecycle, format ID, mitigation review, IOC hunting, import analysis,
disassembly, the analysis-only/detonation boundary). The sample must never
be executed by this tool: no unpacking to runnable artifacts, no exploit
construction, detonation belongs to external sandboxes. `/proc`, `/sys` and
`/dev` paths are refused.

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
rebel-profiler agent chat <case-id> "<goal>"                      # Hermes loop: one <tool_call> per turn
rebel-profiler agent chat <case-id> "<goal>" --max-turns 12
rebel-profiler --config-file hermes.toml agent chat <case-id> "<goal>"   # pinned local GGUF (copy hermes.example.toml first)
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
machine**. With no model pinned the engine order is **best local checkpoint
(GGUF → HF cache) → airllm → tiny** (honest fallback, reason recorded), never
a silent substitution. The auto tier is a hardware fit; a 7B-class Q4 usually
needs `--tier high`.

```bash
rebel-profiler hermes --tier high          # widen the budget for a 7B-class Q4
rebel-profiler hermes --llm /path/model.gguf   # pin one exact checkpoint

# The REAL hermes-agent (Nous Research) as the brain — two ways:
RP_LLM__ENGINE=hermes rebel-profiler hermes "map the scope"   # engine mode (safe toolset child)
#   or the supported MCP direction: the agent calls rp_* tools natively —
#   ~/.hermes/config.yaml →
#   mcp_servers:
#     rebel-profiler:
#       command: <repo>/.venv/bin/rp-mcp
#       args: ["--case", "<case-id>"]
rp-mcp --case <case-id>                    # run the MCP server by hand (stdio JSON-RPC)

# Approvals inside chat — the model shows the queue, YOU decide:
#   "check approval_list"  →  "approve apr_… " (explicit)  →  executed + claims ingested
rebel-profiler approval list <case-id>      # the same queue from the shell
```

CPU reality check: local prefill runs at a few tokens/second on laptop CPUs,
so hermes' **first turn takes a while** (the tool contract has to be read
once; later turns reuse the cached prefix). The shell prints a heads-up and
a per-turn time footer — wait for `hermes is working…` to finish.

## 4. One-shot collection (each = run + evidence + claims)

```bash
rebel-profiler intel collect <case-id> passive-dns target.com -p record_type MX
rebel-profiler intel collect <case-id> whois-lookup target.com
rebel-profiler intel collect <case-id> cert-transparency target.com
rebel-profiler intel collect <case-id> port-scan h1.target.com -p ports 22,80,443
rebel-profiler intel crawl <case-id> https://h1.target.com/ --max-pages 20
rebel-profiler intel hunt <case-id> https://h1.target.com/   # AUTONOMOUS JS HUNT:
#   harvests <script src> + inline JS from the seed page (scope-checked per URL),
#   mines API routes / keys / S3-Firebase-Supabase hosts via jsintel, folds in
#   Wayback history, ranks P1(secrets) > P2(endpoints/cloud) > P3(history),
#   and prints a ready-to-run probe suggestion per item. Coffee optional.
rebel-profiler intel collect <case-id> js-intel https://h1.target.com/app.js
rebel-profiler intel collect <case-id> wayback-urls h1.target.com -p limit 500
rebel-profiler intel collect <case-id> probe https://h1.target.com/api/user/1 -p method GET
#   ^ probe = the PoC instrument (vuln_validation → approval queue, evidence-chained)
rebel-profiler run <case-id> <action> <target> -p key value --dry-run  # preview
rebel-profiler intel claims <case-id> [subject]
rebel-profiler intel sources [source-key]
rebel-profiler intel sanitize "<untrusted text>"
rebel-profiler intel fusion <case-id> [subject]
rebel-profiler intel attack-plan <case-id>      # ranked strategies from this case's evidence
rebel-profiler intel vuln-coverage <case-id>    # which vuln classes are probed vs blind spots
rebel-profiler intel payload build <case-id> <payload-class>   # benign marker, no impact
rebel-profiler intel payload deploy <case-id> <payload-id> --target <url> --approve
rebel-profiler intel playbook list              # reviewed multi-step hunt recipes
rebel-profiler intel playbook show web-audit
rebel-profiler -y intel playbook run web-audit <case-id> <host> -p scheme http
rebel-profiler -y intel playbook run lan-inventory <case-id> 192.168.55.0/24
#   every step passes the six gates; -p overrides merge into steps that
#   declare the key; add your own: <data-dir>/playbooks/*.json
#   lan-inventory = OWN-LAN device sweep (admin use): CIDR scope entry must
#   cover the range; each live host becomes a lan_device claim (MAC + vendor)
```

## 4b. The sci-fi shell (`rebel-profiler shell`)

A unicode interactive console over the SAME argparse main — no second parser,
no second set of gates. ANSI colour auto-disables on pipes/CI; `NO_COLOR` or
`RP_PLAIN=1` flattens the whole aesthetic.

```bash
rebel-profiler shell            # banner + readline loop
# console commands: :help :case <id> :status :plan :cover :tools :banner :clear :exit
# everything else runs verbatim as a rebel-profiler command:
#   intel collect <case> subfinder-enum crypto.com
#   bounty hunt crypto --no-author
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

# The operator's own browser — Chrome/Chromium: load extension/ unpacked;
# Firefox (about:debugging → Load Temporary Add-on): the manifest ships an
# event-page background for Gecko, then click "Grant site access" once in
# the popup (Firefox gates host permissions behind a user grant) and paste
# the bridge token. Extraction falls back to a background fetch of the
# page's own HTML when injection is not granted — reported as
# _mode: "fetch-fallback" in the result, never faked.
rebel-profiler browser serve <case-id>          # 127.0.0.1:8765, token-gated
rebel-profiler browser submit <case-id> https://in.scope/ --extract title,links,forms
rebel-profiler browser submit <case-id> <url> --actions '[{"op":"click","selector":"#id"}]' --approved
rebel-profiler browser result <job-id>

# Or just: rp bridge (start + Firefox setup steps printed) / rp grab <url>
# (submit a browser-extract job) / rp job <id> (read the result)

# Dorking (named templates only; results become search_hit + hostname claims)
rebel-profiler intel collect <case-id> dork-search example.test \
    -p engine google      -p dork site-files -y
rebel-profiler intel collect <case-id> dork-search example.test \
    -p engine duckduckgo  -p dork login-portals -y
rebel-profiler intel collect <case-id> dork-search example \
    -p engine ahmia -p dork open-directories -p tld onion -y   # via torsocks
# Dorks: site-files, open-directories, config-files, backup-files,
#        login-portals, staging-sites, cloud-buckets, exposed-emails, tech-stack
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
rebel-profiler ops update                       # self-update the installed zipapp
#   downloads the latest release, verifies the published sha256, and only
#   then atomically replaces the .pyz — offline/mismatch = structured refusal
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
rebel-profiler bounty report <case-id> --fmt sarif     # SARIF 2.1.0 for code scanning
rebel-profiler bounty report <case-id> --fmt markdown  # disclosure draft
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

### 9b-i. H1 import → full audit in five commands (the fast path)

```bash
# 1. Export the program scope from HackerOne (JSON or CSV), then import it.
#    The importer reads assets from `data[].attributes` and the eligibility
#    flag from `eligible_for_submission` (also accepted: eligible /
#    bounty_eligible / eligible_for_bounty). Ineligible assets become
#    EXCLUSIONS; non-host assets are skipped with a stated reason.
rebel-profiler case create "Acme Program" "imported from HackerOne"
rebel-profiler bounty import <case-id> ~/Downloads/scope.json --program acme --activate

# 2. Review exactly what got authorized before anything runs.
rebel-profiler case scope show <case-id>

# 3. Dry look: what WOULD be audited (plan only, nothing dispatched).
rebel-profiler bounty run <case-id>

# 4. One goal, whole chain: recon → assess → (author) → execute → report.
#    --no-author keeps it deterministic (no LLM script writing).
#    --scheme must match the program's reality (default https).
rebel-profiler bounty auto <case-id> "audit this scope, report real results" \
    --no-author --max-assets 10 --max-pages 20 --scheme https

# 5. Triage + submission-ready report, then prove integrity.
rebel-profiler bounty assess <case-id>
rebel-profiler bounty report <case-id> -o json
rebel-profiler evidence verify <case-id>      # exit 11 on ANY tamper
```

What you get per finding: advisory severity, CWE, a copy-paste repro command
built from the URL the evidence actually came from, remediation, and the
evidence id — an auditor can re-verify the whole chain independently.

Blind spots first? `intel vuln-coverage <case-id>` (or `:cover` in the shell)
shows which vulnerability classes this case has NOT probed yet, each with the
exact command that would close the gap.

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

## 12. CWE knowledge (offline seed + official MITRE catalog, live-fetched once)

```bash
rebel-profiler intel cwe lookup 79              # one weakness: description, likelihood, mitigations
rebel-profiler intel cwe lookup --refresh 639   # force-fetch the latest MITRE catalog first
rebel-profiler intel cwe search "open redirect" # keyword search across the catalog
rebel-profiler intel cwe blind-spots <case-id>  # likelihood-ranked weaknesses this case has NOT probed
rebel-profiler intel cwe status                 # cache status (builtin seed vs MITRE v4.x cache)
rebel-profiler intel cwe refresh                # fetch the official MITRE CWE catalog once
```

The catalog is external content handled like every other input: fetched
once with a distinct User-Agent, wrapped as DATA, cached under the data
dir with its published version, and the blind-spot report ranks by MITRE
exploit likelihood then by what this tool can still run — every entry
still passes the six gates before anything executes.

## The one rule

> The LLM proposes; the system decides. Scope fails closed; nothing runs
> without authorization; nothing is claimed without evidence. Use only on
> targets you are explicitly authorized to assess.
