# Setup — from zero to a working Rebel Profiler

Everything here is copy-paste. The core tool is stdlib-only; the LLM engines are
optional and the tool tells you exactly which ones your machine can carry.

```
┌ 1. install ──▶ 2. verify ──▶ 3. pick an engine ──▶ 4. run your model
│                                                          │
└── 5. create a case ──▶ 6. authorize scope ──▶ 7. work ◀──┘
```

---

## 1. Install

Python **3.11+** is required.

```bash
git clone <your-repo-url> rebel-profiler && cd rebel-profiler
python3 -m pip install -e .          # core: no third-party runtime deps
rebel-profiler --help
```

Optional, for running models locally (install only what you need — see step 3):

```bash
python3 -m pip install 'rebel-profiler[gguf]'     # GGUF files
python3 -m pip install 'rebel-profiler[native]'   # HF safetensors already on disk
python3 -m pip install 'rebel-profiler[airllm]'   # airllm layer streaming
python3 -m pip install pytest                     # only to run the test suite
```

Model **weights are never part of this repository** (they are multi-GB and
gitignored). Keep them in the Hugging Face cache or your own directory and point
the tool at them.

## 2. Verify

```bash
rebel-profiler doctor        # environment + configuration health check
rebel-profiler llm setup     # hardware, tier, per-engine install commands
```

`llm setup` prints your RAM/CPU, the tier the budget guard will use, every
engine with its install command, and the checkpoints already on disk. Take the
`install:` line it recommends.

## 3. Pick an engine

| Engine | Best when | Install |
|--------|-----------|---------|
| `gguf` | you have a single `.gguf` file (llama.cpp, Ollama, LM Studio export) | `pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu` |
| `native` | you have HF safetensors checkpoints already in the HF cache | `pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| `airllm` | you want AirLLM's layer streaming + AutoModel across families | `pip install 'rebel-profiler[airllm]'` |
| `external` | you want an OpenAI-compatible endpoint (opt-in, redacted) | `export RP_LLM__ENGINE=external RP_LLM__API_KEY=sk-…` |
| `tiny` | you cannot or may not load weights | built in — nothing to install |

A bare `pip install llama-cpp-python` compiles from source and needs a C++
toolchain. The `--extra-index-url` above pulls a **prebuilt CPU wheel** instead.
For a CUDA build use `.../whl/cu121` (match your CUDA version).

Tell the tool where your models live:

```bash
export RP_LLM__GGUF_DIRS=/data/models:/another/dir     # GGUF search path
```

## 4. Run your model

```bash
rebel-profiler llm local                      # what is on disk, and does it fit?
rebel-profiler llm generate "explain HSTS" --local
rebel-profiler llm generate "summarize: …" --model /data/models/model.gguf
rebel-profiler llm status                     # tier, caps, current RSS headroom
```

`--local` never downloads: it picks the best checkpoint already on disk that
fits your tier and refuses honestly when none does. A local checkpoint is never
substituted for a *different* model you asked for by name.

### Honest expectations about big models

Layer-wise streaming keeps **one transformer layer resident at a time**, so
resident RAM stays far below the checkpoint size — this is how a 70B-class model
runs on a machine with a few GB of free RAM, and it is what the tier budget
enforces. Two costs are real and worth stating plainly:

* **Disk**: the entire checkpoint must be on disk (a 70B model is tens of GB
  even at 4-bit). Streaming trades disk for RAM, it does not create memory.
* **Speed**: every token re-reads layer weights from disk, so CPU-only
  generation runs at roughly seconds-per-token on large models. Small models
  (0.5B–8B) are comfortable; very large ones are batch-job territory.

Start with the smallest model that can do the job, keep the daemon
(`llm daemon`) for long jobs so the CLI stays light, and remember the model
**unloads after every job**.

4/8-bit compression requires CUDA (AirLLM's path quantizes on-device). On
CPU-only machines the guard refuses it up front with a fix hint — uncompressed
layer streaming already keeps RAM tiny, and the native engine's own block-wise
quantization is CPU-safe.

## 5. Create a case

```bash
rebel-profiler case create "Lab Assessment" "internal authorized test"
rebel-profiler case list
```

## 6. Authorize scope

Nothing runs without an active, explicit scope.

```bash
rebel-profiler case scope add <case-id> "*.lab.example.test" --note "authorized"
rebel-profiler case scope add <case-id> "admin.lab.example.test" --exclude
rebel-profiler case activate <case-id>
rebel-profiler scope-check <case-id> host1.lab.example.test   # exit 5 = blocked
```

For **bug-bounty work the program's published scope is the authorization
document** — import it and review what was read:

```bash
rebel-profiler bounty import <case-id> scope.csv --program acme
rebel-profiler case scope show <case-id>
rebel-profiler case activate <case-id>
```

Non-host assets (source repositories, app-store IDs, ASNs) are skipped with a
reason; assets the program marks ineligible become exclusions.

## 7. Work

```bash
# plan first, always: shows the exact argv and the policy decision
rebel-profiler plan <case-id> host-discovery host1.lab.example.test
rebel-profiler run  <case-id> host-discovery host1.lab.example.test

# one-shot collection (run + evidence + claims)
rebel-profiler intel collect <case-id> passive-dns example.com -p record_type MX
rebel-profiler intel crawl   <case-id> https://host1.lab.example.test/

# the LLM-driven path: plan → execute → repair → extend, every step gated
rebel-profiler agent auto <case-id> "map example.com fully" --local

# bug bounty: audit in-scope assets, then triage into a report
rebel-profiler bounty run <case-id> --execute
rebel-profiler bounty assess <case-id>

# or state one goal and let the whole chain run (LLM authoring included)
rebel-profiler bounty auto <case-id> "find what you can in this scope, test \
it, and give me a report with real results, no demos" --verbose --save

# results
rebel-profiler report <case-id>
rebel-profiler evidence verify <case-id>
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Dependency unavailable: The airllm package is not installed` | no engine installed | `rebel-profiler llm setup`, install the recommended one (a `tiny` fallback still runs) |
| `Interactive Hermes needs real weights; only the tiny engine loaded` | no engine installed, or the local checkpoint does not fit the auto tier (the reason names it) | pin a local file (`--llm /path/model.gguf`), widen the budget (`--tier high`), or `rebel-profiler llm setup` to install an engine |
| `llama-cpp-python` build fails with compiler errors | no C++ toolchain | use the prebuilt wheel index from step 3 |
| `No GGUF checkpoint on disk for '<model>'` | the file was not found | pass the full path with `--model`, or set `RP_LLM__GGUF_DIRS` |
| `Model ~8B exceeds tier cap 3B` | tier too small for that model | use a smaller model, or raise the tier explicitly (`--tier mid`) |
| `Compression requires CUDA` | 4/8-bit requested on a CPU-only box | run uncompressed — streaming already keeps RAM small |
| `Target '…' is not authorized` (exit 5) | scope enforcement working as designed | add the target, or check for an exclusion that wins |
| `Case … is 'draft', not active` | case not activated | `rebel-profiler case activate <case-id>` |
| `LLM plane RSS … exceeds ceiling` | the budget guard refusing to swap-die | lower the tier or the model size |
| `evidence verify` fails (exit 11) | the chain does not recompute | stop and investigate — the ledger is reporting tamper |

## Data locations and removal

```bash
# default workspace
~/.local/share/rebel-profiler/           # override with --data-dir or RP_DATA_DIR
~/.cache/huggingface/                    # HF checkpoints (if you use them)

# back up / restore / package
rebel-profiler ops backup <case-id> out.zip
rebel-profiler ops check  <case-id> --repair
rebel-profiler ops package rebel-profiler.pyz
```

Removal is uninstalling the package plus deleting the workspace directory.

## What this tool will not do

The design law is mechanical, not advisory: no raw shell path exists anywhere,
no adapter is faked, claims require hash-chained evidence, and scope fails
closed. Specifically:

* no functional malware generation — the `malware` domain is analysis only, and
  the detection lab emits benign artifacts (EICAR test files, canaries, IoC
  bundles, YARA rules);
* no unattended exploitation — validation runs are scoped, rate-limited and
  policy/approval-gated, and they target what you authorized;
* no invented findings — the report says what the evidence supports and states
  plainly what was not demonstrated.

Use it only on systems you are explicitly authorized to assess. For bug bounty
work, that means the program's published scope and per-asset instructions:
stay inside them, respect rate limits, and never touch data beyond what proving
the issue requires.
