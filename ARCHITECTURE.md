# Architecture

Rebel Profiler implements the six-plane architecture from the build
specification (PDF 2), with one guiding constraint repeated throughout:

> The LLM may **propose**; only deterministic, versioned engines may
> **decide**; only the broker may **execute**; only evidence may **claim**.

## Planes

```
┌──────────────────────────────────────────────────────────────────┐
│ Intelligence plane          knowledge/ + intel/                  │
│   15 domains · 50 topics · capability classes · Kali tool map     │
│   Source scoring · claim ledger · entity resolution · injection   │
│   defense · collection pipeline · findings/report generator ·     │
│   cross-domain fusion (noisy-OR, conflicts) · persistent          │
│   relationship graph store (v3 tables + queries) · surface graph  │
│   Emits planner context; contains no authority of any kind        │
├──────────────────────────────────────────────────────────────────┤
│ Agent plane                 agent/                               │
│   Goal → planner proposals → broker gates → claims → report       │
│   Planner sees only declared actions/params (PlannerView);        │
│   denials are feedback; sessions are capped and audited           │
├──────────────────────────────────────────────────────────────────┤
│ LLM plane (planner)         llm/                                  │
│   AirLLM-mode inference: layer-wise streaming, 4/8-bit            │
│   compression, CPU/MPS placement, hardware budget guard,          │
│   resident daemon offload (unload after every job).               │
│   Produces ActionRequest structures — never commands, never       │
│   decisions. Same input is available to any frontend.             │
├──────────────────────────────────────────────────────────────────┤
│ Security/Policy plane       security/                             │
│   scope.py    fail-closed authorization boundary                  │
│   risk.py     versioned, deterministic classification             │
│   policy.py   allow ▸ confirm ▸ approve ▸ deny                    │
├──────────────────────────────────────────────────────────────────┤
│ Execution plane             execution/broker.py                   │
│   Adapter registry (declared params, whitelisted flag sets)       │
│   Six-gate sequence; structured results; no raw shell anywhere    │
├──────────────────────────────────────────────────────────────────┤
│ Evidence/Data plane         evidence/ + storage/                  │
│   Content-addressed evidence ledger (SHA-256, hash-chained)       │
│   Hash-linked audit chain · SQLite per case (physical isolation)  │
├──────────────────────────────────────────────────────────────────┤
│ Operations plane            cli/ + core/config.py                 │
│   Human/JSON/JSONL/CSV output · doctor · layered config with      │
│   protected security keys (tighten-only)                          │
└──────────────────────────────────────────────────────────────────┘
```

## Request lifecycle

```
operator/LLM
    │  ActionRequest{case_id, capability, action, target, params}
    ▼
ExecutionBroker.plan()
    ...six gates...
    ▼
ExecutionBroker.execute()  ──ExecutionResult──▶  intel.collection
                                                    ├─ evidence.register()  (hash-chained)
                                                    ├─ injection scan + sanitize
                                                    ├─ parse → claims (scored, provenance)
                                                    └─ persist claims + observations
    ├─ adapter lookup          → UsageError if absent (no fake adapters)
    ├─ param contract check    → UsageError on undeclared params
    ├─ ScopeEngine.validate()  → ScopeViolationError unless ACTIVE + in_scope
    ├─ RiskEngine.classify()   → low / moderate / high / critical
    └─ PolicyEngine.evaluate() → allow / confirm / approve / deny
    ▼
ExecutionBroker.execute()
    ├─ DENY  → PermissionDeniedError + audit("action.denied")     [nothing ran]
    ├─ confirm/approve callbacks (interactive or programmatic)
    ├─ adapter.build_argv()    → whitelisted argv only
    ├─ runner(argv)            → subprocess with timeout, no shell
    ├─ EvidenceStore.register()→ SHA-256 blob + chain linkage
    └─ AuditChain.append()     → hash-linked event (requested/completed…)
```

Dry-run (`rebel-profiler plan`, `run --dry-run`) stops before the runner and
still shows the exact argv and policy outcome.

## Trust boundaries

1. **LLM output is data.** It can fill `ActionRequest` fields; it cannot
   create adapters, alter scope, or influence risk/policy engines.
2. **Scope is evaluated at execution time**, from the live case store —
   not from whatever the planner believed.
3. **Risk classes map to outcomes via a versioned table**; deployment
   overrides may only *tighten* the mapping.
4. **Protected config keys** (`scope.fail_closed`, `evidence.redaction_enabled`,
   `evidence.audit_chain_enabled`, `policy.risk_to_outcome_mapping`) reject
   any attempt to weaken them, at any layer.
5. **Evidence integrity is verifiable offline**: `evidence verify` and
   `audit verify` recompute hashes and chain linkage; any edit, deletion or
   reordering is detected (exit 11).
6. **Claims never outrank their evidence**: claim confidence is computed from
   deterministic source scoring; a claim is a provenance-carrying statement,
   not a fact, until independently corroborated.
7. **External content is data, never instructions**: everything ingested from
   outside is injection-scanned and wrapped as untrusted data before reaching
   any planner context.
8. **The LLM plane never eats the machine**: model memory is bounded by a
   tighten-only tier budget (RSS ceiling, context/new-token caps, model size
   cap, compression requirements), the resident daemon unloads weights after
   every job, and the deterministic tiny engine keeps every contract alive
   where weights cannot load — no silent substitution, the fallback reason
   is always recorded.
9. **Local-first inference, opt-in remote brain**: the default engine is
   on-device AirLLM; the only remote path is an explicitly pinned,
   OpenAI-compatible provider whose payloads and responses are redacted.
   Case data reaches any model exclusively through bounded, redacted data
   packs delivered over the checksummed job-file handshake — the LLM never
   opens the database.

## Data model (per case)

```
<workspace>/cases/<case-id>/
    case.db        # SQLite: cases, scope_entries, targets, observations,
    │              #         evidence_records, audit_events, tasks, claims,
    │              #         graph_nodes, graph_edges
    blobs/         # content-addressed evidence blobs (sha256[:2]/sha256)
```

The workspace-level `index.json` holds case metadata only; all
authoritative state lives in the per-case database. Cross-case queries go
through explicit APIs, never shared tables.

## Extension points

* **Adapters** — subclass `Adapter`, declare `allowed_params`, implement
  `build_argv()`; register with `AdapterRegistry`. Adapters are the only
  code that may talk to external binaries, and only via argv lists.
* **Policy overrides** — pass a mapping to `PolicyEngine`; tighter is legal,
  weaker is rejected.
* **Confirmers/Approvers** — interactive CLI prompts by default; swap for
  ticketing/webhook-based approval in deployments.
