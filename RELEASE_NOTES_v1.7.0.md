# Release notes — Rebel Profiler v1.7.0

**Theme: assessment-plane extensions.** The five capability gaps that kept
this tool short of "all-in-one" are closed — credentialed authenticated
auditing, traffic observation, a SIEM detection plane, compliance-grade
report formats, and container/IaC posture — without bending a single design
law. Where a capability is in-process by nature, it ships as a *plane*
(hash-chained evidence, scope fail-closed) rather than a fake-argv adapter.

## 1. Credentialed authenticated posture audit (`web-auth-audit`)

Every pre-existing web action saw the app the way an anonymous visitor does.
The missing half — what an AUTHENTICATED session exposes — now ships as the
in-process plane `intel/auth_audit.py`:

* the operator stores their own test account in the CredentialBroker as
  `username:password`; the audit resolves the secret **in-process** — it
  never crosses a process boundary, never reaches argv, never reaches
  stdout, and the redaction pipeline guards every output path;
* **one login per run, never a retry** — the anti-brute-force ban stands;
  a rejected credential is an honest `auth_failed` result with a
  verify-out-of-band hint;
* deterministic checks: session cookie flags (Secure / HttpOnly /
  SameSite), session-id rotation between the anonymous and authenticated
  states, cache-control on authenticated pages, bounded MFA hint scan;
* every URL (base + login) is scope-validated fail-closed and redirects
  are never auto-followed; failed checks become `auth_posture:*` claims
  bound to hash-chained evidence.

```
rp audit-ext web-auth-audit <case> https://app.lab.example.test \
    --login-url https://app.lab.example.test/login \
    --credential lab-test-account
```

## 2. Loopback recording proxy (`traffic-proxy`)

Authenticated attack-surface discovery needs the endpoints a real session
touches — the API calls a crawler never guesses. The new
`intel/traffic_proxy.py` plane records the operator's OWN browser traffic
to their OWN lab app:

* binds **127.0.0.1 only** (fixed); it is a tap on traffic the operator
  already makes, never a network-position device;
* records method, path, a header subset (Cookie/Authorization stripped)
  and body SHA-256 as evidence + `proxy_transaction` claims;
* https CONNECT tunnels are recorded as **opaque** events — no TLS
  interception, ever;
* the proxy is a dead end (502 + Connection: close): observe, never
  rewrite, replay or forward; bounded by `--max-transactions`.

```
rp audit-ext proxy <case> --port 18080   # Ctrl-C or --duration N to stop
```

## 3. Sigma / SIEM detection plane

The detection lab gains the `sigma_ruleset` artifact: deterministic Sigma
YAML multi-document rules derived from case IoCs — the open standard
Elastic/Splunk/Wazuh ingest directly.

* one rule per IoC kind with a **stable UUID** (uuid5 over case+name+kind),
  `endswith` for domains, `contains` for hashes, literals for the rest;
* SIEM-agnostic `logsource` block the deploying analyst pins per stack;
* same discipline as the YARA builder: literals only, unknown input yields
  nothing, hash-chained evidence, risk `low`.

```
rp detection generate <case> sigma_ruleset --name web-intrusion --ioc domain=evil.example.test
```

## 4. HTML + PDF report exporters

`bounty report --fmt html|pdf` joins `sarif|markdown`, rendering the SAME
report dict — no findings invented in transit:

* **HTML** — a self-contained, compliance-grade document: inline CSS,
  zero scripting, zero external assets, everything HTML-escaped, severity
  badges, per-finding repro/remediation, evidence ids visible;
* **PDF** — a small valid PDF 1.4 built with ONLY the standard library:
  real object table, xref, Helvetica base-14 fonts, flate-compressed
  streams, latin-1-safe text — a client deliverable with zero new
  dependencies;
* an empty report renders as an honest empty document in both formats.

## 5. Container & IaC posture adapters (cloud/container gap, local half)

Two real adapters following the whitelisted-argv contract:

* **`docker-audit`** — one fixed read-only invocation
  (`docker ps -a --no-trunc --format …`, optional explicit socket) turning
  runtime rows into `container` / `container_stopped` claims. There is
  deliberately no param that could start, stop, exec, pull, build or
  remove anything.
* **`iac-audit`** — trivy with `--scanners config --offline-scan` pinned
  on a file already on the operator's disk (Dockerfile, compose, K8s,
  Terraform): misconfigurations become `iac_finding` claims carrying
  trivy's own rule ids and severities; nothing is uploaded, built, or
  pulled.

Both register in the live registry, carry vuln-coverage rows
(`container_posture` CWE-250, `iac_misconfig` CWE-16), action guides,
tool-matrix entries and collection parsers where unknown input yields no
claims.

## Supporting changes

* new provenance sources, reliability-graded like the rest:
  `scan.webauth`, `scan.proxy`, `scan.iac`;
* `auth_session_hygiene` (CWE-614) joins the vuln-coverage matrix;
  CWE-614 and CWE-250 added to the offline CWE seed;
* the Hermes `collect` tool description now names the new actions;
* `rp adapters` count grows 49 → 51;
* 36 new tests in `tests/test_phase13.py`; full suite
  **1217 passed / 23 skipped**, pyflakes clean.

## Design-law ledger (unchanged)

No raw shell. No fake adapters — the two in-process planes are *planes*,
not argv pretenders, and say so in code. Scope fail-closed everywhere,
including every URL the auth plane touches. No evidence, no claim. The
no-brute-force and no-exploitation bans are untouched: the audit performs
one login with an operator-owned test account, the proxy observes without
rewriting, and the new adapters cannot mutate the runtime they inspect.
