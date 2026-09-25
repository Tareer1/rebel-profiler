# Release notes — Rebel Profiler v1.6.0

**Theme: reach & analysis.** The Kali tool surface grows to 45 gated
actions, the reverse-engineering plane makes static binary analysis a
first-class citizen (capability + knowledge), coverage blind spots become
the default next action, and the GUI gets a one-click session kill.
Same law as always: the LLM proposes, the gates decide, nothing runs
without authorization.

## Reverse-engineering plane (new)

* **New capability class** `binary_analysis` — risk **low**, offline reads
  of a file the operator already possesses. The sample is DATA: nothing
  ever executes it, nothing is sent anywhere, `/proc` `/sys` `/dev` paths
  are refused.
* **Five adapters** (all binutils/Kali-native):
  * `binary-info` — readelf header + dynamic section: format, class,
    architecture, linked libraries, RUNPATH
  * `checksec` — compiled-in exploit mitigations (NX/PIE/canary/RELRO)
  * `string-dump` — bounded printable strings, pattern-classified into
    IOC candidates (URLs, IPs, domains, paths, registry keys, crypto hints)
  * `symbol-dump` — nm dynamic imports/exports; behavioral hints only
  * `disasm` — objdump disassembly of a named section, bytes as data
* **Honest parsers**: unknown input yields no claims; claims
  (`binary_mitigation`, `binary_class`, `binary_library`, `string_url`,
  `symbol_import`, `disasm_call`, …) carry the new `binary.static`
  provenance source.
* **Analysis-only boundary, enforced**: no unpacking to runnable
  artifacts, no exploit construction from found flaws, detonation belongs
  to external sandboxes. The blue-team half of the malware domain.

## Knowledge domain 16 — Reverse Engineering & Binary Analysis (new)

* 7 topics: the static-first RE lifecycle, file/format identification,
  mitigation review, string/IOC hunting, symbol & import analysis,
  disassembly reading, and the analysis-only/detonation boundary.
* 7 techniques with countermeasures; 13 new glossary terms (nx, pie,
  relro, stack canary, checksec, c2, detonation, chain of custody, …).
* Five action guides (45/45 actions guided — consistency pinned by tests).
* `binary-triage` hunter playbook (5 gated steps) + the knowledge-side
  playbook; doctor reports the RE toolset.
* Coverage matrix grows to 32 classes with live detect actions
  (`binary_mitigation_gap`, `sample_ioc`).

## Kali tool expansion — 45 gated actions

* `nikto-scan` (polite CSV misconfiguration sweep), `wpscan-audit`
  (version/plugin exposure — no brute force), `exploit-lookup` (offline
  searchsploit, zero target traffic), `packet-capture` (listen-only
  tcpdump on the operator's own interface, named BPF filters, protocol
  aggregates only), `host-audit` (lynis baseline of the operator's own
  machine).
* `exec-tool` gains searchsploit and host-OR-URL target handling.
* `web-deep-audit`, `own-box-baseline` and `binary-triage` playbooks.
* GUI proxy whitelist + hermes/rp-mcp `collect` operator tool expose the
  whole surface to the chat plane.

## Coverage-driven planning (Phase 12)

* `intel vuln-coverage --plan` turns blind spots into a concrete gated
  proposal list + a ready `agent run --plan` payload.
* `agent run <case> "…" --coverage` audits what the case has NOT covered
  yet through the same planner validation and six gates. Covered classes
  are never re-proposed.

## GUI hardening part 2 — session kill

* One click (Settings → kill session) closes the gateway, the browser
  bridge and the proxy together; in-flight hermes runs stop.
* Same-origin gated `POST /api/session_kill`; teardown SIGTERMs only
  same-user rebel-profiler listeners found via a pure /proc scan.

## Wireless plane (v1.5 line)

* `--privileged` wraps ONLY airmon-ng/airodump-ng via whitelisted sudo
  (`sudo -n`, or `sudo -A` with `RP_SUDO_ASKPASS`) for non-root
  operators; the argv contract is unchanged, tested and documented.

## Engineering

* Empty-argv crash in the default runner replaced with a structured
  `UsageError`; nm `--wide` flag caught by the live Kali smoke test.
* Suite: **1088 passing**, 27 skipped; CI green on Python 3.11–3.14.
* `install.sh` hunter toolset now covers nikto, wpscan, exploitdb,
  tcpdump, lynis, sslscan, enum4linux-ng, dnsrecon, seclists.
