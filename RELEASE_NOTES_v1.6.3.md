# Release notes — Rebel Profiler v1.6.3

**Theme: self-audit.** A full static-analysis pass (pyflakes + bandit + a
targeted pattern hunt) over the whole package, every real finding fixed,
and the tool's own doctor now runs the same class of scan against itself.
The tree reports **zero** pyflakes findings and **zero** banned primitives.

## Two latent NameError bugs fixed

* `llm/hermes.py` `_case_context` — the case-CONTEXT builder carried dead
  code referencing an undefined `row`; the failure-tolerant `except` hid
  it, so the Hermes chat context silently degraded to the case id only.
  It now reads the live case row properly: hunting-workflow and
  pending-approval hints land again.
* `execution/hunters.py` `SubfinderAdapter` — the `limit` param referenced
  an undefined module `_LIMIT` (the pattern lived as an unused class
  attribute): passing `limit=<n>` crashed at plan time. `_LIMIT` is now a
  shared module-level token; bounded-token validation and injection
  rejection are unchanged (gau's `self._LIMIT` consolidated onto it).

## Feature Forge: trust re-verified at LOAD time

`register_into()` used to import every `forge_*.py` it found. Now each
module must present its own HMAC-signed manifest sidecar
(`<module>.toml` + `<module>.sig`, written at accept time alongside the
legacy root manifest) and must byte-match the manifest's declared
`entry` + `source_sha256`. A tampered module, a forged signature or an
orphan file is refused and audit-logged (`forge.load_refused`) — never
executed. Multiple accepts no longer overwrite each other's root manifest.

## Doctor gains a static self-scan row

`core/selfscan.py` (stdlib-only, deterministic): compiles every package
module and pattern-scans for the primitives this project bans on itself —
bare `except`, the weak MD5/SHA-1 digest constructors, `pickle.loads`.
The doctor table shows `static self-scan · 100 module(s) compiled, 0
banned primitives`; any finding names file:line and fails the check.

## Hygiene: static analysis to zero

* pyflakes: **81 → 0 findings** across the package — dead locals, unused
  imports and f-string noise removed, with side-effect imports
  (`ctx.broker(db)`, `RoleEngine(db).require(...)`, `queue.get(...)` —
  validation by exception) preserved as explicit statements.
* The `NucleiAdapter` name shadow between `execution/hunters.py`
  (`nuclei-scan`) and `execution/adapters.py` (`vuln-correlate`) is apart:
  the hunters class is now `NucleiScanAdapter`; both adapters stay
  exported from `rebel_profiler.execution` with their actions unchanged.
* bandit (info): 0 HIGH; the 9 MEDIUMs reviewed and accepted by design —
  the forge `exec` runs only behind the static gate + sandbox + HMAC, the
  flagged SQL builds fixed column fragments with parameterized values, and
  every `urlopen` is loopback or an explicitly operator-pinned endpoint.

## Tests

Full suite: **1181 passed / 23 skipped** — including new pins for load-time
forge trust (tamper / orphan / bad-signature / missing-sidecar), the
self-scan (clean package, fixture tree with banned primitives, syntax
errors) and the adapter export split.

## Upgrade

```bash
./scripts/install.sh --core        # or your existing install route
rebel-profiler --version           # 1.6.3
rebel-profiler doctor              # now includes: static self-scan
```
