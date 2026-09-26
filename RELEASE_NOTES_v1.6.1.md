# Release notes — Rebel Profiler v1.6.1

**Theme: web-expansion + parity.** Four new gated web/DNS adapters take the
registry to 49 actions, the CWE/anomaly knowledge plane reaches Hermes MCP
and the GUI, and the compact-planner fix from 4bbb199 gets a regression
test. Same law: the model proposes, the gates decide, evidence or nothing.

## Web-expansion adapters (new — 45 → 49 actions)

* `cors-check` — ONE foreign-Origin probe (`curl -i`); a reflected
  `Access-Control-Allow-Origin` (+credentials) is the exploitable shape,
  a clean "no reflection" verdict is kept so the report shows the control
  was tested. `web_assessment`, confirmation-gated.
* `security-txt` — RFC 9116 discovery at both canonical locations;
  presence is the control, Contact/Policy lines become context claims.
  `passive_recon`.
* `graphql-introspection` — minimal `__schema` POST (no dump, no
  mutations): is the schema publicly readable? Unparseable replies emit
  NO claim. `web_assessment`, confirmation-gated.
* `email-spoof` — SPF/DMARC posture via `dig TXT` for ONE authorized
  domain; no mail is ever sent. `p=none`/absent records ARE the finding.
  `passive_recon`.

## Ecosystem wiring (every layer, same commit)

* **Parsers** (`intel/collection.py`): honest verdicts —
  `cors_check`, `securitytxt_check`/`securitytxt_field`,
  `graphql_introspection`, `email_spoofing`; garbage in → no claims.
* **Coverage matrix** (`intel/vulncov.py`): new classes
  `cors_misconfig` (CWE-942), `security_contact` (CWE-16),
  `email_spoofing` (CWE-359); `graphql-introspection` joins
  `api_surface`; `URL_TARGET_ACTIONS` pinned for the three URL-shaped
  actions, `email-spoof` stays host-shaped.
* **Bounty rules** (`intel/bounty.py`): every new claim kind maps to an
  advisory severity/CWE/reproduce/remediation — including the honest
  "control held" informationals.
* **Action guides 49/49** + tools-matrix rows + two hunter playbooks:
  `web-exposure` (CORS → GraphQL → security.txt → header-audit) and
  `email-spoofing` (DNS posture → personnel surface).
* **CWE seed**: CWE-942 added offline (coverage rows never reference a
  CWE the offline catalog lacks — pinned by test).

## Knowledge plane parity (MCP + GUI)

* Hermes MCP gains `rp_cwe_lookup`, `rp_cwe_search`,
  `rp_cwe_blind_spots`, `rp_anomalies` — the same operator tools the CLI
  uses; `SERVER_INFO` now tracks the package version (1.6.1).
* GUI: proxy whitelist adds `cors_check`, `security_txt`,
  `graphql_introspection`, `email_spoof`, `cwe_lookup`, `cwe_search`,
  `cwe_blind_spots`, `anomalies`; new **Web exposure & knowledge**
  screen (checks + CWE lookup/search + case blind spots + anomalies).

## Fixes & tests

* `intel/offense.py` docstring placeholder replaced with plain English.
* Planner compact auto-switch (context > 75% of tier cap) now pinned by
  a regression test; operator cwe/anomaly tools covered too.
* Full suite: **1151 passed / 27 skipped**.

## Upgrade

```bash
./scripts/install.sh --zipapp        # or download the .pyz + sha256 below
python3 rebel-profiler.pyz doctor
python3 rebel-profiler.pyz adapters  # 49 gated actions
```
