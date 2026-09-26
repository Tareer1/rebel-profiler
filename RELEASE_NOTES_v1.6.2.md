# Release notes — Rebel Profiler v1.6.2

**Theme: localization + closeout.** ROADMAP Phase 12 is now fully checked
off: the post-quantum readiness review ships as a pinned document, and the
operator plane speaks three languages — **Hinglish joins Urdu and English**
as the everyday register. Version pins aligned to 1.6.2 everywhere.

## Hinglish operator language (new — `RP_LANG=hi-ur`)

* `core/i18n.py` gains the `hi-ur` table: `Wajah:` (Reason), `Kya karein:`
  (Action), `exit N ∴ har denial audit me darj hai` (exit footer) plus the
  shared verdict words (`theek` / `khatra` / `reject`).
* Pure Roman script — safe on terminals without right-to-left shaping,
  no font tricks needed; Urdu (`RP_LANG=ur`) stays for Perso-Arabic
  terminals and renders through the terminal's own bidi.
* Alias codes accepted: `hi-ur`, `hinglish`, `hi`, `roman-urdu`.
* The error frame, `RPError.render()` and every future localized surface
  route through `i18n.t()`; JSON/JSONL/CSV, exit codes and schema keys are
  byte-identical in all three languages (pinned by `tests/test_i18n.py`).

## Post-quantum readiness review (ROADMAP Phase 12 closeout)

* `docs/PQC_REVIEW.md` — every hash and key surface inventoried against the
  NIST PQC path (FIPS 203 ML-KEM / 204 ML-DSA / 205 SLH-DSA): SHA-256
  evidence chains and content addressing (quantum-resilient), HMAC-SHA256
  signing across plugins/webhooks/forge (resilient; ML-DSA is the long-term
  path), scrypt credential KDF (symmetric root, nothing for Shor to break).
* Verdict: the only Shor exposure is a *future* remote transport — hybrid
  ML-KEM TLS is mandated before any such hop. Order of change documented.
* `tests/test_pqc_review.py` pins the inventory and bans MD5/SHA-1 and
  RSA/ECDSA/DH imports from ever entering the tree unreviewed.

## Housekeeping

* Version pins aligned: `__init__`, `pyproject.toml`, MCP `SERVER_INFO` →
  1.6.2 (v1.6.1 had drifted between packaging metadata and code).
* ROADMAP Phase 12: both pending items checked off — the phase is complete.
* CHEATSHEET: `RP_LANG` documented in the environment table with live
  examples.

## Tests

* Full suite: **1170 passed / 23 skipped** — including the new Hinglish
  selection/alias/script-safety tests alongside the Urdu and English pins.

## Upgrade

```bash
./scripts/install.sh --core        # or your existing install route
rebel-profiler --version           # 1.6.2
RP_LANG=hi-ur rebel-profiler --help
```
