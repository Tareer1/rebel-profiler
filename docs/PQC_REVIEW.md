# Post-Quantum Readiness Review (ROADMAP Phase 12)

**Scope:** every cryptographic primitive Rebel Profiler relies on, inventoried
against the NIST PQC migration path (FIPS 203 ML-KEM, FIPS 204 ML-DSA,
FIPS 205 SLH-DSA), with an honest order-of-change. This review is a survey of
*this tool's own code* — not a security guarantee, and not a migration.

Reviewed against the codebase at v1.6.1. "Quantum-fragile" means the primitive
falls to a cryptographically relevant quantum computer (CRQC) running
Shor's algorithm; "quantum-resilient" means no known quantum speedup beyond
Grover (mitigated by doubling key/output length, which SHA-256 already has
room for).

## 1. Inventory — what this tool actually uses

| Surface | File | Primitive | Quantum verdict |
|---|---|---|---|
| Evidence ledger content addressing | `evidence/store.py` | SHA-256 | Resilient (Grover-only; 256-bit preimage margin holds) |
| Evidence chain linkage | `evidence/store.py`, `evidence/audit.py` | SHA-256 over canonical JSON | Resilient — tamper evidence survives; no signatures to break |
| Audit chain (tamper-evident) | `evidence/audit.py` | SHA-256 hash chain | Resilient as *detection*; see §2 for the trust-model caveat |
| Worker-plane job checksums | `execution/worker.py` | SHA-256 (canonical job files) | Resilient — integrity only |
| Worker-plane token compare | `execution/worker.py` | `hmac.compare_digest` on shared token | Fragile *if the shared secret is long-lived*; see §3 |
| Plugin manifests (HMAC-SHA256 signing) | `core/plugins.py` | HMAC-SHA256 | Resilient today (HMAC/SHA-256 has no known Shor attack); long-term, ML-DSA is the replacement path |
| Event webhooks (HMAC-SHA256) | `core/events.py` | HMAC-SHA256 over `timestamp.body` | Same as plugins |
| API gateway token | `cli/main.py` | SHA-256 of the token, compare_digest | Same as worker tokens |
| Browser-bridge token | `browser/bridge.py` | HMAC-style compare_digest | Same as worker tokens |
| Feature Forge adapter signing | `agent/forge.py` | HMAC-SHA256 over the manifest | Same as plugins |
| Credential broker at rest | `security/credentials.py` | scrypt KDF + HMAC-SHA256 counter-mode stream + encrypt-then-MAC | scrypt/HMAC: no Shor attack; confidentiality holds — but see §3 on key agreement |
| LLM daemon job files | `llm/daemon.py` | SHA-256 checksums | Resilient — integrity only |
| Layer shards / scripts / ops backup | `llm/quant.py`, `llm/codescript.py`, `core/ops.py`, `intel/complaint.py`, `intel/detection.py` | SHA-256 digests | Resilient — integrity only |

What the tool deliberately does **not** use today: RSA, finite-field DH/ECDH,
ECDSA, and any TLS terminated by this tool (all transports ride the loopback
interface; the only outbound crypto is whatever the OS TLS stack does for
opt-in external endpoints — that stack is the distro's to migrate, not ours).

## 2. The honest trust-model caveat

A SHA-256 hash chain proves **integrity** (nothing was edited after the fact)
only while the chain's head is anchored somewhere an attacker cannot rewrite.
Rebel Profiler anchors the head on the same disk it runs on. A CRQC does not
change that — SHA-256 preimages stay hard — but a *disk-compromise* adversary
who can recompute whole chains was always out of scope for an unanchored
chain. The PQC-relevant upgrade path is anchoring chain heads into an
external, signed (later: ML-DSA-signed) checkpoint — a "witness" — which is
where SLH-DSA (FIPS 205, stateless hashes) fits naturally if a stateful
LMS/XMML setup is operationally undesirable.

## 3. Key-establishment gap (the only real Shor exposure)

There is exactly one place where the classical key-agreement shape could
enter this codebase: if a future change ever moves case data or the LLM data
pack across a network boundary, TLS 1.3's X25519/ECDH handshake becomes the
weak link — Shor breaks it outright. Today nothing crosses that boundary
(loopback only), so the honest statement is:

* **Now:** no key agreement anywhere in the code ⇒ nothing for Shor to break.
* **First change to make** if a remote transport is ever added: terminate TLS
  with a hybrid PQC group (X25519+ML-KEM-768 — already the default in modern
  OpenSSL ≥ 3.5) and refuse endpoints that cannot negotiate it.
* **Key hierarchy note:** the credential broker derives everything from
  `RP_MASTER_SECRET` (scrypt) — a symmetric root, quantum-resilient at
  adequate length. No asymmetric wrap exists to migrate.

## 4. Order of change (what moves first)

1. **Nothing breaks today.** Every current primitive survives a CRQC.
2. **When remote transport appears** → hybrid ML-KEM TLS only (§3).
3. **When evidence leaves the machine** (complaint packages handed to third
   parties, chain heads published) → sign the bundle manifest with ML-DSA
   (FIPS 204); keep SHA-256 inside as the content addresser.
4. **Long-lived HMAC trust roots** (plugin trust, webhook secrets) → rotate on
   a schedule; swap to ML-DSA only when a non-symmetric trust root becomes a
   real requirement.
5. **Never migrate** the content-addressing itself: SHA-256 stays. A CRQC
   halves its effective preimage strength (Grover) and 2¹²⁸ work remains
   out of reach; the ledger's meaning is integrity, not confidentiality.

## 5. What this review demands of future code

* New crypto must state, in its module docstring, which row of §1 it extends.
* Any new hash use must be SHA-256 or stronger; MD5/SHA-1 remain banned.
* Any new network hop must loop back to §3 before it merges.
* The inventory table is pinned by `tests/test_pqc_review.py`, which asserts
  the surfaces above still exist and that no banned primitive
  (`hashlib.md5`, `hashlib.sha1`, RSA/ECDSA/DH imports) has entered the tree.
