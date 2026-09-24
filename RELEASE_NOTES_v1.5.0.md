# Rebel Profiler v1.5.0 — the offense plane, the coverage matrix & the sci-fi shell

Phase 11: the operator asks *"kya ye har tarah ki vulnerability dhoondh
sakta hai?"* — and the tool answers with an executable matrix, a benign
payload workbench that verifies classes without damage, and a terminal face
worthy of the name REBEL. Everything below was run live on a Kali Rolling
2026.3 laptop before release: install, doctor, a full case lifecycle, the
GUI console, and a real 7B GGUF Hermes session.

## The headline: `intel vuln-coverage` — the honest answer to "what can it find?"

Twenty-two vulnerability classes (XSS, SQLi, SSTI, command injection, IDOR,
open redirect, path traversal, weak TLS, missing headers, insecure cookies,
cleartext credentials, known CVEs, tech exposure, WAF gaps, hidden params,
unauthenticated API surface, subdomain takeover, info disclosure, email
exposure, DNS health, service exposure, network topology), each mapped to:

- the **live actions** that detect it — every name is validated against the
  running `AdapterRegistry` by tests, so the matrix can never drift from
  what the tool actually executes;
- the **payload class** (offense plane) whose marker verifies it, if one
  exists.

Per case it reports **COVERED** (a detect action already produced claims
here), **AVAILABLE** (executable, not yet run) and **NO-ADAPTER**, with a
copy-paste `run:` hint per blind spot. Detection ≠ exploitation — the matrix
says so on every render.

```
rebel-profiler intel vuln-coverage <case-id>
# or inside the shell:  :cover
```

## The offense plane: attack plans & benign payload markers

- `intel attack-plan <case-id>` — ranked strategies derived from the case's
  OWN claim ledger; every proposed strategy names the live actions that
  would execute. Never a generic checklist.
- `intel payload build/deploy` — benign impact markers (reflected-XSS echo
  marker, SSTI `${7*7}` math, single-file traversal read, self-referencing
  redirect, cmdi echo). Markers PROVE a vulnerability class without damage;
  deployment rides only the approval-gated probe with hash-chained evidence.

## The sci-fi shell: `rebel-profiler shell`

A unicode readline console over the ONE argparse main — no second parser,
no second set of gates:

```
╭─[# REBEL ── rebel-profiler ── <case-id> ─
╰─◈ rebel ❯
```

Console commands: `:help :case <id> :status :plan :cover :tools :banner
:clear :exit`. Anything else runs verbatim through the real CLI — scoped,
gated, evidenced, audited. ANSI colour auto-disables on pipes and CI;
`NO_COLOR` or `RP_PLAIN=1` flattens the whole aesthetic (glyphs and box
drawing go ASCII) for accessibility.

## The themed human output (`cli/theme.py`)

One shared palette + glyph set + banner + error frame + table renderer for
the human mode:

- structured errors render as framed blocks — what happened / why / next
  action — with an `exit N ∴ every denial is audited` footer;
- box-drawn tables with glyph markers and human-readable `*_at` timestamps
  (the JSON/JSONL/CSV modes keep raw epoch values byte-identical);
- decoration is **additive only**: every original text fragment stays
  grep-findable, so scripts and tests keep working.

Also: the deprecated `argparse.FileType` is gone — workflow and forge file
arguments now read through `_read_text_arg`, which turns a missing file into
a structured UsageError instead of an interpreter-level crash.

## New parsers & triage rules (bounty assess)

- `_parse_header_head` — curl `-sSI` output becomes security-header
  observations and cookie-FLAG claims; the cookie **value is never
  recorded**, only the name and its Secure/HttpOnly/SameSite state.
- `_parse_sslscan` — enabled legacy protocols (SSLv2/v3, TLS 1.0/1.1) and
  vulnerable-marker lines become claims; "not vulnerable" noise never does.
- Five new `bounty assess` rules: `nuclei_finding`, `nuclei_detail`,
  `tls_vuln`, `tls_protocol`, `cookie_flag:no security flags` — each with
  advisory severity, CWE, a reproduction command and remediation.

## Verified live before release (Kali Rolling 2026.3, 4-core CPU laptop)

- `./scripts/install.sh` full run — doctor: ALL CHECKS PASSED, all 10 hunter
  binaries available, GGUF engine installed.
- Full case lifecycle: create → scope → activate → scope-check → run `echo`
  (six gates) → evidence chain (7 records) → audit chain (32 events) → both
  verify OK.
- Live `header-audit` against a loopback HTTP server produced real claims;
  an out-of-scope `file://` URL was refused with the framed scope error
  (exit 5, audited) — fail-closed verified live.
- Worker plane SYN→ACK, scheduler tick, hypothesis record, search rebuild +
  FTS hit, ops self-check healthy.
- Read-only API gateway: 401 fail-closed without the token, 200 with it;
  GUI proxy served the console and enforced the CLI whitelist (unknown
  command rejected).
- Hermes oneshot with a real Qwen2.5-Coder-7B Q4 checkpoint (`--tier high`)
  answered through the gated session on first try.

## Suite

947 passed, 27 skipped — three consecutive green runs, including the new
`tests/test_shell_and_coverage.py` (shell helpers, piped shell loop,
coverage-matrix honesty against the live registry, both parser shapes).
