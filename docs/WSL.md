# Windows / WSL2 support matrix

Rebel Profiler is built for Kali Linux, but the core runs anywhere Python
3.11+ runs. This matrix records what works under **WSL2** (Windows 10/11,
`wsl --install -d kali-linux`), what degrades gracefully, and what stays
Kali-native hardware. Every gap is stated honestly — the tool never fakes
a capability, and `rebel-profiler doctor` tells you which side you are on
(it detects WSL read-only via `/proc/version` and prints an informational
row; nothing is gated on it).

## Verified on WSL2 (kali-linux distro)

| Area | Status | Notes |
|------|--------|-------|
| Core engine (case, scope, risk, policy, broker, evidence, audit) | ✅ full | stdlib-only; SQLite v3 migrations; identical six-gate sequence |
| CLI surface + output modes (human/JSON/JSONL/CSV) | ✅ full | structured errors and exit codes byte-identical |
| Knowledge layer (16 domains, techniques, glossary, planner context) | ✅ full | pure data |
| Passive recon (dig, whois, curl-based collectors) | ✅ full | DNS/WHOIS/CT/wayback all egress normally through NAT |
| Agent harness (`agent run`, `agent work`, coverage planning) | ✅ full | deterministic planners; LLM planners need an engine (below) |
| Worker plane, scheduler, workflows, hypotheses, RBAC, approvals | ✅ full | file/TCP-free internal machinery |
| Intel pipeline (claims, fusion, surface graph, FTS5 search) | ✅ full | |
| Report generators (human, JSON, SARIF 2.1.0, Markdown) | ✅ full | |
| nmap-based adapters (host-discovery, port-scan, service-detect, os-fingerprint, LAN sweeps) | ✅ full | nmap runs natively in WSL2; target only networks reachable from the Windows host |
| ffuf / whatweb / wafw00f / nuclei / katana / gau / arjun / subfinder / httpx | ✅ full | apt- or go-installable inside the distro; `install.sh` handles both |
| Reverse-engineering plane (readelf, checksec, strings, nm, objdump) | ✅ full | offline reads; binutils from apt; the best-behaved plane under WSL |
| nikto, wpscan, testssl.sh, sslscan, enum4linux-ng | ✅ full | apt packages present in kali-linux WSL image |
| LLM plane — gguf engine (llama-cpp-python) | ✅ full | CPU/CUDA both work; `RP_LLM__ALLOW_GPU=1` to opt into the host GPU |
| LLM plane — external engine (OpenAI-compatible) | ✅ full | opt-in only; payloads redacted before egress |
| GUI console (frontend/proxy.py + index.html) | ✅ full | use `http://127.0.0.1:8898` from the Windows browser; localhost forwarding is automatic |
| Hermes MCP (`rp-mcp`) | ✅ full | stdio transport is host-agnostic |

## Degraded (works with caveats)

| Area | Status | Notes |
|------|--------|-------|
| `packet-capture` (tcpdump) | ⚠️ partial | WSL2's virtual NIC sees only traffic the Windows host sees; promiscuous mode and monitor-style capture do not exist. Counts stay protocol aggregates — no claims change shape, fewer packets flow |
| `hping3` / masscan raw-socket modes | ⚠️ partial | raw packet craft is limited by the WSL2 NAT; TCP-connect modes work |
| `theHarvester` passive sources | ⚠️ partial | some source APIs rate-limit datacenter/cloud IPs harder than residential ones |
| Go toolchain install path | ⚠️ partial | `install.sh` only uses an existing Go toolchain; WSL users can `sudo apt install golang` first for the ProjectDiscovery tools |
| systemd service integration | ⚠️ partial | WSL2 with `systemd=true` (in `/etc/wsl.conf`) runs the resident daemon normally; without it, use `nohup`/`tmux` |

## Not available (Kali-native hardware)

| Area | Status | Notes |
|------|--------|-------|
| `wlan-survey` / `wlan-monitor` / `wlan-ap-audit` | ❌ WSL | RF adapters need real 802.11 hardware + airmon-ng monitor mode; WSL2's virtual NIC has no radio. Run the wireless plane on bare-metal Kali |
| Wi-Fi posture playbook (`wifi-posture`) | ❌ WSL | same hardware dependency — every step refuses cleanly rather than pretending |
| USB-dongle SDR/Bluetooth tooling | ❌ WSL | `usbipd-win` passthrough exists but is untested here; unsupported until verified |

## The honest contract

`rebel-profiler doctor` under WSL prints:

```
WSL environment   yes  WSL2 — RF/wireless adapters unavailable;
                       see docs/WSL.md for the verified support matrix
```

Nothing is hidden: a refused action returns its structured
what/why/next-action error exactly as on Kali, and every capability that
does run is gated, evidenced and audited identically. WSL2 is a supported
analysis platform — bare-metal Kali remains the reference for RF work.
