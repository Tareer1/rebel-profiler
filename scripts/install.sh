#!/usr/bin/env bash
# install.sh — Rebel Profiler onto a fresh Kali/Debian box, one command.
#
#   ./scripts/install.sh              full install (hunter toolset included)
#   ./scripts/install.sh --core       core only (no hunter binaries)
#
# What it does, in order:
#   1. python3 venv + editable install (core is stdlib-only, no pinned deps)
#   2. ~/.local/bin symlinks: rp, rp-mcp, rebel-profiler
#   3. hunter toolset via apt where the distro packages it (advisory — the
#      adapters degrade gracefully, so a slim box still works)
#   4. hermes-agent MCP wiring, IF the Nous hermes CLI is present
#   5. `rebel-profiler doctor` as the final verdict
#
# Idempotent: safe to re-run; every step skips what is already done.
set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
say()  { printf '%s\n' "${BOLD}::${RESET} $*"; }
ok()   { printf '%s\n' "${GREEN} ✓${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW} !${RESET} $*"; }
die()  { printf '%s\n' "${RED} ✗${RESET} $*" >&2; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_ONLY=0
[ "${1:-}" = "--core" ] && CORE_ONLY=1
BIN_DIR="${HOME}/.local/bin"
VENV="${REPO}/.venv"

command -v python3 >/dev/null || die "python3 not found — install Python 3.11+ first"
mkdir -p "${BIN_DIR}"

# --- 1. venv + editable install ------------------------------------------
say "python environment"
if [ ! -x "${VENV}/bin/python" ]; then
    python3 -m venv "${VENV}"
    ok "venv created at ${VENV}"
else
    ok "venv already present"
fi
"${VENV}/bin/pip" install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet -e "${REPO}"
ok "rebel-profiler installed (editable)"

# --- 2. PATH symlinks ------------------------------------------------------
say "commands on PATH (${BIN_DIR})"
ln -sf "${REPO}/tools/rp"                        "${BIN_DIR}/rp"
ln -sf "${VENV}/bin/rp-mcp"                      "${BIN_DIR}/rp-mcp"
ln -sf "${VENV}/bin/rebel-profiler"              "${BIN_DIR}/rebel-profiler"
for c in rp rp-mcp rebel-profiler; do ok "$c"; done
case ":${PATH}:" in
    *":${BIN_DIR}:"*) : ;;
    *) warn "${BIN_DIR} is not on PATH — add:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

# --- 3. hunter toolset (advisory) -----------------------------------------
if [ "${CORE_ONLY}" = "0" ]; then
    say "hunter toolset (apt where packaged)"
    if command -v apt-get >/dev/null; then
        # Distro-packaged hunters first; unknown names are skipped, not fatal.
        APT_PKGS="nmap whois dnsutils whatweb wafw00f amass ffuf subfinder nuclei katana gau arjun naabu dalfox"
        WANT=""
        for p in ${APT_PKGS}; do
            command -v "${p}" >/dev/null || apt-cache show "${p}" >/dev/null 2>&1 && WANT="${WANT} ${p}"
        done
        if [ -n "${WANT}" ]; then
            warn "needs sudo to install:${WANT}"
            sudo -E apt-get update -qq || true
            # shellcheck disable=SC2086
            sudo -E apt-get install -y -qq --no-install-recommends ${WANT} || \
                warn "some apt packages failed — continuing (toolset is advisory)"
        fi
        ok "apt hunters settled"
    fi
    # ProjectDiscovery-style tools the distro may not package: go install
    # only when a Go toolchain already exists — the script never pulls a
    # toolchain on its own.
    if command -v go >/dev/null; then
        GO_TOOLS="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
github.com/projectdiscovery/httpx/cmd/httpx@latest
github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
github.com/projectdiscovery/katana/cmd/katana@latest
github.com/lc/gau/v2/cmd/gau@latest"
        for spec in ${GO_TOOLS}; do
            bin="$(basename "${spec%%@*}")"
            if ! command -v "${bin}" >/dev/null; then
                go install "${spec}" 2>/dev/null && ok "go install ${bin}" || warn "go install ${bin} failed (skipped)"
            fi
        done
    else
        warn "no Go toolchain — subfinder/httpx/nuclei/katana/gau come from apt or skip (doctor reports what is missing)"
    fi
else
    say "hunter toolset skipped (--core)"
fi

# --- 4. hermes-agent MCP wiring (optional) ---------------------------------
HERMES_BIN="$(command -v hermes || true)"
HERMES_HOME="${HERMES_HOME:-${HOME}/.hermes}"
if [ -n "${HERMES_BIN}" ] && [ -f "${HERMES_HOME}/config.yaml" ]; then
    say "hermes-agent MCP wiring"
    if grep -q "rebel-profiler:" "${HERMES_HOME}/config.yaml" 2>/dev/null; then
        ok "mcp_servers.rebel-profiler already wired"
    else
        cp "${HERMES_HOME}/config.yaml" "${HERMES_HOME}/config.yaml.bak-rp.$(date +%s)"
        cat >> "${HERMES_HOME}/config.yaml" <<EOF
mcp_servers:
  rebel-profiler:
    command: ${BIN_DIR}/rp-mcp
    args: []
EOF
        ok "wired rp-mcp into ${HERMES_HOME}/config.yaml (backup kept)"
    fi
else
    say "hermes-agent not detected — skipping MCP wiring (the tool works without it)"
fi

# --- 5. doctor verdict ------------------------------------------------------
say "doctor"
"${VENV}/bin/rebel-profiler" doctor || true
printf '\n%s\n' "${BOLD}Done.${RESET} Try:  ${BOLD}rp${RESET}   (status panel)   ·   ${BOLD}rp talk \"find bugs on <target>\"${RESET}"
