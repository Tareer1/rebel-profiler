"""Reverse-engineering plane: static, offline, analysis-only binary study.

The RE adapters answer the malware-analysis domain's lawful half: a file the
operator ALREADY possesses (downloaded sample, firmware blob, suspicious
attachment already captured as evidence) is dissected on the operator's own
machine. Contracts enforced here, mechanically:

  * NO execution of the analyzed file — only metadata reads, string/section
    dumps, header parsing and disassembly of bytes as data;
  * NO network — the file never leaves the machine and no tool here phones
    home;
  * path validation is strict (evidence-dir style paths, no shell
    metacharacters, no /proc, /sys or /dev);
  * every capability is ``binary_analysis`` → risk LOW (offline reads), but
    plan/execute still passes the broker's six gates like everything else.

Adapters:
  * :class:`ChecksecAdapter`    — mitigations (NX/PIE/canary/RELRO)
  * :class:`BinaryInfoAdapter`  — file type, hashes, linked libraries
  * :class:`StringDumpAdapter`  — printable strings (bounded, IOC hunting)
  * :class:`SymbolDumpAdapter`  — symbols & dynamic imports
  * :class:`DisasmAdapter`      — objdump disassembly of one function/section

The ``max_lines`` param on :class:`StringDumpAdapter` bounds how many
strings the PARSER turns into claims (the argv itself stays a single
process — no pipe, no head, no second binary).

Nothing here detonates, unpacks in memory, or exploits: detection and
understanding, not offense.
"""

from __future__ import annotations

from ..core.errors import UsageError
from .broker import ActionRequest, Adapter
from .adapters import _single_token

# A file path safe to hand to the RE tools: absolute (leading /) or
# relative, no shell metacharacters, no traversal games into kernel
# pseudo-filesystems, and a sane length. Binaries live in evidence blobs
# or the operator's sample dir.
_PATH = r"/?[A-Za-z0-9][A-Za-z0-9._/@+-]{2,300}"
_SECTION = r"[A-Za-z0-9._-]{1,40}"


def _validate_sample_path(path: str) -> str:
    """Reject kernel pseudo-fs and device paths; everything else is data."""
    bad_prefixes = ("/proc", "/sys", "/dev",)
    normalized = path.strip()
    for bad in bad_prefixes:
        if normalized == bad or normalized.startswith(bad + "/"):
            raise UsageError(
                f"Sample path '{normalized[:60]}' is not analyzable",
                reason=f"{bad} trees are kernel interfaces, not sample files.",
                action="Copy the sample into the case evidence dir and pass that path.",
            )
    return _single_token(normalized, field="sample", pattern=_PATH)


class ChecksecAdapter(Adapter):
    """Binary mitigation posture (NX, PIE, canary, RELRO) via checksec.

    Tells the operator WHICH exploit-prevention mitigations a shipped
    binary was built with — the defensive read that decides how a
    memory-corruption report should be weighted.
    """

    name = "checksec"
    binary = "checksec"
    capability_class = "binary_analysis"
    allowed_params = ()
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        path = _validate_sample_path(request.target)
        return [self.binary, "--file=" + path]


class BinaryInfoAdapter(Adapter):
    """File identity: type, architecture, hashes and linked libraries.

    readelf -h gives the header (type/machine/entry), -d the dynamic
    section (needed libraries, RUNPATH). Paired with the file's SHA-256
    (already computed by the evidence store at ingest), this is the
    sample's identity card.
    """

    name = "binary-info"
    binary = "readelf"
    capability_class = "binary_analysis"
    allowed_params = ()
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        path = _validate_sample_path(request.target)
        return [self.binary, "-h", "-d", "--wide", path]


class StringDumpAdapter(Adapter):
    """Bounded printable-string dump for IOC hunting (strings).

    Minimum length 6 (drops noise), output capped so a multi-megabyte
    sample cannot flood the evidence store. Strings often carry C2
    domains, mutexes, user agents and error messages — the analyst's
    first passive read of a sample.
    """

    name = "string-dump"
    binary = "strings"
    capability_class = "binary_analysis"
    allowed_params = ("max_lines",)
    required_params = ()

    _COUNT = r"\d{1,5}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        path = _validate_sample_path(request.target)
        max_lines = _single_token(
            str(request.params.get("max_lines", "400")),
            field="max_lines", pattern=self._COUNT)
        if not (20 <= int(max_lines) <= 5000):
            raise UsageError(f"max_lines out of range: {max_lines}",
                             action="Capture 20-5000 strings.")
        # -n 6 drops sub-6-char noise; the PIPELINE caps the parsed claim
        # count, so no second process (head) is ever needed in the argv
        return [self.binary, "-n", "6", path]


class SymbolDumpAdapter(Adapter):
    """Symbol table and dynamic imports (nm -D / readelf --dyn-syms).

    Exported/undefined symbols reveal what a library exposes and what a
    binary consumes — imports like socket/connect are behavioral hints
    for the analysis notes, read as data, never executed.
    """

    name = "symbol-dump"
    binary = "nm"
    capability_class = "binary_analysis"
    allowed_params = ("defined_only",)
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        path = _validate_sample_path(request.target)
        defined = request.params.get("defined_only")
        argv = [self.binary, "-D"]
        if str(defined) in {"1", "true", "yes"}:
            argv.append("--defined-only")
        argv.append(path)
        return argv


class DisasmAdapter(Adapter):
    """Disassemble one section/function (objdump) — bytes as data.

    Disassembly is reading, not running: objdump decodes the instruction
    bytes of a section the operator names. Used to confirm what a
    suspicious function actually does before writing the analysis note.
    """

    name = "disasm"
    binary = "objdump"
    capability_class = "binary_analysis"
    allowed_params = ("section",)
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        path = _validate_sample_path(request.target)
        section = str(request.params.get("section", "")).strip()
        argv = [self.binary, "-d", "--no-show-raw-insn", path]
        if section:
            section = _single_token(section, field="section",
                                    pattern=_SECTION)
            argv += ["-j", section]
        return argv


RE_ADAPTERS: tuple[type[Adapter], ...] = (
    ChecksecAdapter,
    BinaryInfoAdapter,
    StringDumpAdapter,
    SymbolDumpAdapter,
    DisasmAdapter,
)
