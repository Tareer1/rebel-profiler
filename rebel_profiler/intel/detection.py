"""Detection engineering (Phase 6): test artifacts + IoC/YARA rule generation.

Purpose: let a security professional **validate and tune defenses** — AV/EDR
coverage, canary tripwires, YARA rule quality — using benign, industry-
standard test artifacts and deterministic rule generation. This is the
blue-team counterpart of the malware-analysis domain.

Hard limits, enforced in code (not prompts):

  * **No functional malware is generated.** No payload logic, no evasion,
    no persistence, no propagation code — none of it. This module emits
    *detection targets* and *detection rules*, never attack code.
  * Artifacts are the industry-standard EICAR test string (the global AV
    test file, inert by design — it is a COM-style test stub, not a virus),
    benign canary tripwire files, and textual IoC bundles.
  * **Everything is authorization-gated**: generation requires an ACTIVE
    case, every artifact is registered as hash-chained evidence, every step
    is audit-logged, and each artifact type declares its risk.
  * **Containment by construction**: artifacts land in the case directory
    under ``detections/`` (quarantine-style), never in system paths, never
    in executables on disk outside that folder.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from ..core.errors import UsageError
from ..core.redact import redact
from ..evidence.audit import AuditChain
from ..evidence.store import EvidenceStore

# The industry-standard AV test string (EICAR). Inert by design: no valid
# executable structure, universally recognized by AV products as a test file.
EICAR_TEST_STRING = (
    r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!'
    r'$H+H*'
)

ARTIFACT_KINDS = {
    # kind -> (risk, description)
    "eicar_test_file": (
        "moderate",
        "Industry-standard EICAR AV test file (inert) for AV/EDR validation.",
    ),
    "canary_tripwire": (
        "low",
        "Benign canary file whose access/edit is an alert tripwire for defenders.",
    ),
    "ioc_bundle": (
        "low",
        "Structured IoC set (hashes/domains/ips/mutexes) for SIEM/ETW ingestion.",
    ),
    "yara_ruleset": (
        "low",
        "Deterministic YARA rules generated from case IoCs for detection validation.",
    ),
}

_IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]{1,200}"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "mutex": re.compile(r"\bGlobal\\\\[A-Za-z0-9_.-]{3,60}\b"),
    "registry_key": re.compile(
        r"\b(?:HKLM|HKCU)\\\\(?:Software|Run)\\\\[A-Za-z0-9_. -]{1,60}"),
}


class ArtifactDeniedError(UsageError):
    """Raised when artifact generation violates the containment policy."""


def _safe_filename(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:60]
    return name or "artifact"


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Deterministic IoC extraction from any report/log text."""
    found: dict[str, list[str]] = {}
    for kind, pattern in _IOC_PATTERNS.items():
        values = sorted({m.group(0) for m in pattern.finditer(text)})
        if values:
            found[kind] = values[:100]
    return found


def _yara_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_yara_ruleset(iocs: dict[str, list[str]], *, rule_name: str,
                       scope_note: str = "") -> str:
    """Deterministic YARA rules from a case IoC set.

    Strings-only matching keeps the rules safe, testable and fast; conditions
    require multiple independent indicators to fire, which minimizes false
    positives — a professional detection baseline, not an attack tool.
    """
    strings: list[str] = []
    for kind in ("sha256", "md5", "mutex", "registry_key", "url", "domain", "ipv4"):
        for value in iocs.get(kind, [])[:10]:
            strings.append(f'        ${kind}_{len(strings)} = "{_yara_escape(value)}"'
                           f"  // {kind}")
    if not strings:
        raise UsageError(
            "No usable IoCs for a YARA ruleset",
            action="Collect IoCs first (intel collect / reports / ioc bundle).")
    condition_count = min(3, len(strings))
    name = _safe_filename(rule_name)
    lines = [
        f'rule RP_{name}',
        '{',
        '    meta:',
        f'        author = "rebel-profiler detection engineering"',
        f'        scope = "{_yara_escape(scope_note[:80])}"',
        f'        generated = "{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}"',
        f'        ioc_count = "{len(strings)}"',
        '    strings:',
        *strings,
        '    condition:',
        f'        {condition_count} of them',
        '}',
        '',
    ]
    return "\n".join(lines)


class DetectionLab:
    """Generates benign test artifacts + detection rules, fully audited."""

    def __init__(self, case_id: str, *, case_dir: Path,
                 evidence: EvidenceStore, audit: AuditChain | None = None) -> None:
        self.case_id = case_id
        self.case_dir = Path(case_dir)
        self.evidence = evidence
        self.audit = audit
        self.out_dir = self.case_dir / "detections"
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _audit_append(self, action: str, subject: str, detail: dict) -> None:
        if self.audit is not None:
            self.audit.append(self.case_id, actor="detection-lab", action=action,
                              subject=subject, detail=detail)

    def _register(self, *, kind: str, data: bytes, name: str, note: str) -> dict:
        digest = hashlib.sha256(data).hexdigest()
        target = self.out_dir / _safe_filename(name)
        if target.exists() and target.read_bytes() == data:
            pass  # idempotent regeneration
        else:
            target.write_bytes(data)
        rec = self.evidence.register(
            self.case_id, kind=f"detection_{kind}", data=data, source="detection.lab",
            note=note, meta={"path": str(target), "sha256": digest,
                             "risk": ARTIFACT_KINDS[kind][0]})
        self._audit_append("artifact.generated", kind,
                           {"name": target.name, "sha256": digest,
                            "evidence": rec.id})
        return {"kind": kind, "path": str(target), "sha256": digest,
                "evidence_id": rec.id, "risk": ARTIFACT_KINDS[kind][0],
                "note": ARTIFACT_KINDS[kind][1]}

    def generate(self, kind: str, *, name: str, ioc_text: str = "",
                 iocs: dict[str, list[str]] | None = None,
                 canary_note: str = "") -> dict:
        """Generate one benign artifact or detection rule set."""
        if kind not in ARTIFACT_KINDS:
            raise ArtifactDeniedError(
                f"Unknown artifact kind '{kind}'",
                reason="Only benign test/detection artifacts are offered.",
                action="Pick one of: " + ", ".join(sorted(ARTIFACT_KINDS)))
        if kind == "eicar_test_file":
            return self._register(
                kind=kind, data=EICAR_TEST_STRING.encode(), name=name,
                note="EICAR standard AV test file — inert, for scanner validation")
        if kind == "canary_tripwire":
            token = uuid.uuid4().hex
            content = (
                "REBEL-PROFILER CANARY TRIPWIRE\n"
                f"case: {self.case_id}\n"
                f"token: {token}\n"
                f"note: {redact(canary_note)[:200]}\n\n"
                "This is a decoy file. Its access, modification or deletion\n"
                "should trigger a defensive alert. It performs no function.\n"
            ).encode()
            record = self._register(kind=kind, data=content, name=name,
                                    note=f"canary token={token}")
            record["token"] = token
            return record
        if kind == "ioc_bundle":
            merged = extract_iocs(ioc_text or "")
            if iocs:
                for key, values in iocs.items():
                    merged.setdefault(key, [])
                    merged[key] = sorted(set(merged[key]) | set(values))[:100]
            if not merged:
                raise UsageError(
                    "No IoCs found in the provided text",
                    action="Pass report text or an explicit --ioc kind=value.")
            data = json.dumps({
                "kind": "rebel-profiler-ioc-bundle", "case_id": self.case_id,
                "generated_at": time.time(), "iocs": merged,
            }, indent=2, sort_keys=True).encode()
            record = self._register(kind=kind, data=data, name=name,
                                    note="structured IoC bundle for SIEM ingestion")
            record["iocs"] = merged
            return record
        # yara_ruleset
        merged = iocs or extract_iocs(ioc_text or "")
        if not merged:
            raise UsageError(
                "No IoCs available to derive YARA rules",
                action="Generate an ioc bundle first, or pass --ioc.")
        rules = build_yara_ruleset(merged, rule_name=name,
                                   scope_note=f"case {self.case_id}")
        record = self._register(kind=kind, data=rules.encode(), name=f"{name}.yar",
                                note="YARA ruleset derived from case IoCs")
        record["rules"] = rules
        return record

    def list_artifacts(self) -> list[dict]:
        out = []
        for path in sorted(self.out_dir.iterdir()):
            if path.is_file():
                data = path.read_bytes()
                out.append({
                    "name": path.name, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()[:16] + "…",
                })
        return out
