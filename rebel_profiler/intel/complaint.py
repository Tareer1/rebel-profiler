"""Law-enforcement complaint package generator (FIA CCW / IC3.gov ready).

Turns an investigated case into the artifact authorities actually accept: a
structured, integrity-verified complaint bundle containing

  * a machine- and human-readable **narrative** (what happened, what was
    found, why it matters),
  * the extracted **IoC set** (C2 domains, IPs, hashes, URLs, mutexes),
  * the **evidence manifest** — every supporting record with its SHA-256 and
    chain position, re-verified at export time,
  * the **audit timeline** (who did what, when — tamper-evident),
  * a **hash of the bundle itself** so the receiving agency can detect any
    post-export modification.

No exploitation capability, no offensive content — this is the defensive
deliverable that gets complaints filed, domains sinkholed and accounts
frozen. The operator fills in the legal fields (complainant identity,
jurisdiction); the tool supplies only what it can prove cryptographically.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from ..core.errors import UsageError
from ..evidence.audit import AuditChain
from ..evidence.store import EvidenceStore

SCHEMA_VERSION = 1

# complaint kinds map to agency templates
AGENCIES = {
    "fia_ccw": {
        "name": "FIA Cyber Crime Wing (Pakistan)",
        "channels": ["complaint portal: complaint.fia.gov.pk", "helpline: 1991"],
        "notes": "Attach CNIC of complainant; PECA 2016 sections apply.",
    },
    "ic3": {
        "name": "FBI Internet Crime Complaint Center (US)",
        "channels": ["ic3.gov complaint form"],
        "notes": "IC3 accepts international complaints where US nexus exists.",
    },
    "cert_in": {
        "name": "CERT-In (India)",
        "channels": ["incident@cert-in.org.in"],
        "notes": "Use for incidents with Indian infrastructure nexus.",
    },
    "generic_cert": {
        "name": "National CERT / CSIRT",
        "channels": ["your national CERT contact"],
        "notes": "Generic template for any jurisdiction.",
    },
}

_INCIDENT_TYPES = (
    "phishing", "ransomware", "beaconing_c2", "account_takeover",
    "data_theft", "scam_fraud", "impersonation", "malware_distribution",
    "other",
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ComplaintPackageBuilder:
    """Assembles the verified complaint bundle for one case."""

    def __init__(self, case_id: str, *, case_dir: Path, db,
                 evidence: EvidenceStore, audit: AuditChain | None = None) -> None:
        self.case_id = case_id
        self.case_dir = Path(case_dir)
        self.db = db
        self.evidence = evidence
        self.audit = audit
        self.out_dir = self.case_dir / "complaints"
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def build(
        self,
        *,
        agency: str = "generic_cert",
        incident_type: str = "other",
        narrative: str = "",
        complainant: str = "",
        subject_targets: list[str] | None = None,
    ) -> dict:
        """Assemble + hash the bundle. Returns the package record."""
        if agency not in AGENCIES:
            raise UsageError(
                f"Unknown agency '{agency}'",
                reason="Bundle templates exist per agency.",
                action="Pick one of: " + ", ".join(sorted(AGENCIES)))
        if incident_type not in _INCIDENT_TYPES:
            raise UsageError(
                f"Unknown incident type '{incident_type}'",
                action="Pick one of: " + ", ".join(_INCIDENT_TYPES))

        # 1. re-verify every chain right now — evidence that fails verification
        #    must NOT go into a complaint
        ev_report = self.evidence.verify_case(self.case_id)
        if not ev_report["chain_ok"]:
            raise UsageError(
                "Evidence chain failed verification — package not built",
                reason="A complaint built on broken evidence harms the case.",
                action="Run ops check, restore integrity, then rebuild.")
        audit_report = self.audit.verify(self.case_id) if self.audit else {"chain_ok": True}

        # 2. gather claims (the investigative findings)
        claims = [dict(r) for r in self.db.claims_for(self.case_id)]
        iocs = self._iocs_from_claims(claims)

        # 3. evidence manifest with hashes
        manifest = []
        for rec in self.evidence.list_records(self.case_id):
            manifest.append({
                "evidence_id": rec.id, "kind": rec.kind,
                "sha256": rec.sha256, "size": rec.size,
                "created_at": rec.created_at, "source": rec.source,
                "note": rec.note, "prev_hash": rec.prev_hash,
            })

        # 4. audit timeline
        timeline = []
        if self.audit is not None:
            for event in self.audit.events(self.case_id):
                timeline.append({
                    "seq": event.seq, "at": event.at, "actor": event.actor,
                    "action": event.action, "subject": event.subject,
                    "hash": event.hash,
                })

        agency_info = AGENCIES[agency]
        package = {
            "schema_version": SCHEMA_VERSION,
            "kind": "rebel-profiler-complaint-package",
            "case_id": self.case_id,
            "generated_at": time.time(),
            "agency": agency,
            "agency_guidance": agency_info,
            "incident_type": incident_type,
            "complainant": complainant[:120],
            "subject_targets": sorted(set(subject_targets or []))[:50],
            "narrative": narrative[:5000],
            "iocs": iocs,
            "claims": claims[:500],
            "evidence_manifest": manifest,
            "evidence_verification": {
                "records": ev_report["records"], "chain_ok": ev_report["chain_ok"],
            },
            "audit_verification": {
                "events": audit_report.get("events", 0),
                "chain_ok": audit_report.get("chain_ok", True),
            },
            "timeline": timeline[:500],
        }

        # 5. bundle hash — the agency can verify post-export integrity
        canonical = json.dumps(
            {k: v for k, v in package.items() if k != "bundle_sha256"},
            sort_keys=True, separators=(",", ":"))
        package["bundle_sha256"] = _sha256_bytes(canonical.encode())

        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        out_path = self.out_dir / f"complaint-{agency}-{stamp}.json"
        out_path.write_text(json.dumps(package, indent=2, sort_keys=True) + "\n")
        if self.audit is not None:
            self.audit.append(self.case_id, actor="complaint-builder",
                              action="complaint.generated", subject=agency,
                              detail={"path": str(out_path),
                                      "bundle_sha256": package["bundle_sha256"],
                                      "evidence": len(manifest)})
        return {
            "path": str(out_path),
            "bundle_sha256": package["bundle_sha256"],
            "agency": agency_info["name"],
            "evidence_records": len(manifest),
            "claims": len(claims),
            "iocs": sum(len(v) for v in iocs.values()),
            "timeline_events": len(timeline),
        }

    def _iocs_from_claims(self, claims: list[dict]) -> dict[str, list[str]]:
        """Extract the IoC vocabulary from case claims (deterministic)."""
        iocs: dict[str, list[str]] = {}
        for claim in claims:
            kind, value = claim.get("kind", ""), str(claim.get("value", ""))
            bucket = {
                "ip": "ips", "hostname": "domains", "domain": "domains",
                "mx": "domains", "nameserver": "domains", "cname": "domains",
                "ipv6": "ips", "url": "urls", "certificate": "certs",
            }.get(kind)
            if bucket:
                iocs.setdefault(bucket, [])
                if value not in iocs[bucket]:
                    iocs[bucket].append(value)
        # cap per bucket for a submittable document
        return {k: sorted(v)[:100] for k, v in sorted(iocs.items())}

    def list_packages(self) -> list[dict]:
        out = []
        for path in sorted(self.out_dir.glob("complaint-*.json")):
            data = json.loads(path.read_text())
            out.append({
                "path": str(path),
                "agency": data.get("agency"),
                "bundle_sha256": data.get("bundle_sha256"),
                "generated_at": data.get("generated_at"),
            })
        return out


def render_complaint_human(record: dict, package: dict) -> str:
    """Human summary suitable for pasting into a complaint portal."""
    lines = [
        "COMPLAINT PACKAGE — for submission to " + record["agency"],
        f"case: {package['case_id']}   incident: {package['incident_type']}",
        f"bundle sha256: {record['bundle_sha256']}",
        "",
        "narrative:",
        textwrap_indent(package.get("narrative", "(operator-provided)")),
        "",
        "indicators of compromise:",
    ]
    for bucket, values in package.get("iocs", {}).items():
        lines.append(f"  {bucket}: " + ", ".join(values[:10]) +
                     (f" (+{len(values) - 10} more)" if len(values) > 10 else ""))
    lines += [
        "",
        f"evidence: {record['evidence_records']} hash-chained record(s), "
        f"chain verified at export",
        f"timeline: {record['timeline_events']} audit event(s)",
        "",
        "next steps:",
        "  1. File via: " + "; ".join(package["agency_guidance"]["channels"]),
        "  2. Attach this JSON + the evidence blobs directory.",
        "  3. Quote the bundle sha256 — the agency can verify integrity.",
        "  4. Note: " + package["agency_guidance"]["notes"],
    ]
    return "\n".join(lines)


def textwrap_indent(text: str, prefix: str = "  ") -> str:
    return "\n".join(prefix + line for line in text.splitlines()[:40])
