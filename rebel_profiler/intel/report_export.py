"""Bounty-report exporters: SARIF 2.1.0 and Markdown.

The bounty report already carries everything a triager needs (severity, CWE,
a reproduction command built from the URL the evidence came from, remediation,
evidence ids). These renderers re-shape the SAME data — no new findings are
ever invented here:

  * ``to_sarif``  — SARIF 2.1.0 for GitHub code scanning / triage tooling.
    Severity maps onto SARIF's ``level`` (error/warning/note) and the full
    advisory severity rides ``properties``; CWE and the repro land in
    ``properties`` too so nothing is lost in translation.
  * ``to_markdown`` — a disclosure-draft document: executive summary table,
    per-finding sections with repro + remediation, and the evidence ids kept
    visible so every claim stays independently verifiable.

The import side of the law applies here as everywhere: these functions read
the report dict (``BountyReport.as_dict()``) and emit text. They never touch
the ledger, never run anything, and an empty report renders as an honest
empty document.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "informational": "note",
    "info": "note",
}


def to_sarif(report: dict) -> str:
    """Render ``BountyReport.as_dict()`` as a SARIF 2.1.0 JSON document."""
    findings = report.get("findings", [])
    rules: list[dict] = []
    results: list[dict] = []
    seen: set[str] = set()

    for i, f in enumerate(findings):
        subject = f.get("asset") or f.get("subject", "")
        cwe = str(f.get("cwe", "")) or "CWE-UNKNOWN"
        rule_id = cwe if cwe not in seen else f"{cwe}-{i}"
        seen.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": f.get("title", "Finding"),
            "shortDescription": {"text": f.get("title", "Finding")},
            "fullDescription": {"text": f.get("detail", "")},
            "help": {"text": f.get("remediation", "")},
            "properties": {
                "advisory_severity": f.get("severity", "informational"),
                "reproduce": f.get("reproduce", ""),
                "evidence_ids": list(f.get("evidence_ids", ())),
                "claim_ids": list(f.get("claim_ids", ())),
            },
        })
        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(str(f.get("severity", "")).lower(), "note"),
            "message": {"text": (
                f"{f.get('title', 'Finding')} on {subject or '?'} — "
                f"{f.get('impact', '')}".strip())},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("url") or subject},
                },
            }],
            "partialFingerprints": {
                "rebelEvidence/v1": "|".join(f.get("evidence_ids", ())) or str(i),
            },
            "properties": {
                "confidence": f.get("confidence"),
                "source": f.get("source", ""),
                "method": f.get("method", ""),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rebel-profiler",
                    "informationUri": "https://github.com/Tareer1/rebel-profiler",
                    "rules": rules,
                },
            },
            "properties": {
                "case_id": report.get("case_id", ""),
                "program": report.get("program", ""),
                "severity_note": report.get("severity_note", ""),
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def to_markdown(report: dict) -> str:
    """Render ``BountyReport.as_dict()`` as a disclosure-draft Markdown doc."""
    case_id = report.get("case_id", "")
    program = report.get("program") or "unspecified program"
    findings = report.get("findings", [])
    stats = report.get("stats", {})
    generated = report.get("generated_at")
    when = ""
    try:
        when = datetime.fromtimestamp(
            float(generated), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        pass

    lines: list[str] = [
        f"# Bounty report — {program}",
        "",
        f"*Case `{case_id}` · generated {when} · rebel-profiler*",
        "",
        f"{len(findings)} reportable finding(s)"
        + (f" · {stats.get('assets', '?')} asset(s) audited" if stats else ""),
        "",
        "> Advisory severities — the program's own taxonomy and payout rules",
        "> take precedence. Every claim is hash-chained evidence; re-verify",
        f"> with `rebel-profiler evidence verify {case_id}`.",
        "",
    ]

    if findings:
        lines += ["| # | Severity | Finding | Subject | CWE |", "|---|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            asset = f.get("asset") or f.get("subject", "?")
            lines.append(
                f"| {i} | {f.get('severity', '?')} | {f.get('title', '?')} "
                f"| {asset} | {f.get('cwe', '?')} |")
        lines.append("")
        for i, f in enumerate(findings, 1):
            asset = f.get("asset") or f.get("subject", "?")
            lines += [
                f"## {i}. {f.get('title', 'Finding')} — {asset}",
                "",
                f"- **Severity:** {f.get('severity', '?')} "
                f"({f.get('cwe', 'CWE-?')}) · confidence {f.get('confidence', '?')}",
                f"- **Detail:** {f.get('detail', '')}",
                f"- **Impact:** {f.get('impact', '')}",
                "- **Reproduce:**",
                "  ```bash",
                f"  {f.get('reproduce', '# (no repro command recorded)')}",
                "  ```",
                f"- **Remediation:** {f.get('remediation', '')}",
                f"- **Evidence:** {', '.join('`' + e + '`' for e in f.get('evidence_ids', ())) or '—'}",
                "",
            ]
    else:
        lines += [
            "No reportable findings were observed. Nothing is invented to fill",
            "this document — an honest empty report is a result.",
            "",
        ]

    unmapped = report.get("unmapped_observations", [])
    if unmapped:
        lines += [
            "## Unmapped observations",
            "",
            "Collected but not mapped to a vulnerability class (kept, never inflated):",
            "",
        ]
        for u in unmapped[:25]:
            lines.append(f"- `{u.get('kind', '?')}` {u.get('value', '')}")
        lines.append("")
    return "\n".join(lines)
