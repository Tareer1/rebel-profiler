"""Bounty-report exporters: SARIF 2.1.0, Markdown, HTML and PDF.

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
  * ``to_html``   — a self-contained, compliance-grade HTML report (inline
    CSS, no external assets, no scripting) for client deliverables. All
    dynamic content is HTML-escaped.
  * ``to_pdf``    — the same document rendered as a small, valid PDF 1.4
    file with ONLY the Python standard library: real PDF objects, xref
    table, Helvetica base-14 fonts. Enough fidelity for a client-ready
    deliverable without adding a single dependency.

The import side of the law applies here as everywhere: these functions read
the report dict (``BountyReport.as_dict()``) and emit text/bytes. They never
touch the ledger, never run anything, and an empty report renders as an
honest empty document.
"""

from __future__ import annotations

import html
import json
import re
import zlib
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


# -- HTML + PDF (Phase 13: compliance-grade deliverables) ----------------------

_SEVERITY_COLORS = {
    "critical": ("#b71c1c", "Critical"),
    "high": ("#e65100", "High"),
    "medium": ("#f9a825", "Medium"),
    "low": ("#2e7d32", "Low"),
    "informational": ("#455a64", "Informational"),
    "info": ("#455a64", "Informational"),
}


def _sev_badge(severity: str) -> tuple[str, str]:
    key = str(severity or "info").lower()
    if key not in _SEVERITY_COLORS:
        key = "informational"
    color, label = _SEVERITY_COLORS[key]
    return color, label


def to_html(report: dict) -> str:
    """Render ``BountyReport.as_dict()`` as a self-contained HTML report.

    Inline CSS only, zero scripting, zero external assets — the file can be
    attached to a client deliverable or archived as evidence. Everything
    report-derived is HTML-escaped; nothing is executed on open.
    """
    case_id = html.escape(str(report.get("case_id", "")))
    program = html.escape(str(report.get("program") or "unspecified program"))
    findings = report.get("findings", [])
    generated = report.get("generated_at")
    when = ""
    try:
        when = datetime.fromtimestamp(
            float(generated), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        pass
    sev_note = html.escape(str(report.get("severity_note", "")))

    rows: list[str] = []
    for i, f in enumerate(findings, 1):
        color, label = _sev_badge(f.get("severity", ""))
        asset = html.escape(str(f.get("asset") or f.get("subject", "?")))
        rows.append(
            f"<tr><td>{i}</td>"
            f"<td><span class='badge' style='background:{color}'>{label}</span></td>"
            f"<td>{html.escape(str(f.get('title', '?')))}</td>"
            f"<td>{asset}</td>"
            f"<td>{html.escape(str(f.get('cwe', '?')))}</td></tr>")

    sections: list[str] = []
    for i, f in enumerate(findings, 1):
        color, label = _sev_badge(f.get("severity", ""))
        asset = html.escape(str(f.get("asset") or f.get("subject", "?")))
        evidence = ", ".join(
            html.escape(e) for e in f.get("evidence_ids", ())) or "—"
        repro = html.escape(str(f.get("reproduce", "") or "# (no repro command recorded)"))
        sections.append(f"""
<section>
  <h2>{i}. {html.escape(str(f.get('title', 'Finding')))}</h2>
  <p><span class='badge' style='background:{color}'>{label}</span>
     <code>{html.escape(str(f.get('cwe', 'CWE-?')))}</code>
     · confidence {html.escape(str(f.get('confidence', '?')))}</p>
  <p><strong>Subject:</strong> {asset}</p>
  <p><strong>Detail:</strong> {html.escape(str(f.get('detail', '')))}</p>
  <p><strong>Impact:</strong> {html.escape(str(f.get('impact', '')))}</p>
  <p><strong>Reproduce:</strong></p>
  <pre>{repro}</pre>
  <p><strong>Remediation:</strong> {html.escape(str(f.get('remediation', '')))}</p>
  <p><strong>Evidence:</strong> <code>{evidence}</code></p>
</section>""")

    unmapped_rows = "".join(
        f"<li><code>{html.escape(str(u.get('kind', '?')))}</code> "
        f"{html.escape(str(u.get('value', '')))}</li>"
        for u in report.get("unmapped_observations", [])[:25])
    unmapped_html = (
        f"<h2>Unmapped observations</h2><p>Collected but not mapped to a "
        f"vulnerability class (kept, never inflated):</p><ul>{unmapped_rows}</ul>"
        if unmapped_rows else "")

    empty_html = (
        "<p class='empty'>No reportable findings were observed. Nothing is "
        "invented to fill this document — an honest empty report is a result.</p>"
        if not findings else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>rebel-profiler report — {program}</title>
<style>
  body {{ font-family: Georgia, 'Times New Roman', serif; margin: 3em auto;
         max-width: 860px; padding: 0 1em; color: #1a1a1a; line-height: 1.5; }}
  h1 {{ border-bottom: 3px solid #1a1a1a; padding-bottom: .3em; }}
  h2 {{ margin-top: 1.6em; font-size: 1.15em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #999; padding: .45em .6em; text-align: left;
           font-size: .95em; }}
  th {{ background: #efefef; }}
  .badge {{ color: #fff; padding: .15em .6em; border-radius: 3px;
           font-size: .8em; font-family: sans-serif; }}
  pre {{ background: #f4f4f4; border: 1px solid #ddd; padding: .7em;
        overflow-x: auto; font-size: .88em; }}
  code {{ font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: .9em; }}
  .meta {{ color: #555; font-size: .9em; }}
  .note {{ background: #f4f4f4; border-left: 4px solid #999;
          padding: .6em 1em; font-size: .9em; }}
  .empty {{ font-style: italic; color: #444; }}
  footer {{ margin-top: 3em; border-top: 1px solid #999; padding-top: .8em;
           color: #555; font-size: .85em; }}
</style>
</head>
<body>
<h1>Bounty report — {program}</h1>
<p class="meta">Case <code>{case_id}</code> · generated {when} · rebel-profiler</p>
<p>{len(findings)} reportable finding(s)</p>
{f'<p class="note">{sev_note}</p>' if sev_note else ''}
<h2>Summary</h2>
<table>
<tr><th>#</th><th>Severity</th><th>Finding</th><th>Subject</th><th>CWE</th></tr>
{''.join(rows)}
</table>
{empty_html}
{''.join(sections)}
{unmapped_html}
<footer>
Every claim in this report is backed by hash-chained evidence; verify
anytime with <code>rebel-profiler evidence verify {case_id}</code>.
Advisory severities — the program's own taxonomy and payout rules take
precedence.
</footer>
</body>
</html>
"""


def _pdf_escape(text: str) -> str:
    """Escape for a PDF literal string (latin-1-safe subset)."""
    cleaned = (text.replace("\\", r"\\").replace("(", r"\(")
               .replace(")", r"\)"))
    # latin-1 fallback keeps the PDF valid even for non-ASCII input
    return cleaned.encode("latin-1", errors="replace").decode("latin-1")


def _pdf_wrap(text: str, width: int = 92) -> list[str]:
    words = re.split(r"\s+", text.strip()) if text.strip() else []
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word[:width]
    if current:
        lines.append(current)
    return lines or [""]


class _PdfPage:
    """Accumulates one PDF page's content stream (Helvetica 10/14pt grid)."""

    def __init__(self) -> None:
        self.ops: list[str] = []

    def text(self, x: float, y: float, size: int, s: str, *, bold: bool = False) -> None:
        font = "F2" if bold else "F1"
        self.ops.append(
            f"BT /{font} {size} Tf {x:.1f} {y:.1f} Td ({_pdf_escape(s)}) Tj ET")

    def stream(self) -> bytes:
        return "\n".join(self.ops).encode("latin-1", errors="replace")


def to_pdf(report: dict) -> bytes:
    """Render ``BountyReport.as_dict()`` as a small valid PDF (stdlib only).

    Pure PDF 1.4: real object table, xref, Helvetica/Helvetica-Bold base-14
    fonts, flate-compressed content streams. No dependency, no LaTeX, no
    wkhtmltopdf — the report is the bytes this function returns.
    """
    case_id = str(report.get("case_id", ""))
    program = str(report.get("program") or "unspecified program")
    findings = report.get("findings", [])
    generated = report.get("generated_at")
    try:
        when = datetime.fromtimestamp(
            float(generated), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        when = ""

    PAGE_W, PAGE_H = 595, 842      # A4 @72dpi
    MARGIN = 50
    BOTTOM = 60
    pages: list[_PdfPage] = []
    page = _PdfPage()
    y = PAGE_H - MARGIN

    def new_page() -> None:
        nonlocal page, y
        pages.append(page)
        page = _PdfPage()
        y = PAGE_H - MARGIN

    def need(space: int) -> None:
        if y - space < BOTTOM:
            new_page()

    def line(s: str, *, size: int = 10, bold: bool = False,
             gap: int = 16, indent: float = 0.0) -> None:
        nonlocal y
        need(gap)
        page.text(MARGIN + indent, y, size, s, bold=bold)
        y -= gap

    def para(s: str, *, size: int = 10, bold: bool = False,
             gap: int = 16, indent: float = 0.0) -> None:
        for chunk in _pdf_wrap(s) or [""]:
            line(chunk, size=size, bold=bold, gap=gap, indent=indent)

    # header
    line("rebel-profiler bounty report", size=18, bold=True, gap=30)
    para(f"Program: {program}", gap=15)
    para(f"Case: {case_id}    Generated: {when}", gap=15)
    para(f"Reportable findings: {len(findings)}", gap=15)
    para("Advisory severities - the program's own taxonomy takes precedence.",
         size=8, gap=22)
    y -= 8

    for i, f in enumerate(findings, 1):
        _, label = _sev_badge(f.get("severity", ""))
        asset = str(f.get("asset") or f.get("subject", "?"))
        para(f"{i}. [{label}] {f.get('title', 'Finding')}", size=13, bold=True, gap=20)
        para(f"Subject: {asset}", gap=14, indent=12)
        para(f"Class: {f.get('cwe', 'CWE-?')}   "
             f"Confidence: {f.get('confidence', '?')}", gap=14, indent=12)
        for field_label, value in (("Detail", f.get("detail", "")),
                                   ("Impact", f.get("impact", "")),
                                   ("Remediation", f.get("remediation", ""))):
            if value:
                para(f"{field_label}: {value}", indent=12)
        repro = str(f.get("reproduce", "") or "# (no repro command recorded)")
        for chunk in _pdf_wrap(repro, 84):
            line(chunk, size=9, indent=12)
        ev = ", ".join(str(e) for e in f.get("evidence_ids", ())) or "-"
        para(f"Evidence: {ev}", size=8, gap=18, indent=12)
        y -= 6

    unmapped = report.get("unmapped_observations", [])
    if unmapped:
        line("Unmapped observations (kept, never inflated):", size=12, bold=True, gap=20)
        for u in unmapped[:25]:
            para(f"- {u.get('kind', '?')}: {u.get('value', '')}", size=9, indent=12)

    if not findings:
        para("No reportable findings were observed. Nothing is invented to "
             "fill this report - an honest empty report is a result.",
             size=10)
    y -= 10
    para("Every claim is backed by hash-chained evidence; verify with "
         f"rebel-profiler evidence verify {case_id}", size=8)

    pages.append(page)

    # -- assemble the PDF object graph -------------------------------------
    def pdf_object(num: int, body: bytes) -> bytes:
        return f"{num} 0 obj\n".encode() + body + b"\nendobj\n"

    objects: list[bytes] = []
    # 1: catalog, 2: pages, 3: font F1, 4: font F2, then per page: content + page
    objects.append(pdf_object(1, b"<< /Type /Catalog /Pages 2 0 R >>"))
    kids = " ".join(f"{5 + i * 2 + 1} 0 R" for i in range(len(pages)))
    objects.append(pdf_object(
        2, f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode()))
    objects.append(pdf_object(
        3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
           b"/Encoding /WinAnsiEncoding >>"))
    objects.append(pdf_object(
        4, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
           b"/Encoding /WinAnsiEncoding >>"))

    for i, pg in enumerate(pages):
        raw = pg.stream()
        compressed = zlib.compress(raw)
        content_num = 5 + i * 2
        page_num = content_num + 1
        objects.append(pdf_object(
            content_num,
            f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode()
            + compressed + b"\nendstream"))
        objects.append(pdf_object(
            page_num,
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {content_num} 0 R >>".encode()))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for num, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += obj
    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n").encode()
    return bytes(out)
