#!/usr/bin/env python3
"""Generate docs/FRONTEND_BRIEF.pdf from docs/FRONTEND_BRIEF.md.

The handoff brief must travel as a single file (hand the PDF to any AI or
developer — no clone needed), so this generator is committed next to its
output. fpdf2 is a dev-only dependency; the core package stays stdlib-only.

    .venv/bin/python docs/generate_frontend_brief_pdf.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "FRONTEND_BRIEF.md"
OUT = ROOT / "docs" / "FRONTEND_BRIEF.pdf"

# Core PDF fonts are latin-1 only: fold the few Unicode characters the
# brief uses down to ASCII instead of shipping a Unicode font.
_TRANSLATE = {
    "\u2014": " - ", "\u2013": "-", "\u2192": "->", "\u2022": "*",
    "\u2026": "...", "\u2713": "ok", "\u2717": "x", "\u00b7": "-",
    "\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'",
}


def S(text: str) -> str:
    for src, dst in _TRANSLATE.items():
        text = text.replace(src, dst)
    text = text.encode("latin-1", "replace").decode("latin-1")
    # URLs and hashes have no spaces; a token wider than the column makes
    # fpdf2 raise "Not enough horizontal space". Give every long token
    # break opportunities at 50-char intervals.
    out: list[str] = []
    for word in text.split(" "):
        while len(word) > 60:
            out.append(word[:50])
            word = word[50:]
        out.append(word)
    return " ".join(out)


class Brief(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font("helvetica", "I", 8)
            self.set_text_color(120)
            self.cell(0, 6, "Rebel Profiler - Frontend Handoff Brief (v1.4.0)",
                      align="C")
            self.ln(10)
            self.set_text_color(0)

    def footer(self):
        self.set_y(-14)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(120)
        self.cell(0, 8, f"page {self.page_no()}/{{nb}}", align="C")
        self.set_text_color(0)


def _emit(pdf: Brief, line: str, *, size: int, style: str = "",
          bullet: bool = False, mono: bool = False, gap: int = 1) -> None:
    pdf.set_font("courier" if mono else "helvetica", style, size)
    text = S(line.strip())
    if not text:
        pdf.ln(gap)
        return
    if bullet:
        pdf.set_x(pdf.l_margin + 4)
        pdf.multi_cell(0, 5, f"* {text}", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.multi_cell(0, 5, text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(gap)


def main() -> int:
    pdf = Brief()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.alias_nb_pages()

    in_code = False
    code: list[str] = []
    for raw in SRC.read_text().splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            if in_code:
                pdf.set_font("courier", "", 8.5)
                pdf.set_fill_color(244, 244, 248)
                for cl in code or [""]:
                    pdf.cell(0, 4.6, cl, new_x="LMARGIN", new_y="NEXT",
                             fill=True)
                pdf.ln(2)
                code = []
            in_code = not in_code
            continue
        if in_code:
            code.append(S(raw.expandtabs(4))[:95])
            continue
        if stripped.startswith("# "):
            pdf.set_font("helvetica", "B", 17)
            pdf.multi_cell(0, 8, S(stripped[2:].replace("**", "")), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif stripped.startswith("## "):
            pdf.ln(2)
            pdf.set_font("helvetica", "B", 12.5)
            pdf.set_text_color(20, 60, 120)
            pdf.multi_cell(0, 7, S(stripped[3:].replace("**", "")), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0)
        elif stripped.startswith("### "):
            pdf.set_font("helvetica", "B", 10.5)
            pdf.multi_cell(0, 6, S(stripped[4:].replace("**", "")), new_x="LMARGIN", new_y="NEXT")
        elif re.match(r"^\s*[-*] ", raw):
            _emit(pdf, re.sub(r"^\s*[-*] ", "", raw), size=9.5, bullet=True)
        elif re.match(r"^\s*\d+\. ", stripped):
            _emit(pdf, re.sub(r"^\s*\d+\. ", "", raw), size=9.5, bullet=True)
        elif stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if set("".join(cells)) <= {"-", ":", " "}:   # separator row
                continue
            pdf.set_font("helvetica", "", 8.5)
            pdf.multi_cell(0, 4.8, S("  |  ".join(
                c.replace("`", "") for c in cells)),
                            new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith(">"):
            pdf.set_text_color(90)
            _emit(pdf, stripped.lstrip("> "), size=9, style="I")
            pdf.set_text_color(0)
        elif stripped in {"---", ""}:
            pdf.ln(1.5)
        else:
            _emit(pdf, stripped.replace("**", "").replace("`", ""), size=9.5)

    pdf.output(OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
