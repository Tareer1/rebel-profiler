#!/usr/bin/env python3
"""Generate docs/frontend.pdf from docs/frontend.md.

docs/frontend.md is the paste-into-ChatGPT GUI build brief; this renders it
as a PDF so it can be handed to any AI (or human) as a single artifact.
fpdf2 is a dev-only dependency; the core package stays stdlib-only.

    .venv/bin/python docs/generate_frontend_pdf.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "frontend.md"
OUT = ROOT / "docs" / "frontend.pdf"

# Core PDF fonts are latin-1 only: fold the Unicode characters the brief
# uses down to ASCII, and give over-long tokens (URLs, hashes) break points
# so multi_cell never runs out of horizontal space.
_TRANSLATE = {
    "\u2014": " - ", "\u2013": "-", "\u2192": "->", "\u2022": "*",
    "\u2026": "...", "\u2713": "ok", "\u2717": "x", "\u00b7": "-",
    "\u25c6": "<>", "\u25cf": "(o)", "\u201c": '"', "\u201d": '"',
    "\u2018": "'", "\u2019": "'", "\u2717": "x", "\u2610": "[]",
}


def S(text: str) -> str:
    for src, dst in _TRANSLATE.items():
        text = text.replace(src, dst)
    text = text.encode("latin-1", "replace").decode("latin-1")
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
            self.cell(0, 6, "Rebel Profiler - GUI Build Brief (paste into ChatGPT)",
                      align="C")
            self.ln(10)
            self.set_text_color(0)

    def footer(self):
        self.set_y(-14)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(120)
        self.cell(0, 8, f"page {{nb}}", align="C")


def _block(pdf: Brief, text: str, *, size: float = 9.5, style: str = "",
           mono: bool = False) -> None:
    pdf.set_font("courier" if mono else "helvetica", style, size)
    pdf.multi_cell(0, 5, text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def main() -> int:
    pdf = Brief()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()

    in_code = False
    for raw in SRC.read_text().splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            pdf.ln(0.5)
            continue
        if in_code:
            pdf.set_font("courier", "", 8.5)
            pdf.set_fill_color(240, 242, 248)
            pdf.cell(0, 4.4, S(raw.expandtabs(4))[:98] or " ",
                     new_x="LMARGIN", new_y="NEXT", fill=True)
            continue
        if stripped.startswith("# "):
            pdf.set_font("helvetica", "B", 16)
            pdf.multi_cell(0, 8, S(stripped[2:].replace("**", "")),
                           new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif stripped.startswith("## "):
            pdf.ln(2)
            pdf.set_font("helvetica", "B", 12.5)
            pdf.set_text_color(15, 76, 129)
            pdf.multi_cell(0, 7, S(stripped[3:].replace("**", "")),
                           new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0)
        elif stripped.startswith("### "):
            pdf.set_font("helvetica", "B", 10.5)
            pdf.multi_cell(0, 6, S(stripped[4:].replace("**", "")),
                           new_x="LMARGIN", new_y="NEXT")
        elif re.match(r"^\s*[-*] ", raw):
            pdf.set_x(pdf.l_margin + 4)
            pdf.set_font("helvetica", "", 9.5)
            pdf.multi_cell(0, 5, "* " + S(re.sub(r"^\s*[-*] ", "", raw)
                                          .replace("**", "").replace("`", "")),
                           new_x="LMARGIN", new_y="NEXT")
        elif re.match(r"^\s*\d+\. ", stripped):
            pdf.set_x(pdf.l_margin + 4)
            pdf.set_font("helvetica", "", 9.5)
            pdf.multi_cell(0, 5, S(stripped.replace("**", "").replace("`", "")),
                           new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if set("".join(cells)) <= {"-", ":", " "}:
                continue
            pdf.set_font("helvetica", "", 8.5)
            pdf.multi_cell(0, 4.8,
                           S("  |  ".join(c.replace("`", "") for c in cells)),
                           new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith(">"):
            pdf.set_text_color(90)
            _block(pdf, S(stripped.lstrip("> ").replace("**", "")),
                   size=9, style="I")
            pdf.set_text_color(0)
        elif stripped in {"---", ""}:
            pdf.ln(1.5)
        else:
            _block(pdf, S(stripped.replace("**", "").replace("`", "")))

    pdf.output(OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
