#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Genera el informe final de Clínica Segura v1.1.0 mediante LaTeX.

Uso:
    python generar_informe_latex.py
    python generar_informe_latex.py --pdf
    python generar_informe_latex.py --entrada docs/informe-final.md --salida informe.tex

La fuente versionada es docs/informe-final.md. El script transforma el subconjunto
Markdown usado por el informe (títulos, listas, tablas, código e inline) a LaTeX y,
con --pdf, ejecuta pdflatex dos veces si está instalado.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

PREAMBLE = r"""\documentclass[11pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[spanish,es-nodecimaldot]{babel}
\usepackage{lmodern}
\usepackage[a4paper,margin=2.4cm]{geometry}
\usepackage{microtype}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{ragged2e}
\usepackage{xcolor}
\usepackage{enumitem}
\usepackage{fancyhdr}
\usepackage{hyperref}
\usepackage{url}
\usepackage{listings}
\usepackage{titlesec}
\usepackage{setspace}
\hypersetup{colorlinks=true,linkcolor=black,urlcolor=blue,pdfauthor={Clinica Segura},pdftitle={Clinica Segura v1.1.0 - Informe final}}
\setstretch{1.08}
\setlength{\parindent}{0pt}
\setlength{\parskip}{0.55em}
\setlist[itemize]{leftmargin=1.6em,itemsep=0.2em,topsep=0.25em}
\setlist[enumerate]{leftmargin=1.8em,itemsep=0.2em,topsep=0.25em}
\pagestyle{fancy}
\fancyhf{}
\lhead{Clínica Segura v1.1.0}
\rhead{Informe final de ciberseguridad}
\cfoot{\thepage}
\titleformat{\section}{\Large\bfseries}{\thesection.}{0.6em}{}
\titleformat{\subsection}{\large\bfseries}{\thesubsection.}{0.6em}{}
\lstset{basicstyle=\ttfamily\small,breaklines=true,frame=single,columns=fullflexible,showstringspaces=false}
\begin{document}
"""
POSTAMBLE = "\\end{document}\n"

_SPECIALS = {
    "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
    "#": r"\#", "_": r"\_\allowbreak{}", "{": r"\{", "}": r"\}",
    "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
}


def _escape_plain(text: str) -> str:
    return "".join(_SPECIALS.get(ch, ch) for ch in text)


def latex_inline(text: str) -> str:
    placeholders: dict[str, str] = {}
    def stash(value: str) -> str:
        key = f"@@TOKEN{len(placeholders)}@@"; placeholders[key] = value; return key
    text = re.sub(r"`([^`]+)`", lambda m: stash(r"\texttt{" + _escape_plain(m.group(1)) + "}"), text)
    text = re.sub(r"https?://[^\s)]+", lambda m: stash(r"\url{" + m.group(0).replace('%', r'\%').replace('#', r'\#') + "}"), text)
    text = re.sub(r"\*\*([^*]+)\*\*", lambda m: stash(r"\textbf{" + _escape_plain(m.group(1)) + "}"), text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", lambda m: stash(r"\emph{" + _escape_plain(m.group(1)) + "}"), text)
    out = _escape_plain(text)
    for key, value in placeholders.items(): out = out.replace(_escape_plain(key), value)
    return out


def parse_table(lines: list[str]) -> str:
    rows = [[c.strip() for c in line.strip().strip('|').split('|')] for line in lines]
    if len(rows) >= 2 and all(re.fullmatch(r":?-{3,}:?", c.replace(' ', '')) for c in rows[1]):
        header, body = rows[0], rows[2:]
    else:
        header, body = rows[0], rows[1:]
    n = max(1, len(header)); font_cmd, usable = ((r"\scriptsize", .84) if n >= 5 else (r"\footnotesize", .88) if n == 4 else (r"\small", .90))
    width = usable / n
    cols = " ".join([rf">{{\RaggedRight\arraybackslash}}p{{{width:.3f}\textwidth}}" for _ in range(n)])
    result = [r"\begingroup", font_cmd, r"\setlength{\tabcolsep}{2pt}", r"\renewcommand{\arraystretch}{1.12}", rf"\begin{{longtable}}{{{cols}}}", r"\toprule"]
    result.append(" & ".join(latex_inline(c) for c in header) + r" \\")
    result += [r"\midrule", r"\endfirsthead", r"\toprule", " & ".join(latex_inline(c) for c in header) + r" \\", r"\midrule", r"\endhead"]
    for row in body:
        row = row + [""] * (n - len(row)); result.append(" & ".join(latex_inline(c) for c in row[:n]) + r" \\")
    result += [r"\bottomrule", r"\end{longtable}", r"\endgroup"]
    return "\n".join(result)


def markdown_to_latex(md: str) -> str:
    lines = md.splitlines(); out: list[str] = []; i = 0; in_code = False; list_kind: str | None = None; para: list[str] = []; first_h1 = True
    def flush_para() -> None:
        nonlocal para
        if para:
            text = " ".join(s.strip() for s in para).strip()
            if text: out.append(latex_inline(text) + "\n")
            para = []
    def close_list() -> None:
        nonlocal list_kind
        if list_kind: out.append(r"\end{" + list_kind + "}"); list_kind = None
    while i < len(lines):
        line = lines[i]; stripped = line.strip()
        if stripped.startswith("```"):
            flush_para(); close_list(); out.append(r"\end{lstlisting}" if in_code else r"\begin{lstlisting}"); in_code = not in_code; i += 1; continue
        if in_code: out.append(line); i += 1; continue
        if stripped.startswith("|") and i + 1 < len(lines) and lines[i+1].strip().startswith("|"):
            flush_para(); close_list(); block = []
            while i < len(lines) and lines[i].strip().startswith("|"): block.append(lines[i]); i += 1
            out.append(parse_table(block)); continue
        if not stripped: flush_para(); close_list(); i += 1; continue
        if stripped == r"\newpage": flush_para(); close_list(); out.append(r"\newpage"); i += 1; continue
        m = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if m:
            flush_para(); close_list(); level = len(m.group(1)); title = latex_inline(m.group(2))
            if level == 1 and first_h1 and m.group(2).strip().lower() == "portada":
                out += [r"\thispagestyle{empty}", r"\begin{center}", r"{\Large\bfseries PORTADA}\\[0.8cm]", r"\end{center}"]; first_h1 = False
            elif level == 1: out.append(r"\section{" + title + "}"); first_h1 = False
            elif level == 2: out.append(r"\subsection{" + title + "}")
            else: out.append(r"\subsubsection{" + title + "}")
            i += 1; continue
        if stripped.startswith("> "):
            flush_para(); close_list(); out.append(r"\begin{quote}\small " + latex_inline(stripped[2:]) + r"\end{quote}"); i += 1; continue
        mb = re.match(r"^-\s+(.*)$", stripped); mn = re.match(r"^\d+\.\s+(.*)$", stripped)
        if mb or mn:
            flush_para(); desired = "itemize" if mb else "enumerate"
            if list_kind != desired: close_list(); out.append(r"\begin{" + desired + "}"); list_kind = desired
            out.append(r"\item " + latex_inline((mb or mn).group(1))); i += 1; continue
        para.append(line); i += 1
    flush_para(); close_list()
    if in_code: out.append(r"\end{lstlisting}")
    return "\n".join(out)


def build_tex(md: str) -> str:
    return PREAMBLE + markdown_to_latex(md) + "\n" + POSTAMBLE


def compile_pdf(tex_path: Path) -> Path:
    pdflatex = shutil.which("pdflatex")
    if not pdflatex: raise RuntimeError("pdflatex no está instalado. Compile el .tex en TeX Live, MiKTeX u Overleaf.")
    cmd = [pdflatex, "-interaction=nonstopmode", "-halt-on-error", tex_path.name]
    for _ in range(2):
        proc = subprocess.run(cmd, cwd=tex_path.parent, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0: raise RuntimeError("LaTeX devolvió un error:\n" + "\n".join(proc.stdout.splitlines()[-35:]))
    return tex_path.with_suffix(".pdf")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entrada", default="docs/informe-final.md", help="Markdown fuente")
    parser.add_argument("--salida", default="Clinica_Segura_Informe_Final_v1.1.0.tex", help="Ruta .tex")
    parser.add_argument("--pdf", action="store_true", help="Compilar .tex con pdflatex")
    args = parser.parse_args()
    source = Path(args.entrada).expanduser().resolve(); tex_path = Path(args.salida).expanduser().resolve()
    md = source.read_text(encoding="utf-8"); tex_path.parent.mkdir(parents=True, exist_ok=True); tex_path.write_text(build_tex(md), encoding="utf-8")
    print(f"[OK] LaTeX generado: {tex_path}")
    if args.pdf: print(f"[OK] PDF generado: {compile_pdf(tex_path)}")

if __name__ == "__main__": main()
