#!/usr/bin/env bash
# Render the paper to PDF, using the best available toolchain.
#
#   1. LaTeX (latexmk / pdflatex) -> the IEEEtran two-column source of truth
#   2. WeasyPrint (main.html)     -> faithful preview of the same content
#   3. LibreOffice (main.html)    -> fallback, single-column
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if command -v latexmk >/dev/null 2>&1; then
  latexmk -pdf -interaction=nonstopmode main.tex
elif command -v pdflatex >/dev/null 2>&1; then
  pdflatex -interaction=nonstopmode main.tex
  bibtex main || true
  pdflatex -interaction=nonstopmode main.tex >/dev/null
  pdflatex -interaction=nonstopmode main.tex >/dev/null
elif command -v weasyprint >/dev/null 2>&1; then
  weasyprint main.html main.pdf
elif python3 -c "import weasyprint" >/dev/null 2>&1; then
  python3 -m weasyprint main.html main.pdf
else
  echo "no LaTeX or WeasyPrint; falling back to LibreOffice (single column)" >&2
  soffice --headless --convert-to pdf --outdir . main.html
fi

echo "built: $(pwd)/main.pdf"
