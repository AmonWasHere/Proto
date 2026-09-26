# paper/

IEEE-format manuscript for the RewardAudit measurement study.

- `main.tex` — IEEEtran conference paper (two-column).
- `references.bib` — bibliography (IEEEtran style).

## Compile

```bash
./build.sh          # picks LaTeX if present, else WeasyPrint, else LibreOffice
# or: make paper   (from the repository root)
```

`main.pdf` is committed so the paper is readable without a toolchain. It was
produced with WeasyPrint from `main.html` (a faithful HTML mirror of `main.tex`),
because no LaTeX toolchain was available on the build machine. Where TeX exists,
`build.sh` uses `main.tex` and produces the true IEEEtran two-column PDF.

### Sources

| File | Role |
|---|---|
| `main.tex` + `references.bib` | **submission source** (IEEEtran, two-column) |
| `main.html` | HTML mirror used for the preview PDF (and easy reading) |
| `main.pdf` | rendered preview (committed) |

## Status and honesty

This is a **draft**, written to be submittable to a **workshop or short-track**
venue — not a top-tier security paper. The measured evidence is:

- **n = 21** JavaVFC security pairs for the scaled result,
- **n = 5** Python pairs for the cross-family comparison,
- a single model family (`deepseek-flash`) at scale.

Every number in the paper comes from `docs/e1-results.md` and `docs/COST.md`. The
Threats to Validity section states the small-sample caveats plainly. Before
submission, the honest path is to scale (Section IX of the paper): n≥100 genuine
fixes, ≥2 languages, ≥3 model families, k repeats with confidence intervals, and a
blinded human audit for precision/FNR.

## What must be updated before submission

1. Author block (currently a placeholder).
2. Scale the experiment and replace the directional numbers with mean ± CI.
3. Replace the `sastaudit` citation with the real reference (author/venue) rather
   than the anonymised technical-report placeholder.
4. A responsible-release statement for the adversarial component (already present;
   confirm with the venue).
5. Re-verify all arXiv identifiers at submission time.
