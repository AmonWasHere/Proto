# paper/

IEEE-format manuscript for the RewardAudit measurement study.

- `main.tex` — IEEEtran conference paper (two-column).
- `references.bib` — bibliography (IEEEtran style).

## Compile

```bash
cd paper
pdflatex main
bibtex main
pdflatex main
pdflatex main
# -> main.pdf
```

Or with `latexmk`:

```bash
latexmk -pdf main.tex
```

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
