# Shared files: how to edit and merge them

These files are touched by almost every branch. Edit them the same way so merges are mechanical.

| File | How to edit | How to merge a conflict |
|---|---|---|
| `CHANGELOG.md` | Your lines under the run's date heading (`## YYYY-MM-DD`), one `###` section per feature | Keep every branch's section under one date heading |
| `static/whats_new.js` | Add your features under the run's release date; the manifest shows the **newest two** releases (`keep: 2`), so a new release rotates the oldest out — remove those features; never change `keep` | Union of features by id; keep only the two newest releases; a release can't be both shown and `skipped` |
| `tests/test_new_marks.py` | Already release-agnostic: don't hard-code releases or element ids; add CHANGELOG phrases to `EXCLUDED` only for features with no UI | Keep every branch's `EXCLUDED` entries |
| `static/help_catalog.js` + `browser_extension/help_catalog.js` | One entry per new control (what it does, what input it expects, whether it reads or changes the tenant); the two copies must stay byte-identical | Union of entries, then copy to the extension |
| `tools/security_test_matrix.py` QA_FILES, `tools/quality_score.py` areas, `pyproject.toml` modules | Add your entries | Union |
| `docs/SECURITY_TESTING.md`, `docs/QUALITY_SCORE.md`, `docs/quality_score.json` | Never by hand: regenerate with the tools | Take either side, then regenerate |
| `docs/OVERVIEW.md`, `SECURITY.md` | Add to the right section; declare new outbound hosts in SECURITY.md | Keep both sides |
| `sample_tenant.py` | Add data; don't change existing rows other tests pin (positions, ids) | Combine; rerun tests that depend on positions |
| Test tables: `test_scope_rule_routes.py`, `test_write_safety_gates.py`, `test_sbd_writes.py`, `test_api_contracts.py`, `team_routes.py` | Add your rows with reasons | Union; check no id clashes |
| Check ids (e.g. `RBAC.n`) and finding ids | Pick the next free id on the integration branch | Renumber the later branch; ids must be unique |
