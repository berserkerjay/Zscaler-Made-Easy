# Testing

## Style (every new test)
- First line of the docstring maps the standards it checks: OWASP ASVS 4.0.3 id · CWE · OWASP WSTG id, plus the WCAG 2.2 success criterion for UI, e.g. `"""ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an oversized upload is refused."""`
- Deterministic and offline: no sleeps, no real clock or randomness (inject them), no network; tmp dirs and monkeypatch; one behaviour per test; Arrange-Act-Assert; negative and boundary cases.
- **Proved** means: the test fails without the change. Show it (revert the change, run, restore) for every fix.

## Fakes
`sample_tenant.py` (offline SDK client over a made-up tenant), `tests/sdk_wire_fake.py`, `tests/zpa_fake.py`, `tests/admin_fakes.py`, `tests/config_fake.py`, `tests/fake_rule_tenant.py`, `tests/admin_identity_fake.py`; secret canaries: `tests/test_secret_canaries.py` helpers.

## Running
- `python -m pytest -o addopts="" -q --tb=line -rf -p no:cacheprovider -p no:warnings tests/<files> | tail -n 30` (short failure output; see token-efficiency.md)
- Browser tests **skip silently** unless `NODE_PATH=$(npm root -g)` and `CHROME_BIN` (a wrapper running Chromium with `--no-sandbox`) are set. Never run `playwright install`.
- Run your new tests plus the existing files covering every module you touched; one browser test file at a time.
- The full suite (~27,000 tests, ~50–70 minutes on 4 CPUs) is run by stage 4 on the merged code, through the coordinating session's shared runner, never by many agents at once. Browser tests time out under heavy load: rerun a failing file alone before calling it a defect.

## Registries to keep current
- New test files: `tools/security_test_matrix.py` QA_FILES and the area mapping in `tools/quality_score.py`; regenerate `docs/SECURITY_TESTING.md`, `docs/QUALITY_SCORE.md`, `docs/quality_score.json` with those tools; both `--check` must pass.
- Findings record: `docs/qa/findings/<wave>-<slug>.json` (same schema as the others; unique ids).
- `docs/qa/test_run.json` is re-recorded only from a full run with 0 failed (`tools/quality_score.py --from-junit`).
- Code scanning: `make sast` (bandit) gates on new medium+ findings; no literal bidirectional control characters in source.
