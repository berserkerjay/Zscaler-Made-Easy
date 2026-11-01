# Standards and the quality score

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

- Every test's first docstring line names the standards it checks: **OWASP ASVS 4.0.3** (Level 2 requirement id), **OWASP Top 10 2021**, **CWE**, **OWASP WSTG** test id, **WCAG 2.2 AA** success criterion for UI, and for supply chain **SLSA v1.0**, **OpenSSF Scorecard** or **NIST SSDF**.
- `tools/security_test_matrix.py` reads those lines from the files in `QA_FILES` and writes `docs/SECURITY_TESTING.md` (which requirement is tested where).
- `tools/quality_score.py` reads `docs/qa/findings/*.json` (the QA records: checks, findings with id, severity, CWE, status, fix, test, commit), `docs/qa/test_run.json` (the last full run, recorded from JUnit) and the matrix, and writes `docs/QUALITY_SCORE.md` and `docs/quality_score.json`. Open critical/high findings or any failing test cap the score. CI runs `--check` on both tools.
- Fixes follow CISA Secure by Design: secure defaults, deny by default, fail closed, least privilege. Severity follows CVSS v3.1.
- Code scanning: bandit (`make sast`, gate on new medium+) and CodeQL in CI.
