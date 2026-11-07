# Feature evidence

One line per comparison row: tool, row, where it lives, the test that proves it.

- assistant-skill row 1 — reference_corpus.py lookup(), mcp_tools.lookup (`lookup` tool) — tests/test_w12_skill.py::test_lookup_answers_from_the_corpus_with_sources_and_says_when_nothing_matches
- assistant-skill row 4 — mcp_tools.py grade() — tests/test_w12_skill.py::test_every_answer_is_graded_with_source_tier_and_confidence
- assistant-skill row 7 — investigation_journal.py, `journal_open`/`journal_add`/`journal_show`, GET/POST /api/journal — tests/test_w12_skill.py::test_journal_enforces_hypothesis_evidence_conclusion_and_resumes
- assistant-skill row 8 — reference_corpus.py cite(), `cite` tool, POST /api/cite — tests/test_w12_skill.py::test_cite_fetch_only_through_allowlisted_zscaler_hosts
- assistant-skill row 9 — capacity_review.py, `capacity_review` tool, POST /api/capacity-review, static/report_capacity.html — tests/test_w12_skill.py::test_read_used_reads_only_the_products_in_scope
- assistant-skill row 12 — postmortem.py, `postmortem` tool, POST /api/postmortem — tests/test_w12_skill.py::test_postmortem_builds_markdown_and_csv_from_the_window
