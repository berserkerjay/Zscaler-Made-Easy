# Feature evidence

One line per comparison row: tool, row, where it lives, the test that proves it.

- assistant-skill row 1 — dlp_mcp_server.py (28 read-only tools) — tests/test_w12_skill.py::test_every_answer_is_graded_with_source_tier_and_confidence
- assistant-skill row 4 — mcp_tools.py grade() — tests/test_w12_skill.py::test_every_answer_is_graded_with_source_tier_and_confidence
- assistant-skill row 7 — workspace_notes.py + mcp_tools.case_notes (resumable notes, tags, to-dos) — tests/test_mcp_tools_w9.py::test_case_notes_reads_a_local_note_without_touching_the_tenant
- assistant-skill row 9 — capacity_review.py, mcp_tools.capacity_review — tests/test_w12_skill.py::test_capacity_review_tool_counts_the_sample_and_changes_nothing
- assistant-skill row 12 — postmortem.py, POST /api/postmortem, mcp_tools.postmortem — tests/test_w12_skill.py::test_postmortem_builds_markdown_and_csv_from_the_window
