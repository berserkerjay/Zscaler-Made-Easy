# Feature evidence

One line per comparison row: tool row N, file:line, test name.

- Terraform export row 4 (resource selection) — tenant_terraform.py:778 — test_types_and_exclude_take_keys_resource_names_and_patterns
- Terraform export row 5 (validate) — tenant_terraform.py:1854 — test_static_check_finds_a_broken_workspace, test_validate_script_is_written_but_nothing_is_run
- Terraform export row 6 (progress / support) — tenant_terraform.py:1904 — test_support_log_is_opt_in_and_masked
- Terraform export row 7 (prefix, folder, namespace) — tenant_terraform.py:800 — test_output_folder_name_is_checked_and_used
- Terraform export row 12 (Cloud & Branch Connector coverage) — tenant_terraform.py:721 — test_cloud_connector_unsupported_items_are_listed_not_hidden
One line per confirmed or built comparison row: `<tool> row N — <file:line> — <test name>`.

- Policy simulator row 3 — path_port_check.py:check — tests/test_w12_simulator.py::test_a_port_blocked_by_a_rule_for_everyone_is_said_so_and_other_ports_are_not
- Policy simulator row 5 — path_analyzer.py:38 (ASSUMPTIONS), zia_path_modules.py:1897, path_analyzer.py:358 — tests/test_w12_simulator.py::test_the_default_assumptions_are_stated_with_every_result_and_follow_the_traffic
- Policy simulator row 14 — bulk_test.py:1749 (area_list), bulk_test.py:40-48 — tests/test_bulk_test.py::test_the_summary_names_top_rules_categories_misses_and_lists_per_area
# Feature evidence (comparison rows)

## Wave 12: day-to-day admin peer (rows 6, 13, 14, 27, 30)

- row 6 (ZDX device search/health, user lookup) — ops_zdx_trace.py:267 (`lookup`: users, devices, health, device_app, app_scores), POST /api/operations/lookup dlp_api_server.py — tests/test_ops_admin_zdx.py::test_the_read_only_views_read_and_never_write
- row 27 (ZDX device health, app scores, user lookup) — same code and test as row 6; browser views in static/ops_admin.js
- row 13 Scheduled sync (approval-gated) — sync_jobs.py (read-only compare, plan filed in the change queue), `sync_jobs.awaiting_approval`, GET /api/sync-jobs/awaiting-approval, apply through POST /api/change-queue/{rid}/apply (admin_ops.execute: approval, plan hash, re-read, read-back, Undo) — tests/test_w12_zsconfig.py::test_a_scheduled_tick_never_calls_a_write_and_queues_the_plan, ::test_the_sync_module_has_no_path_to_a_write, ::test_applying_without_approval_is_refused_and_nothing_is_written, ::test_applying_after_the_drift_changed_marks_it_stale_and_refuses, ::test_an_approved_plan_with_a_matching_hash_goes_through_admin_ops, ::test_the_timer_is_off_by_default_and_a_setting_turns_it_on
- row 14 (SCIM visibility) — scim_view.py, POST /api/scim/overview (read-only IdPs, SCIM groups, sync status; the SDK cannot list SCIM users, so users are not listed) — tests/test_w12_zsconfig.py::test_scim_view_lists_idps_groups_and_sync_status_and_only_reads, ::test_scim_route_needs_zpa_in_scope_and_reads_nothing_otherwise
- row 30 (audit log full-text search) — audit.py `search`, GET /api/audit/search (team-filtered, bounded) — tests/test_w12_zsconfig.py::test_audit_search_requires_every_word_ignores_case_and_returns_newest_first, ::test_audit_search_is_bounded_and_empty_query_matches_nothing, ::test_audit_search_route_filters_to_what_the_person_may_see_and_rejects_empty

Scheduled sync (approval-gated): a schedule (off by default; `DLP_CHECK_SYNC_TIMER=1` turns the timer on) only reads, compares a saved source against the target and files the resulting plan as "Awaiting approval". It never applies. Applying needs another writer's approval, write mode, the assessor and typed confirmation, and a fresh plan whose hash matches (else the plan is marked stale and nothing is written).
One line per comparison row: tool, row, where it lives, the test that proves it.

- assistant-skill row 1 — reference_corpus.py lookup(), mcp_tools.lookup (`lookup` tool) — tests/test_w12_skill.py::test_lookup_answers_from_the_corpus_with_sources_and_says_when_nothing_matches
- assistant-skill row 4 — mcp_tools.py grade() — tests/test_w12_skill.py::test_every_answer_is_graded_with_source_tier_and_confidence
- assistant-skill row 7 — investigation_journal.py, `journal_open`/`journal_add`/`journal_show`, GET/POST /api/journal — tests/test_w12_skill.py::test_journal_enforces_hypothesis_evidence_conclusion_and_resumes
- assistant-skill row 8 — reference_corpus.py cite(), `cite` tool, POST /api/cite — tests/test_w12_skill.py::test_cite_fetch_only_through_allowlisted_zscaler_hosts
- assistant-skill row 9 — capacity_review.py, `capacity_review` tool, POST /api/capacity-review, static/report_capacity.html — tests/test_w12_skill.py::test_read_used_reads_only_the_products_in_scope
- assistant-skill row 12 — postmortem.py, `postmortem` tool, POST /api/postmortem — tests/test_w12_skill.py::test_postmortem_builds_markdown_and_csv_from_the_window
