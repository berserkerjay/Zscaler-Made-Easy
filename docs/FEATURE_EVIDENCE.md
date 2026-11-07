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
