# Feature evidence

One line per comparison row: tool row N, file:line, test name.

- Terraform export row 4 (resource selection) — tenant_terraform.py:778 — test_types_and_exclude_take_keys_resource_names_and_patterns
- Terraform export row 5 (validate) — tenant_terraform.py:1854 — test_static_check_finds_a_broken_workspace, test_validate_script_is_written_but_nothing_is_run
- Terraform export row 6 (progress / support) — tenant_terraform.py:1904 — test_support_log_is_opt_in_and_masked
- Terraform export row 7 (prefix, folder, namespace) — tenant_terraform.py:800 — test_output_folder_name_is_checked_and_used
- Terraform export row 12 (Cloud & Branch Connector coverage) — tenant_terraform.py:721 — test_cloud_connector_unsupported_items_are_listed_not_hidden
