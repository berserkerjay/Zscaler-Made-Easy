# Feature evidence

One line per comparison row: tool row N, where the feature is, and the test that exercises it.

## Policy wizard

- Policy wizard row 2 (saved POV progress, resume) built — pov.py progress(), posture_pair(); static/pov.js "Resume here" line — tests/test_w12_pov_posture.py::test_reopening_the_saved_pov_says_where_it_stands_and_what_is_next
- Policy wizard row 3 (Education preset) built — education_ferpa_baseline/, vertical.py INDUSTRY_PACKS, compliance_profiles.py FERPA — tests/test_education_pack.py::test_the_education_industry_and_ferpa_profile_offer_the_pack_first
- Policy wizard row 5 (posture score at start and end) built — pov.py add_posture(), POST /api/pov/posture — tests/test_w12_pov_posture.py::test_first_reading_is_the_start_and_the_latest_later_one_the_end
- Policy wizard row 9 (JSONL audit log, CSV export) evidence + export built — audit.py record(), export(); GET /api/audit/export — tests/test_w12_audit_export.py::test_the_log_is_one_compact_json_object_per_line
- Policy wizard row 13 (frameworks, per-rule control mapping) evidence — compliance_profiles.py PROFILES, map_rule() — tests/test_w12_wizard_evidence.py::test_baseline_rules_map_to_named_controls_of_each_framework
- Policy wizard row 17 (SSL catch-all last, TLS 1.2, DoH, Trusted Resolver) evidence — ops_zia_baseline.py:297 ssl.catch_all, :321 dns.doh, :327 dns.resolver — tests/test_ops_zia_baseline.py::test_apply_creates_disabled_rules_below_the_tenants_with_the_ssl_catch_all_last, ::test_an_existing_catch_all_that_is_no_longer_last_is_moved_to_the_bottom, tests/test_w12_wizard_evidence.py::test_ssl_catch_all_is_last_with_a_tls_1_2_floor_and_doh_and_trusted_resolver_rules_exist
- Policy wizard row 23 (AI prompt capture builder) built — ops_zia_ai_prompt.py, static/ops_zia_ai_prompt.js — tests/test_w12_ai_prompt.py::test_apply_writes_the_whole_object_with_only_those_switches_changed_and_undo_restores
- Policy wizard row 25 (isolation profile and SSL certificate pickers) evidence — ops_zia_baseline.py _read_catalog(), static/ops_zia_baseline.js zbProfile/zbCert — tests/test_w12_wizard_evidence.py::test_the_isolation_profile_and_certificate_pickers_are_filled_from_the_tenant_and_in_the_form
- Policy wizard row 27 (block page theme builder) built — block_page_theme.py, ops_zia_eun.py, static/ops_zia_eun.js, /api/block-page/* — tests/test_block_page_theme.py::test_apply_puts_the_object_as_read_with_only_the_planned_fields_then_undo_restores
- Policy wizard row 31 (leftover rules with Keep boxes) built — pack_removal.py leftover_reason(), mark_leftovers(), selection_without_kept(); static/deploy_studio.js — tests/test_w12_leftover_keep.py::test_only_unticked_leftovers_become_the_removal_selection
- Policy wizard row 44 (ZDX Web and CloudPath probes, interval, protocol) evidence — ops_zdx.py:104-106 INTERVALS_MIN, PROTOCOLS — tests/test_ops_zdx.py::test_apply_creates_and_turns_on_everything_in_order_reads_back_and_offers_undo, ::test_bad_requests_are_refused_before_anything_is_read
