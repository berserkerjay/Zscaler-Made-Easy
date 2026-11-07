# Feature evidence

One line per confirmed or built comparison row: `<tool> row N — <file:line> — <test name>`.

- Policy simulator row 3 — path_port_check.py:check — tests/test_w12_simulator.py::test_a_port_blocked_by_a_rule_for_everyone_is_said_so_and_other_ports_are_not
- Policy simulator row 5 — path_analyzer.py:38 (ASSUMPTIONS), zia_path_modules.py:1897, path_analyzer.py:358 — tests/test_w12_simulator.py::test_the_default_assumptions_are_stated_with_every_result_and_follow_the_traffic
- Policy simulator row 14 — bulk_test.py:1749 (area_list), bulk_test.py:40-48 — tests/test_bulk_test.py::test_the_summary_names_top_rules_categories_misses_and_lists_per_area
