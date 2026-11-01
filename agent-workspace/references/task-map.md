# Task map: which files a change touches

The compiler's lookup table. Find the kind of change, then read only these files (plus what they import that you call).

| Kind of change | Files |
|---|---|
| New assessment check | the check module for its product (`zscaler_full_checks.py`, `zscaler_rbac_checks.py`, `zscaler_zdx_checks.py`, `zscaler_genai_checks.py`, …, or `other_products.py`); the compliance mapping it feeds; `sample_tenant.py` data; the check-id registry tests |
| New tenant read | the reader/module for its area; `offline_tenant.py` CAPTURE (snapshots); `config_backup.py` TYPES (backup/diff) if it's configuration; `tenant_terraform.py` if Terraform can express it; `scope_permissions.py` |
| New write (builder, editor, admin action, restore, fix) | a new `ops_<name>.py` registered on `admin_ops.py`; `pack_ops.py` (write kinds); `static/ops_<name>.js`; `static/report_operations.html` only for hooks; `static/explain.js`; `tests/test_sbd_writes.py`; see `_config/safe-writes.md` |
| New API route | `dlp_api_server.py`; the tables in `_config/scope-and-routes.md`; `team_routes.py` |
| Path analyzer / traffic answer | `path_analyzer.py`, `data_flow.py`, `zia_path_modules.py`, `rule_fields.py` (evaluated/neutral fields), `zpa_path.py`, `zcc_bypass.py`, `path_whatif.py`, `bulk_test.py` (Test a list), `static/path_modules.js`, `static/report_path.html` |
| Admin rank / rule order | `admin_rank.py`, `rank_inherit.py`, `shadow_rules.py` |
| New page | `static/report_<name>.html` + script; route in `dlp_api_server.py`; sidebar, Find anything and `static/explain.js` cards; help catalogues; tooltip tour list in `tests/test_c6_tooltips.py`; `static/whats_new.js` |
| Export / download | the exporter (`xlsx_writer.py`, `pdf_writer.py`, `policy_exports.py`, `csv_safe` users); an authenticated route; escaping tests |
| Uploaded file / pasted input | the parser module; caps and malformed handling; escaping on every output; `tests/test_sbd_untrusted_input.py`-style tests |
| Outbound fetch | a module like `m365_endpoints.py` / `zscaler_ip_ranges.py`; SECURITY.md outbound list; `secure_by_design.py` outbound line; `zscaler_update_check.ALLOWED_HOSTS` |
| Team server / auth | `team_server.py`, `team_routes.py`, `team_api.py`, `sso.py`, `store_crypto.py`, `server_acme.py` |
| Assistant (MCP) tool | `mcp_tools.py`, `dlp_mcp_server.py`, `skills/zscaler-made-easy/` |
| Policy pack | `pack_library.py`, `pack_channels.py`, `pack_deploy.py`, `pack_terraform.py`, `pack_removal.py`, the pack folder, `terraform/` |
| Docker / install | `Dockerfile`, `docker-compose.yml`, `update_container.sh`/`.ps1`, `install.sh`, `INSTALL.md`, `.github/workflows/` |
