"""Build docs/SECURITY_TESTING.md: every regression and security test that
names the standard it checks, grouped by standard, from the tests' own
docstrings (the first line starts with the mapping, e.g.
"ASVS V4.2.2 · CWE-352 · WSTG-SESS-05: a cross-site form post is refused").

    python tools/security_test_matrix.py          # rewrite the document
    python tools/security_test_matrix.py --check  # exit 1 when it is stale

tests/test_security_test_matrix.py runs --check in CI, and fails when a
test in one of the QA files has no mapping.
"""
from __future__ import annotations

import ast
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from open_source import NOTE_MD  # noqa: E402  (the repository root's one wording)

DOC = os.path.join(ROOT, "docs", "SECURITY_TESTING.md")

# The QA files: every test in them must carry a mapping.
QA_FILES = (
    "test_suite_stability.py", "test_api_contracts.py", "test_scope_rule_routes.py",
    "test_write_safety_gates.py", "test_export_integrity.py", "test_export_injection.py",
    "test_extension_security.py", "test_auth_session.py", "test_xss_sinks.py",
    "test_xss_render_sites.py", "test_files_paths.py", "test_secret_canaries.py",
    "test_supply_chain_qa.py", "test_outbound_ssrf.py", "test_dos_limits.py", "test_findings_reflow.py", "test_report_reflow.py", "test_ops_plugins.py", "test_ops_zcc.py", "test_ops_zdx.py", "test_ops_zpa.py", "test_ops_aiguard.py", "test_readiness.py", "test_offline_tenant.py", "test_pov.py", "test_standalone.py", "test_path_zia_modules.py", "test_path_zpa_workloads.py", "test_bulk_test.py", "test_pac_eval.py", "test_path_whatif.py", "test_ops_zia_baseline.py", "test_zcc_device_state.py", "test_connect_reflow.py", "test_sbd_writes.py", "test_sbd_offline_least_privilege.py", "test_sbd_untrusted_input.py", "test_sbd_canary_renderers.py", "test_openapi_regression.py", "test_regression_flows.py", "test_regression_migration.py", "test_qa_func_path.py", "test_qa6_builders_lifecycle.py", "test_qa6_verdicts_reports.py", "test_flow_motion_models.py", "test_flow_motion_browser.py", "test_path_live_motion.py", "test_path_live_motion_browser.py", "test_flow_pages.py", "test_quality_score.py", "test_sample_tenant_browser.py", "test_c6_open_low.py", "test_glass.py", "test_glass_browser.py", "test_docker_rename.py", "test_old_repo_name.py", "test_admin_rank.py", "test_rule_fields.py", "test_category_lookup.py", "test_category_lookup_browser.py", "test_ucaas_oneclick.py", "test_m365_app_services.py", "test_rule_editor.py", "test_config_backup.py", "test_config_restore.py", "test_zpa_identity.py", "test_zpa_identity_browser.py", "test_sast.py", "test_ops_admin_zpa.py", "test_ops_admin_zcc.py", "test_ops_admin_zdx.py", "test_ops_admin_routes.py", "test_rank_inherit.py", "test_compliance_profiles.py", "test_compliance_profiles_browser.py", "test_w8_zia_governance.py", "test_zpa_rbac.py", "test_rule_csv.py", "test_sync_jobs.py", "test_sync_template_source.py", "test_ops_zia_admin.py", "test_ops_zid.py", "test_mcp_tools.py", "test_panos_migrate.py", "test_local_plugins.py", "test_tui.py", "test_update_notify.py", "test_net_files.py", "test_net_files_browser.py", "test_zcc_bypass_path.py", "test_zcc_tamper_passwords.py", "test_zcc_otp.py", "test_path_device_compare.py", "test_path_probe.py", "test_path_extras_browser.py", "test_ops_list_fix.py", "test_team_server.py", "test_team_server_extras.py", "test_tenant_terraform.py", "test_zcc_fleet_plus.py", "test_zcc_fleet_plus_browser.py", "test_traffic_logs.py", "test_health_diag.py", "test_pov_build.py", "test_pov_rehearsal.py", "test_pov_build_browser.py", "test_ops_zpa_fields.py", "test_url_analyzer_resume.py", "test_pack_any_levels.py", "test_zpa_policy_completeness.py", "test_zia_forwarding.py", "test_w8_zia_threat_saas.py", "test_shadow_it.py", "test_w8_cloud_connector.py", "test_other_products.py", "test_w8_zwa_aiguard.py", "test_w8_zdx_zid_zcc.py", "test_w8_zdx_zcc_browser.py", "test_agent_workspace.py", "test_security_gates.py", "test_security_gates_ui.py", "test_team_saml.py", "test_team_passkeys.py", "test_team_signin_settings.py", "test_w9_zia_activation.py", "test_w9_url_category_admin.py", "test_w9_ip_groups.py", "test_w9_dlp_objects.py", "test_w9_zid_user.py", "test_w9_service_edge_toggle.py", "test_restore_breadth.py", "test_rehearsal_simulation.py", "test_simulation_ui.py", "test_editions.py", "test_baseline_selection.py", "test_w9_coverage_checks.py", "test_zcc_lists_w9.py", "test_mcp_tools_w9.py", "test_tf_providers_w9.py", "test_traffic_log_sources.py", "test_dns_windows.py", "test_fix_flow_browser.py", "test_path_manual.py", "test_vendor_app_services.py", "test_app_service_snapshots.py", "test_open_source_note.py",
)

STANDARDS = [
    ("OWASP ASVS 4.0.3", re.compile(r"\bASVS\s+(V\d+(?:\.\d+){0,2})")),
    ("CWE", re.compile(r"\b(CWE-\d+)")),
    ("OWASP Top 10 2021", re.compile(r"\b(A\d\d:2021)")),
    ("OWASP WSTG", re.compile(r"\b(WSTG-[A-Z]+-\d+)")),
    ("WCAG 2.2", re.compile(r"\b(?:WCAG\s*2\.[12]\s*)?(SC\s*\d\.\d\.\d+)")),
    ("SLSA v1.0", re.compile(r"\b(SLSA[^·:]*)")),
    ("OpenSSF Scorecard", re.compile(r"\bScorecard\s+([A-Za-z-]+)")),
    ("NIST SP 800-218 (SSDF)", re.compile(r"\bSSDF\s+([A-Z]{2}\.\d(?:\.\d)?)")),
]
MAPPED = re.compile(r"\b(ASVS|CWE-\d|WSTG-|WCAG|SC\s*\d\.\d|SLSA|Scorecard|SSDF|A\d\d:2021)")


def _tests(path: str):
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            doc = (ast.get_docstring(node) or "").strip().splitlines()
            yield node.name, (doc[0] if doc else "")


def collect():
    """{standard: {id: [(file, test)]}}, the unmapped QA tests and the count of mapped tests."""
    by = defaultdict(lambda: defaultdict(list))
    unmapped, mapped = [], 0
    tdir = os.path.join(ROOT, "tests")
    for name in sorted(os.listdir(tdir)):
        if not (name.startswith("test_") and name.endswith(".py")):
            continue
        for test, first in _tests(os.path.join(tdir, name)):
            head = first.split(": ", 1)[0]   # "A01:2021" keeps its colon; the label ends at ": "
            if not MAPPED.search(head):
                if name in QA_FILES:
                    unmapped.append(f"{name}::{test}")
                continue
            mapped += 1
            for std, rx in STANDARDS:
                for ident in rx.findall(head):
                    by[std][re.sub(r"\s+", " ", ident).strip()].append((name, test))
    return by, unmapped, mapped


def _key(ident: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", ident)]


def render() -> str:
    by, _, mapped = collect()
    out = ["# Security and regression tests, mapped to standards", "", NOTE_MD, "",
           "Generated by `python tools/security_test_matrix.py` from the tests' own docstrings; CI fails when it is stale",
           "or when a test in a QA file names no standard. Each test's docstring starts with the controls it checks.", "",
           f"{mapped} tests carry a mapping. Standards: OWASP ASVS 4.0.3 Level 2, OWASP Top 10 2021, CWE, OWASP WSTG,",
           "WCAG 2.2 AA, SLSA v1.0, OpenSSF Scorecard and NIST SP 800-218 (SSDF). Fixes follow CISA Secure by Design:",
           "secure defaults, deny by default, fail closed, least privilege.", ""]
    for std, _ in STANDARDS:
        ids = by.get(std)
        if not ids:
            continue
        out += [f"## {std}", "", "| Control | Tests | Files |", "|---|---|---|"]
        for ident in sorted(ids, key=_key):
            rows = ids[ident]
            files = sorted({f for f, _ in rows})
            out.append(f"| {ident} | {len(rows)} | {', '.join('`' + f + '`' for f in files)} |")
        out.append("")
    return "\n".join(out)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    text = render()
    if "--check" in argv:
        cur = open(DOC, encoding="utf-8").read() if os.path.exists(DOC) else ""
        if cur != text:
            print("docs/SECURITY_TESTING.md is stale: run python tools/security_test_matrix.py", file=sys.stderr)
            return 1
        return 0
    with open(DOC, "w", encoding="utf-8") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
