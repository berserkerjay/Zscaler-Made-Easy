"""Build the app's quality and security score: docs/QUALITY_SCORE.md (for
people) and docs/quality_score.json (for the Advanced settings page).

    python tools/quality_score.py                       # rewrite both outputs
    python tools/quality_score.py --check               # exit 1 when either is stale
    python tools/quality_score.py --from-junit r.xml    # write docs/qa/test_run.json from a pytest JUnit file
        [--commit SHA] [--date YYYY-MM-DDTHH:MM:SS] [--out PATH]

Inputs, all in the repository:
  docs/qa/findings/<slug>.json   one findings record per QA check (schema below), untrusted
  docs/qa/test_run.json          the last full test run: passed, failed, skipped, duration,
                                 commit, date and per-file counts (written by --from-junit)
  tools/security_test_matrix.py  which standards controls have a mapped test

The score (0-100) is computed per sub-area from three parts, each 0-100:
  tests     share of the sub-area's tests that passed in the recorded run
  findings  100 minus the CVSS-band penalty of every OPEN finding in the sub-area's records
            (fixed and accepted findings are recorded and listed, never penalised)
  coverage  share of the sub-area's required standards controls that have a mapped test
weighted 40 / 40 / 20; a part with no input is left out and the weights of the
others re-normalised (the output names the parts each score is based on). An
area is the mean of its sub-areas; the overall score is the weighted mean of
the areas. Any open critical finding caps the overall score at 39, any open
high at 69, and any failed or errored test in the recorded run at 79 (grade C
at best, and the grade's words start with how many failed); the output says
what caused the cap. There is no score without a recorded test run. The constants below are the whole formula;
docs/QUALITY_SCORE.md prints them.

Fail closed: a findings file or test run that breaks the schema stops the
build (exit 2) with every reason listed, and nothing is written.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import md_safe  # noqa: E402

FINDINGS_DIR = os.path.join(ROOT, "docs", "qa", "findings")
TEST_RUN = os.path.join(ROOT, "docs", "qa", "test_run.json")
OUT_MD = os.path.join(ROOT, "docs", "QUALITY_SCORE.md")
OUT_JSON = os.path.join(ROOT, "docs", "quality_score.json")
SCHEMA_VERSION = 1

# ── The formula ──────────────────────────────────────────────────────

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("open", "fixed", "accepted")
CHECK_RESULTS = ("pass", "fixed", "open", "accepted")
# CVSS v3.1 qualitative bands; the penalty of one OPEN finding of that severity.
CVSS_BANDS = {"critical": "9.0-10.0", "high": "7.0-8.9", "medium": "4.0-6.9", "low": "0.1-3.9", "info": "0.0"}
PENALTY = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
CAPS = {"critical": 39, "high": 69}          # hard rule: an open finding of this severity caps the overall score
FAILED_TESTS_CAP = 79                        # hard rule: any failed or errored test in the recorded run: grade C at best
PART_WEIGHTS = {"tests": 0.4, "findings": 0.4, "coverage": 0.2}
GRADES = (   # (lowest score, grade, label, plain-language meaning)
    (90, "A", "Strong", "Tests pass, no serious finding is open and the standards are well covered."),
    (80, "B", "Good", "Mostly sound: a few gaps or minor open findings."),
    (70, "C", "Fair", "Usable, with gaps worth closing soon."),
    (60, "D", "Weak", "Serious gaps: an open high finding, failing tests or thin coverage."),
    (0, "F", "Poor", "Not acceptable: an open critical finding or many failures."),
)

# Areas, their weight in the overall score, and per sub-area: the findings
# records (by file slug; a trailing * matches a prefix), the test files
# (glob on the file name; "*" is the whole suite) and the standards controls
# it must cover (as named in docs/SECURITY_TESTING.md).
AREAS: Tuple[Dict[str, Any], ...] = (
    {"key": "regression", "name": "Regression", "weight": 25, "subs": (
        {"key": "regression", "name": "Regression", "slugs": ("regression",), "tests": ("*",),
         "controls": ("SSDF PW.8.2", "SSDF PW.9.1", "SSDF RV.1.1", "Scorecard CI-Tests")},
    )},
    {"key": "secure_by_design", "name": "Secure by design", "weight": 35, "subs": (
        {"key": "write_paths", "name": "Write paths", "slugs": ("sbd-writes", "c6-admin-ops", "c6-deploy", "c6-packs", "c6-migrate", "c6-update-heal", "review-backend"),
         "tests": ("test_write_safety_gates.py", "test_pack_deploy.py", "test_pack_removal.py", "test_remediation.py",
                   "test_admin_ops.py", "test_proposal_apply.py", "test_channel_targets_undo.py", "test_team_queue.py",
                   "test_sbd_writes.py", "test_c6_admin_ops.py", "test_c6_deploy.py", "test_c6_packs.py", "test_c6_migrate.py",
                   "test_c6_update_heal.py"),
         "controls": ("ASVS V4.1.3", "ASVS V4.1.5", "ASVS V4.2.2", "ASVS V7.1.3", "ASVS V11.1.1",
                      "CWE-284", "CWE-352", "CWE-862", "CWE-863")},
        {"key": "untrusted_input", "name": "Untrusted input", "slugs": ("sbd-input", "c6-exports", "c6-reports", "c6-traffic-reports", "c6-misc"),
         "tests": ("test_api_contracts.py", "test_dos_limits.py", "test_xss_*.py", "test_files_paths.py", "test_outbound_ssrf.py",
                   "test_export_injection.py", "test_csv_injection.py", "test_har_import.py", "test_log_analyzer.py",
                   "test_pack_library.py", "test_quality_score.py", "test_sbd_untrusted_input.py", "test_sbd_canary_renderers.py",
                   "test_c6_exports.py", "test_c6_reports.py", "test_c6_traffic_reports.py", "test_c6_misc.py"),
         "controls": ("ASVS V5.1.3", "ASVS V5.1.4", "ASVS V5.2.4", "ASVS V5.3.3", "ASVS V12.1.1", "ASVS V12.3.1",
                      "CWE-20", "CWE-22", "CWE-79", "CWE-400", "CWE-611", "CWE-918", "CWE-1333")},
        {"key": "auth_scope_secrets", "name": "Auth, scope and secrets", "slugs": ("sbd-auth", "c6-auth", "c6-api-server", "c6-scope-offline"),
         "tests": ("test_auth_session.py", "test_scope_rule_routes.py", "test_secret_canaries.py", "test_ui_auth.py", "test_sso.py",
                   "test_extension_security.py", "test_tools_read_only_in_scope.py", "test_no_implicit_reads.py",
                   "test_report_scope_reads.py", "test_sbd_offline_least_privilege.py", "test_c6_auth.py", "test_c6_api_server.py",
                   "test_c6_scope_offline.py"),
         "controls": ("ASVS V3.4.1", "ASVS V3.4.3", "ASVS V4.1.1", "ASVS V4.2.1", "ASVS V6.4.1", "ASVS V7.1.1", "ASVS V8.3.4",
                      "CWE-200", "CWE-306", "CWE-532", "CWE-639", "CWE-798")},
        {"key": "supply_chain", "name": "Supply chain", "slugs": ("sbd-supply", "supply-chain"),
         "tests": ("test_supply_chain_qa.py", "test_ci_pinning.py", "test_sbom_*.py", "test_lock_platforms.py",
                   "test_keyring_pinned.py", "test_packaging.py", "test_docker_rename.py"),
         "controls": ("SLSA v1.0 Build L2", "SLSA v1.0 Build L3", "Scorecard Pinned-Dependencies", "Scorecard Token-Permissions",
                      "Scorecard Dangerous-Workflow", "Scorecard Vulnerabilities", "Scorecard SBOM",
                      "SSDF PS.1.1", "SSDF PS.2.1", "SSDF PS.3.2", "SSDF PW.4.1", "CWE-494", "CWE-829")},
    )},
    {"key": "functionality", "name": "Functionality", "weight": 25, "subs": (
        {"key": "traffic_analysis", "name": "Traffic analysis", "slugs": ("func-path", "c6-path", "c6-zpa", "c6-posture", "c6-checks", "c6-assessment",
                                                                         "w7-path-coverage", "w7-o365-endpoints"),
         "tests": ("test_path_*.py", "test_pac_eval.py", "test_data_flow.py", "test_ssl_flow.py", "test_ssl_coverage.py",
                   "test_insights.py", "test_bulk_test.py", "test_zpa_*.py", "test_shared_path.py", "test_qa_func_path.py",
                   "test_c6_path.py", "test_c6_zpa.py", "test_c6_posture.py", "test_c6_checks.py", "test_c6_assessment.py",
                   "test_admin_rank.py", "test_rule_fields.py", "test_category_lookup*.py", "test_ucaas_oneclick.py",
                   "test_m365_app_services.py"),
         "controls": ("ASVS V11.1.1", "ASVS V11.1.4", "CWE-670", "CWE-682", "CWE-754")},
        {"key": "builders", "name": "Builders", "slugs": ("func-builders", "c6-zia-baseline-aiguard", "c6-zcc-zdx"),
         "tests": ("test_ops_*.py", "test_pack_*.py", "test_pov.py", "test_readiness.py", "test_offline_tenant.py",
                   "test_vendor_migrate.py", "test_policy_exports.py", "test_qa6_*.py", "test_c6_zia_baseline_aiguard.py",
                   "test_c6_zcc_zdx.py"),
         "controls": ("ASVS V4.1.3", "ASVS V5.1.3", "ASVS V11.1.4", "CWE-20", "CWE-841", "CWE-1188")},
        {"key": "ui_a11y", "name": "UI and accessibility", "slugs": ("ui", "c6-ui-core", "c6-ui-ops", "c6-tooltips", "glass", "review-ui"),
         "tests": ("test_accessibility.py", "test_*reflow*.py", "test_page_layout.py", "test_polish.py", "test_icons.py",
                   "test_explain.py", "test_safety_banner.py", "test_static_js_parses.py", "test_simple_mode.py",
                   "test_navigation.py", "test_sidebar_*.py", "test_c6_ui_core.py", "test_c6_ui_ops.py", "test_c6_tooltips.py", "test_new_marks.py",
                   "test_glass*.py"),
         "controls": ("WCAG SC 1.1.1", "WCAG SC 1.3.1", "WCAG SC 1.4.3", "WCAG SC 1.4.10", "WCAG SC 1.4.11", "WCAG SC 2.1.1",
                      "WCAG SC 2.4.7", "WCAG SC 2.5.8", "WCAG SC 3.3.2", "WCAG SC 4.1.2", "WCAG SC 4.1.3")},
    )},
    {"key": "motion", "name": "Motion", "weight": 15, "subs": (
        {"key": "motion", "name": "Motion", "slugs": ("motion*",),
         "tests": ("test_flow_*.py", "test_*motion*.py"),
         "controls": ("WCAG SC 1.1.1", "WCAG SC 2.1.1", "WCAG SC 2.2.2", "WCAG SC 2.3.3", "WCAG SC 1.4.10", "CWE-79")},
    )},
)

# Test files no sub-area above counts: the Regression sub-area (the whole
# suite) is their only part in the score. The Wave 6 regression journeys and
# the cross-area follow-up (test_c6_open_low.py, which pins fixes in every
# area) are here on purpose; the rest are the older suites that check the app
# as a whole. tests/test_quality_score.py fails when a tests/test_*.py file is
# neither in a sub-area's tests nor here, or when a glob here or above
# matches no file.
REGRESSION_ONLY: Tuple[str, ...] = (
    "test_regression_*.py", "test_openapi_regression.py", "test_c6_open_low.py",
    "test_api_paths.py", "test_app_update.py", "test_assess_stream.py", "test_assessor_attribution.py",
    "test_assessor_attribution_r2.py", "test_assessor_not_tool.py", "test_assessor_required.py", "test_audit_timeline.py",
    "test_banking_baseline.py", "test_baselines.py", "test_beacon.py", "test_beacon_scope.py", "test_benchmarks.py",
    "test_best_practice_review.py", "test_bp_crawler.py", "test_browser_extension.py", "test_browser_security.py",
    "test_channel_scope.py", "test_ci_smoke_contract.py", "test_classic_api_run_gate.py", "test_classic_fingerprint.py",
    "test_classic_profile_isolation_r2.py", "test_clouds.py", "test_compliance_tab.py", "test_console_index.py",
    "test_container_parity.py", "test_continuous_eval.py", "test_continuous_eval_scope_reads.py",
    "test_continuous_eval_unread_and_classic.py", "test_control_channels.py", "test_corpus_engines.py",
    "test_dashboard.py", "test_deploy_clarity.py", "test_detection_health.py", "test_device_posture.py",
    "test_dsa_reference_player.py", "test_endpoint_baseline.py", "test_engine_explain.py", "test_engine_pruning.py",
    "test_entrypoints.py", "test_export_filter_keeps_focus.py", "test_export_integrity.py", "test_exports_excel_pdf.py",
    "test_find_anything.py", "test_findings.py", "test_gui_addons.py", "test_guidance.py", "test_hardening.py",
    "test_help_center.py", "test_install_guide.py", "test_job_audit.py", "test_legacy_api.py",
    "test_legacy_send_rate_stop.py", "test_monitoring_clarity.py", "test_native_install_contracts.py",
    "test_native_tls_proxy.py", "test_native_zscaler.py", "test_offline_network_guard.py", "test_page_stop_is_final.py",
    "test_pause_countdown.py", "test_pdf_writer.py", "test_permissions.py", "test_plain_english.py",
    "test_posture_checks.py", "test_posture_plus.py", "test_product_name.py", "test_old_repo_name.py", "test_profile_integration.py",
    "test_proposals.py", "test_rate_forecast.py", "test_reference.py", "test_reference_embeds.py",
    "test_release_docs_export_and_assessor.py", "test_reports.py", "test_required_dlp_ci_triggers.py",
    "test_required_dlp_controls.py", "test_required_dlp_review_regressions.py", "test_rules_labels_scope_stop.py",
    "test_run_control.py", "test_saas_email_checks.py", "test_sample_tenant_browser.py",
    "test_scope_integration_regression.py", "test_scope_prerequisites.py", "test_scoring.py", "test_secure_by_design.py",
    "test_secure_defaults.py", "test_security_hardening_review.py", "test_security_test_matrix.py", "test_self_heal.py",
    "test_shadow_rules.py", "test_standalone.py", "test_static_round2_fixes.py", "test_suite_stability.py",
    "test_template_aliases.py", "test_tenant_pacing.py", "test_tenant_profiles.py", "test_tenant_read_stops.py",
    "test_terraform_job.py", "test_upstream_check.py", "test_url_tools.py", "test_vertical.py", "test_workspace_notes.py",
    "test_xlsx_writer.py", "test_zcc_device_state.py", "test_zcc_evaluation.py", "test_zcc_fleet.py",
    "test_zcc_fleet_xlsx.py", "test_zcc_paths.py", "test_zia_contract.py",
)

# How docs/SECURITY_TESTING.md's standards name a control here.
MATRIX_PREFIX = {"OWASP ASVS 4.0.3": "ASVS ", "CWE": "", "OWASP Top 10 2021": "", "OWASP WSTG": "", "WCAG 2.2": "WCAG ",
                 "SLSA v1.0": "", "OpenSSF Scorecard": "Scorecard ", "NIST SP 800-218 (SSDF)": "SSDF "}

# ── Untrusted input: the findings records and the test run ───────────

MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 64
MAX_DEPTH = 6                 # {root: {"findings": [ {finding} ]}} is 3 deep
MAX_FINDINGS = 500
MAX_CHECKS = 1000
MAX_STANDARDS = 200
MAX_TEST_RUN_BYTES = 2 * 1024 * 1024
MAX_TEST_FILES = 2000
MAX_JUNIT_BYTES = 64 * 1024 * 1024

SLUG_FILE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}\.json$")
FINDING_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{1,4}$")
CHECK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,59}$")
CWE = re.compile(r"^CWE-\d{1,5}$")
ASVS = re.compile(r"^(?:ASVS )?V\d{1,2}(?:\.\d{1,2}){0,2}$")
WCAG = re.compile(r"^(?:WCAG (?:2\.[12] )?)?(?:SC )?\d\.\d\.\d{1,2}$")
TEST_REF = re.compile(r"^tests/[A-Za-z0-9_./-]{1,150}\.py(?:::[^\s<>`|\\]{1,200})?$")
COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
COMMITS = re.compile(r"^[0-9a-f]{7,40}(?:, [0-9a-f]{7,40}){0,4}$")   # a finding's fix can take up to five commits
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)?$")
TEST_FILE = re.compile(r"^tests/[A-Za-z0-9_/-]{1,150}\.py$")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069\u2028\u2029]")
# A unified diff is lines: newline, tab and carriage return are its own; any
# other control or direction-override character is still refused.
PATCH_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069\u2028\u2029]")
MAX_CONTEXT_BYTES = 8192   # a record's coverage context (method, per-file numbers), serialised
MARKUP = re.compile(r"<\s*[A-Za-z!/?]|&#?[A-Za-z0-9]+;")

ROOT_KEYS = {"area": True, "title": True, "findings": True, "standards": False, "checks": False, "tests_added": False,
             "notes": False, "baseline": False, "files": False, "coverage": False}
FINDING_KEYS = {"id": True, "title": True, "severity": True, "status": True, "cwe": False, "asvs": False, "wcag": False,
                "fix": False, "test": False, "commit": False, "reason": False, "proposed_patch": False, "files": False}
CHECK_KEYS = {"id": True, "what": True, "result": True, "standard": False}
RUN_KEYS = {"passed": True, "failed": True, "skipped": True, "duration_s": True, "commit": True, "date": True,
            "errors": False, "files": False}


class InputError(ValueError):
    """A findings record or test run that breaks the schema."""


def _depth(text: str) -> int:
    """Deepest nesting of [ and { outside strings, without parsing (so a
    hostile file cannot exhaust the parser's recursion first)."""
    depth = best = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            best = max(best, depth)
        elif ch in "]}":
            depth -= 1
    return best


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise InputError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _refuse_constant(name):
    raise InputError(f"{name} is not a number")


def parse_json_text(raw: bytes, limit: int, what: str) -> Any:
    """Bytes of an untrusted JSON file to a value: size, encoding, nesting,
    duplicate keys and NaN/Infinity are refused before anything is used."""
    if len(raw) > limit:
        raise InputError(f"{what}: larger than {limit} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InputError(f"{what}: starts with a byte-order mark")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError(f"{what}: not UTF-8") from None
    if _depth(text) > MAX_DEPTH:
        raise InputError(f"{what}: nested deeper than {MAX_DEPTH} levels")
    try:
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_refuse_constant)
    except InputError as e:
        raise InputError(f"{what}: {e}") from None
    except (ValueError, RecursionError) as e:
        raise InputError(f"{what}: not valid JSON ({str(e)[:80]})") from None


def _read_capped(path: str, limit: int, what: str) -> bytes:
    """A regular file's bytes, at most limit + 1 read; a link or a device is refused."""
    st = os.lstat(path)
    import stat as _stat
    if not _stat.S_ISREG(st.st_mode):
        raise InputError(f"{what}: not a regular file")
    with open(path, "rb") as f:
        raw = f.read(limit + 1)
    if len(raw) > limit:
        raise InputError(f"{what}: larger than {limit} bytes")
    return raw


def _keys(obj: Any, spec: Dict[str, bool], where: str) -> None:
    if not isinstance(obj, dict):
        raise InputError(f"{where}: must be an object")
    extra = sorted(set(obj) - set(spec))
    if extra:
        raise InputError(f"{where}: unknown key(s) {', '.join(repr(k)[:40] for k in extra[:5])}")
    missing = sorted(k for k, req in spec.items() if req and k not in obj)
    if missing:
        raise InputError(f"{where}: missing {', '.join(missing)}")


def _text(v: Any, where: str, limit: int, *, pattern: Optional[re.Pattern] = None, empty: bool = False,
          markup: bool = True, controls: re.Pattern = CONTROL_CHARS) -> str:
    if not isinstance(v, str):
        raise InputError(f"{where}: must be a string")
    if len(v) > limit:
        raise InputError(f"{where}: longer than {limit} characters")
    if not v.strip() and not empty:
        raise InputError(f"{where}: must not be empty")
    if controls.search(v):
        raise InputError(f"{where}: holds control or direction-override characters")
    if not markup and MARKUP.search(v):
        raise InputError(f"{where}: holds HTML markup (plain text only)")
    if pattern is not None and v and not pattern.match(v):
        raise InputError(f"{where}: not in the expected form")
    return v


def _int(v: Any, where: str, hi: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= hi:
        raise InputError(f"{where}: must be a whole number from 0 to {hi}")
    return v


def _files(files: Any, where: str) -> None:
    if not isinstance(files, list) or len(files) > 200:
        raise InputError(f"{where}: must be a list of at most 200 paths")
    for i, p in enumerate(files):
        _text(p, f"{where}[{i}]", 200, markup=False)


def _context(v: Any, where: str) -> None:
    """Free-form context beside a record's numbers (how coverage was measured,
    per-file numbers): read, never scored or shown. Bounded in size, and its
    text is as plain as any other field."""
    try:
        size = len(json.dumps(v, ensure_ascii=False))
    except (TypeError, ValueError):
        raise InputError(f"{where}: not plain JSON") from None
    if size > MAX_CONTEXT_BYTES:
        raise InputError(f"{where}: its context is larger than {MAX_CONTEXT_BYTES} bytes")

    def walk(x: Any, at: str) -> None:
        if isinstance(x, str):
            _text(x, at, 2000, empty=True)
        elif isinstance(x, dict):
            for k, y in x.items():
                _text(k, f"{at} key", 80, markup=False)
                walk(y, f"{at}.{k}")
        elif isinstance(x, list):
            for i, y in enumerate(x):
                walk(y, f"{at}[{i}]")
        elif isinstance(x, bool) or x is None or isinstance(x, (int, float)):
            return
        else:
            raise InputError(f"{at}: not plain JSON")
    walk(v, where)


def validate_record(obj: Any, slug: str) -> Dict[str, Any]:
    """One findings record, checked field by field; returns a clean copy."""
    w = slug
    _keys(obj, ROOT_KEYS, w)
    out: Dict[str, Any] = {"slug": slug,
                           "area": _text(obj["area"], f"{w}.area", 600, markup=False),
                           "title": _text(obj["title"], f"{w}.title", 300, markup=False)}
    # Context the agents record (kept out of the score and the page): plain
    # notes, the baseline compared against, the files covered, coverage.
    notes = obj.get("notes", [])
    if not isinstance(notes, list) or len(notes) > 50:
        raise InputError(f"{w}.notes: must be a list of at most 50 strings")
    for i, n in enumerate(notes):
        _text(n, f"{w}.notes[{i}]", 2000)
    _text(obj.get("baseline", ""), f"{w}.baseline", 300, empty=True)
    _files(obj.get("files", []), f"{w}.files")
    cov = obj.get("coverage", {})
    if not isinstance(cov, dict):
        raise InputError(f"{w}.coverage: must be {{before, after}} (and how it was measured)")
    for k in ("before", "after"):
        v = cov.get(k, 0)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 100:
            raise InputError(f"{w}.coverage.{k}: must be a number from 0 to 100")
    _context({k: v for k, v in cov.items() if k not in ("before", "after")}, f"{w}.coverage")
    std = obj.get("standards", [])
    if not isinstance(std, list) or len(std) > MAX_STANDARDS:
        raise InputError(f"{w}.standards: must be a list of at most {MAX_STANDARDS} strings")
    out["standards"] = [_text(s, f"{w}.standards[{i}]", 80, markup=False) for i, s in enumerate(std)]
    checks = obj.get("checks", [])
    if not isinstance(checks, list) or len(checks) > MAX_CHECKS:
        raise InputError(f"{w}.checks: must be a list of at most {MAX_CHECKS} checks")
    out["checks"] = []
    for i, c in enumerate(checks):
        cw = f"{w}.checks[{i}]"
        _keys(c, CHECK_KEYS, cw)
        result = _text(c["result"], f"{cw}.result", 10)
        if result not in CHECK_RESULTS:
            raise InputError(f"{cw}.result: must be one of {', '.join(CHECK_RESULTS)}")
        out["checks"].append({"id": _text(c["id"], f"{cw}.id", 60, pattern=CHECK_ID), "what": _text(c["what"], f"{cw}.what", 1000),
                              "standard": _text(c.get("standard", ""), f"{cw}.standard", 120, empty=True), "result": result})
    finds = obj["findings"]
    if not isinstance(finds, list) or len(finds) > MAX_FINDINGS:
        raise InputError(f"{w}.findings: must be a list of at most {MAX_FINDINGS} findings")
    out["findings"] = []
    seen = set()
    for i, f in enumerate(finds):
        fw = f"{w}.findings[{i}]"
        _keys(f, FINDING_KEYS, fw)
        fid = _text(f["id"], f"{fw}.id", 40, pattern=FINDING_ID)
        if fid in seen:
            raise InputError(f"{fw}.id: {fid} appears twice")
        seen.add(fid)
        sev = _text(f["severity"], f"{fw}.severity", 10)
        if sev not in SEVERITIES:
            raise InputError(f"{fw}.severity: must be one of {', '.join(SEVERITIES)}")
        status = _text(f["status"], f"{fw}.status", 10)
        if status not in STATUSES:
            raise InputError(f"{fw}.status: must be one of {', '.join(STATUSES)}")
        _files(f.get("files", []), f"{fw}.files")   # the files a finding touches: context, never scored
        _text(f.get("proposed_patch", ""), f"{fw}.proposed_patch", 65536, empty=True,   # a diff for the integrator, never shown
              controls=PATCH_CONTROL_CHARS)
        item = {"id": fid, "title": _text(f["title"], f"{fw}.title", 400, markup=False), "severity": sev, "status": status,
                "cwe": _text(f.get("cwe", ""), f"{fw}.cwe", 12, pattern=CWE, empty=True),
                "asvs": _text(f.get("asvs", ""), f"{fw}.asvs", 16, pattern=ASVS, empty=True),
                "wcag": _text(f.get("wcag", ""), f"{fw}.wcag", 24, pattern=WCAG, empty=True),
                "fix": _text(f.get("fix", ""), f"{fw}.fix", 300, empty=True),
                "test": _text(f.get("test", ""), f"{fw}.test", 360, pattern=TEST_REF, empty=True),
                "commit": _text(f.get("commit", ""), f"{fw}.commit", 210, pattern=COMMITS, empty=True),
                "reason": _text(f.get("reason", ""), f"{fw}.reason", 300, empty=True)}
        if status != "fixed" and not (item["reason"].strip() or item["fix"].strip()):
            raise InputError(f"{fw}: an {status} finding needs a reason")
        out["findings"].append(item)
    out["tests_added"] = _int(obj.get("tests_added", 0), f"{w}.tests_added", 100000)
    return out


def load_findings(directory: str = FINDINGS_DIR) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Every docs/qa/findings/*.json, validated: (records sorted by slug, errors)."""
    if not os.path.isdir(directory):
        return [], []
    names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    if len(names) > MAX_FILES:
        return [], [f"{len(names)} findings files: at most {MAX_FILES}"]
    records, errors, ids = [], [], {}
    for name in names:
        if not SLUG_FILE.match(name):
            errors.append(f"{name[:60]!r}: the file name must be <slug>.json (a-z, 0-9, -)")
            continue
        slug = name[:-5]
        try:
            raw = _read_capped(os.path.join(directory, name), MAX_FILE_BYTES, name)
            rec = validate_record(parse_json_text(raw, MAX_FILE_BYTES, name), slug)
        except InputError as e:
            errors.append(str(e))
            continue
        for f in rec["findings"]:
            if f["id"] in ids:
                errors.append(f"{slug}: finding {f['id']} is also in {ids[f['id']]}")
            ids[f["id"]] = slug
        records.append(rec)
    return records, errors


def validate_test_run(obj: Any) -> Dict[str, Any]:
    _keys(obj, RUN_KEYS, "test_run")
    out = {k: _int(obj[k], f"test_run.{k}", 10_000_000) for k in ("passed", "failed", "skipped")}
    out["errors"] = _int(obj.get("errors", 0), "test_run.errors", 10_000_000)
    d = obj["duration_s"]
    if isinstance(d, bool) or not isinstance(d, (int, float)) or not 0 <= d <= 10_000_000 or math.isnan(d):
        raise InputError("test_run.duration_s: must be a number of seconds")
    out["duration_s"] = round(float(d), 1)
    out["commit"] = _text(obj["commit"], "test_run.commit", 40, pattern=COMMIT)
    out["date"] = _text(obj["date"], "test_run.date", 40, pattern=DATE)
    files = obj.get("files", {})
    if not isinstance(files, dict) or len(files) > MAX_TEST_FILES:
        raise InputError(f"test_run.files: must be an object of at most {MAX_TEST_FILES} files")
    out["files"] = {}
    for path in sorted(files):
        _text(path, "test_run.files key", 160, pattern=TEST_FILE)
        c = files[path]
        _keys(c, {"passed": True, "failed": True, "skipped": True}, f"test_run.files[{path}]")
        out["files"][path] = {k: _int(c[k], f"test_run.files[{path}].{k}", 1_000_000) for k in ("passed", "failed", "skipped")}
    return out


def load_test_run(path: str = TEST_RUN) -> Optional[Dict[str, Any]]:
    if not os.path.lexists(path):
        return None
    return validate_test_run(parse_json_text(_read_capped(path, MAX_TEST_RUN_BYTES, "test_run.json"), MAX_TEST_RUN_BYTES, "test_run.json"))


# ── Standards coverage (tools/security_test_matrix.py) ──────────────

def matrix_coverage() -> Dict[str, List[str]]:
    """{standard: [control ids with a mapped test]} from the security test matrix."""
    import security_test_matrix as stm
    by, _, _ = stm.collect()
    return {std: sorted(by.get(std, {}), key=_key) for std, _ in stm.STANDARDS}


def _key(ident: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", ident)]


def _covered_names(coverage: Dict[str, List[str]]) -> set:
    return {MATRIX_PREFIX.get(std, "") + ident for std, ids in coverage.items() for ident in ids}


def _is_covered(control: str, names: set) -> bool:
    return control in names or any(n.startswith(control + ".") or n.startswith(control + " ") for n in names)


def standards_summary(coverage: Dict[str, List[str]]) -> Dict[str, Any]:
    asvs = coverage.get("OWASP ASVS 4.0.3", [])
    chapters = sorted({a.split(".")[0] for a in asvs}, key=_key)
    return {
        "asvs_chapters": chapters,
        "asvs_requirements": len(asvs),
        "wcag": list(coverage.get("WCAG 2.2", [])),
        "cwe": list(coverage.get("CWE", [])),
        "top10": list(coverage.get("OWASP Top 10 2021", [])),
        "wstg": len(coverage.get("OWASP WSTG", [])),
        "slsa": list(coverage.get("SLSA v1.0", [])),
        "scorecard": list(coverage.get("OpenSSF Scorecard", [])),
        "ssdf": list(coverage.get("NIST SP 800-218 (SSDF)", [])),
    }


# ── The score ────────────────────────────────────────────────────────

def _r1(x: float) -> float:
    return math.floor(x * 10 + 0.5) / 10


def _matches_slug(slug: str, pats) -> bool:
    return any(slug == p or (p.endswith("*") and slug.startswith(p[:-1])) for p in pats)


def _sub_area_of(slug: str) -> Tuple[Optional[str], Optional[str]]:
    for a in AREAS:
        for s in a["subs"]:
            if _matches_slug(slug, s["slugs"]):
                return a["key"], s["key"]
    return None, None


def grade(score: Optional[int], failed: int = 0) -> Dict[str, str]:
    """The grade of a score. `failed` (failed + errored tests of the run)
    leads the words, so a run with failures never reads "Tests pass"."""
    if score is None:
        return {"grade": "", "label": "No score yet", "meaning": "No full test run is recorded yet (docs/qa/test_run.json)."}
    for lo, g, label, meaning in GRADES:
        if score >= lo:
            if failed > 0:
                meaning = f"{failed} test{'s' if failed != 1 else ''} failed in the recorded run. " + meaning.replace("Tests pass, no", "No")
            return {"grade": g, "label": label, "meaning": meaning}
    raise AssertionError("unreachable")


def _tests_part(sub, run) -> Optional[Dict[str, Any]]:
    if run is None:
        return None
    if sub["tests"] == ("*",):
        p, f, sk, files = run["passed"], run["failed"] + run["errors"], run["skipped"], None
    else:
        hits = [k for k in run["files"] if any(fnmatch.fnmatchcase(k.rsplit("/", 1)[-1], g) for g in sub["tests"])]
        p = sum(run["files"][k]["passed"] for k in hits)
        f = sum(run["files"][k]["failed"] for k in hits)
        sk = sum(run["files"][k]["skipped"] for k in hits)
        files = len(hits)
    if p + f == 0:
        return None
    return {"score": _r1(100 * p / (p + f)), "passed": p, "failed": f, "skipped": sk, "files": files}


def compute(records: List[Dict[str, Any]], run: Optional[Dict[str, Any]], coverage: Dict[str, List[str]]) -> Dict[str, Any]:
    """The whole score from validated inputs. Pure: same inputs, same output."""
    names = _covered_names(coverage)
    findings: List[Dict[str, Any]] = []
    for rec in records:
        ak, sk = _sub_area_of(rec["slug"])
        for f in rec["findings"]:
            findings.append(dict(f, slug=rec["slug"], area=ak or "other", sub_area=sk or "other"))
    areas_out = []
    for a in AREAS:
        subs_out = []
        for s in a["subs"]:
            recs = [r for r in records if _matches_slug(r["slug"], s["slugs"])]
            mine = [f for f in findings if f["sub_area"] == s["key"] and f["area"] == a["key"]]
            open_ = [f for f in mine if f["status"] == "open"]
            fpart = None
            if recs:
                fpart = {"score": float(max(0, 100 - sum(PENALTY[f["severity"]] for f in open_))),
                         "open": len(open_), "fixed": sum(f["status"] == "fixed" for f in mine),
                         "accepted": sum(f["status"] == "accepted" for f in mine), "records": [r["slug"] for r in recs]}
            tpart = _tests_part(s, run)
            got = [c for c in s["controls"] if _is_covered(c, names)]
            cpart = {"score": _r1(100 * len(got) / len(s["controls"])), "covered": got,
                     "missing": [c for c in s["controls"] if c not in got]}
            parts = {"tests": tpart, "findings": fpart, "coverage": cpart}
            used = {k: v for k, v in parts.items() if v is not None}
            wsum = sum(PART_WEIGHTS[k] for k in used)
            score = _r1(sum(PART_WEIGHTS[k] * v["score"] for k, v in used.items()) / wsum) if run is not None else None
            subs_out.append({"key": s["key"], "name": s["name"], "score": score, "based_on": list(used) if run is not None else [], **parts})
        area_score = _r1(sum(x["score"] for x in subs_out) / len(subs_out)) if run is not None else None
        areas_out.append({"key": a["key"], "name": a["name"], "weight": a["weight"], "score": area_score, "subs": subs_out})

    raw = _r1(sum(a["weight"] * a["score"] for a in areas_out) / sum(a["weight"] for a in areas_out)) if run is not None else None
    open_all = [f for f in findings if f["status"] == "open"]
    cap = None
    for sev in ("critical", "high"):
        hit = [f["id"] for f in open_all if f["severity"] == sev]
        if hit:
            limit = CAPS[sev]
            n = len(hit)
            why = (f"{n} {sev} finding{'s are' if n > 1 else ' is'} open ({', '.join(hit[:8])}{', …' if n > 8 else ''}); "
                   f"any open {sev} finding caps the overall score at {limit}.")
            cap = {"kind": "findings", "severity": sev, "limit": limit, "findings": hit, "reason": why, "applied": False}
            break
    failed = 0 if run is None else run["failed"] + run["errors"]
    if cap is None and failed > 0:
        # The finding caps (39, 69) are lower: when one holds it stays, and the
        # grade's words still say how many tests failed.
        cap = {"kind": "tests", "severity": "", "limit": FAILED_TESTS_CAP, "findings": [], "applied": False,
               "reason": (f"{failed} test{'s' if failed != 1 else ''} failed or errored in the recorded run; any failed test "
                          f"caps the overall score at {FAILED_TESTS_CAP} (grade C at best).")}
    score: Optional[int] = None
    if run is not None:
        score = int(math.floor(raw + 0.5))
        if cap is not None:
            cap["applied"] = score > cap["limit"]
            score = min(score, cap["limit"])
    warnings = []
    if run is None:
        warnings.append("No full test run is recorded (docs/qa/test_run.json), so there is no overall score yet.")
    no_record = [s["name"] for a in AREAS for s in a["subs"] if not any(_matches_slug(r["slug"], s["slugs"]) for r in records)]
    if no_record:
        warnings.append(f"No findings record yet for: {', '.join(no_record)}. Their scores leave the findings part out.")
    # A sub-area with records can still miss one it names (a QA slice that
    # never wrote its record): its fixes and open findings would go uncounted.
    missing = [p for a in AREAS for s in a["subs"] if s["name"] not in no_record for p in s["slugs"]
               if not p.endswith("*") and not any(r["slug"] == p for r in records)]
    if missing:
        warnings.append(f"Named findings record{'s' if len(missing) > 1 else ''} with no file in docs/qa/findings: "
                        f"{', '.join(missing)}. Their findings are not counted.")
    unknown = sorted({f["slug"] for f in findings if f["area"] == "other"} | {r["slug"] for r in records if _sub_area_of(r["slug"])[0] is None})
    if unknown:
        warnings.append(f"Records with no area in the formula: {', '.join(unknown)}. Their open findings still count toward the cap.")

    by_sev = {sev: {st: sum(1 for f in findings if f["severity"] == sev and f["status"] == st) for st in STATUSES} for sev in SEVERITIES}
    checks = {res: sum(1 for r in records for c in r["checks"] if c["result"] == res) for res in CHECK_RESULTS}
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    st_rank = {"open": 0, "accepted": 1, "fixed": 2}
    findings.sort(key=lambda f: (st_rank[f["status"]], sev_rank[f["severity"]], _key(f["id"])))
    g = grade(score, failed)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "tools/quality_score.py",
        "run": None if run is None else {k: run[k] for k in ("commit", "date", "passed", "failed", "errors", "skipped", "duration_s")},
        "overall": {"score": score, "raw": raw, **g, "cap": cap},
        "areas": areas_out,
        "counts": {"findings": len(findings), "by_severity": by_sev, "checks": checks,
                   "tests_added": sum(r["tests_added"] for r in records)},
        "findings": findings,
        "records": [{"slug": r["slug"], "area": r["area"], "title": r["title"], "standards": r["standards"],
                     "checks": len(r["checks"]), "findings": len(r["findings"]), "tests_added": r["tests_added"]} for r in records],
        "standards": standards_summary(coverage),
        "formula": {"part_weights": PART_WEIGHTS, "area_weights": {a["key"]: a["weight"] for a in AREAS},
                    "penalty": PENALTY, "cvss_bands": CVSS_BANDS, "caps": CAPS, "failed_tests_cap": FAILED_TESTS_CAP,
                    "grades": [{"min": lo, "grade": gr, "label": la} for lo, gr, la, _ in GRADES]},
        "warnings": warnings,
    }


# ── Outputs ──────────────────────────────────────────────────────────

def render_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False) + "\n"


def _t(v: Any) -> str:
    return md_safe.text(v) if v not in (None, "") else "—"


def _n(v: Any) -> str:
    return "—" if v is None else (f"{v:g}" if isinstance(v, float) else str(v))


def render_md(r: Dict[str, Any]) -> str:
    o, run = r["overall"], r["run"]
    out = ["# Quality and security score", "",
           "Generated by `python tools/quality_score.py` from `docs/qa/findings/*.json`, `docs/qa/test_run.json` and the",
           "standards mapping in `docs/SECURITY_TESTING.md`; CI fails when this file or `docs/quality_score.json` is stale.",
           "It scores this app (Zscaler Made Easy), not a customer tenant. The Advanced settings page shows the same data.", ""]
    if run is None:
        out += ["**No score yet.** No full test run is recorded (`docs/qa/test_run.json`).", ""]
    else:
        out += [f"**Overall: {o['score']} / 100, grade {o['grade']} ({o['label']}).** {o['meaning']}", "",
                f"Run: commit `{run['commit']}`, {_t(run['date'])}. {run['passed']} passed, {run['failed']} failed, "
                f"{run['errors']} errors, {run['skipped']} skipped, {_n(run['duration_s'])} s.", ""]
    if o["cap"]:
        c = o["cap"]
        verb = "Capped" if c.get("applied") else "Cap in force"
        out += [f"**{verb} at {c['limit']}:** {_t(c['reason'])}" + (f" Before the cap: {_n(o['raw'])}." if c.get("applied") else ""), ""]
    for w in r["warnings"]:
        out.append(f"- {_t(w)}")
    if r["warnings"]:
        out.append("")
    out += ["## Scores by area", "", "| Area | Sub-area | Score | Tests | Findings (open) | Standards covered | Based on |", "|---|---|---|---|---|---|---|"]
    for a in r["areas"]:
        for s in a["subs"]:
            t, f, c = s["tests"], s["findings"], s["coverage"]
            tt = "—" if t is None else f"{_n(t['score'])} ({t['passed']} passed, {t['failed']} failed)"
            ff = "no record" if f is None else f"{_n(f['score'])} ({f['open']})"
            cc = f"{_n(c['score'])} ({len(c['covered'])} of {len(c['covered']) + len(c['missing'])})"
            out.append(f"| {a['name']} ({_n(a['score'])}, weight {a['weight']}) | {s['name']} | **{_n(s['score'])}** | {tt} | {ff} | {cc} | "
                       f"{', '.join(s['based_on']) or '—'} |")
    out.append("")
    out += ["## Findings", "", "| Severity | Open | Fixed | Accepted |", "|---|---|---|---|"]
    for sev in SEVERITIES:
        b = r["counts"]["by_severity"][sev]
        out.append(f"| {sev} | {b['open']} | {b['fixed']} | {b['accepted']} |")
    out.append("")
    names = {a["key"]: a["name"] for a in AREAS}
    subs = {s["key"]: s["name"] for a in AREAS for s in a["subs"]}
    for a in list(AREAS) + [{"key": "other", "name": "Other", "subs": ()}]:
        rows = [f for f in r["findings"] if f["area"] == a["key"]]
        if not rows:
            continue
        out += [f"### {names.get(a['key'], 'Other')}", "", "| Id | Title | Severity | CWE | ASVS | Status | Sub-area | Fix or reason | Test |",
                "|---|---|---|---|---|---|---|---|---|"]
        for f in rows:
            note = f["fix"] if f["status"] == "fixed" or not f["reason"] else f["reason"]
            out.append(f"| {_t(f['id'])} | {_t(f['title'])} | {f['severity']} | {_t(f['cwe'])} | {_t(f['asvs'] or f['wcag'])} | "
                       f"{f['status']} | {_t(subs.get(f['sub_area'], 'Other'))} | {_t(note)} | {_t(f['test'])} |")
        out.append("")
    if not r["findings"]:
        out += ["No findings are recorded yet.", ""]
    if r["records"]:
        out += ["### Records", "", "| Record | Area | Title | Checks | Findings | Tests added |", "|---|---|---|---|---|---|"]
        for rec in r["records"]:
            out.append(f"| {_t(rec['slug'])} | {_t(rec['area'])} | {_t(rec['title'])} | {rec['checks']} | {rec['findings']} | {rec['tests_added']} |")
        out.append("")
    st = r["standards"]
    out += ["## Standards covered by tests", "",
            f"- OWASP ASVS 4.0.3: {st['asvs_requirements']} requirements in {len(st['asvs_chapters'])} of 14 chapters ({', '.join(st['asvs_chapters']) or 'none'})",
            f"- WCAG 2.2 AA: {len(st['wcag'])} success criteria ({', '.join(st['wcag']) or 'none'})",
            f"- CWE: {len(st['cwe'])} weaknesses ({', '.join(st['cwe']) or 'none'})",
            f"- OWASP Top 10 2021: {', '.join(st['top10']) or 'none'}; OWASP WSTG: {st['wstg']} tests ids",
            f"- SLSA v1.0: {', '.join(st['slsa']) or 'none'}",
            f"- OpenSSF Scorecard: {', '.join(st['scorecard']) or 'none'}",
            f"- NIST SP 800-218 (SSDF): {', '.join(st['ssdf']) or 'none'}", "",
            "Required controls not yet covered, per sub-area:", ""]
    for a in r["areas"]:
        for s in a["subs"]:
            miss = s["coverage"]["missing"]
            out.append(f"- {s['name']}: {', '.join(miss) if miss else 'none'}")
    out += ["", "## How the score is computed", "",
            "Each sub-area has three parts, each from 0 to 100:", "",
            f"- **Tests** ({int(PART_WEIGHTS['tests'] * 100)}%): passed / (passed + failed) of the sub-area's test files in the recorded run "
            "(skipped tests are left out; Regression uses the whole suite).",
            f"- **Findings** ({int(PART_WEIGHTS['findings'] * 100)}%): 100 minus the penalty of each open finding in the sub-area's records, "
            "never below 0. Fixed and accepted findings are listed but not penalised.",
            f"- **Coverage** ({int(PART_WEIGHTS['coverage'] * 100)}%): required standards controls with at least one mapped test "
            "(OWASP ASVS 4.0.3 L2, CWE, WCAG 2.2 AA, SLSA v1.0, OpenSSF Scorecard, NIST SSDF).", "",
            "A part with no input (no record, no matching tests) is left out and the other weights are scaled up; the table says what "
            "each score is based on. An area is the mean of its sub-areas; the overall score is the weighted mean of the areas, rounded.", "",
            "| Severity (CVSS v3.1) | Base score band | Penalty per open finding | Cap on the overall score |", "|---|---|---|---|"]
    for sev in SEVERITIES:
        out.append(f"| {sev} | {CVSS_BANDS[sev]} | {PENALTY[sev]} | {CAPS.get(sev, '—')} |")
    out += ["", "| Area | Weight | Sub-areas |", "|---|---|---|"]
    for a in AREAS:
        out.append(f"| {a['name']} | {a['weight']} | {', '.join(s['name'] for s in a['subs'])} |")
    out += ["", "| Score | Grade | Meaning |", "|---|---|---|"]
    for lo, g, label, meaning in GRADES:
        out.append(f"| {lo} or more | {g} ({label}) | {meaning} |")
    out += ["", f"Hard rule: any open critical finding caps the overall score at {CAPS['critical']} and any open high finding at "
            f"{CAPS['high']}, and any failed or errored test in the recorded run caps it at {FAILED_TESTS_CAP} (grade C at best), "
            "whatever the other parts say; the score line names what caused it. There is no overall score without a recorded "
            "full test run (`docs/qa/test_run.json`, written by `python tools/quality_score.py --from-junit`).", ""]
    return "\n".join(out)


def build(findings_dir: str = FINDINGS_DIR, test_run: str = TEST_RUN, coverage: Optional[Dict[str, List[str]]] = None):
    """(markdown, json text, errors) from the inputs on disk."""
    records, errors = load_findings(findings_dir)
    run = None
    try:
        run = load_test_run(test_run)
    except InputError as e:
        errors.append(str(e))
    if errors:
        return None, None, errors
    result = compute(records, run, matrix_coverage() if coverage is None else coverage)
    return render_md(result), render_json(result), []


# ── --from-junit ─────────────────────────────────────────────────────

def _refuse_dtd(data: bytes) -> None:
    """No DOCTYPE or entity declaration, in any encoding (CWE-776, CWE-611)."""
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise InputError("JUnit file: DTD/entities are not accepted")
    from xml.parsers import expat

    class _Refused(Exception):
        pass

    def refuse(*_a):
        raise _Refused()
    p = expat.ParserCreate()
    p.StartDoctypeDeclHandler = refuse
    p.EntityDeclHandler = refuse
    try:
        p.Parse(data, True)
    except _Refused:
        raise InputError("JUnit file: DTD/entities are not accepted") from None
    except expat.ExpatError:
        pass


def _test_file(case) -> Optional[str]:
    f = case.get("file")
    if f:
        f = f.replace("\\", "/")
        f = f if f.startswith("tests/") else "tests/" + f.rsplit("/", 1)[-1]
        return f if TEST_FILE.match(f) else None
    parts = (case.get("classname") or "").split(".")
    for i, part in enumerate(parts):
        if part.startswith("test_"):
            path = "/".join(parts[: i + 1]) + ".py"
            path = path if path.startswith("tests/") else "tests/" + path.rsplit("/", 1)[-1]
            return path if TEST_FILE.match(path) else None
    return None


def run_from_junit(xml_path: str, commit: Optional[str] = None, date: Optional[str] = None) -> Dict[str, Any]:
    """docs/qa/test_run.json's content from a pytest --junitxml file."""
    import xml.etree.ElementTree as ET
    data = _read_capped(xml_path, MAX_JUNIT_BYTES, "JUnit file")
    _refuse_dtd(data)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise InputError(f"JUnit file: not well-formed XML ({e})") from None
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    tot = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    files: Dict[str, Dict[str, int]] = {}
    duration, stamp = 0.0, ""
    for s in suites:
        try:
            duration += float(s.get("time") or 0)
        except ValueError:
            pass
        stamp = stamp or (s.get("timestamp") or "")
        for case in s.iter("testcase"):
            kids = {c.tag for c in case}
            kind = "errors" if "error" in kids else "failed" if "failure" in kids else "skipped" if "skipped" in kids else "passed"
            tot[kind] += 1
            path = _test_file(case)
            if path:
                if len(files) >= MAX_TEST_FILES and path not in files:
                    continue
                b = files.setdefault(path, {"passed": 0, "failed": 0, "skipped": 0})
                b["failed" if kind == "errors" else kind] += 1
    if commit is None:
        try:
            commit = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                                    timeout=10, check=True).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            raise InputError("no --commit given and git could not name HEAD") from None
    date = date or stamp[:19]
    if not date:
        raise InputError("the JUnit file has no timestamp: pass --date")
    return validate_test_run({**tot, "duration_s": round(duration, 1), "commit": commit, "date": date, "files": files})


# ── Command line ─────────────────────────────────────────────────────

def _current(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def main(argv=None, findings_dir: str = FINDINGS_DIR, test_run: str = TEST_RUN, out_md: str = OUT_MD, out_json: str = OUT_JSON,
         coverage: Optional[Dict[str, List[str]]] = None) -> int:
    ap = argparse.ArgumentParser(prog="quality_score.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 when an output is stale, 2 when an input is invalid")
    ap.add_argument("--from-junit", metavar="XML", help="write the test run record from a pytest JUnit XML file")
    ap.add_argument("--commit")
    ap.add_argument("--date")
    ap.add_argument("--out", default=None, help="where --from-junit writes (default docs/qa/test_run.json)")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    if a.from_junit:
        try:
            rec = run_from_junit(a.from_junit, a.commit, a.date)
        except InputError as e:
            print(f"quality_score: {e}", file=sys.stderr)
            return 2
        dest = a.out or test_run
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(json.dumps(rec, indent=2) + "\n")
        print(f"wrote {os.path.relpath(dest, ROOT)}: {rec['passed']} passed, {rec['failed']} failed, {rec['errors']} errors, {rec['skipped']} skipped")
        return 0
    md, js, errors = build(findings_dir, test_run, coverage)
    if errors:
        for e in errors:
            print(f"quality_score: invalid input: {e}", file=sys.stderr)
        return 2
    if a.check:
        stale = [p for p, text in ((out_md, md), (out_json, js)) if _current(p) != text]
        if stale:
            print("stale: " + ", ".join(os.path.relpath(p, ROOT) for p in stale) + "; run python tools/quality_score.py", file=sys.stderr)
            return 1
        return 0
    for path, text in ((out_md, md), (out_json, js)):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
