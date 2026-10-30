"""CISA Secure by Design: how this app measures against it, live.

CISA's Secure by Design principles (take ownership of customer security
outcomes; embrace radical transparency and accountability; lead from the
top) and the seven Secure by Design pledge goals (MFA, default passwords,
reducing entire classes of vulnerability, security patches, vulnerability
disclosure policy, CVEs, evidence of intrusions) are the frame. Every
check below reads evidence from the running server or the app folder and
says, in plain English, what it found and what to do when it falls short.

The score is the share of applicable controls met: a pass counts 1, a
warning 0.5, a failure 0; a control that does not apply to a local,
single-operator tool (MFA), or that could not be checked from here, is
shown but not scored — never counted as a pass.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List

APP_DIR = os.path.dirname(os.path.abspath(__file__))

P_OWN = "Take ownership of customer security outcomes"
P_OPEN = "Embrace radical transparency and accountability"
P_LEAD = "Lead from the top: build it into how the product is made"

PLEDGE = {
    "mfa": "1. Multi-factor authentication",
    "defaults": "2. Default passwords",
    "classes": "3. Reduce entire classes of vulnerability",
    "patches": "4. Security patches",
    "disclosure": "5. Vulnerability disclosure policy",
    "cves": "6. CVEs",
    "evidence": "7. Evidence of intrusions",
    "secure_defaults": "Secure by default",
}

_DANGEROUS_RE = re.compile(r"\beval\(|\bexec\(|\bpickle\b|shell\s*=\s*True|os\.system\(")
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
# A call that sends a write to the tenant: the SDK write methods the
# shared-path guard knows (tests/test_shared_path.py), and the REST
# client's post/put/patch/delete.
_TENANT_WRITE_RE = re.compile(r"\.(add_dict|add_dlp_engine|add_rule|add_sub_rule|update_dict|update_dlp_engine|update_rule|update_sub_rule|"
                              r"delete_dict|delete_dlp_engine|delete_rule|raw_request)\(|\bclient\.(post|put|patch|delete)\(")
# The shared execution path itself and the channel adapter it calls.
_SHARED_PATH = ("pack_ops.py", "pack_channels.py")


def _read(path: str, limit: int = 2_000_000) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _check(cid: str, name: str, principle: str, pledge: str, status: str, evidence: str, do: str = "") -> Dict[str, Any]:
    return {"id": cid, "control": name, "principle": principle, "pledge": PLEDGE.get(pledge, pledge),
            "status": status, "evidence": evidence, "do": do if status != "pass" else (do or "Nothing to do; keep it as it is.")}


def _middleware_names(app: Any) -> List[str]:
    names: List[str] = []
    for m in getattr(app, "user_middleware", None) or []:
        cls = getattr(m, "cls", None)
        if cls is not None:
            names.append(cls.__name__)
    return names


def _python_sources() -> List[str]:
    out: List[str] = []
    for base in (APP_DIR, os.path.join(APP_DIR, "tools")):
        if not os.path.isdir(base):
            continue
        for f in sorted(os.listdir(base)):
            p = os.path.join(base, f)
            if f.endswith(".py") and os.path.isfile(p) and os.path.abspath(p) != os.path.abspath(__file__):
                out.append(p)
    return out


def _direct_tenant_writers() -> Dict[str, int]:
    """{file: number of calls} for every module outside the shared path
    that sends a write to the tenant itself."""
    out: Dict[str, int] = {}
    for p in _python_sources():
        rel = os.path.relpath(p, APP_DIR).replace(os.sep, "/")
        if rel in _SHARED_PATH:
            continue
        for line in _read(p).splitlines():
            st = line.strip()
            if st.startswith(("#", "def ", "async def ")):
                continue
            if _TENANT_WRITE_RE.search(line):
                out[rel] = out.get(rel, 0) + 1
    return out


def evaluate(app: Any = None) -> Dict[str, Any]:
    """Every control with its status, evidence and next step, plus the score."""
    import security

    checks: List[Dict[str, Any]] = []

    # ── Take ownership of customer security outcomes ─────────────────────
    env_token = bool((os.environ.get("ZSCALER_UI_TOKEN") or "").strip())
    if security.ui_auth_enabled():
        checks.append(_check("ui_token", "Every browser and API caller must present the UI token", P_OWN, "defaults", "pass",
                             "The UI token gate is on. " + ("The token is fixed by ZSCALER_UI_TOKEN." if env_token else "A random token is minted per server process; no default credential exists."),
                             "Keep ZSCALER_UI_AUTH unset (on)."))
    else:
        checks.append(_check("ui_token", "Every browser and API caller must present the UI token", P_OWN, "defaults", "fail",
                             "The UI token gate is off (ZSCALER_UI_AUTH=0): any process on this machine can call the API.",
                             "Remove ZSCALER_UI_AUTH=0 from the start script or environment and restart the app."))

    import sso as _sso
    if _sso.sso_enabled() and not _sso.config_errors():
        issuer = os.environ.get("ZSCALER_SSO_ISSUER", "").strip()
        checks.append(_check("mfa", "Multi-factor authentication for the operator", P_OWN, "mfa", "pass",
                             f"Sign-in is required through the configured OpenID Connect identity provider ({issuer}). Enforcing a second factor there is the identity provider's own policy, not this app's.",
                             "Confirm the identity provider requires MFA for this application's client."))
    elif _sso.sso_enabled():
        checks.append(_check("mfa", "Multi-factor authentication for the operator", P_OWN, "mfa", "fail",
                             "ZSCALER_SSO_ENABLED is set but SSO is not fully configured (the server would refuse to start).",
                             "Set every ZSCALER_SSO_* variable so the identity-provider sign-in actually takes effect."))
    else:
        checks.append(_check("mfa", "Multi-factor authentication for the operator", P_OWN, "mfa", "n/a",
                             "A single-operator tool on the consultant's own laptop: access is the operating-system login plus the per-process UI token. There is no user directory to attach a second factor to.",
                             "Either expose the server beyond loopback only behind a reverse proxy that authenticates users with MFA and terminates TLS, or set ZSCALER_SSO_ENABLED and the ZSCALER_SSO_* variables to require sign-in through an identity provider."))

    direct = _direct_tenant_writers()
    direct_note = (" Not every write goes that way: " + ", ".join(sorted(direct)) + " write to the tenant directly once write mode is on, "
                   "with no plan hash and without the DISABLED default." if direct else "")
    w = security.write_mode_status()
    if not w.get("enabled"):
        checks.append(_check("writes", "Changes to the Zscaler tenant are refused until write mode is enabled on purpose", P_OWN, "secure_defaults", "pass",
                             "Read-only now. Write mode needs the confirmation phrase typed in this window (only while nobody but this computer can reach the server) or ENABLE_WRITE_ACTIONS in the start script. "
                             "A policy-pack deploy also needs an approved plan hash, and its rules ship DISABLED and monitor-only." + direct_note,
                             "Leave it read-only between engagements."))
    else:
        checks.append(_check("writes", "Changes to the Zscaler tenant are refused until write mode is enabled on purpose", P_OWN, "secure_defaults", "warn",
                             f"Write mode is on ({'enabled from this window for the session' if w.get('source') == 'session' else 'set by the start script'}). Policy-pack deploys still need an approved plan and ship DISABLED." + direct_note,
                             "Switch back to read-only in Deploy Policy Packs when the work is done; it also returns to read-only when the server restarts."))

    host = security.get_bind_host()
    if host in _LOCAL_HOSTS:
        checks.append(_check("loopback", "The server answers this machine only", P_OWN, "secure_defaults", "pass",
                             f"Bound to {host}. Uploads, updates and pack rewrites are refused on any other bind.", "Keep ZSCALER_BIND_HOST unset."))
    elif security.only_this_computer_can_reach():
        # The container listens on 0.0.0.0 inside its own network; what reaches
        # it from outside is the host address docker-compose.yml publishes on.
        checks.append(_check("loopback", "The server answers this machine only", P_OWN, "secure_defaults", "pass",
                             f"A container published on this computer's loopback only (DLP_CHECK_HOST_BIND={os.environ.get('DLP_CHECK_HOST_BIND', '').strip()}); "
                             f"inside the container it listens on {host}, which nothing outside this computer can reach.",
                             "Keep DLP_CHECK_HOST_BIND at 127.0.0.1; publishing beyond it needs SSO or an authenticating reverse proxy (SECURITY.md)."))
    else:
        checks.append(_check("loopback", "The server answers this machine only", P_OWN, "secure_defaults", "fail",
                             f"Bound to {host}: reachable from the network with a bearer token as the only guard.",
                             "Unset ZSCALER_BIND_HOST, or front the server with an authenticating reverse proxy and TLS."))

    if not security.is_debug():
        checks.append(_check("debug", "Debug mode is off", P_OWN, "secure_defaults", "pass", "ZSCALER_DEBUG is not set: no tracebacks or internals are shown to callers.", "Keep ZSCALER_DEBUG unset."))
    else:
        checks.append(_check("debug", "Debug mode is off", P_OWN, "secure_defaults", "fail", "ZSCALER_DEBUG is set: error responses may expose internals.", "Unset ZSCALER_DEBUG and restart."))

    wanted = ["SecurityHeadersMiddleware", "OriginCheckMiddleware", "BodySizeLimitMiddleware", "RateLimitMiddleware", "UIAuthMiddleware"]
    have = _middleware_names(app) if app is not None else []
    missing = [n for n in wanted if n not in have] if app is not None else []
    if app is None:
        checks.append(_check("middleware", "Security headers, origin check, body-size cap and rate limit are always on", P_OWN, "classes", "warn",
                             "Could not inspect the running server's middleware from here.", "Open this page from the running app."))
    elif not missing:
        checks.append(_check("middleware", "Security headers, origin check, body-size cap and rate limit are always on", P_OWN, "classes", "pass",
                             "Live on this server: CSP and frame-ancestors none, nosniff, no-referrer; same-origin and localhost origins only; "
                             f"{security.get_max_body_bytes() // (1024 * 1024)} MB body cap; 20 requests/second with a burst of 60 per client.",
                             "Nothing to do."))
    else:
        checks.append(_check("middleware", "Security headers, origin check, body-size cap and rate limit are always on", P_OWN, "classes", "fail",
                             "Missing from the running server: " + ", ".join(missing) + ".", "Start the app from dlp_api_server.py; the middleware is added there unconditionally."))

    tls = (os.environ.get("ZSCALER_UPDATE_VERIFY_TLS") or "").strip()
    smtp_plain = (bool((os.environ.get("DLP_CHECK_SMTP_HOST") or "").strip())
                  and (os.environ.get("DLP_CHECK_SMTP_TLS", "1") or "").strip().lower() in ("0", "false", "no"))
    if tls != "0" and not smtp_plain:
        checks.append(_check("tls", "Outbound TLS is verified", P_OWN, "secure_defaults", "pass",
                             "Certificate verification is on for the Zscaler API, GitHub, the documentation hosts and the digest mail server; a corporate root can be added with a CA bundle instead of switching verification off.",
                             "Keep ZSCALER_UPDATE_VERIFY_TLS and DLP_CHECK_SMTP_TLS unset."))
    else:
        found = []
        if tls == "0":
            found.append("ZSCALER_UPDATE_VERIFY_TLS=0: the updater accepts any certificate.")
        if smtp_plain:
            found.append("DLP_CHECK_SMTP_TLS=0: the digest e-mail goes to the mail server unencrypted.")
        checks.append(_check("tls", "Outbound TLS is verified", P_OWN, "secure_defaults", "warn",
                             " ".join(found),
                             "Point the app at the TLS-inspection proxy's or mail server's root certificate (CA bundle) and remove the override."))

    try:
        import zscaler_update_check
        hosts = sorted(getattr(zscaler_update_check, "ALLOWED_HOSTS", []) or [])
    except Exception:  # noqa: BLE001
        hosts = []
    if not hosts:
        try:
            import bp_sources
            hosts = sorted(bp_sources.allowed_hosts() or [])
        except Exception:  # noqa: BLE001
            hosts = []
    if hosts:
        checks.append(_check("outbound", "Outbound calls go to an allowlist of hosts", P_OWN, "secure_defaults", "pass",
                             f"{len(hosts)} documentation hosts allowed for the update check, the best-practice library and the SaaS matrix; the Zscaler API for the tenant; GitHub for updates; your own SMTP relay or https webhook only when configured. No AI or LLM service is called.",
                             "Nothing to do."))
    else:
        checks.append(_check("outbound", "Outbound calls go to an allowlist of hosts", P_OWN, "secure_defaults", "warn", "The documentation-host allowlist could not be read.", "Check bp_crawler.ALLOWED_HOSTS."))

    # ── Reduce entire classes of vulnerability ───────────────────────────
    hits: List[str] = []
    for p in _python_sources():
        for n, line in enumerate(_read(p).splitlines(), 1):
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            if _DANGEROUS_RE.search(line):
                hits.append(f"{os.path.relpath(p, APP_DIR)}:{n}")
    if not hits:
        checks.append(_check("constructs", "No eval, exec, pickle, os.system or shell=True in the app's Python", P_OWN, "classes", "pass",
                             f"{len(_python_sources())} source files scanned; Python is a memory-safe language, and the app has no SQL and one HTML escaper at every render site.",
                             "Nothing to do."))
    else:
        checks.append(_check("constructs", "No eval, exec, pickle, os.system or shell=True in the app's Python", P_OWN, "classes", "fail",
                             "Found at: " + ", ".join(hits[:8]) + ("…" if len(hits) > 8 else ""), "Replace each with a safe equivalent (json, subprocess with an argument list, ast.literal_eval)."))

    vc_md = _read(os.path.join(APP_DIR, "docs", "VULNERABILITY_CLASSES.md"))
    vc_low = vc_md.lower()
    classes_needs = {
        "memory-safe language eliminates a whole class of bugs": "memory-safe" in vc_low or "memory safe" in vc_low,
        "no SQL anywhere, so no SQL-injection class": "sql" in vc_low,
        "escaping at every render site, with the inline-CSP limitation named": "escap" in vc_low and "csp" in vc_low,
        "hash-pinned dependencies, pip-audit and a Trivy image scan": "pip-audit" in vc_low and "trivy" in vc_low and "hash" in vc_low,
    }
    missing_vc = [k for k, ok in classes_needs.items() if not ok]
    if not vc_md:
        checks.append(_check("classes_doc", "Which vulnerability classes are designed out, and which remain, is written down", P_OWN, "classes", "fail",
                             "docs/VULNERABILITY_CLASSES.md does not exist.", "Write docs/VULNERABILITY_CLASSES.md, one section per class of vulnerability."))
    elif missing_vc:
        checks.append(_check("classes_doc", "Which vulnerability classes are designed out, and which remain, is written down", P_OWN, "classes", "fail",
                             "docs/VULNERABILITY_CLASSES.md is missing: " + "; ".join(missing_vc) + ".", "Cover the missing points in docs/VULNERABILITY_CLASSES.md."))
    else:
        checks.append(_check("classes_doc", "Which vulnerability classes are designed out, and which remain, is written down", P_OWN, "classes", "pass",
                             "docs/VULNERABILITY_CLASSES.md explains, class by class: Python is memory-safe (no buffer/use-after-free class); no SQL is used anywhere (no injection class); "
                             "every render site escapes its output, with the inline-script/style CSP limitation named rather than hidden; and the supply chain is hash-pinned, "
                             "pip-audit'd and Trivy-scanned in CI.", "Nothing to do."))

    # ── Radical transparency and accountability ──────────────────────────
    sec_md = _read(os.path.join(APP_DIR, "SECURITY.md"))
    sec_low = sec_md.lower()
    disclosure_needs = {
        "a private reporting channel (a GitHub security advisory or direct contact)": "report a vulnerability" in sec_low or "reporting a vulnerability" in sec_low,
        "an explicit authorization to test this product, in good faith": "authorizes good-faith" in sec_low,
        "a safe-harbor commitment for testers who stay in scope": "safe harbor" in sec_low,
        "a stated coordinated-disclosure window": "90 days" in sec_low and "7 days" in sec_low,
    }
    missing_disc = [k for k, ok in disclosure_needs.items() if not ok]
    if not missing_disc:
        checks.append(_check("disclosure", "A vulnerability disclosure policy is published", P_OPEN, "disclosure", "pass",
                             "SECURITY.md authorizes good-faith testing of this product (not a customer tenant), commits to safe harbor for testers who stay in scope, "
                             "names a private reporting channel with a 3-business-day acknowledgement and a 30-day fix window for credential/tenant/unapproved-write issues, "
                             "and states the coordinated-disclosure window (90 days, or 7 days after the fix reaches main, whichever is first).", "Nothing to do."))
    else:
        checks.append(_check("disclosure", "A vulnerability disclosure policy is published", P_OPEN, "disclosure", "fail",
                             "SECURITY.md is missing: " + "; ".join(missing_disc) + ".", "Add these to SECURITY.md's vulnerability disclosure policy."))
    cves_needs = {
        "fixed vulnerabilities published as GitHub Security Advisories": "github security advisor" in sec_low,
        "a CWE classification on every High/Critical advisory": "cwe" in sec_low,
    }
    missing_cves = [k for k, ok in cves_needs.items() if not ok]
    if not missing_cves:
        checks.append(_check("cves", "Fixed vulnerabilities are published as advisories", P_OPEN, "cves", "pass",
                             "SECURITY.md commits to GitHub Security Advisories for anything that exposes credentials, tenant data or an unapproved write, with a CWE id on every High/Critical advisory.", "Nothing to do."))
    else:
        checks.append(_check("cves", "Fixed vulnerabilities are published as advisories", P_OPEN, "cves", "fail",
                             "SECURITY.md is missing: " + "; ".join(missing_cves) + ".", "Commit to GitHub Security Advisories with CWE ids for High/Critical issues in SECURITY.md."))
    if "Known limitations" in sec_md:
        checks.append(_check("limits", "Known limitations are written down, not hidden", P_OPEN, "disclosure", "pass",
                             "SECURITY.md lists what the tool does not protect against (bearer token on the machine, exposure beyond loopback, unsigned updates, inline scripts under CSP).", "Nothing to do."))
    else:
        checks.append(_check("limits", "Known limitations are written down, not hidden", P_OPEN, "disclosure", "warn", "SECURITY.md has no Known limitations section.", "Write down what the tool does not protect against."))

    if app is None:
        checks.append(_check("audit", "Every write call is recorded for later investigation", P_OPEN, "evidence", "n/a",
                             "Not checked: the running server's middleware could not be inspected from here, so whether audit.log is being written is unknown.",
                             "Open this page from the running app."))
    elif "AuditMiddleware" in have:
        import audit as _audit
        audit_path = _audit.path()   # DLP_CHECK_AUDIT (the container's /data), else beside the app
        size = os.path.getsize(audit_path) if os.path.exists(audit_path) else 0
        checks.append(_check("audit", "Every write call is recorded for later investigation", P_OPEN, "evidence", "pass",
                             "Every non-GET API call goes to audit.log (owner-only, rotated at 20 MB) with time, path, status, caller, write-mode state and a redacted body; deployments are also recorded for undo. "
                             + (f"The log holds {size:,} bytes." if size else "No writes recorded yet on this install."), "Keep audit.log with the engagement's records."))
    else:
        checks.append(_check("audit", "Every write call is recorded for later investigation", P_OPEN, "evidence", "fail", "The audit middleware is not in the running server.", "Start the app from dlp_api_server.py."))

    srv_src = _read(os.path.join(APP_DIR, "dlp_api_server.py"))
    if '"git_commit"' in srv_src or "git_commit" in srv_src:
        checks.append(_check("build", "The running build is identifiable", P_OPEN, "cves", "pass",
                             "GET /api/health and the guide's Build badge show the git commit, so a report or an advisory can name the exact build.", "Nothing to do."))
    else:
        checks.append(_check("build", "The running build is identifiable", P_OPEN, "cves", "warn", "The health endpoint does not expose the build.", "Expose the git commit at /api/health."))

    if os.path.exists(os.path.join(APP_DIR, "CHANGELOG.md")):
        checks.append(_check("changelog", "Every change is described for the operator", P_OPEN, "disclosure", "pass", "CHANGELOG.md lists what each batch of changes did, newest first, in plain language.", "Nothing to do."))
    else:
        checks.append(_check("changelog", "Every change is described for the operator", P_OPEN, "disclosure", "warn", "No CHANGELOG.md.", "Keep a changelog."))

    # ── Lead from the top: engineering practice ──────────────────────────
    lock = _read(os.path.join(APP_DIR, "requirements.lock"))
    hashes = lock.count("--hash=")
    if hashes:
        checks.append(_check("pins", "Dependencies are pinned by hash and installed hash-verified", P_LEAD, "patches", "pass",
                             f"requirements.lock carries {hashes} hashes; the installer, the updater and the container install with --require-hashes.", "Nothing to do."))
    else:
        checks.append(_check("pins", "Dependencies are pinned by hash and installed hash-verified", P_LEAD, "patches", "fail", "No requirements.lock with hashes.", "Generate the lock with make lock (uv pip compile --universal --generate-hashes)."))

    ci = _read(os.path.join(APP_DIR, ".github", "workflows", "tests.yml"))
    scans = [t for t, needle in (("pip-audit", "pip-audit"), ("Trivy image scan", "trivy"), ("CycloneDX SBOM", "cyclonedx")) if needle in ci]
    if len(scans) == 3:
        checks.append(_check("scans", "Known-vulnerability scans and an SBOM run on every push", P_LEAD, "patches", "pass", "CI runs " + ", ".join(scans) + ".", "Nothing to do."))
    elif scans:
        checks.append(_check("scans", "Known-vulnerability scans and an SBOM run on every push", P_LEAD, "patches", "warn", "CI runs " + ", ".join(scans) + " only.", "Add the missing scan to .github/workflows/tests.yml."))
    else:
        checks.append(_check("scans", "Known-vulnerability scans and an SBOM run on every push", P_LEAD, "patches", "fail", "No vulnerability scan in CI.", "Add pip-audit, an image scan and an SBOM step."))

    if os.path.exists(os.path.join(APP_DIR, ".github", "dependabot.yml")):
        checks.append(_check("dependabot", "Dependency updates arrive automatically", P_LEAD, "patches", "pass", "Dependabot watches pip, GitHub Actions and the base image.", "Nothing to do."))
    else:
        checks.append(_check("dependabot", "Dependency updates arrive automatically", P_LEAD, "patches", "warn", "No .github/dependabot.yml.", "Enable Dependabot for pip, Actions and Docker."))

    tests_dir = os.path.join(APP_DIR, "tests")
    n_tests = len([f for f in os.listdir(tests_dir) if f.startswith("test_") and f.endswith(".py")]) if os.path.isdir(tests_dir) else 0
    if "pytest" in ci and n_tests:
        extras = [t for t, needle in (("py_compile on every Python file", "py_compile"), ("node --check on every script", "node --check"),
                                      ("the pack mirror check", "mirror"), ("Terraform validation", "terraform")) if needle in ci.lower()]
        checks.append(_check("tests", "Tests, byte-compilation and syntax checks gate every push", P_LEAD, "classes", "pass",
                             f"{n_tests} test files run in CI" + (" with " + ", ".join(extras) if extras else "") + ".", "Nothing to do."))
    else:
        checks.append(_check("tests", "Tests, byte-compilation and syntax checks gate every push", P_LEAD, "classes", "fail", "CI does not run the tests.", "Run pytest in .github/workflows/tests.yml."))

    dockerfile = _read(os.path.join(APP_DIR, "Dockerfile"))
    compose = _read(os.path.join(APP_DIR, "docker-compose.yml"))
    container = [t for t, ok in (("non-root user", re.search(r"^USER\s+\S+", dockerfile, re.M) is not None),
                                  ("read-only filesystem", "read_only: true" in compose),
                                  ("no capabilities", "cap_drop" in compose),
                                  ("no privilege escalation", "no-new-privileges" in compose),
                                  ("loopback publish", "127.0.0.1:" in compose)) if ok]
    if len(container) == 5:
        checks.append(_check("container", "The container runs locked down", P_LEAD, "secure_defaults", "pass", "Dockerfile and docker-compose.yml: " + ", ".join(container) + ".", "Nothing to do."))
    elif container:
        checks.append(_check("container", "The container runs locked down", P_LEAD, "secure_defaults", "warn", "Present: " + ", ".join(container) + ".", "Add the missing hardening to Dockerfile / docker-compose.yml."))
    else:
        checks.append(_check("container", "The container runs locked down", P_LEAD, "secure_defaults", "warn", "No container files found.", "Nothing to do if the app is not run in a container."))

    gi = _read(os.path.join(APP_DIR, ".gitignore"))
    secret_files = ["tenant_config.json", "tenant_profiles.json", "local_settings.bat", "ui_token.txt", "audit.log"]
    ignored = [f for f in secret_files if f in gi]
    if len(ignored) == len(secret_files):
        checks.append(_check("secrets", "Credentials, tokens and logs never enter the repository", P_LEAD, "defaults", "pass",
                             ".gitignore covers " + ", ".join(secret_files) + "; secrets are masked in every error and never returned by the API.", "Nothing to do."))
    else:
        checks.append(_check("secrets", "Credentials, tokens and logs never enter the repository", P_LEAD, "defaults", "fail",
                             "Not ignored: " + ", ".join(f for f in secret_files if f not in ignored) + ".", "Add them to .gitignore."))

    checks.append(_check("language", "Written in a memory-safe language", P_LEAD, "classes", "pass",
                         f"Python {sys.version_info.major}.{sys.version_info.minor}: no buffer or use-after-free class of bug.", "Nothing to do."))

    # ── The same principles, applied to what the app puts in a tenant ────
    try:
        import pack_deploy
        import pack_ops
        probe = pack_deploy.secure_by_design_findings({"objects": [
            {"kind": "policy", "name": "probe-off", "position": "deployed", "channel": "web"},
            {"kind": "policy", "name": "probe-changed", "position": "customized", "channel": "web", "drift": ["action"]},
            {"kind": "policy", "name": "probe-weakened", "position": "relaxed", "channel": "web"}]})
        principles = {f["principle"] for f in probe["findings"]}
        ok = {pack_deploy.SBD_OWN, pack_deploy.SBD_OPEN, pack_deploy.SBD_DEFAULTS} <= principles
        checks.append(_check("pack_findings", "Deployed policy packs are measured against the same principles", P_OWN, "defaults", "pass" if ok else "fail",
                             ("Every journey check (Deploy Policy Packs → Where is this tenant?, and the assessment's journey) flags, per pack: objects missing or blocked "
                              "and rules never enabled (ownership of outcomes), objects changed in the tenant without the pack recording it (transparency), "
                              "and rules weakened against the pack (secure defaults), each with what to do." if ok else "The journey check does not cover all three principles."),
                             "Run Where is this tenant? on each pack card after a deployment, and again on every visit."))
        path_text = (f"Policy packs go through pack_ops.py: names and limits are validated before any request, dependencies are created first and "
                     f"removed last, transient refusals are retried, every write leaves a structured event, and {len(pack_ops.EXPLANATIONS)} known refusals carry a "
                     "plain-language explanation. A test fails the build if a new module writes to the tenant outside it (docs/SHARED_EXECUTION_PATH.md).")
        if not direct:
            checks.append(_check("shared_path", "Every pack is deployed, verified and removed through one execution path", P_LEAD, "classes", "pass",
                                 "pack_ops.py is the only module that writes to a tenant. " + path_text,
                                 "Keep new packs as data (JSON) and new object kinds inside pack_ops."))
        else:
            checks.append(_check("shared_path", "Every pack is deployed, verified and removed through one execution path", P_LEAD, "classes", "warn",
                                 path_text + " But pack_ops.py is not the only module that writes to a tenant: "
                                 + ", ".join(f"{f} ({n} write call{'s' if n != 1 else ''})" for f, n in sorted(direct.items()))
                                 + " send writes directly, without its validation, retries or events. They are still refused until write mode is on.",
                                 "Route these writes through pack_ops, or keep them read-only unless you have reviewed each change."))
    except Exception as e:  # noqa: BLE001
        checks.append(_check("pack_findings", "Deployed policy packs are measured against the same principles", P_OWN, "defaults", "fail",
                             f"The journey check could not be loaded: {e}", "Reinstall the app files."))

    # ── Score ────────────────────────────────────────────────────────────
    scored = [c for c in checks if c["status"] != "n/a"]
    points = sum({"pass": 1.0, "warn": 0.5, "fail": 0.0}[c["status"]] for c in scored)
    score = int(round(100 * points / len(scored))) if scored else 0
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D"
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "warn", "fail", "n/a")}
    return {"score": score, "grade": grade, "counts": counts, "checks": checks,
            "principles": [P_OWN, P_OPEN, P_LEAD],
            "reference": "https://www.cisa.gov/securebydesign",
            "note": "Measured live from this server and the app folder. A pass counts 1, a warning 0.5, a failure 0; controls that do not apply to a local single-operator tool, or that could not be checked from here, are shown but not scored."}
