"""Supply-chain and CI regression tests (QA check T14).

Each test names, on the first line of its docstring, the controls it
enforces: SLSA v1.0 build requirements, OpenSSF Scorecard checks, NIST SP
800-218 (SSDF) practices, and the CWE / OWASP ASVS 4.0.3 L2 ids where they
apply. Everything here is offline and deterministic: the tests read the
committed workflow, lock, Docker and install files (and fake the one HTTP
call the updater makes), so they run in milliseconds and never touch PyPI,
GitHub or a Docker daemon.
"""
from __future__ import annotations

import fnmatch
import glob
import os
import re
import subprocess

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml")))
LOCK_LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", re.M)


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _workflow(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        wf = yaml.safe_load(f)
    # YAML 1.1 reads the bare key `on` as the boolean True.
    if True in wf:
        wf["on"] = wf.pop(True)
    return wf


def _steps():
    """(workflow file, job id, step) for every step of every workflow."""
    for path in WORKFLOWS:
        for job_id, job in (_workflow(path).get("jobs") or {}).items():
            for step in job.get("steps") or []:
                yield os.path.basename(path), job_id, step


def _step_id(v):
    """Readable parametrize ids for (workflow, job, step) triples."""
    if isinstance(v, dict):
        return re.sub(r"\W+", "-", str(v.get("name") or v.get("uses") or "step"))[:50]
    return str(v)


def _pins(name: str) -> dict:
    return dict(LOCK_LINE.findall(_read(name)))


def _lock_blocks(name: str):
    return re.split(r"\n(?=[A-Za-z0-9_.-]+==)", _read(name))[1:]


# ── pip installs: hash-verified everywhere ─────────────────────────────

def _shell_lines(text: str):
    """Command lines of a shell, batch, Makefile or workflow text, with
    backslash continuations joined and comment lines dropped."""
    for line in text.replace("\\\n", " ").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.upper().startswith(("REM ", "::")):
            continue
        yield s


def _pip_install_violation(cmd: str):
    """Why a `pip install` command line is not hash-verified, or None.

    Allowed: `--require-hashes ... -r <file>.lock` (every argument after it
    is a lock), or the app's own folder as an editable install with
    `--no-deps --no-build-isolation` (which downloads nothing)."""
    m = re.search(r"\bpip[\"']?,?\s*[\"']?install\b(.*)", cmd)
    if not m:
        return None
    args = re.findall(r"[^\s,\[\]\"']+", m.group(1))
    if "-e" in args or "--editable" in args:
        return None if {"--no-deps", "--no-build-isolation"} <= set(args) else f"editable install that can download: {cmd}"
    if "--require-hashes" not in args:
        return f"not hash-verified (--require-hashes missing): {cmd}"
    # The file after each -r (in a Python list it may follow a `str(app /` prefix).
    reqs = [next((t for t in args[i + 1:i + 4] if re.search(r"requirements|\.(lock|txt|in)\b", t)), args[i + 1])
            for i, a in enumerate(args[:-1]) if a == "-r"]
    if not reqs:
        return f"--require-hashes without a lock file: {cmd}"
    for r in reqs:
        if not r.rstrip(")").endswith(".lock"):
            return f"installs from {r}, not a hash-pinned .lock: {cmd}"
    return None


# Every place that runs `pip install`: CI, the container build, the native
# installers, the updater, the developer Makefile and the CI install driver.
INSTALL_SOURCES = (
    [os.path.relpath(p, ROOT) for p in WORKFLOWS]
    + ["Dockerfile", "Makefile", "install.sh", "INSTALL_Zscaler_Made_Easy.bat", "UPDATE_Zscaler_Made_Easy.bat",
       "app_update.py", os.path.join("tools", "verify_native_install.py")]
)


@pytest.mark.parametrize("source", INSTALL_SOURCES)
def test_every_pip_install_is_hash_verified(source):
    """SLSA v1.0 Build L3 (pinned inputs) · Scorecard Pinned-Dependencies · SSDF PW.4.1 · CWE-494: every pip install verifies hashes."""
    # Arrange
    text = _read(source)
    if source == "app_update.py":
        # The updater passes the lock as a variable; resolve it to its file.
        assert 'lock = os.path.join(app_dir, "requirements.lock")' in text, "the updater's lock moved; keep this test pointed at it"
        text = text.replace('"-r", lock]', '"-r", "requirements.lock"]')
    lines = list(_shell_lines(text))
    if source.endswith(".py"):
        # Python code runs pip as an argument list; prose mentioning pip is not a command.
        lines = [l for l in lines if re.search(r"[\"']pip[\"'],\s*[\"']install[\"']", l)]
        assert lines, "no pip command found; keep this test pointed at it"
    # Act
    problems = [p for p in map(_pip_install_violation, lines) if p]
    # Assert
    assert problems == []


@pytest.mark.parametrize("cmd, ok", [
    ("pip install pip-audit==2.10.1", False),                                  # exact pin, but its dependencies float
    ("python -m pip install pip==26.2.1 uv==0.12.22", False),
    ("pip install --quiet uv", False),
    ("pip install -r requirements.lock", False),                               # lock without hash enforcement
    ("pip install --require-hashes -r requirements.txt", False),               # hashes demanded of an unhashed file
    ("pip install --require-hashes", False),
    ("pip install -e .", False),                                               # editable install may fetch build deps
    ("pip install --require-hashes --no-deps -r requirements-ci.lock", True),
    ("python -m pip install --quiet --require-hashes --no-deps -r \"%INSTALL_DIR%\\requirements.lock\"", True),
    ("pip install --quiet --no-deps --no-build-isolation -e .", True),
])
def test_the_hash_rule_rejects_unhashed_installs(cmd, ok):
    """SSDF PW.4.1 · CWE-494: the rule above refuses exact-pin-only, lock-without-hashes and editable-with-fetch installs."""
    assert (_pip_install_violation(cmd) is None) is ok


def test_ci_tool_locks_are_complete_hash_pinned_and_keep_the_app_pins():
    """SLSA v1.0 Build L3 · Scorecard Pinned-Dependencies · SSDF PO.3.2: the tools CI runs are hash-locked like the app."""
    # Arrange
    app, ci, pip_lock = _pins("requirements.lock"), _pins("requirements-ci.lock"), _pins("requirements-pip.lock")
    wanted = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", _read("requirements-ci.txt"), re.M))
    # Act
    unhashed = [b.splitlines()[0] for name in ("requirements-ci.lock", "requirements-pip.lock")
                for b in _lock_blocks(name) if "--hash=sha256:" not in b]
    clash = {n: (app[n], ci[n]) for n in set(app) & set(ci) if app[n] != ci[n]}
    # Assert
    assert unhashed == []
    assert clash == {}, "installed with --no-deps after requirements.lock, a different version would replace the app's pin"
    assert set(wanted) == {"uv", "pip-audit", "cyclonedx-bom", "pyinstaller"} and all(ci[n] == v for n, v in wanted.items())
    assert list(pip_lock) == ["pip"] and ci.get("pip") == pip_lock["pip"], "one pip version everywhere"


# Advisories against a CI tool's pinned version (deterministic floor table;
# CI's pip-audit of requirements-ci.lock is the live source).
TOOL_FLOORS = {
    "uv": ("0.13.4", "GHSA-hq85-5cpj-mr62: trusted a root whose intermediates' keys leaked (TLS MITM)"),
}


@pytest.mark.parametrize("tool", sorted(TOOL_FLOORS))
def test_ci_tools_are_not_on_a_version_with_a_known_advisory(tool):
    """Scorecard Vulnerabilities · SSDF RV.1.1 · CWE-1395: no CI tool stays on a version with a known advisory."""
    from packaging.version import Version
    floor, why = TOOL_FLOORS[tool]
    assert Version(_pins("requirements-ci.lock")[tool]) >= Version(floor), why


# Advisories against an app dependency (deterministic floor table; CI's
# pip-audit of every lock is the live source). Each floor holds in every lock
# that pins the package, in the declared minimum (requirements.txt and
# pyproject.toml, so a re-lock cannot fall back) and in the committed SBOM.
APP_FLOORS = {
    "msgpack": ("1.2.3", "CVE-2026-114613 / GHSA-j586-36cw-2gc2: fixed in 1.2.3"),
}
LOCKS = ("requirements.lock", "requirements-dev.lock", "requirements-ci.lock", "requirements-pip.lock")


@pytest.mark.parametrize("lock", LOCKS)
@pytest.mark.parametrize("pkg", sorted(APP_FLOORS))
def test_no_lock_pins_a_dependency_version_with_a_known_advisory(pkg, lock):
    """Scorecard Vulnerabilities · SSDF RV.1.1 · CWE-1395 · A06:2021: no lock pins a version below the advisory's fix."""
    from packaging.version import Version
    floor, why = APP_FLOORS[pkg]
    pinned = _pins(lock).get(pkg)
    assert pinned is None or Version(pinned) >= Version(floor), (lock, pinned, why)


@pytest.mark.parametrize("source", ["requirements.txt", "pyproject.toml"])
@pytest.mark.parametrize("pkg", sorted(APP_FLOORS))
def test_declared_minimum_excludes_the_vulnerable_versions(pkg, source):
    """Scorecard Vulnerabilities · SSDF PW.4.4 · CWE-1395: the declared minimum is the fixed version, so a re-lock cannot pick a vulnerable one."""
    from packaging.version import Version
    floor, why = APP_FLOORS[pkg]
    mins = re.findall(rf"""^\s*["']?{re.escape(pkg)}\s*>=\s*([0-9][^\s"',;#]*)""", _read(source), re.M)
    assert mins and all(Version(m) >= Version(floor) for m in mins), (source, mins, why)


@pytest.mark.parametrize("pkg", sorted(APP_FLOORS))
def test_sbom_lists_the_locked_version(pkg):
    """SSDF PS.3.2 · Scorecard SBOM · CWE-1395: docs/sbom.cdx.json and THIRD_PARTY_NOTICES.md name the version requirements.lock pins."""
    import json
    pinned = _pins("requirements.lock")[pkg]
    sbom = json.loads(_read("docs", "sbom.cdx.json"))
    versions = {c.get("version") for c in sbom.get("components", []) if c.get("name") == pkg}
    assert versions == {pinned}, (versions, pinned)
    assert re.search(rf"^\| {re.escape(pkg)} \| {re.escape(pinned)} \|", _read("THIRD_PARTY_NOTICES.md"), re.M)


def test_ci_audits_every_lock_with_pip_disabled():
    """Scorecard Vulnerabilities · SSDF RV.1.1 · CWE-1395: every lock is audited, and the audit itself runs no unpinned pip."""
    # Arrange
    wf = _workflow(os.path.join(ROOT, ".github", "workflows", "tests.yml"))

    def audited(job):
        text = "\n".join(s.get("run", "") for s in wf["jobs"][job]["steps"])
        loops = re.findall(r"for l in ([^;\n]+); do\n((?:(?!\bdone\b)[\s\S])*)\bdone", text)
        loop = [(names, re.search(r"pip-audit -r \"\$l\"([^\n]*)", body)) for names, body in loops]
        loop = [(names, m.group(1)) for names, m in loop if m]
        files = {f for names, _ in loop for f in names.split()}
        flags = [f for _, f in loop] + re.findall(r"pip-audit -r [^\s$\"]+([^\n]*)", text)
        return files, flags

    # Act
    linux, linux_flags = audited("supply-chain")
    windows, windows_flags = audited("windows-lock")
    # Assert
    assert {"requirements.lock", "requirements-dev.lock", "requirements-ci.lock", "requirements-pip.lock"} <= linux
    assert {"requirements.lock", "requirements-dev.lock", "requirements-ci.lock"} <= windows, "Windows-only pins"
    for flags in linux_flags + windows_flags:
        assert "--disable-pip" in flags and "--strict" in flags, flags


# ── GitHub Actions: least privilege, no injection, no token at rest ────

# The only write grants any workflow needs, and the job that needs each.
WRITE_GRANTS = {("apply-patch.yml", "apply", "contents"), ("upstream_check.yml", "upstream", "issues"),
                # The standalone builds: a Sigstore certificate and the stored provenance per build,
                # and the GitHub Release on a version tag (release-standalone.yml).
                ("release-standalone.yml", "build", "id-token"), ("release-standalone.yml", "build", "attestations"),
                ("release-standalone.yml", "release", "contents")}


@pytest.mark.parametrize("path", WORKFLOWS, ids=os.path.basename)
def test_workflow_token_permissions_are_least_privilege(path):
    """Scorecard Token-Permissions · SLSA v1.0 Build L2 · SSDF PO.5.1 · CWE-250: read-only by default, writes only on the job that needs them."""
    # Arrange
    name, wf = os.path.basename(path), _workflow(path)
    top = wf.get("permissions")
    # Act
    jobs = {jid: (job.get("permissions") or {}) for jid, job in wf["jobs"].items()}
    writes = {(name, jid, scope) for jid, perms in jobs.items() if isinstance(perms, dict)
              for scope, level in perms.items() if level == "write"}
    # Assert
    assert isinstance(top, dict), f"{name}: no top-level permissions block (the repository default applies)"
    assert all(v in ("read", "none") for v in top.values()), f"{name}: write granted to every job: {top}"
    assert all(isinstance(p, dict) for p in jobs.values()), f"{name}: a job uses a permissions shorthand (read-all/write-all)"
    assert writes <= WRITE_GRANTS, writes - WRITE_GRANTS


def _expression_in_script(step: dict):
    """A `${{ }}` expression spliced into code text (a run: script or
    github-script's script:), where its value would be parsed as code."""
    code = [step.get("run") or ""]
    if str(step.get("uses", "")).startswith("actions/github-script@"):
        code.append(str((step.get("with") or {}).get("script") or ""))
    return any("${{" in c for c in code)


@pytest.mark.parametrize("wf_name, job, step", list(_steps()), ids=_step_id)
def test_no_expression_is_spliced_into_a_script(wf_name, job, step):
    """ASVS V5.3.8 · CWE-78 · CWE-94 · Scorecard Dangerous-Workflow: values reach scripts through env:, never by template expansion."""
    assert not _expression_in_script(step), f"{wf_name}/{job}: {step.get('name') or step.get('uses')}"


@pytest.mark.parametrize("step, bad", [
    ({"run": "echo ${{ github.event.pull_request.title }}"}, True),
    ({"uses": "actions/github-script@" + "f" * 40, "with": {"script": "const x = '${{ steps.a.outputs.b }}'"}}, True),
    ({"run": "echo \"$TITLE\"", "env": {"TITLE": "${{ github.event.pull_request.title }}"}}, False),
    ({"uses": "actions/github-script@" + "f" * 40, "env": {"RC": "${{ steps.a.outputs.rc }}"}, "with": {"script": "process.env.RC"}}, False),
])
def test_the_injection_rule_tells_spliced_from_env_values(step, bad):
    """CWE-94 · Scorecard Dangerous-Workflow: the rule flags expressions in code and allows them in env:."""
    assert _expression_in_script(step) is bad


# Jobs that push with the checkout's token (and upload no artifact).
PUSHING_JOBS = {("apply-patch.yml", "apply")}


@pytest.mark.parametrize("wf_name, job, step", [s for s in _steps() if str(s[2].get("uses", "")).startswith("actions/checkout@")],
                         ids=_step_id)
def test_checkout_does_not_leave_the_token_in_git_config(wf_name, job, step):
    """SSDF PO.5.1 · CWE-522 · Scorecard Token-Permissions: GITHUB_TOKEN is not persisted where later steps and artifacts can read it."""
    persisted = (step.get("with") or {}).get("persist-credentials", True)
    assert persisted is False or (wf_name, job) in PUSHING_JOBS, f"{wf_name}/{job}: set persist-credentials: false"


@pytest.mark.parametrize("path", WORKFLOWS, ids=os.path.basename)
def test_untrusted_triggers_get_no_secrets_and_no_privileged_trigger(path):
    """Scorecard Dangerous-Workflow · SLSA v1.0 Build L2 · CWE-829: no pull_request_target/workflow_run, no secrets on PR runs."""
    wf, text = _workflow(path), open(path, encoding="utf-8").read()
    triggers = wf["on"] if isinstance(wf["on"], (dict, list)) else [wf["on"]]
    assert not {"pull_request_target", "workflow_run"} & set(triggers)
    if "pull_request" in triggers:
        assert "secrets." not in text


def _exact(version) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", str(version)))


@pytest.mark.parametrize("wf_name, job, step", [s for s in _steps() if str(s[2].get("uses", "")).startswith("actions/setup-node@")],
                         ids=_step_id)
def test_node_is_pinned_to_an_exact_release(wf_name, job, step):
    """SLSA v1.0 Build L3 · Scorecard Pinned-Dependencies · SSDF PW.4.1: CI's Node is an exact release, not a moving major line."""
    assert _exact((step.get("with") or {}).get("node-version")), f"{wf_name}/{job}"


@pytest.mark.parametrize("version, ok", [("22", False), ("22.x", False), ("lts/*", False), ("22.22", False), ("22.22.2", True)])
def test_the_exact_version_rule(version, ok):
    """SSDF PW.4.1: "22", "22.x", "lts/*" and "22.22" float; only major.minor.patch is exact."""
    assert _exact(version) is ok


# ── Container build context: nothing local reaches the image ───────────

def _docker_excluded(path: str, patterns) -> bool:
    """Docker's .dockerignore rule: patterns are relative to the context
    root (no implicit **/), `*` and `?` stay within one path segment, `**`
    spans any number of them, a match on a parent folder excludes what is
    inside it, `!` re-includes, and the last matching pattern wins."""
    def rx(p):
        out, i = "", 0
        while i < len(p):
            if p.startswith("**", i):
                out += ".*"
                i += 2
                if p.startswith("/", i):
                    out, i = out[:-2] + "(?:.*/)?", i + 1
                continue
            c = p[i]
            out += "[^/]*" if c == "*" else "[^/]" if c == "?" else c if c in "[]" else re.escape(c)
            i += 1
        return re.compile(out + r"\Z")

    parts = path.split("/")
    candidates = ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]
    excluded = False
    for raw in patterns:
        neg = raw.startswith("!")
        pat = os.path.normpath(raw[1:] if neg else raw).replace(os.sep, "/").lstrip("/")
        if any(rx(pat).match(c) for c in candidates):
            excluded = not neg
    return excluded


def _patterns(name: str):
    return [l.strip() for l in _read(name).splitlines() if l.strip() and not l.strip().startswith("#")]


# Git-ignored, but deliberately part of the build: the organisation's root
# certificates (Dockerfile, certs/README.md).
BUILD_INPUTS = {"certs/*.crt", "certs/*.pem", "certs/*.cer"}


def _sample(pattern: str) -> str:
    """A concrete file name that the .gitignore pattern ignores."""
    p = pattern.rstrip("/") + ("/x" if pattern.endswith("/") else "")
    return re.sub(r"\[([^\]]+)\]", lambda m: m.group(1)[0], p).replace("*", "x")


# A `!` line re-includes a file git keeps (agent-workspace/output/README.md):
# it names no ignored file, so it is not a pattern to keep out of the image.
@pytest.mark.parametrize("pattern", [p for p in _patterns(".gitignore") if p not in BUILD_INPUTS and not p.startswith("!")])
def test_every_git_ignored_file_stays_out_of_the_image(pattern):
    """ASVS V14.1.1 · ASVS V8.3.4 · CWE-538 · SSDF PS.1.1: local state git ignores is not baked into the image by COPY . ."""
    # Arrange
    sample = _sample(pattern)
    assert fnmatch.fnmatch(sample, pattern.rstrip("/")) or pattern.endswith("/"), (pattern, sample)
    # Act / Assert
    assert _docker_excluded(sample, _patterns(".dockerignore")), f"{sample} ({pattern} in .gitignore) would be copied into the image"


@pytest.mark.parametrize("name, excluded", [
    ("tenant_profiles.json.last-good", True),            # self_heal's copy of the profile store
    ("deployments.json.last-good", True),
    ("proposals.json.corrupt-20261026T120000Z", True),
    ("user_packs/x.json.last-good", True),
    ("change_requests.json", True),
    (".change_requests.ab12.tmp", True),
    (".workspace_notes.ab12.tmp", True),
    ("posture_settings.json", True),
    ("self_heal.json", True),
    (".selfheal-ab12.tmp", True),
    ("tenant_profiles.json", True),
    ("local_settings.env", True),
    ("store_keys.json", True),                            # the store encryption key (Linux / container default)
    (".store_keys.json.ab12.tmp", True),
    ("store_encryption_migration.json", True),
    ("store-encryption-backup/0000-tenant_profiles.json", True),   # the migration's plaintext safety copy
    ("dlp_api_server.py", False),                         # the app itself must still be built
    ("requirements.lock", False),
    ("static/index.html", False),
    ("certs/README.md", False),
    ("certs/corp-root.crt", False),                       # TLS inspection root goes into the build on purpose
])
def test_the_build_context_keeps_the_app_and_drops_local_data(name, excluded):
    """ASVS V14.1.1 · CWE-538 · SSDF PS.1.1: the image gets the app and the build's certificates, never local data."""
    assert _docker_excluded(name, _patterns(".dockerignore")) is excluded


@pytest.mark.parametrize("name", ["store_keys.json", "store_encryption_migration.json", "store-encryption-backup/", ".store_crypto.lock"])
def test_the_store_key_and_migration_files_are_ignored_by_git_and_docker(name):
    """ASVS V6.4.1 · ASVS V14.1.1 · CWE-321 · CWE-538 · WSTG-CONF-04: the store key, the migration journal and its plaintext backup are never committed or copied into the image."""
    # Arrange
    sample = _sample(name)
    # Act
    in_git = any(fnmatch.fnmatch(sample, p.rstrip("/")) or (p.endswith("/") and sample.startswith(p)) for p in _patterns(".gitignore"))
    # Assert
    assert in_git, f"{name} is not in .gitignore"
    assert _docker_excluded(sample, _patterns(".dockerignore")), f"{name} would be copied into the image"


def test_the_dockerignore_matcher_follows_docker_semantics():
    """SSDF PW.7.2: the helper above matches Docker's rules (root-anchored, ** spans folders, ! re-includes, last match wins)."""
    assert _docker_excluded("a.log", ["*.log"]) and not _docker_excluded("sub/a.log", ["*.log"])
    assert _docker_excluded("sub/deep/a.log", ["**/*.log"]) and _docker_excluded("a.log", ["**/*.log"])
    assert _docker_excluded("digests/x/y.json", ["digests/"])
    assert not _docker_excluded("keep.log", ["*.log", "!keep.log"])


# ── The updater's cross-check vouches only for the upstream repository ─

def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class _Api:
    """The GitHub REST API, faked: answers every commit lookup with `sha`
    and records the URLs asked for."""

    def __init__(self, sha):
        self.sha, self.urls = sha, []

    def __call__(self, url, headers=None, timeout=None):
        self.urls.append(url)
        api = self

        class R:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return {"sha": api.sha}
        return R()


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    monkeypatch.delenv("DLP_CHECK_GITHUB_REPO", raising=False)
    monkeypatch.setenv("DLP_CHECK_GITHUB_TOKEN", "fake-test-token")
    repo = tmp_path / "app"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    return repo


@pytest.mark.parametrize("origin", [
    "https://github.com/someone-else/DLP-Check.git",       # a fork
    "https://github.com/berserkerjay/DLP-Check-mirror",    # a look-alike name
    "git@github.com:someone-else/DLP-Check.git",
])
def test_update_cross_check_refuses_to_vouch_for_a_fork(checkout, monkeypatch, origin):
    """ASVS V10.3.2 · CWE-345 · SLSA v1.0 Source (verified provenance) · SSDF PS.2.1: a fork's own API never marks its pull verified."""
    # Arrange
    import app_update as au
    import requests
    _git(checkout, "remote", "add", "origin", origin)
    api = _Api("a" * 40)
    monkeypatch.setattr(requests, "get", api)
    # Act
    v = au.verify_against_github_api(str(checkout), "main", "a" * 40)
    # Assert
    assert v["checked"] is False and "not the upstream repository" in v["reason"]
    assert api.urls == [], "the fork's API is not even asked"
    assert "fake-test-token" not in str(v)


@pytest.mark.parametrize("origin, setting", [
    ("https://github.com/berserkerjay/DLP-Check.git", None),
    ("https://github.com/BerserkerJay/dlp-check", None),          # GitHub names are case-insensitive
    ("https://github.com/acme-it/DLP-Check.git", "acme-it/DLP-Check"),   # the operator names the repository they trust
])
def test_update_cross_check_runs_for_the_upstream_repository(checkout, monkeypatch, origin, setting):
    """ASVS V10.3.2 · CWE-345 · SSDF PS.2.1: the upstream (or the one DLP_CHECK_GITHUB_REPO names) is still cross-checked."""
    # Arrange
    import app_update as au
    import requests
    _git(checkout, "remote", "add", "origin", origin)
    if setting:
        monkeypatch.setenv("DLP_CHECK_GITHUB_REPO", setting)
    api = _Api("a" * 40)
    monkeypatch.setattr(requests, "get", api)
    # Act
    v = au.verify_against_github_api(str(checkout), "main", "a" * 40)
    # Assert
    assert v["checked"] is True and v["match"] is True and len(api.urls) == 1
    assert api.urls[0].startswith("https://api.github.com/repos/")
