"""Static analysis (SAST) of the app's Python, offline, in every test run.

bandit (hash-pinned in requirements-dev.lock) runs over the repository with
pyproject.toml's [tool.bandit] configuration, exactly as `make sast` does,
and the run fails on any finding of medium severity or higher. A finding is
fixed at the root, or, when bandit misreads the code, suppressed on its own
line as `# nosec <id> # <why>`; every such suppression must be on the
reviewed list below, and must still silence a live finding. CodeQL
(.github/workflows/codeql.yml) adds Python and JavaScript data-flow queries
in CI; its workflow's shape is pinned here too.
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tokenize
from collections import Counter

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The gate, the same flags as the Makefile's `sast` target.
GATE = ["-c", "pyproject.toml", "-r", ".", "--severity-level", "medium", "--confidence-level", "low"]
EXCLUDED = ["./tests/", "./.venv/", "./venv/", "./build/", "./dist/", "./node_modules/"]

# The reviewed suppressions: (file, bandit check) -> how many. Each one is a
# false positive explained on its line; adding one means adding it here, in
# the same review. docs/qa/findings/w7-sast.json records the triage.
REVIEWED_SUPPRESSIONS = {
    # The container healthcheck opens a fixed http(s)://127.0.0.1 ping URL; no scheme comes from input.
    ("docker_healthcheck.py", "B310"): 1,
    # An address compared to word a message, or a family probe: nothing binds.
    ("dlp_api_server.py", "B104"): 1,
    ("workload_path.py", "B104"): 1,
    ("tools/smoke_standalone.py", "B104"): 1,
    # XML parsed only after _refuse_dtd refused any DOCTYPE or ENTITY, size-capped.
    ("vendor_migrate.py", "B314"): 2,
    ("tools/quality_score.py", "B314"): 1,
    # The smoke test's own http://127.0.0.1 requests, and zipfile (not tarfile) extraction.
    ("tools/smoke_standalone.py", "B310"): 1,
    ("tools/smoke_standalone.py", "B202"): 1,
}

SUPPRESSION = re.compile(r"#\s*nosec\s+(B\d{3}(?:\s*,\s*B\d{3})*)\s+#\s+(\S.{14,})$")


def _bandit_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("bandit") is not None


def _need_bandit():
    if not _bandit_available():
        if os.environ.get("CI"):
            pytest.fail("bandit is not installed: CI installs it from requirements-dev.lock")
        pytest.skip("bandit is not installed here (make dev installs it from requirements-dev.lock)")


def _bandit(args, cwd=ROOT):
    cp = subprocess.run([sys.executable, "-m", "bandit", *args, "-f", "json", "-q"], cwd=cwd,
                        capture_output=True, text=True, timeout=300)
    try:
        report = json.loads(cp.stdout)
    except ValueError:
        raise AssertionError(f"bandit gave no report (exit {cp.returncode}): {cp.stderr[-2000:]}")
    return cp.returncode, report


def _show(results):
    return "\n".join(f"{r['filename']}:{r['line_number']} {r['test_id']} {r['issue_severity']}/{r['issue_confidence']} "
                     f"{r['issue_text']}" for r in results)


@pytest.fixture(scope="module")
def repo_scan():
    _need_bandit()
    return _bandit(GATE)


def _python_files():
    for base, dirs, files in os.walk(ROOT):
        rel = os.path.relpath(base, ROOT).replace(os.sep, "/")
        prefix = "./" if rel == "." else f"./{rel}/"
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d != "__pycache__" and f"{prefix}{d}/" not in EXCLUDED)
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.relpath(os.path.join(base, name), ROOT).replace(os.sep, "/")


def _suppressions():
    """{(file, check): count} and the malformed ones, from the comments only."""
    found, bad = Counter(), []
    for rel in _python_files():
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            src = f.read()
        if "nosec" not in src:
            continue
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type != tokenize.COMMENT or not re.search(r"\bnosec\b", tok.string, re.I):
                continue
            m = SUPPRESSION.search(tok.string)
            if not m:
                bad.append(f"{rel}:{tok.start[0]}: {tok.string}")
                continue
            for check in re.findall(r"B\d{3}", m.group(1)):
                found[(rel, check)] += 1
    return found, bad


def test_bandit_finds_nothing_at_medium_severity_or_higher(repo_scan):
    """ASVS V10.1.1 · Scorecard SAST · SSDF PW.7.2: bandit finds nothing of medium severity or higher in the app's Python."""
    # Arrange
    code, report = repo_scan
    scanned = set(report["metrics"]) - {"_totals"}
    # Act
    findings = report["results"]
    # Assert
    assert not report["errors"], f"bandit could not read: {report['errors']}"
    assert {"./dlp_api_server.py", "./security.py", "./tools/quality_score.py"} <= scanned, "the scan missed the app"
    assert not any(p.startswith("./tests/") for p in scanned), "the tests are out of scope (fakes, asserts)"
    assert not findings and code == 0, "new SAST findings; fix them at the root, or add a reviewed\n" \
        "`# nosec <id> # <why>` and list it in REVIEWED_SUPPRESSIONS:\n" + _show(findings)


def test_every_suppression_names_its_check_says_why_and_is_reviewed(repo_scan):
    """SSDF PW.7.2 · Scorecard SAST: every # nosec names its bandit check, gives a reason and is on the reviewed list."""
    # Arrange
    _, report = repo_scan
    # Act
    found, bad = _suppressions()
    # Assert
    assert not bad, "a # nosec without a check id and a reason (`# nosec B104 # why`):\n" + "\n".join(bad)
    assert report["metrics"]["_totals"]["nosec"] == 0, "a bare # nosec silences every check on its line"
    assert dict(found) == REVIEWED_SUPPRESSIONS, (
        f"unreviewed: {sorted(set(found.items()) - set(REVIEWED_SUPPRESSIONS.items()))}; "
        f"gone: {sorted(set(REVIEWED_SUPPRESSIONS.items()) - set(found.items()))}")


def test_every_reviewed_suppression_still_silences_a_live_finding():
    """SSDF PW.7.2: no reviewed suppression is stale; without them bandit reports exactly those findings."""
    _need_bandit()
    # Arrange
    files = sorted({f for f, _ in REVIEWED_SUPPRESSIONS})
    # Act
    _, report = _bandit(["-c", "pyproject.toml", "--ignore-nosec", "--severity-level", "medium",
                         "--confidence-level", "low", *files])
    live = Counter((r["filename"].replace("\\", "/").removeprefix("./"), r["test_id"]) for r in report["results"])
    # Assert
    assert dict(live) == REVIEWED_SUPPRESSIONS, _show(report["results"])


@pytest.mark.parametrize("comment, ok", [
    ("# nosec B104 # compared to word a message; binds nothing", True),
    ("# noqa: S310  # nosec B310 # only http://127.0.0.1 URLs this tool builds", True),
    ("# nosec B314, B405 # DOCTYPE refused before the parse", True),
    ("# nosec", False),                       # every check, no reason
    ("# nosec B104", False),                  # no reason
    ("# nosec B104: binds nothing", False),   # bandit would read each word of the reason as a check name
    ("# nosec # because", False),             # no check id
])
def test_the_suppression_rule(comment, ok):
    """SSDF PW.7.2: the reviewed-suppression format is enforced (check id, then `# reason`)."""
    assert bool(SUPPRESSION.search(comment)) is ok


def test_the_configuration_runs_every_check_and_excludes_only_tests_and_environments():
    """SSDF PW.7.2 · Scorecard SAST: no blanket skips; the Makefile and this test run the same gate."""
    import tomllib
    # Arrange
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        conf = tomllib.load(f)["tool"]["bandit"]
    with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as f:
        make = f.read()
    # Act
    target = re.search(r"^sast:\n\t(.+)$", make, re.M)
    # Assert
    assert set(conf) == {"exclude_dirs"}, f"only exclusions are configured (no skips, no tests allow-list): {conf}"
    assert conf["exclude_dirs"] == EXCLUDED
    assert target and target.group(1).split()[1:] == ["-m", "bandit", *GATE, "-q"], target and target.group(1)


@pytest.mark.parametrize("snippet, check", [
    ("import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n", "B602"),
    ("import yaml\n\ndef load(text):\n    return yaml.load(text)\n", "B506"),
    ("import hashlib\n\ndef key(data):\n    return hashlib.md5(data).hexdigest()\n", "B324"),
    ("import xml.etree.ElementTree as ET\n\ndef parse(data):\n    return ET.fromstring(data)\n", "B314"),
    ("import os\n\ndef cmd(name):\n    os.system('ls ' + name)\n", "B605"),
])
def test_the_gate_fails_on_a_new_finding(tmp_path, snippet, check):
    """SSDF PW.7.2 · CWE-78 · CWE-327 · CWE-611: the gate fails on a new medium+ finding, and tests/ stays out of scope."""
    _need_bandit()
    # Arrange
    (tmp_path / "app_module.py").write_text(snippet, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_fake.py").write_text(snippet, encoding="utf-8")
    args = list(GATE)
    args[1] = os.path.join(ROOT, "pyproject.toml")
    # Act
    code, report = _bandit(args, cwd=str(tmp_path))
    # Assert
    assert code == 1
    assert {(r["filename"], r["test_id"]) for r in report["results"]} == {("./app_module.py", check)}


@pytest.mark.parametrize("call", [
    lambda: __import__("guidance")._slug("https://help.zscaler.com/zia/about-dlp"),
    lambda: __import__("pack_library").pack_slug("名前"),
], ids=["guidance-url-key", "pack-id"])
def test_an_id_hash_is_not_a_security_use_and_works_on_fips_openssl(monkeypatch, call):
    """ASVS V6.2.5 · CWE-328: an id or cache-key SHA-1 is marked usedforsecurity=False, so a FIPS-mode OpenSSL allows it."""
    # Arrange
    expected = call()
    real = hashlib.sha1

    def fips_sha1(*args, **kwargs):
        if kwargs.get("usedforsecurity", True):
            raise ValueError("[digital envelope routines] unsupported")   # what FIPS-mode OpenSSL answers
        return real(*args, **kwargs)

    monkeypatch.setattr(hashlib, "sha1", fips_sha1)
    # Act
    got = call()
    # Assert
    assert got == expected and got


# ── CodeQL in CI ─────────────────────────────────────────────────────

def _codeql():
    with open(os.path.join(ROOT, ".github", "workflows", "codeql.yml"), encoding="utf-8") as f:
        wf = yaml.safe_load(f)
    if True in wf:   # YAML 1.1 reads the bare key `on` as True
        wf["on"] = wf.pop(True)
    return wf


def test_codeql_scans_python_and_javascript_on_pull_requests_and_weekly():
    """Scorecard SAST · SSDF PW.7.2: CodeQL (security-extended) runs on pull requests to dev, qa and main, and weekly, on Linux."""
    # Arrange
    wf = _codeql()
    on, jobs = wf["on"], wf["jobs"]
    # Act
    steps = [s for job in jobs.values() for s in job["steps"]]
    init = next(s for s in steps if str(s.get("uses", "")).startswith("github/codeql-action/init@"))
    analyze = next(s for s in steps if str(s.get("uses", "")).startswith("github/codeql-action/analyze@"))
    langs = {x.strip() for x in init["with"]["languages"].split(",")}
    cron = on["schedule"][0]["cron"].split()
    # Assert
    assert set(on["pull_request"]["branches"]) == {"dev", "qa", "main"}
    assert len(cron) == 5 and cron[2] == "*" and cron[4] not in ("*", "*/1"), "weekly: one day of the week"
    assert langs == {"python", "javascript-typescript"}
    assert init["with"]["queries"] == "security-extended"
    assert init["uses"].split("@")[1] == analyze["uses"].split("@")[1], "init and analyze from the same release"
    assert all(job["runs-on"] == "ubuntu-latest" for job in jobs.values())


def test_codeql_is_least_privilege_cancels_stale_runs_and_is_time_boxed():
    """Scorecard Token-Permissions · Scorecard SAST · SSDF PO.5.1: read-only at the top, security-events: write only on the analysis job."""
    # Arrange
    wf = _codeql()
    # Act
    jobs = wf["jobs"]
    writers = {jid for jid, job in jobs.items() if (job.get("permissions") or {}).get("security-events") == "write"}
    # Assert
    assert wf["permissions"] == {"contents": "read"}
    assert writers == {"analyze"} and len(jobs) == 1
    assert set(jobs["analyze"]["permissions"]) == {"contents", "actions", "security-events"}
    assert jobs["analyze"]["permissions"]["actions"] == "read"
    assert wf["concurrency"]["cancel-in-progress"] is True
    assert 0 < jobs["analyze"]["timeout-minutes"] <= 30
