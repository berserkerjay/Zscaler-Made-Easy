"""Test suite stability (QA T1): every test is hermetic and deterministic.

Each guard here failed before its fix:
  - stores: a test that reached an app store without setting its path wrote
    proposals.json (and its .last-good copy) or audit.log into the
    repository, or read and wrote the user's shared ~/.cache;
  - environment: the shell's ZSCALER_* / DLP_CHECK_* settings changed results
    (ZSCALER_UI_AUTH=1 failed 10 tests, ZSCALER_PORT=8443 two);
  - Beacon status: a poll that read the history just before a run saved it,
    and the running flag just after the run ended, said "finished" with no
    snapshot (tests/test_rules_labels_scope_stop.py failed about 1 run in 13);
  - pacing: the request pacer is driven by an injectable clock, so pacing is
    asserted exactly instead of against the machine's load;
  - browsers: a test's Chrome picks its own free debugging port instead of a
    random guess another browser on the machine may already own.
"""
from __future__ import annotations

import glob
import os
import re

import pytest
from fastapi.testclient import TestClient

import conftest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME_CACHE = os.path.join(os.path.expanduser("~"), ".cache")


def _resolvers():
    """Every place the app decides where a store or cache lives."""
    import audit
    import beacon
    import bp_crawler
    import change_queue
    import continuous_eval
    import deployments
    import guidance
    import pack_library
    import posture_plus
    import proposals
    import saas_matrix
    import self_heal
    import ssl_coverage
    import tenant_fingerprint
    import tenant_profiles
    import workspace_notes
    import zia_rate
    import zscaler_best_practices
    import zscaler_update_check
    return {
        "proposals": proposals.store_path, "proposals last-good copy": lambda: proposals.store_path() + self_heal.LAST_GOOD,
        "change queue": change_queue.store_path, "deployments": deployments.store_path,
        "tenant profiles": tenant_profiles.store_path, "audit log": audit.path, "ZIA rate state": zia_rate.state_path,
        "guidance state": guidance.state_path, "approved checks": guidance.config_path, "SaaS matrix": saas_matrix._local_path,
        "posture settings": posture_plus.settings_path, "self-healing state": self_heal.state_path,
        "workspace notes": workspace_notes.store_path, "digests": continuous_eval.digest_dir,
        "Beacon history": beacon.state_path, "SSL coverage history": ssl_coverage.history_path,
        "update cache": zscaler_update_check._cache_path, "best-practice crawl cache": bp_crawler._cache_path,
        "discovered best practices": zscaler_best_practices._discovered_store_path,
        "user packs": pack_library.user_packs_dir, "fingerprint key": tenant_fingerprint.key_path,
    }


def _inside(path: str, folder: str) -> bool:
    return os.path.realpath(path).startswith(os.path.realpath(folder) + os.sep)


@pytest.mark.parametrize("store", sorted(_resolvers()))
def test_every_app_store_resolves_inside_this_tests_own_data_folder(store):
    """SSDF PW.8.2 · Scorecard CI-Tests · CWE-459: no test writes a store into the repository or the shared ~/.cache."""
    # Arrange: the folder conftest gave this test.
    data = os.path.dirname(os.environ["DLP_CHECK_AUDIT"])
    # Act
    path = _resolvers()[store]()
    # Assert
    assert _inside(path, data), (store, path, data)
    assert not _inside(path, ROOT) and not _inside(path, HOME_CACHE), (store, path)


def test_no_two_tests_share_a_data_folder():
    """SSDF PW.8.2 · CWE-1325: each test's stores start empty, so no result depends on the test that ran before."""
    data = os.path.dirname(os.environ["DLP_CHECK_AUDIT"])
    assert os.listdir(data) == [] or set(os.listdir(data)) <= {"cache"}, os.listdir(data)
    assert not _inside(data, conftest.SESSION_DATA), "a per-test folder, not the session floor"


@pytest.mark.parametrize("store", sorted(_resolvers()))
def test_a_thread_that_outlives_its_test_still_writes_to_the_session_folder(monkeypatch, store):
    """SSDF PW.8.2 · CWE-459: after a test's settings are undone (a job thread still running), stores stay out of the repository."""
    # Arrange: undo every setting this test made, as its teardown does while
    # a background job of the test may still be running.
    monkeypatch.undo()
    # Act
    path = _resolvers()[store]()
    # Assert
    assert _inside(path, conftest.SESSION_DATA), (store, path)
    assert not _inside(path, ROOT) and not _inside(path, HOME_CACHE), (store, path)


@pytest.mark.parametrize("name, removed", [
    ("ZSCALER_UI_AUTH", True), ("ZSCALER_PORT", True), ("ZSCALER_CLIENT_SECRET", True), ("DLP_CHECK_FOUR_EYES", True),
    ("DLPCHECK_PROPOSALS_FILE", True), ("ENABLE_WRITE_ACTIONS", True), ("ASSESS_WORKERS", True),
    ("CHROME_BIN", False), ("DLP_RUN_BROWSER_ACCEPTANCE", False), ("NATIVE_REQUIRE_TERRAFORM", False),
    ("MY_ZSCALER_PORT", False), ("PATH", False), ("", False),
])
def test_the_shells_app_settings_never_reach_a_test(name, removed):
    """SSDF PW.8.2 · CWE-454: an app setting exported in the shell is cleared; test switches and unrelated variables stay."""
    # Arrange
    env = {name: "1", "HOME": "/home/x"}
    # Act
    gone = conftest.scrub_app_env(env)
    # Assert
    assert (name in gone) is removed and (name not in env) is removed
    assert env["HOME"] == "/home/x"


def test_the_running_suite_has_only_its_own_app_settings():
    """SSDF PW.8.2 · CWE-454: the only app settings a test sees are the suite's baseline (and what the test sets itself)."""
    # The Zscaler SDK itself writes ZSCALER_SDK_LOG (and _VERBOSE when logging
    # is on) each time a client is built (zscaler/config/config_setter.py); the
    # app always builds it with logging off, so a later test sees "false".
    baseline = set(conftest.STORE_ENV) | {"ZSCALER_UI_AUTH", "DLP_CHECK_SELF_HEAL_MINUTES", "DLP_CHECK_BACKUP_SCHEDULE_MINUTES", "ZSCALER_SDK_LOG"}
    if conftest.PLAIN_STORE_RUN:
        baseline.add("DLP_CHECK_STORE_ENCRYPTION")   # DLP_TEST_STORE_ENCRYPTION=0: the opt-out's own run
    assert os.environ.get("ZSCALER_SDK_LOG", "false") == "false" and "ZSCALER_SDK_VERBOSE" not in os.environ
    stray = sorted(k for k in os.environ
                   if (k.startswith(conftest.APP_ENV_PREFIXES) or k in conftest.APP_ENV_NAMES) and k not in baseline
                   and not k.startswith("DLP_CHECK_ZIA_LIMIT_"))   # conftest turns ZIA's limits off per test
    assert stray == []
    assert os.environ["ZSCALER_UI_AUTH"] == "0" and os.environ["DLP_CHECK_SELF_HEAL_MINUTES"] == "0"


def test_the_suite_runs_with_encrypted_stores_on_as_shipped():
    """ASVS V6.1.1 · ASVS V14.1.1 · CWE-1188 · SSDF PW.8.2: the suite tests the shipped default (encrypted stores on); no global opt-out hides it."""
    import store_crypto
    if conftest.PLAIN_STORE_RUN:
        pytest.skip("DLP_TEST_STORE_ENCRYPTION=0: the opt-out's own run")
    assert "DLP_CHECK_STORE_ENCRYPTION" not in os.environ and store_crypto.enabled()
    assert store_crypto.seal_text("x").startswith(store_crypto.PREFIX)


# ── Beacon: a run that ends while its status is read ───────────────────────
@pytest.mark.parametrize("route", ["/api/beacon", "/api/beacon/status"])
@pytest.mark.parametrize("before, after, running", [
    (True, False, True),     # the run saves and ends during the read: still running, so the page reads again
    (False, True, True),     # a run starts during the read: running
    (True, True, True),
    (False, False, False),   # nothing running: finished, and the history read is the latest
])
def test_beacon_status_never_reports_a_run_finished_before_its_snapshot_is_read(monkeypatch, route, before, after, running):
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-04: a status read cannot say a run finished while returning the history from before it."""
    import beacon
    import dlp_api_server as srv
    # Arrange: the run's lock as it is before the read; the read itself
    # happens before the run's save, and the run's state changes during it.
    monkeypatch.setitem(srv._BEACON_STATE, "running", False)
    if before:
        assert beacon.RUN_LOCK.acquire(blocking=False)

    def read_then_run_changes(path=None):
        if before and not after:
            beacon.RUN_LOCK.release()     # the run saved (after this read) and ended
        elif after and not before:
            assert beacon.RUN_LOCK.acquire(blocking=False)
        return []
    monkeypatch.setattr(beacon, "load_history", read_then_run_changes)
    try:
        # Act
        r = TestClient(srv.app).get(route)
    finally:
        if beacon.RUN_LOCK.locked():
            beacon.RUN_LOCK.release()
    # Assert
    assert r.status_code == 200, r.text
    assert r.json()["running"] is running, r.json()


# ── The pacer's clock ──────────────────────────────────────────────────────
@pytest.mark.parametrize("seconds, stop_after, slept, finished", [
    (0, None, [], True),                     # nothing to wait: no sleep at all
    (1.2, None, [1.2], True),                # no Stop: one sleep of the whole time
    (1.2, 99, [0.5, 0.5, 0.2], True),        # with a Stop hook: half-second steps that add up exactly
    (1.2, 0, [], False),                     # Stop already pressed: nothing slept, the wait is refused
    (1.2, 2, [0.5, 0.5], False),             # Stop pressed during the wait: it ends there
])
def test_the_pacers_wait_runs_on_an_injected_clock(pacer_clock, seconds, stop_after, slept, finished):
    """SSDF PW.8.2 · CWE-770: the pacer's sleeps go through one clock seam, so tests check pacing exactly and without real waits."""
    import dlp_assessment_full_auto as full
    # Arrange
    calls = [0]

    def stop():
        calls[0] += 1
        return calls[0] > stop_after
    start = pacer_clock.time()
    # Act
    done = full._nap(seconds, None if stop_after is None else stop)
    # Assert
    assert done is finished
    assert [round(w - a, 6) for a, w in zip([start] + pacer_clock.wakeups, pacer_clock.wakeups)] == slept


def test_the_pacer_books_one_tenants_slots_a_gap_apart_on_the_injected_clock(pacer_clock):
    """SSDF PW.8.2 · CWE-770: two pacers of one tenant share its slots: exact gaps, no real sleep."""
    import dlp_assessment_full_auto as full
    # Arrange
    a, b = full._RateLimiter(0.25, key="tenant-x"), full._RateLimiter(0.25, key="tenant-x")
    other = full._RateLimiter(0.25, key="tenant-y")
    # Act
    for lim in (a, b, a, b, other):
        assert lim.wait()
    # Assert: the second tenant's first request is not held by the first's
    assert [round(w - pacer_clock.start, 6) for w in pacer_clock.wakeups] == [0.25, 0.5, 0.75]


# ── Real browsers in tests ─────────────────────────────────────────────────
def _browser_drivers():
    files = sorted(glob.glob(os.path.join(ROOT, "tests", "*.py")) + glob.glob(os.path.join(ROOT, "tests", "js", "*.mjs")))
    out = []
    for f in files:
        if os.path.basename(f) == os.path.basename(__file__):
            continue
        text = open(f, encoding="utf-8").read()
        if "remote-debugging-port" in text:
            out.append((os.path.relpath(f, ROOT), text))
    return out


@pytest.mark.parametrize("name, text", _browser_drivers(), ids=[n for n, _ in _browser_drivers()])
def test_every_test_browser_picks_its_own_free_debugging_port(name, text):
    """SSDF PW.8.2 · CWE-668: a test's Chrome listens on a port the OS chose, on loopback, never a guessed one another browser may own."""
    ports = re.findall(r"remote-debugging-port=([^'\"`,\s\]]+)", text)
    assert ports and set(ports) == {"0"}, (name, ports)
    assert "remote-debugging-address=127.0.0.1" in text, name
    assert not re.search(r"Math\.random\(\)\s*\*\s*\d+", text), (name, "a random port guess")
    assert "DevToolsActivePort" in text, (name, "reads the port Chrome chose")


def test_there_are_browser_drivers_to_check():
    """SSDF PW.8.2: the browser-port guard above is not vacuous."""
    assert len(_browser_drivers()) >= 3
