import os
import sys

# Make the project root importable when pytest is run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# The app's own settings never leak in from the shell that runs the tests
# (a developer's ZSCALER_UI_AUTH=1 or ZSCALER_PORT=8443 must not change a
# result): every one is cleared, and a test that needs one sets it.
APP_ENV_PREFIXES = ("ZSCALER_", "DLP_CHECK_", "DLPCHECK_")
APP_ENV_NAMES = ("ENABLE_WRITE_ACTIONS", "ASSESS_CHECK_TIMEOUT", "ASSESS_JOURNEY_TIMEOUT", "ASSESS_WORKERS")


def scrub_app_env(environ):
    """Remove every app setting from `environ` (a dict or os.environ); the
    names removed, sorted. Test switches (CHROME_BIN, DLP_RUN_BROWSER_ACCEPTANCE...) stay."""
    gone = sorted(k for k in list(environ) if k.startswith(APP_ENV_PREFIXES) or k in APP_ENV_NAMES)
    for k in gone:
        del environ[k]
    return gone


scrub_app_env(os.environ)

# The UI token guards every API call from a browser; the test suite talks to
# the app directly, so it is off here. tests/test_ui_auth.py switches it on.
os.environ["ZSCALER_UI_AUTH"] = "0"
# Encrypted stores (store_crypto.py) are ON in the suite, as they ship: a
# test that reads a store file opens it through read_store_text /
# read_store_json / audit_events below. Only a test whose subject is the
# plain format (the opt-out, unseal-all, old-format readers) sets
# DLP_CHECK_STORE_ENCRYPTION=0 itself. DLP_TEST_STORE_ENCRYPTION=0 runs the
# whole suite with the opt-out instead (the plain path's own CI run).
PLAIN_STORE_RUN = os.environ.get("DLP_TEST_STORE_ENCRYPTION", "").strip().lower() in ("0", "off", "false", "no")
if PLAIN_STORE_RUN:
    os.environ["DLP_CHECK_STORE_ENCRYPTION"] = "0"
# Self-healing's startup run and timer (self_heal.py) stay off in tests: a
# test runs the checks itself, on its own temporary files.
os.environ["DLP_CHECK_SELF_HEAL_MINUTES"] = "0"
# Scheduled configuration backups (config_backup.py) stay off too: a test runs them itself.
os.environ["DLP_CHECK_BACKUP_SCHEDULE_MINUTES"] = "0"

# Every file the app writes (its stores, audit log, caches) lives in a data
# folder, as /data does in the container (Dockerfile), never in the repository
# or the user's ~/.cache, which other runs share. Each test gets its own (the
# autouse fixture below); this session folder is the floor underneath, so a
# background thread that outlives its test still never writes next to the code.
STORE_ENV = {
    "DLPCHECK_PROPOSALS_FILE": "proposals.json",
    "DLPCHECK_CHANGE_QUEUE_FILE": "change_requests.json",
    "DLP_CHECK_PROFILES": "tenant_profiles.json",
    "DLP_CHECK_DEPLOYMENTS": "deployments.json",
    "DLP_CHECK_ZIA_RATE_STATE": "zia_rate.json",
    "DLP_CHECK_AUDIT": "audit.log",
    "DLP_CHECK_UI_TOKEN_DIR": "",
    "DLP_CHECK_DIGESTS": "digests",
    "DLP_CHECK_GUIDANCE_STATE": "guidance_state.json",
    "DLP_CHECK_CHECKS_CONFIG": "checks_config.json",
    "DLP_CHECK_SAAS_MATRIX": "saas_apps.local.json",
    "DLP_CHECK_POSTURE_SETTINGS": "posture_settings.json",
    "DLP_CHECK_USER_PACKS": "user_packs",
    "DLP_CHECK_FINGERPRINT_KEY": "tenant_fingerprint.key",
    "XDG_CACHE_HOME": "cache",      # Beacon, SSL coverage, update and best-practice caches (Linux)
    "LOCALAPPDATA": "cache",        # the same caches on Windows
}


def point_stores_at(folder):
    """{setting: path} for every app store inside `folder`."""
    folder = str(folder)
    return {k: os.path.join(folder, v) if v else folder for k, v in STORE_ENV.items()}


import tempfile  # noqa: E402

SESSION_DATA = tempfile.mkdtemp(prefix="dlp-check-tests-")
os.environ.update(point_stores_at(SESSION_DATA))


import pytest  # noqa: E402


# ── Reading a store the way the app does (encrypted stores are on) ──────
def read_store_text(path) -> str:
    """A store file's content, opened: a sealed file (one line) or a file
    sealed line by line (the audit log) through store_crypto.open_text; a
    plain file as it is. StoreLocked when a sealed line does not open."""
    import store_crypto
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    return "".join(store_crypto.open_text(ln.rstrip("\n")) + ("\n" if ln.endswith("\n") else "")
                   for ln in raw.splitlines(keepends=True))


def read_any_text(path) -> str:
    """read_store_text, or the raw text (undecodable bytes replaced) for a
    file that is not text or a sealed file that does not open: for scans of
    every file in a folder (secret canaries), which must see opened content."""
    try:
        return read_store_text(path)
    except (UnicodeDecodeError, ValueError, RuntimeError):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()


def read_store_json(path):
    """json.load for a store file, opened first (read_store_text)."""
    import json
    return json.loads(read_store_text(path))


def audit_lines(path=None):
    """The audit log's lines, each opened (it is sealed line by line)."""
    import audit
    try:
        text = read_store_text(path or audit.path())
    except FileNotFoundError:
        return []
    return [ln for ln in text.splitlines() if ln.strip()]


def audit_events(path=None):
    """The audit log's events (dicts), opened."""
    import json
    return [json.loads(ln) for ln in audit_lines(path)]


def is_store_bookkeeping(name) -> bool:
    """A file store encryption keeps beside the data (the key file, the
    migration journal and its backup folder), not a store of its own."""
    import store_crypto
    return os.path.basename(str(name).rstrip("/\\")) in ("store_keys.json", store_crypto.MIGRATION_FILE, store_crypto.BACKUP_DIR)


# Every test process is hermetic: a forgotten SDK/request mock must never
# authenticate to a real tenant or contact any non-local service. Dependency
# installation happens before pytest, outside this guard. Local fixture servers
# remain usable for genuine browser acceptance.
def _loopback_host(host):
    import ipaddress
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    if host in (None, "", "localhost"):
        return True
    try:
        return ipaddress.ip_address(str(host).split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def pytest_sessionstart(session):
    import socket
    from _pytest.monkeypatch import MonkeyPatch
    guard = MonkeyPatch()
    original_dns = socket.getaddrinfo
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def dns(host, *args, **kwargs):
        if not _loopback_host(host):
            raise RuntimeError("Offline test guard: non-loopback DNS is forbidden; add a fixture/mock")
        return original_dns(host, *args, **kwargs)

    def connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6) and not _loopback_host(address[0]):
            raise RuntimeError("Offline test guard: non-loopback connection is forbidden; add a fixture/mock")
        return original_connect(sock, address)

    def connect_ex(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6) and not _loopback_host(address[0]):
            raise RuntimeError("Offline test guard: non-loopback connection is forbidden; add a fixture/mock")
        return original_connect_ex(sock, address)

    guard.setattr(socket, "getaddrinfo", dns)
    guard.setattr(socket.socket, "connect", connect)
    guard.setattr(socket.socket, "connect_ex", connect_ex)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        guard.delenv(key, raising=False)
    session._offline_guard = guard


def pytest_sessionfinish(session, exitstatus):
    # Keep the guard until process exit: a late background thread must not
    # acquire network access merely because the last assertion finished.
    pass


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch, tmp_path_factory):
    """The shared execution path backs off between retries of a transient
    refusal; tests never wait for that."""
    import pack_ops
    monkeypatch.setattr(pack_ops, "_sleep", lambda s: None)
    import zia_rate
    for bucket in zia_rate.DEFAULTS:   # ZIA's rate limits are off in tests (test_run_control turns them on with a fake clock)
        monkeypatch.setenv(f"DLP_CHECK_ZIA_LIMIT_{bucket.upper()}", "off")
    # Turned off to run fast, not as a setting under test: the forecast does not
    # flag it as pacing looser than ZIA's (test_rate_forecast checks that itself).
    monkeypatch.setattr(zia_rate, "_covers", lambda bucket: True)
    monkeypatch.setattr(zia_rate, "_sleep", lambda s: None)
    monkeypatch.delenv("DLP_CHECK_RATE_TONE", raising=False)   # the verdict's tone as shipped, whatever the shell says
    # This test's own data folder for every store (STORE_ENV): never the repo's
    # audit.log or proposals.json, never ~/.cache, never another test's files.
    for key, value in point_stores_at(tmp_path_factory.mktemp("data")).items():
        monkeypatch.setenv(key, value)
    zia_rate.reset()
    full = sys.modules.get("dlp_assessment_full_auto")
    if full is not None and hasattr(full, "_reset_tenant_gates"):
        full._reset_tenant_gates()   # one tenant's pacing and 429 hold never carry into the next test


@pytest.fixture(autouse=True)
def _no_real_credential_store(monkeypatch):
    """keyring is a pinned dependency on Windows and macOS, so it is installed
    where the tests run. A test that remembers a profile secret must never
    write it to this machine's real Credential Manager or Keychain: keyring
    is unimportable here, the owner-only file is used, and a test that wants
    the credential store installs its own fake in sys.modules."""
    monkeypatch.setitem(sys.modules, "keyring", None)


@pytest.fixture(autouse=True)
def _fresh_rate_limit_bucket():
    """The API rate limiter (20 requests/s, burst 60, per client IP) is
    process-wide and every test talks from the same "testclient" address,
    so a long run of quick tests can spend the bucket and hand a later,
    unrelated test a 429. Each test starts with a full bucket; the limiter
    itself is unchanged and still tested where it matters."""
    def _reset():
        try:
            import dlp_api_server as srv
            import security
        except Exception:  # noqa: BLE001
            return
        layer = getattr(srv.app, "middleware_stack", None)
        while layer is not None:
            if isinstance(layer, security.RateLimitMiddleware):
                layer.buckets.clear()
                break
            layer = getattr(layer, "app", None)
    _reset()
    yield


class FakeClock:
    """A clock for the request pacer that moves only when the code under
    test sleeps: a sleep moves it forward to that sleeper's wake-up time
    (never back) at once, so pacing is checked exactly, with no real waits
    and no dependence on how busy the machine is. `wakeups` lists every
    sleeper's wake-up time: the send slots the pacer booked."""

    def __init__(self, start=1_000_000.0):
        import threading
        self.now, self.start, self.wakeups = float(start), float(start), []
        self._lock = threading.Lock()

    def time(self):
        with self._lock:
            return self.now

    def sleep(self, seconds):
        with self._lock:
            target = self.now + max(0.0, float(seconds))
            self.wakeups.append(target)
            self.now = max(self.now, target)


@pytest.fixture
def pacer_clock(monkeypatch):
    """The tenant pacer (dlp_assessment_full_auto) and ZIA's rate state
    (zia_rate) on one FakeClock."""
    import dlp_assessment_full_auto as full
    import zia_rate
    clock = FakeClock()
    for mod in (full, zia_rate):
        monkeypatch.setattr(mod, "_now", clock.time)
        monkeypatch.setattr(mod, "_sleep", clock.sleep)
    zia_rate.reset()
    return clock
