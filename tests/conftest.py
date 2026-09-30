import os
import sys

# Make the project root importable when pytest is run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# The UI token guards every API call from a browser; the test suite talks to
# the app directly, so it is off here. tests/test_ui_auth.py switches it on.
os.environ.setdefault("ZSCALER_UI_AUTH", "0")


import pytest


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
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(tmp_path_factory.mktemp("zia_rate") / "zia_rate.json"))
    zia_rate.reset()


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
