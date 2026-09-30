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
def _no_backoff_sleep(monkeypatch):
    """The shared execution path backs off between retries of a transient
    refusal; tests never wait for that."""
    import pack_ops
    monkeypatch.setattr(pack_ops, "_sleep", lambda s: None)
    monkeypatch.setattr(pack_ops, "_pace_sleep", lambda s: None)   # write pacing (DLP_CHECK_WRITE_GAP)


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
