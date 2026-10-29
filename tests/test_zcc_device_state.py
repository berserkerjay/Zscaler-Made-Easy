"""Client Connector device `state` arrives as text, a number or nothing (the
SDK model types it as Any; the API returns both). Check 6.3 and the device
fleet check read every form and never crash on one."""
import pytest

import zcc_evaluation as ze
from dlp_assessment_full_auto import R, _zcc_state, c_6_3


class FakeCl:
    customer_id = ""

    def __init__(self, devices, code=200):
        self.devices, self.code = devices, code

    def get(self, path, params=None):
        return (self.devices, self.code) if path == "/zcc/devices" else ({"error": "not found"}, 404)


@pytest.mark.parametrize("raw, want", [
    (None, ""), ("", ""), ("Removed", "removed"), ("  ORPHANED ", "orphaned"), ("registered", "registered"),
    (1, "registered"), (3, "removal_pending"), (4, "unregistered"), (5, "removed"), (6, "quarantined"),
    ("5", "removed"), (5.0, "removed"), (0, "unknown"), (2, "unknown"), (99, "unknown"), (-1, "unknown"),
    (True, "unknown"), ([5], "unknown"), ({"state": 5}, "unknown"),
])
def test_state_normaliser_reads_text_numbers_and_none(raw, want):
    """ASVS V5.1.4 · CWE-754 · CWE-20: every device state form (text, SDK registration code, None, junk) maps to known text or "unknown"."""
    assert _zcc_state(raw) == want


@pytest.mark.parametrize("state", [5, 3, 1, 0, 99, None, "inactive", True, 2.5])
def test_check_6_3_never_raises_on_any_state_type(state):
    """ASVS V5.1.4 · CWE-754: check 6.3 returns a result, never an exception, for a numeric, missing or unusual state."""
    r = c_6_3(FakeCl([{"id": 1, "state": state}]))
    assert r.status in (R.PASS, R.WARN)


def test_check_6_3_counts_numeric_removed_as_orphaned():
    """ASVS V5.1.4 · CWE-754: state 5 (removed in the SDK's registration codes) counts as orphaned, like the text "removed"."""
    r = c_6_3(FakeCl([{"id": 1, "state": 5}, {"id": 2, "state": "REMOVED"}, {"id": 3, "state": 1}]))
    assert r.status == R.WARN and r.detail.startswith("2 orphaned device(s).")


def test_check_6_3_reports_unknown_states_apart_without_failing():
    """ASVS V5.1.4 · CWE-754: an unrecognised numeric state is reported as unknown, not as orphaned and not as a crash."""
    r = c_6_3(FakeCl([{"id": 1, "state": 42}, {"id": 2, "state": 1}]))
    assert r.status == R.PASS and "1 device(s) report a state this app does not recognise" in r.detail


def test_check_6_3_state_zero_is_not_hidden_by_status():
    """ASVS V5.1.4 · CWE-754: a numeric state of 0 is read as a state (unknown), and status is used only when state is absent."""
    r = c_6_3(FakeCl([{"id": 1, "state": 0, "status": "removed"}, {"id": 2, "status": "removed"}]))
    assert r.status == R.WARN and r.detail.startswith("1 orphaned device(s).") and "1 device(s) report" in r.detail


def test_check_6_3_unreadable_devices_pass_without_error():
    """ASVS V5.1.4 · CWE-754: an unreadable device list (HTTP 403) does not raise."""
    assert c_6_3(FakeCl({"error": "forbidden"}, 403)).status == R.PASS


def test_device_fleet_excludes_numeric_removed_devices():
    """ASVS V5.1.4 · CWE-754: the device fleet check leaves out a device whose numeric state is removed (5) and keeps state 1."""
    devs = [{"id": 1, "registrationState": "Registered", "state": 5, "strictEnforcement": 0},
            {"id": 2, "state": 1, "strictEnforcement": 1, "antiTamperingStatus": 1, "zdpEnabled": 1, "tunnelVersion": "2.0"}]
    r = ze.z_device_fleet(FakeCl(devs))
    assert r.status == R.PASS, r.detail


@pytest.mark.parametrize("state", [5, 99, None, True, "removal pending"])
def test_device_fleet_never_raises_on_any_state_type(state):
    """ASVS V5.1.4 · CWE-754: the device fleet check returns a result for every state type."""
    assert ze.z_device_fleet(FakeCl([{"id": 1, "state": state, "registrationState": state}])).status in (R.PASS, R.WARN, R.FAIL, R.INFO)
