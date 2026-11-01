"""Client Connector one-time passwords for one device (zcc_otp, /api/zcc/otp).

A sensitive read guarded like a write: ZCC in scope, a person allowed to
change the tenant, write mode on, the named assessor, "SHOW OTP <device>" typed, a rate
limit; the values only in the answer (no-store), the audit entry naming
who, when and which device, never a value. A fake SDK stands in for
zcc.devices.list_devices and zcc.secrets.get_otp (zscaler-sdk-python
1.11.3); nothing touches the network."""
from __future__ import annotations

import os
import re

import pytest
from fastapi.testclient import TestClient

import zcc_otp as zo
from test_secret_canaries import _leaks

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OTPS = {"otp": "CANARYotp7Qx9", "uninstallOtp": "CANARYuninst42", "ziaDisableOtp": "CANARYzia88x", "exitOtp": "CANARYexit731", "logoutOtp": ""}
CANARIES = [v for v in OTPS.values() if v]
DEVICES = [{"udid": "UDID-AAA-1", "machineHostname": "LT-0042", "user": "jdoe@acme.example"},
           {"udid": "UDID-BBB-2", "machineHostname": "LT-0099", "user": "jdoe@acme.example"},
           {"udid": "UDID-CCC-3", "machineHostname": "LT-0099", "user": "jdoe@acme.example"}]


class Devices:
    def __init__(self, f):
        self.f = f

    def list_devices(self, query_params=None):
        self.f.calls.append(("devices", dict(query_params or {})))
        if self.f.refuse:
            return None, None, "HTTP 403 Forbidden"
        return [d for d in DEVICES if d["user"] == (query_params or {}).get("username")], None, None


class Secrets:
    def __init__(self, f):
        self.f = f

    def get_otp(self, query_params=None):
        self.f.calls.append(("otp", dict(query_params or {})))
        return dict(OTPS), None, None


class FakeSdk:
    def __init__(self):
        self.calls, self.refuse = [], False
        self.zcc = type("Z", (), {})()
        self.zcc.devices, self.zcc.secrets = Devices(self), Secrets(self)


@pytest.fixture
def api(monkeypatch, tmp_path):
    for k in [k for k in os.environ if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(zo, "LIMITER", zo.Limiter())
    import dlp_api_server as srv
    sdk = FakeSdk()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or sdk)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)   # an OTP needs write mode (owner decision, wave 9)
    return TestClient(srv.app), sdk, built, tmp_path


BODY = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "not-a-real-secret", "scopes": ["zcc"], "channels": {},
        "from_page": True, "assessor": "Jane Doe", "user": "jdoe@acme.example", "device": "LT-0042", "confirm_text": "SHOW OTP LT-0042"}


def audit_lines(tmp_path):
    p = tmp_path / "audit.log"
    return [ln for ln in p.read_text().splitlines() if '"zcc_otp"' in ln] if p.exists() else []


# ── The happy path, and what is kept ─────────────────────────────────
def test_an_authorised_admin_sees_the_otps_once_and_the_audit_names_the_device_not_the_value(api):
    """ASVS V8.3.4 · V7.1.1 · CWE-532 · CWE-524: the OTPs come back once with no-store; the audit entry names who, the device and the kinds, never a value."""
    c, sdk, built, tmp = api
    r = c.post("/api/zcc/otp", json=BODY)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [(o["key"], o["value"]) for o in d["otps"]] == [("otp", OTPS["otp"]), ("uninstallOtp", OTPS["uninstallOtp"]),
                                                          ("ziaDisableOtp", OTPS["ziaDisableOtp"]), ("exitOtp", OTPS["exitOtp"])]
    assert d["device"] == {"hostname": "LT-0042", "ref": zo.device_ref("UDID-AAA-1")} and d["show_seconds"] == 60
    assert r.headers["cache-control"] == "no-store" and r.headers["pragma"] == "no-cache"
    assert ("otp", {"udid": "UDID-AAA-1"}) in sdk.calls and built == [1]
    (line,) = audit_lines(tmp)
    assert '"result":"shown"' in line and '"by":"Jane Doe"' in line and '"device":"LT-0042"' in line and '"uninstallOtp"' in line
    assert not _leaks((tmp / "audit.log").read_text(), CANARIES), "the audit log holds no OTP (nor the api entry)"


def test_a_device_is_found_by_its_udid_too(api):
    """ASVS V5.1.3 · CWE-20: the device may be named by its UDID; the phrase then names the UDID."""
    c, sdk, _b, _t = api
    r = c.post("/api/zcc/otp", json=dict(BODY, device="udid-bbb-2", confirm_text="SHOW OTP udid-bbb-2"))
    assert r.status_code == 200 and r.json()["device"]["hostname"] == "LT-0099"


@pytest.mark.parametrize("device,status,words", [("LT-0099", 409, "UDID instead"), ("LT-9999", 404, "No enrolled device")])
def test_an_ambiguous_or_unknown_device_shows_nothing_and_is_audited(api, device, status, words):
    """ASVS V4.1.3 · CWE-706 · CWE-778: two devices with one name, or none, show nothing; the refusal is audited."""
    c, sdk, _b, tmp = api
    r = c.post("/api/zcc/otp", json=dict(BODY, device=device, confirm_text=f"SHOW OTP {device}"))
    assert r.status_code == status and words in r.json()["detail"]
    assert not any(k == "otp" for k, _q in sdk.calls) and '"result":"refused"' in audit_lines(tmp)[0]


def test_a_refused_device_read_is_said_in_words(api):
    """ASVS V7.4.1 · CWE-209: a refused device list is said in words (the permission), and no OTP is asked for."""
    c, sdk, _b, tmp = api
    sdk.refuse = True
    r = c.post("/api/zcc/otp", json=BODY)
    assert r.status_code == 502 and "HTTP 403" in r.json()["detail"] and '"result":"failed"' in audit_lines(tmp)[0]


# ── The gates, each before sign-in ───────────────────────────────────
@pytest.mark.parametrize("change,status,words", [
    ({"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}}, 400, "not in scope"),
    ({"assessor": ""}, 400, "assessor's name"),
    ({"assessor": "Zscaler Made Easy"}, 400, "not the tool"),
    ({"confirm_text": ""}, 400, "Type SHOW OTP LT-0042"),
    ({"confirm_text": "SHOW OTP LT-0043"}, 400, "Type SHOW OTP LT-0042"),
    ({"user": ""}, 400, "enrolled user name"),
    ({"device": "a\nb", "confirm_text": "SHOW OTP a\nb"}, 400, "control characters"),
    ({"auth_method": "legacy", "username": "admin@acme.example", "password": "x", "api_key": "abcdefghijkl", "client_id": "", "client_secret": ""},
     400, "classic ZIA API"),
])
def test_every_gate_refuses_before_sign_in(api, change, status, words):
    """ASVS V4.1.3 · V4.2.2 · CWE-862 · CWE-863 · WSTG-ATHZ-02: out of scope, no assessor, a wrong phrase or a bad device is refused before any sign-in or read."""
    c, sdk, built, _t = api
    r = c.post("/api/zcc/otp", json=dict(BODY, **change))
    assert r.status_code == status and words in r.json()["detail"], r.text
    assert built == [] and sdk.calls == []


def test_a_person_who_may_not_change_the_tenant_is_refused(api, monkeypatch):
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: an OTP needs the same permission as a write; a reader gets 403 before sign-in."""
    import security
    c, sdk, built, _t = api
    monkeypatch.setattr(security, "may_write", lambda: False)
    r = c.post("/api/zcc/otp", json=BODY)
    assert r.status_code == 403 and "may not change the tenant" in r.json()["detail"] and built == []


def test_write_mode_off_refuses_the_otp_before_sign_in_and_audits_nothing_as_shown(api, monkeypatch):
    """ASVS V4.1.3 · V1.4.1 · CWE-862 · WSTG-ATHZ-02: with a writer, the assessor and the phrase but write mode off, nothing is signed in to or read and nothing is audited as shown; with write mode on it works."""
    import dlp_api_server as srv
    c, sdk, built, tmp = api
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    r = c.post("/api/zcc/otp", json=BODY)
    assert r.status_code == 403 and "write mode" in r.json()["detail"] and "ENABLE_WRITE_ACTIONS" in r.json()["detail"], r.text
    assert built == [] and sdk.calls == []
    assert not any('"result":"shown"' in ln for ln in audit_lines(tmp))
    assert not _leaks(r.text, CANARIES)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    r = c.post("/api/zcc/otp", json=BODY)
    assert r.status_code == 200 and built == [1] and '"result":"shown"' in audit_lines(tmp)[-1]


def test_the_scope_rule_is_checked_first(api, monkeypatch):
    """ASVS V4.1.3 · CWE-863: a request out of scope is refused with the scope reason even from a person who may not write."""
    import security
    c, _sdk, built, _t = api
    monkeypatch.setattr(security, "may_write", lambda: False)
    r = c.post("/api/zcc/otp", json=dict(BODY, scopes=["dlp"]))
    assert r.status_code == 400 and "not in scope" in r.json()["detail"] and built == []


# ── The rate limit ───────────────────────────────────────────────────
def test_the_rate_limit_answers_429_with_retry_after_and_is_audited(api):
    """ASVS V11.1.4 · CWE-799 · CWE-307 · WSTG-BUSL-05: the sixth request in ten minutes is refused (429, Retry-After) before sign-in, and audited."""
    c, _sdk, built, tmp = api
    for _ in range(zo.RATE_PER_ACTOR):
        assert c.post("/api/zcc/otp", json=BODY).status_code == 200
    n = len(built)
    r = c.post("/api/zcc/otp", json=BODY)
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0 and len(built) == n
    assert '"result":"rate_limited"' in audit_lines(tmp)[-1]


def test_the_limiter_counts_per_actor_and_overall_and_frees_up_with_time():
    """ASVS V11.1.4 · CWE-799: per actor and overall windows; an old request falls out of the window."""
    now = [0.0]
    lim = zo.Limiter(per_actor=2, window=60, total=3, window_total=600, clock=lambda: now[0])
    assert [lim.take("a"), lim.take("a")] == [0, 0] and lim.take("a") == 60
    assert lim.take("b") == 0 and lim.take("c") == 600, "the overall window is full"
    now[0] = 61
    assert lim.take("a") == 539, "a's own window freed, the overall one not yet"
    now[0] = 601
    assert lim.take("a") == 0


# ── The SDK answer and the page ──────────────────────────────────────
def test_fetch_reads_the_sdk_model_and_skips_empty_fields():
    """ASVS V5.1.3 · CWE-1287: the OtpResponse model (snake-case attributes) and a dict both read; an empty field is left out; none at all is a 404."""
    from zscaler.zcc.models.secrets_otp import OtpResponse

    class Sec:
        def __init__(self, obj):
            self.obj = obj

        def get_otp(self, query_params=None):
            return self.obj, None, None
    sdk = type("S", (), {})()
    sdk.zcc = type("Z", (), {})()
    sdk.zcc.secrets = Sec(OtpResponse({"uninstallOtp": "CANARYu1", "exitOtp": "", "revertOtp": "CANARYr2"}))
    assert [o["key"] for o in zo.fetch(sdk, "U")] == ["uninstallOtp", "revertOtp"]
    sdk.zcc.secrets = Sec({})
    with pytest.raises(zo.OtpError) as e:
        zo.fetch(sdk, "U")
    assert e.value.status == 404


def test_the_page_shows_them_once_hides_them_after_60_seconds_and_stores_nothing():
    """ASVS V8.2.2 · CWE-922 · CWE-524 · WCAG 2.2 SC 2.2.1 · SC 4.1.3: the fleet page section has labelled inputs and a live status; the OTPs are cleared after 60 s or on Hide now and never stored."""
    html = open(os.path.join(ROOT, "static", "report_fleet.html"), encoding="utf-8").read()
    js = open(os.path.join(ROOT, "static", "zcc_fleet.js"), encoding="utf-8").read()
    assert 'id="zfOtp"' in html and 'id="zfOtpStatus" role="status" aria-live="polite"' in html and 'id="zfOtpHide"' not in html
    assert "/api/zcc/otp" in js and "SHOW OTP" in js and "otpHide(" in js and "Hide now" in js and "* 1000" in js
    otp_js = js[js.index("One-time passwords for one device"):]
    assert not re.search(r"localStorage|sessionStorage|indexedDB|console\.", otp_js)
    assert "$('zfOtpPhrase').value = ''" in otp_js, "the typed confirmation is cleared after each request"
