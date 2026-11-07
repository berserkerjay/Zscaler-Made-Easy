"""Client Connector tamper-protection passwords, revealed on demand
(zcc_passwords, /api/zcc/passwords).

Off by default; an administrator only on a team server; the typed phrase;
one user and one operating system per request; the values only in the
answer (Cache-Control: no-store), never stored, logged, audited, exported
or put in a snapshot or backup. A fake SDK stands in for
zcc.secrets.get_passwords (zscaler-sdk-python 1.11.3); nothing touches the
network."""
from __future__ import annotations

import json
import os
import re

import pytest
from conftest import read_store_text
from fastapi.testclient import TestClient

import config_backup
import zcc_passwords as zp
from test_secret_canaries import _leaks
from test_team_server import ORIGIN, _login, _refill, team_on, world  # noqa: F401 — fixtures

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORDS = {"uninstallPass": "CANARYuninst7Qx9", "logoutPass": "CANARYlogout42", "exitPass": "CANARYexit5531",
             "ziaDisablePass": "CANARYzia88x", "zpaDisablePass": ""}
CANARIES = [v for v in PASSWORDS.values() if v]
BODY = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "not-a-real-secret", "scopes": ["zcc"], "channels": {},
        "from_page": True, "assessor": "Jane Doe", "user": "jdoe@acme.example", "os": "windows",
        "confirm_text": "SHOW PASSWORDS jdoe@acme.example windows"}


class Secrets:
    def __init__(self, f):
        self.f = f

    def get_passwords(self, query_params=None):
        self.f.calls.append(dict(query_params or {}))
        if self.f.refuse:
            return None, None, "HTTP 403 Forbidden"
        return dict(PASSWORDS), None, None


class FakeSdk:
    def __init__(self):
        self.calls, self.refuse = [], False
        self.zcc = type("Z", (), {})()
        self.zcc.secrets = Secrets(self)


@pytest.fixture
def api(monkeypatch, tmp_path):
    for k in [k for k in os.environ if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(zp, "LIMITER", zp.zcc_otp.Limiter(per_actor=5, window=600.0, total=30, window_total=3600.0))
    import dlp_api_server as srv
    sdk = FakeSdk()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or sdk)
    return TestClient(srv.app), sdk, built, tmp_path


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setenv(zp.ENV_SETTING, "1")


def audit_text(tmp_path):
    p = tmp_path / "audit.log"
    return read_store_text(p) if p.exists() else ""


# ── Rule 1: off by default ───────────────────────────────────────────
def test_off_by_default_nothing_is_read(api):
    """ASVS V8.3.4 · CWE-1188 · WSTG-CONF-11: without the setting the route refuses (403) before any sign-in or read."""
    c, sdk, built, _ = api
    r = c.post("/api/zcc/passwords", json=BODY)
    assert r.status_code == 403 and zp.ENV_SETTING in r.json()["detail"]
    assert not built and not sdk.calls
    assert zp.enabled() is False


@pytest.mark.parametrize("val", ["", "0", "no", "off", "maybe"])
def test_only_an_explicit_yes_turns_it_on(monkeypatch, val):
    """ASVS V14.1.1 · CWE-1188: the setting is on only for 1, true, yes or on."""
    monkeypatch.setenv(zp.ENV_SETTING, val)
    assert zp.enabled() is False
    monkeypatch.setenv(zp.ENV_SETTING, "1")
    assert zp.enabled() is True


# ── The happy path, header, and gates ───────────────────────────────
def test_reveal_returns_once_with_no_store(api, on):
    """ASVS V8.1.1 · CWE-524 · WSTG-CONF-11: the passwords are in the answer with Cache-Control: no-store; the SDK is asked for one user and one OS."""
    c, sdk, _, _ = api
    r = c.post("/api/zcc/passwords", json=BODY)
    assert r.status_code == 200, r.text
    assert "no-store" in r.headers["cache-control"] and r.headers["pragma"] == "no-cache"
    d = r.json()
    assert {p["value"] for p in d["passwords"]} == set(CANARIES)
    assert d["show_seconds"] == 60 and d["user"] == "jdoe@acme.example" and d["os"] == "windows"
    assert sdk.calls == [{"username": "jdoe@acme.example", "os_type": "windows"}]


def test_wrong_or_missing_phrase_is_refused_before_any_read(api, on):
    """ASVS V4.1.3 · CWE-863 · WSTG-BUSL-01: a wrong confirmation phrase (other user, other OS, empty) reads nothing."""
    c, sdk, built, _ = api
    for bad in ("", "SHOW OTP jdoe@acme.example", "SHOW PASSWORDS jdoe@acme.example macos", "SHOW PASSWORDS other@acme.example windows"):
        r = c.post("/api/zcc/passwords", json=dict(BODY, confirm_text=bad))
        assert r.status_code == 400 and "to confirm" in r.json()["detail"], bad
    assert not built and not sdk.calls


def test_one_user_and_one_os_at_a_time(api, on):
    """ASVS V4.1.3 · CWE-20 · WSTG-INPV-01: no OS, an unknown OS, a list of users or a list of systems is refused; nothing is read."""
    c, sdk, built, _ = api
    for patch in ({"os": ""}, {"os": "beos"}, {"os": "windows,macos"}, {"os": ["windows"]}, {"user": ""}, {"user": ["a", "b"]}):
        r = c.post("/api/zcc/passwords", json=dict(BODY, **patch))
        assert r.status_code in (400, 422), (patch, r.status_code)
    assert not built and not sdk.calls


def test_assessor_and_scope_are_required(api, on):
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: no assessor is refused; Client Connector out of scope is refused before sign-in."""
    c, sdk, built, _ = api
    assert c.post("/api/zcc/passwords", json=dict(BODY, assessor="")).status_code == 400
    r = c.post("/api/zcc/passwords", json=dict(BODY, scopes=["dlp"]))
    assert r.status_code == 400
    assert not built and not sdk.calls


def test_rate_limit(api, on):
    """ASVS V11.1.4 · CWE-307: the sixth request in the window is 429 with Retry-After."""
    c, sdk, _, _ = api
    for _i in range(5):
        assert c.post("/api/zcc/passwords", json=BODY).status_code == 200
    r = c.post("/api/zcc/passwords", json=BODY)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert len(sdk.calls) == 5


def test_a_refusal_by_the_tenant_is_words_without_values(api, on):
    """ASVS V7.4.1 · CWE-209: a tenant refusal is a plain sentence naming the permission, with no value."""
    c, sdk, _, _ = api
    sdk.refuse = True
    r = c.post("/api/zcc/passwords", json=BODY)
    assert r.status_code == 502 and "403" in r.json()["detail"]


# ── Never stored, logged, audited, exported ───────────────────────────
def _all_text(tmp_path):
    out = []
    for root, _d, files in os.walk(tmp_path):
        for f in files:
            p = os.path.join(root, f)
            try:
                out.append(read_store_text(p))
            except Exception:  # noqa: BLE001
                out.append(open(p, "rb").read().decode("utf-8", "replace"))
    return "\n".join(out)


def test_audit_names_who_when_which_user_never_a_value(api, on, caplog):
    """ASVS V7.1.1 · CWE-532 · CWE-312: the audit entry records the actor, the assessor, the user, the OS and the kinds, and no password appears in it, on disk or in the log."""
    c, _, _, tmp = api
    caplog.set_level("DEBUG")
    assert c.post("/api/zcc/passwords", json=BODY).status_code == 200
    a = audit_text(tmp)
    line = next(ln for ln in a.splitlines() if '"zcc_passwords"' in ln)
    e = json.loads(line)
    assert e["event"] == "zcc_passwords" and e["result"] == "shown" and e["by"] == "Jane Doe"
    assert e["user"] == "jdoe@acme.example" and e["os"] == "windows" and "uninstallPass" in e["kinds"] and e["actor"] and e["at"]
    assert not _leaks(a, CANARIES) and not _leaks(_all_text(tmp), CANARIES)
    assert not _leaks(caplog.text, CANARIES)


def test_refusals_are_audited_without_values(api, on):
    """ASVS V7.1.1 · CWE-532: a refused read (tenant said 403) is audited as failed, with no value."""
    c, sdk, _, tmp = api
    sdk.refuse = True
    c.post("/api/zcc/passwords", json=BODY)
    a = audit_text(tmp)
    assert '"failed"' in a and not _leaks(a, CANARIES)


def test_backup_restore_and_snapshots_never_carry_or_read_them(api, on, monkeypatch):
    """ASVS V8.3.4 · CWE-312 · CWE-200: after a reveal, a config backup document, its export and a snapshot hold no password and never call get_passwords."""
    c, sdk, _, tmp = api
    assert c.post("/api/zcc/passwords", json=BODY).status_code == 200
    calls_after_reveal = list(sdk.calls)
    doc = config_backup.build_doc({"zia.rule_labels": [], "zpa.segment_groups": [],
                                   "zcc.trusted_networks": [], "zcc.app_profiles": [{"id": "1", "name": "P", "uninstall_password": "",
                                                                                    "windowsPolicy": {"uninstall_password": ""}}]},
                                  {"tenant_label": "acme (production)", "products": ["zia", "zpa", "zcc"]})
    text = json.dumps(doc)
    assert not _leaks(text, CANARIES)
    # nothing else on disk (profiles, audit, backups, snapshots, jobs) holds a value
    assert not _leaks(_all_text(tmp), CANARIES)
    # the reveal is the only reader of the passwords call
    assert sdk.calls == calls_after_reveal


def test_no_other_module_reads_the_passwords_call():
    """ASVS V8.3.4 · CWE-200: get_passwords is called only from zcc_passwords; backup, restore, snapshots, exports and the profile builder never read it."""
    hits = []
    for f in sorted(os.listdir(ROOT)):
        if f.endswith(".py") and f != "zcc_passwords.py":
            with open(os.path.join(ROOT, f), encoding="utf-8") as fh:
                for n, ln in enumerate(fh, 1):
                    if re.search(r"get_passwords\b", ln) and not ln.lstrip().startswith(("#", '"', "'")):
                        hits.append(f"{f}:{n}")
    assert hits == [] or all(h.startswith("tenant_api_map.py") for h in hits), hits


def test_the_backup_warning_says_never_read_unless_revealed():
    """ASVS V1.14.1 · CWE-1059: the restore preview and the backup page say the passwords are never read unless revealed on demand."""
    import ops_config_restore as ocr
    assert "never read unless revealed on demand" in ocr.ZCC_PROFILE_WORDS and "never read unless revealed on demand" in ocr.ZCC_PASSWORD_WORDS


def test_the_page_masks_and_clears_after_60_seconds():
    """WCAG 2.2 SC 3.3.2 · CWE-200: the page masks the values, has a reveal button, clears after the server's show_seconds, and uses no browser storage for them."""
    js = open(os.path.join(ROOT, "static", "zcc_fleet.js"), encoding="utf-8").read()
    seg = js[js.index("Tamper-protection passwords for one user"):js.index("instLoad();")]
    assert "data-pwreveal" in seg and "pwHide" in seg and "setTimeout" in seg and "show_seconds" in seg
    assert "localStorage" not in seg and "sessionStorage" not in seg
    html = open(os.path.join(ROOT, "static", "report_fleet.html"), encoding="utf-8").read()
    assert 'id="zfPwShow"' in html and 'id="zfPwOut"' in html and "ZSCALER_ZCC_TAMPER_REVEAL" in html


# ── Team server: administrators only ─────────────────────────────────
def test_team_rule_is_admin():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-03: the route's team rule is the administrator rule."""
    import team_routes
    assert team_routes.ROUTE_RULES["POST /api/zcc/passwords"] == team_routes.ADMIN


def test_team_non_admin_is_refused_and_admin_is_not(api, world, on):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-03: on a team server a viewer, an operator and an approver get 403 and nothing is read; an administrator is let through."""
    _c, sdk, built, tmp = api
    import dlp_api_server as srv
    for who in ("vic", "olga", "april"):
        c = _login(who)
        _refill()
        r = c.post("/api/zcc/passwords", json=BODY, headers=ORIGIN)
        assert r.status_code == 403, (who, r.status_code)
    assert not built and not sdk.calls
    c = _login("root")
    _refill()
    r = c.post("/api/zcc/passwords", json=dict(BODY, profile_id=world["a"], vanity_domain="acme.example", client_id="cid-Acme", cloud="zscalerten"), headers=ORIGIN)
    assert r.status_code == 200, r.text
    assert "no-store" in r.headers["cache-control"]
    assert sdk.calls == [{"username": "jdoe@acme.example", "os_type": "windows"}]
    assert not _leaks(audit_text(tmp), CANARIES)
