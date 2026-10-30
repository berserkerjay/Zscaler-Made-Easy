"""Client Connector day-to-day administration (ops_zcc_admin): device
removal, custom bypass apps and the ZPA / ZDX entitlements, on the Bulk
changes engine. Fakes only (tests/admin_fakes.py): no network, state in tmp_path."""
from __future__ import annotations

import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zcc_admin as zc  # noqa: E402
from admin_fakes import CANARY_OTP, ZccClient  # noqa: E402

ZCC = ao.scope_for(["zcc"], {})
NO_ZCC = ao.scope_for(["zpa", "zdx"], {})
ASSESSOR = "Jane Doe"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    ao.load_plugins()
    return tmp_path


def seeded():
    c = ZccClient()
    c.tenant.seed()
    return c


def apply(c, spec, phrase=None):
    p = ao.plan(c, spec, scope=ZCC, tenant_label="acme")
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZCC, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") if phrase is None else phrase)
    return p, r


@pytest.mark.parametrize("spec", [{"type": zc.T_REMOVE, "mode": "remove", "devices": [{"udid": "VMW-1:AAA", "user": "jdoe@acme.com"}]},
                                  {"type": zc.T_BYPASS, "action": "create", "name": "x", "entries": [{"proto": "TCP", "port": "443", "address": "10.0.0.1"}]},
                                  {"type": zc.T_ENT, "service": "zpa", "enable_for_all": False}])
def test_zcc_not_ticked_is_refused_before_anything_is_read(spec):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZCC ticked nothing is read or written, the lookup included."""
    c = seeded()
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(c, spec, scope=NO_ZCC)
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.read_objects(c, zc.FAMILY, NO_ZCC)
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.require_scope(zc.FAMILY, NO_ZCC)
    assert c.tenant.reads == [] and c.tenant.writes == [] and c.executor.sent == []


# ── device removal ─────────────────────────────────────────────────────

def test_lookup_lists_one_users_devices_without_their_one_time_passwords(isolated, caplog):
    """ASVS V8.3.4 · CWE-200 · CWE-532: a device answer's OTPs never reach the lookup, a plan, a result, a record or a log."""
    caplog.set_level(logging.DEBUG)
    c = seeded()
    out = zc.lookup(c, "devices", {"user": "jdoe@acme.com"})
    assert [d["udid"] for d in out["devices"]] == ["VMW-1:AAA", "MAC-2:BBB"] and out["devices"][1]["state"] == "removal pending"
    spec = {"type": zc.T_REMOVE, "mode": "force", "devices": [{"udid": "VMW-1:AAA", "user": "jdoe@acme.com"}]}
    p, r = apply(c, spec)
    rec = ao.record(r, by=ASSESSOR)
    files = "".join((isolated / f).read_text(encoding="utf-8") for f in os.listdir(isolated))
    assert CANARY_OTP not in json.dumps([out, p, r, rec]) + caplog.text + files


def test_remove_always_asks_the_typed_phrase_and_sends_only_the_udid():
    """ASVS V4.1.3 · CWE-841 · CWE-352: a removal names its count and kind in the phrase whatever the count; payload oracle: udids only."""
    c = seeded()
    spec = {"type": zc.T_REMOVE, "mode": "remove", "devices": [{"udid": "VMW-1:AAA", "user": "jdoe@acme.com"}]}
    p = ao.plan(c, spec, scope=ZCC)
    assert p["confirm_phrase"] == "REMOVE 1 DEVICE" and "No Undo" in p["notes"][0]
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZCC, writes_enabled=True, assessor=ASSESSOR, confirm_text="")
    assert r["status"] == "refused" and c.tenant.writes == []
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZCC, writes_enabled=True, assessor=ASSESSOR, confirm_text="remove 1 device")
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1 and r["inverse"] is None
    assert c.tenant.writes == [("remove", "device", {"udids": ["VMW-1:AAA"]})]


def test_force_remove_says_force_and_drops_the_device():
    """ASVS V4.1.3 · CWE-841: force remove has its own phrase (FORCE REMOVE n DEVICES) and its own API call."""
    c = seeded()
    spec = {"type": zc.T_REMOVE, "mode": "force", "devices": [{"udid": "VMW-1:AAA", "user": "jdoe@acme.com"},
                                                              {"udid": "MAC-2:BBB", "user": "jdoe@acme.com"}]}
    p, r = apply(c, spec)
    assert p["confirm_phrase"] == "FORCE REMOVE 2 DEVICES" and r["status"] == "applied"
    assert [w[0] for w in c.tenant.writes] == ["force_remove", "force_remove"] and [d["udid"] for d in c.tenant.devices] == ["VMW-9:ZZZ"]


def test_soft_remove_of_a_pending_device_is_a_noop_and_a_missing_one_is_excluded():
    """ASVS V1.4.1 · CWE-841: a device already Removal Pending is left; one not found for that user is excluded (never another user's)."""
    c = seeded()
    p = ao.plan(c, {"type": zc.T_REMOVE, "mode": "remove", "devices": [{"udid": "MAC-2:BBB", "user": "jdoe@acme.com"},
                                                                       {"udid": "VMW-9:ZZZ", "user": "jdoe@acme.com"}]}, scope=ZCC)
    assert [u["status"] for u in p["items"]] == ["noop", "excluded"] and p["status"] == "nothing_to_do"


def test_a_refused_removal_is_reported_failed():
    """ASVS V7.4.1 · CWE-754: ZCC answering errorMsg is a failure, not a success."""
    c = seeded()
    c.tenant.fail["remove"] = "device is locked"
    _p, r = apply(c, {"type": zc.T_REMOVE, "mode": "remove", "devices": [{"udid": "VMW-1:AAA", "user": "jdoe@acme.com"}]})
    assert r["items"][0]["status"] == "failed" and "device is locked" in r["items"][0]["error"]


@pytest.mark.parametrize("dev", [{"udid": "", "user": "a@b.c"}, {"udid": "x y", "user": "a@b.c"}, {"udid": "A", "user": "a b"},
                                 {"udid": "A" * 300, "user": "a@b.c"}, {"udid": ["A"], "user": "a@b.c"}])
def test_bad_device_ids_are_refused_before_a_read(dev):
    """ASVS V5.1.3 · CWE-20: a device id or user that is not one is refused before anything is read."""
    c = seeded()
    with pytest.raises(ao.OperationError):
        ao.plan(c, {"type": zc.T_REMOVE, "mode": "remove", "devices": [dev]}, scope=ZCC)
    assert c.tenant.reads == []


# ── custom bypass apps ─────────────────────────────────────────────────

def test_create_is_off_by_default_with_the_portal_body_and_undo_deletes_it():
    """ASVS V1.4.1 · CWE-1188 · CWE-841: payload oracle: appName, active false, IPv4 and IPv6 entries apart; read back; Undo deletes it."""
    c = seeded()
    spec = {"type": zc.T_BYPASS, "action": "create", "name": "Zoom media",
            "entries": [{"proto": "udp", "port": "8801-8810", "address": "3.7.35.0/25"}, {"proto": "TCP", "port": 443, "address": "zoom.us"},
                        {"proto": "UDP", "port": "3478", "address": "2620:123:2000::/40"}]}
    p, r = apply(c, spec)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1
    method, path, body = c.tenant.writes[0]
    assert (method, path) == ("post", "/custom-ip-based-apps") and body["appName"] == "Zoom media" and body["active"] is False
    assert body["appDataBlob"] == [{"proto": "TCP", "port": "443", "ipaddr": "", "fqdn": "zoom.us"},
                                   {"proto": "UDP", "port": "8801-8810", "ipaddr": "3.7.35.0/25", "fqdn": ""}]
    assert body["appDataBlobV6"] == [{"proto": "UDP", "port": "3478", "ipaddr": "2620:123:2000::/40", "fqdn": ""}]
    inv = r["inverse"]
    assert inv["action"] == "delete" and ao.is_undo_only(inv)
    _p, r2 = apply(c, inv)
    assert r2["status"] == "applied" and not any(a["appName"] == "Zoom media" for a in c.tenant.apps.values())


def test_edit_sends_the_app_as_read_with_the_changes_and_undo_puts_it_back():
    """ASVS V1.4.1 · CWE-841: an edit keeps what it does not change; Undo restores name, entries and on/off."""
    c = seeded()
    p, r = apply(c, {"type": zc.T_BYPASS, "action": "update", "id": "502", "active": True,
                     "entries": [{"proto": "TCP", "port": "5061", "address": "10.9.0.0/16"}]})
    assert r["status"] == "applied"
    _m, path, body = c.tenant.writes[0]
    assert path == "/custom-ip-based-apps/502" and body["active"] is True and body["appName"] == "Old VoIP" and body["id"] == 502
    _p, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and c.tenant.apps["502"]["active"] is False and c.tenant.apps["502"]["appDataBlob"][0]["port"] == "5060"


def test_an_app_a_profile_bypasses_is_never_deleted_and_unreadable_profiles_block():
    """ASVS V4.1.3 · CWE-284 · CWE-636: an app listed in an app profile's bypassCustomAppIds is excluded; profiles that cannot be read block."""
    c = seeded()
    p = ao.plan(c, {"type": zc.T_BYPASS, "action": "delete", "id": "501", "name": "Teams media"}, scope=ZCC)
    assert p["items"][0]["status"] == "excluded" and "Default Windows" in p["items"][0]["reason"]
    c.tenant.fail["profiles"] = "HTTP 503"
    p = ao.plan(c, {"type": zc.T_BYPASS, "action": "delete", "id": "502", "name": "Old VoIP"}, scope=ZCC)
    assert p["status"] == "blocked"


def test_delete_asks_for_the_apps_name_and_has_no_undo():
    """ASVS V4.1.3 · CWE-352: a delete always asks DELETE <NAME>; it says there is no Undo."""
    c = seeded()
    spec = {"type": zc.T_BYPASS, "action": "delete", "id": "502", "name": "Old VoIP"}
    p = ao.plan(c, spec, scope=ZCC)
    assert p["confirm_phrase"] == "DELETE OLD VOIP" and p["notes"][0].startswith("No Undo")
    _p, r = apply(c, spec)
    assert r["status"] == "applied" and "502" not in c.tenant.apps and r["inverse"] is None


@pytest.mark.parametrize("entry", [{"proto": "ICMP", "port": "1", "address": "10.0.0.1"}, {"proto": "TCP", "port": "0", "address": "10.0.0.1"},
                                   {"proto": "TCP", "port": "9-1", "address": "10.0.0.1"}, {"proto": "TCP", "port": "443", "address": "0.0.0.0/0"},
                                   {"proto": "TCP", "port": "443", "address": "bad host!"}, {"proto": "TCP", "port": "443", "address": ""}])
def test_bad_entries_are_refused_before_a_read(entry):
    """ASVS V5.1.3 · CWE-20: protocols, ports, a bypass of every address and bad hosts are refused before a read."""
    c = seeded()
    with pytest.raises(ao.OperationError):
        ao.plan(c, {"type": zc.T_BYPASS, "action": "create", "name": "x", "entries": [entry]}, scope=ZCC)
    assert c.tenant.reads == []


# ── entitlements ───────────────────────────────────────────────────────

def test_narrowing_zpa_asks_the_phrase_puts_the_entitlement_as_read_and_undo_restores_it():
    """ASVS V4.1.3 · CWE-841: turning 'all users' off and adding a group is a PUT of the entitlement as read with those fields; the phrase is
    asked; Undo puts the exact list back."""
    c = seeded()
    spec = {"type": zc.T_ENT, "service": "zpa", "enable_for_all": False, "add_groups": ["Contractors"]}
    p, r = apply(c, spec)
    assert p["confirm_phrase"] == "CHANGE ZPA ENTITLEMENTS" and r["status"] == "applied" and r["verification"]["confirmed"] == 2
    _m, path, body = c.tenant.writes[0]
    assert path == "/updateZpaGroupEntitlement" and body == {"zpaEnableForAll": False, "groupList": ["Engineering", "Contractors"],
                                                              "deviceGroupList": [], "machineTunEnabledForAll": False}
    _p, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and c.tenant.ent["zpa"]["zpaEnableForAll"] is True and c.tenant.ent["zpa"]["groupList"] == ["Engineering"]


def test_widening_zdx_needs_no_phrase_and_a_change_since_the_preview_is_kept():
    """ASVS V11.1.4 · CWE-367: adding a ZDX group asks no phrase; a change made in the portal after the preview is a conflict."""
    c = seeded()
    spec = {"type": zc.T_ENT, "service": "zdx", "add_groups": ["Helpdesk"]}
    p = ao.plan(c, spec, scope=ZCC)
    assert p["confirm_phrase"] == ""
    c.tenant.ent["zdx"]["upmGroupList"] = ["IT", "Sales"]
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZCC, writes_enabled=True, assessor=ASSESSOR)
    assert r["status"] == "plan_changed" and c.tenant.writes == []


def test_entitlement_lists_are_validated():
    """ASVS V5.1.3 · CWE-20: group names with control characters, a group both added and removed, or nothing to change are refused."""
    c = seeded()
    for bad in ({"add_groups": ["a\x00b"]}, {"add_groups": ["<b>"]}, {"add_groups": ["X"], "remove_groups": ["x"]}, {}, {"enable_for_all": "no"}):
        with pytest.raises(ao.OperationError):
            ao.plan(c, dict({"type": zc.T_ENT, "service": "zpa"}, **bad), scope=ZCC)
