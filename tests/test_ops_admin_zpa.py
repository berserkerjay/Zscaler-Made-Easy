"""ZPA day-to-day administration (ops_zpa_admin) on the Bulk changes engine.

Every test runs against the stateful fake in tests/admin_fakes.py: no
network, no clock (ZPA pacing set to 0), state files in tmp_path."""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zpa  # noqa: E402
import ops_zpa_admin as za  # noqa: E402
import zpa_reader  # noqa: E402
from admin_fakes import CANARY_ECHO, CANARY_PROV_KEY, ZpaClient  # noqa: E402

ZPA = ao.scope_for(["zpa"], {})
NO_ZPA = ao.scope_for(["zcc", "zdx"], {})
ASSESSOR = "Jane Doe"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.delenv("ZSCALER_SDK_LOG", raising=False)
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    monkeypatch.setattr(za, "_CERTS", {})
    ao.load_plugins()
    return tmp_path


def seeded():
    c = ZpaClient()
    return c, c.tenant.seed()


def apply(c, spec, *, phrase=None, undo_of=""):
    p = ao.plan(c, spec, scope=ZPA, tenant_label="acme")
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") if phrase is None else phrase)
    return p, r


def sinks(tmp_path, *objs, logs=""):
    files = "".join((tmp_path / f).read_text(encoding="utf-8") for f in os.listdir(tmp_path) if (tmp_path / f).is_file())
    return json.dumps(objs, default=str) + logs + files


# ── registration and the Scope rule ────────────────────────────────────

def test_the_four_zpa_admin_types_are_registered_on_the_engine():
    """ASVS V1.4.4 · CWE-1059: the ZPA admin operations are plugin types of the one engine, with the shared form and the ZPA product."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    for t in (za.T_UPDATE, za.T_DELETE, za.T_KEY, za.T_CERT):
        assert cat[t]["family"] == za.FAMILY and cat[t]["product"] == "zpa" and cat[t]["script"] == "ops_admin.js"
        assert cat[t]["group"] == "Day-to-day admin"


@pytest.mark.parametrize("spec", [{"type": za.T_UPDATE, "targets": [{"kind": "connector", "id": "1", "set": {"enabled": False}}]},
                                  {"type": za.T_DELETE, "targets": [{"kind": "connector", "id": "1", "name": "x"}]},
                                  {"type": za.T_KEY, "key_type": "connector", "group_id": "1", "name": "k"},
                                  {"type": za.T_CERT, "certificate_id": "1", "assign": [{"segment_id": "2", "app_id": "3"}]}])
def test_zpa_not_ticked_is_refused_before_anything_is_read(spec):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZPA ticked on the Scope page nothing is read or written."""
    c, _ = seeded()
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(c, spec, scope=NO_ZPA)
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.read_objects(c, za.FAMILY, NO_ZPA)
    assert c.tenant.reads == [] and c.tenant.writes == []


# ── health (read-only) ─────────────────────────────────────────────────

def test_the_picker_shows_health_schedules_expiry_and_never_a_key():
    """ASVS V8.3.4 · CWE-200: connectors and edges with their health and versions, groups with schedules, certificates with expiry; no key value."""
    c, s = seeded()
    out = ao.read_objects(c, za.FAMILY, ZPA)
    conns = {x["name"]: x for x in out["connectors"]}
    assert conns["hq-ac-1"]["health"] == "connected" and conns["hq-ac-1"]["update_pending"] is True
    assert conns["hq-ac-2"]["health"] == "disconnected" and conns["old-ac"]["health"] == "turned off"
    g = {x["name"]: x for x in out["connector_groups"]}["HQ connectors"]
    assert g["members"] == 2 and g["members_connected"] == 1 and g["upgrade_day"] == "SUNDAY" and g["upgrade_time_label"] == "18:30"
    assert out["certificates"][0]["expiry"].startswith("expires in") and out["certificates"][0]["used_by"]
    assert {p["name"] for p in out["pra_portals"]} == {"Ops PRA", "Spare PRA"} and out["user_portals"][0]["in_use"]
    assert c.tenant.writes == [] and CANARY_PROV_KEY not in json.dumps(out)


# ── zpa_infra_update ───────────────────────────────────────────────────

def test_rename_move_and_schedule_send_the_object_as_read_with_the_changes(isolated):
    """ASVS V1.4.1 · CWE-841: payload oracle: the PUT carries the object as read, the asked fields changed; read back; Undo puts it back."""
    c, s = seeded()
    spec = {"type": za.T_UPDATE, "targets": [
        {"kind": "connector", "id": s["c1"]["id"], "set": {"name": "hq-ac-1b", "group_id": s["g2"]["id"]}},
        {"kind": "connector_group", "id": s["g1"]["id"], "set": {"upgrade_day": "wednesday", "upgrade_hour": 3, "version_profile": "new_release"}},
        {"kind": "service_edge_group", "id": s["sg"]["id"], "set": {"enabled": False}}]}
    p, r = apply(c, spec)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == r["verification"]["checked"] == 7
    w = {(x[1], x[2]): x[3] for x in c.tenant.writes}
    assert w[("connector", s["c1"]["id"])] == {"name": "hq-ac-1b", "description": "rack 4", "enabled": True, "app_connector_group_id": s["g2"]["id"]}
    g = w[("connector_group", s["g1"]["id"])]
    assert g["upgrade_day"] == "WEDNESDAY" and g["upgrade_time_in_secs"] == "10800" and g["version_profile_id"] == "2"
    assert g["override_version_profile"] is True and g["location"] == "San Jose, CA, USA" and g["enrollment_cert_id"] == "11"
    eg = w[("service_edge_group", s["sg"]["id"])]
    assert eg["enabled"] is False and eg["service_edge_ids"] == [s["se"]["id"]] and eg["trusted_network_ids"] == ["77"]
    rec = ao.record(r, by=ASSESSOR, actor="alice")
    inv = r["inverse"]
    assert inv["undo"] is True and ao.is_undo_only(inv)
    _p2, r2 = apply(c, inv)
    assert r2["status"] == "applied"
    row = c.tenant.rows["connector_group"][s["g1"]["id"]]
    assert row["upgradeTimeInSecs"] == "66600" and row["versionProfileId"] == "0" and row["overrideVersionProfile"] is False
    assert c.tenant.rows["connector"][s["c1"]["id"]]["appConnectorGroupId"] == s["g1"]["id"]
    audit = [json.loads(x) for x in (isolated / "audit.log").read_text(encoding="utf-8").splitlines() if x.strip()]
    assert any(e.get("event") == "admin_operation" and e.get("actor") == "alice" for e in audit) and rec["actor"] == "alice"


def test_a_change_made_in_zpa_after_the_preview_is_never_overwritten():
    """ASVS V11.1.4 · CWE-367: the object is read again right before its PUT; a change since the preview is a conflict, nothing sent."""
    c, s = seeded()
    spec = {"type": za.T_UPDATE, "targets": [{"kind": "connector", "id": s["c2"]["id"], "set": {"enabled": False}}]}
    p = ao.plan(c, spec, scope=ZPA)
    # the plan hash covers the before values: a change in between gives plan_changed
    c.tenant.rows["connector"][s["c2"]["id"]]["enabled"] = False
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR)
    assert r["status"] == "plan_changed" and c.tenant.writes == []


@pytest.mark.parametrize("bad", [{"kind": "connector", "id": "1", "set": {"upgrade_day": "MONDAY"}},
                                 {"kind": "connector_group", "id": "1", "set": {"upgrade_hour": 24}},
                                 {"kind": "connector_group", "id": "1", "set": {"version_profile": "beta"}},
                                 {"kind": "connector", "id": "../1", "set": {"enabled": True}},
                                 {"kind": "connector", "id": "1", "set": {"name": "<script>"}},
                                 {"kind": "connector", "id": "1", "set": {"enabled": "yes"}},
                                 {"kind": "segment", "id": "1", "set": {"enabled": True}}])
def test_bad_changes_are_refused_before_anything_is_read(bad):
    """ASVS V5.1.3 · CWE-20: unknown fields, days, hours, profiles, ids and names are refused before a read."""
    c, _ = seeded()
    with pytest.raises(ao.OperationError):
        ao.plan(c, {"type": za.T_UPDATE, "targets": [bad]}, scope=ZPA)
    assert c.tenant.reads == []


def test_turning_off_portals_and_consoles_is_planned_and_reversible():
    """ASVS V1.4.1 · CWE-841: PRA portals, consoles and user portals turn on or off through the same engine; Undo restores them."""
    c, s = seeded()
    spec = {"type": za.T_UPDATE, "targets": [{"kind": k, "id": s[n]["id"], "set": {"enabled": False}} for k, n in
                                             (("pra_portal", "pp"), ("pra_console", "pc"), ("user_portal", "up"))]}
    p, r = apply(c, spec)
    assert r["status"] == "applied" and all("takes it away" in w or "Turning off" in w for w in p["warnings"])
    con = next(x[3] for x in c.tenant.writes if x[1] == "pra_console")
    assert con["enabled"] is False and con["pra_portal_ids"] == [s["pp"]["id"]] and con["pra_application_id"] == "7001"
    _p, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and c.tenant.rows["pra_portal"][s["pp"]["id"]]["enabled"] is True


# ── zpa_infra_delete: stronger confirmation, in-use and connected checks ─

def test_a_delete_always_asks_for_the_typed_confirmation_naming_it():
    """ASVS V4.1.3 · CWE-352 · CWE-841: one deletion asks DELETE <NAME> whatever the count; a wrong or missing phrase writes nothing."""
    c, s = seeded()
    spec = {"type": za.T_DELETE, "targets": [{"kind": "connector", "id": s["c3"]["id"], "name": "old-ac"}]}
    p = ao.plan(c, spec, scope=ZPA)
    assert p["confirm_phrase"] == "DELETE OLD-AC" and "No Undo" in p["notes"][0]
    for wrong in ("", "DELETE 1 ZPA OBJECTS", "delete old-ac!"):
        r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR, confirm_text=wrong)
        assert r["status"] == "refused"
    assert c.tenant.writes == []
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR, confirm_text="delete old-ac")
    assert r["status"] == "applied" and r["inverse"] is None and s["c3"]["id"] not in c.tenant.rows["connector"]


def test_connected_used_or_renamed_objects_are_kept_and_named():
    """ASVS V4.1.3 · CWE-284 · CWE-1188: a connected connector, a group with members or a server group, a used certificate, a portal a console
    uses and a target whose name differs are excluded with the reason."""
    c, s = seeded()
    spec = {"type": za.T_DELETE, "targets": [
        {"kind": "connector", "id": s["c1"]["id"], "name": "hq-ac-1"}, {"kind": "connector_group", "id": s["g1"]["id"], "name": "HQ connectors"},
        {"kind": "certificate", "id": s["cert"]["id"], "name": "wiki-cert"}, {"kind": "pra_portal", "id": s["pp"]["id"], "name": "Ops PRA"},
        {"kind": "user_portal", "id": s["up"]["id"], "name": "Contractors"}, {"kind": "service_edge_group", "id": s["sg"]["id"], "name": "PSE Frankfurt"},
        {"kind": "connector", "id": s["c2"]["id"], "name": "not-its-name"}]}
    p = ao.plan(c, spec, scope=ZPA)
    why = {u["object"]["name"]: u["reason"] for u in p["items"]}
    assert p["counts"]["change"] == 0 and p["status"] == "nothing_to_do" and not p["confirm_phrase"]
    assert "connected" in why["hq-ac-1"] and "App Connector(s) are still in it" in why["HQ connectors"]
    assert "still uses it" in why["wiki-cert"] and "jump-rdp" in why["Ops PRA"] and "Ops PRA" in why["Contractors"]
    assert "Service Edge(s)" in why["PSE Frankfurt"] and "not 'not-its-name'" in why["not-its-name"]


def test_users_deleted_first_in_the_same_run_free_what_they_used():
    """ASVS V11.1.1 · CWE-841: a console and its portal go in one run, the console first; the portal depends on it."""
    c, s = seeded()
    spec = {"type": za.T_DELETE, "targets": [{"kind": "pra_portal", "id": s["pp"]["id"], "name": "Ops PRA"},
                                             {"kind": "pra_console", "id": s["pc"]["id"], "name": "jump-rdp"}]}
    p, r = apply(c, spec)
    assert p["confirm_phrase"] == "DELETE 2 ZPA OBJECTS" and r["status"] == "applied"
    assert [x[1] for x in c.tenant.writes] == ["pra_console", "pra_portal"]
    portal = next(u for u in p["items"] if u["object"]["name"] == "Ops PRA")
    assert portal["depends_on"] == [f"del:pra_console:{s['pc']['id']}"]


def test_a_refused_member_delete_keeps_what_depends_on_it():
    """ASVS V11.1.1 · CWE-460: when the console's delete is refused, its portal is not attempted."""
    c, s = seeded()
    c.tenant.fail[("delete", "pra_console")] = "HTTP 400: locked"
    spec = {"type": za.T_DELETE, "targets": [{"kind": "pra_portal", "id": s["pp"]["id"], "name": "Ops PRA"},
                                             {"kind": "pra_console", "id": s["pc"]["id"], "name": "jump-rdp"}]}
    _p, r = apply(c, spec)
    st = {u["object"]["name"]: u["status"] for u in r["items"]}
    assert st == {"jump-rdp": "failed", "Ops PRA": "skipped"} and s["pp"]["id"] in c.tenant.rows["pra_portal"]


def test_an_object_that_connected_after_the_preview_is_not_deleted():
    """ASVS V11.1.4 · CWE-367: the re-read right before the DELETE finds it connected: conflict, kept."""
    c, s = seeded()
    spec = {"type": za.T_DELETE, "targets": [{"kind": "connector", "id": s["c2"]["id"], "name": "hq-ac-2"}]}
    p = ao.plan(c, spec, scope=ZPA)
    orig = za.get_one

    def sneaky(zpa, kind, oid, key_type=""):
        row, err = orig(zpa, kind, oid, key_type)
        if row is not None and kind == "connector" and len([x for x in c.tenant.reads if x == "get:connector"]) >= 1:
            row["controlChannelStatus"] = "ZPN_STATUS_AUTHENTICATED"
        return row, err
    za.get_one = sneaky
    try:
        r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR, confirm_text=p["confirm_phrase"])
    finally:
        za.get_one = orig
    assert r["items"][0]["status"] == "conflict" and [w for w in c.tenant.writes if w[0] == "delete"] == []


# ── provisioning keys ──────────────────────────────────────────────────

def test_a_new_key_is_created_off_shown_once_and_never_in_any_sink(isolated, caplog):
    """ASVS V8.3.4 · V7.1.1 · CWE-532 · CWE-312: the key ZPA answers is in no plan, result, record, log or audit entry; it is revealed once
    to the actor who ran the change; Undo revokes it."""
    caplog.set_level(logging.DEBUG)
    c, s = seeded()
    spec = {"type": za.T_KEY, "key_type": "service_edge", "group_id": s["sg"]["id"], "name": "fra-key", "max_usage": 2}
    import pack_ops as ops
    with ops.audit_scope(actor="alice"):
        p, r = apply(c, spec)
    assert r["status"] == "applied"
    kw = next(x[3] for x in c.tenant.writes if x[0] == "create")
    assert kw == {"name": "fra-key", "max_usage": "2", "enrollment_cert_id": c.tenant.rows["enrollment"][next(
        k for k, v in c.tenant.rows["enrollment"].items() if v["name"] == "Service Edge")]["id"], "component_id": s["sg"]["id"], "enabled": False}
    rec = ao.record(r, by=ASSESSOR, actor="alice")
    objs = ao.read_objects(c, za.FAMILY, ZPA)
    assert CANARY_PROV_KEY not in sinks(isolated, p, r, rec, objs, logs=caplog.text)
    tok = r["one_time_secrets"][0]["token"]
    assert ops_zpa.reveal(tok, actor="mallory") is None
    assert ops_zpa.reveal(tok, actor="alice")["provisioning_key"] == CANARY_PROV_KEY and ops_zpa.reveal(tok, actor="alice") is None
    inv = r["inverse"]
    assert inv["targets"][0]["kind"] == "provisioning_key" and inv["targets"][0]["key_type"] == "service_edge"
    _p, r2 = apply(c, inv)
    assert r2["status"] == "applied" and c.tenant.rows["key:service_edge"] == {}


def test_a_key_name_that_exists_is_excluded_and_a_missing_group_blocks():
    """ASVS V1.4.1 · CWE-841: an existing key name is not created twice; a group that is gone blocks the plan."""
    c, s = seeded()
    p = ao.plan(c, {"type": za.T_KEY, "key_type": "connector", "group_id": s["g1"]["id"], "name": "hq-key"}, scope=ZPA)
    assert p["counts"]["excluded"] == 1 and p["counts"]["change"] == 0
    p = ao.plan(c, {"type": za.T_KEY, "key_type": "connector", "group_id": "999", "name": "k2"}, scope=ZPA)
    assert p["status"] == "blocked"
    for bad in ({"max_usage": 0}, {"max_usage": 501}, {"key_type": "browser"}, {"enabled": "1"}):
        with pytest.raises(ao.OperationError):
            ao.plan(c, dict({"type": za.T_KEY, "key_type": "connector", "group_id": s["g1"]["id"], "name": "k3"}, **bad), scope=ZPA)


# ── Browser Access certificates ────────────────────────────────────────

def make_cert(names=("wiki.example.com",), days=365):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1) if days > 0 else dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=abs(days)))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    kp = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return pem, kp


def key_lines(kp):
    return [ln for ln in kp.splitlines() if ln and "-----" not in ln]


def test_upload_and_assign_sends_the_key_once_and_it_reaches_no_sink(isolated, caplog):
    """ASVS V8.3.4 · V6.4.1 · CWE-312 · CWE-532: the private key is in no spec, plan, result, record, log, audit entry or object list;
    it is sent once in certBlob and dropped; the application points at the new certificate; Undo points it back and deletes it."""
    caplog.set_level(logging.DEBUG)
    c, s = seeded()
    pem, kp = make_cert(("*.example.com",))
    up = za.stash_upload(pem, kp, None)
    assert set(up["facts"]) >= {"subject", "sans", "valid_to", "fingerprint_sha256"} and "_key" not in json.dumps(up)
    spec = {"type": za.T_CERT, "upload_token": up["token"], "name": "wildcard-2027", "description": "rotated",
            "assign": [{"segment_id": s["seg"]["id"], "app_id": "6001"}]}
    p, r = apply(c, spec)
    assert r["status"] == "applied", r.get("message") or r["items"]
    created = [x for x in c.tenant.writes if x[0] == "create"]
    assert len(created) == 1 and created[0][3]["cert_blob"] == pem.strip() + "\n" + kp.strip() and set(created[0][3]) == {"name", "description", "cert_blob"}
    new_id = r["created"][0]["id"]
    app = c.tenant.rows["segment"][s["seg"]["id"]]["clientlessApps"][0]
    assert app["certificateId"] == new_id
    assert za.peek_upload(up["token"], None) is None, "the key is held for one use only"
    rec = ao.record(r, by=ASSESSOR)
    objs = ao.read_objects(c, za.FAMILY, ZPA)
    blob = sinks(isolated, spec, p, r, rec, objs, logs=caplog.text)
    assert all(ln not in blob for ln in key_lines(kp)) and "PRIVATE KEY" not in blob
    _p, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and c.tenant.rows["segment"][s["seg"]["id"]]["clientlessApps"][0]["certificateId"] == s["cert"]["id"]
    assert new_id not in c.tenant.rows["certificate"]


def test_an_error_that_echoes_the_request_never_carries_the_key(isolated, caplog):
    """ASVS V7.4.1 · CWE-209 · CWE-532: ZPA refusing the upload and quoting the request: the error shown, logged and audited has no key."""
    caplog.set_level(logging.DEBUG)
    c, s = seeded()
    c.tenant.fail[("create", "certificate")] = "x"
    pem, kp = make_cert()
    up = za.stash_upload(pem, kp, None)
    p, r = apply(c, {"type": za.T_CERT, "upload_token": up["token"], "name": "c2", "assign": [{"segment_id": s["seg"]["id"], "app_id": "6001"}]})
    assert r["items"][0]["status"] == "failed" and CANARY_ECHO in r["items"][0]["error"]
    blob = sinks(isolated, p, r, logs=caplog.text)
    assert all(ln not in blob for ln in key_lines(kp)) and "PRIVATE KEY" not in blob
    assert r["items"][1]["status"] == "skipped", "the assignment depends on the certificate"


@pytest.mark.parametrize("case", ["mismatch", "garbage", "key_in_cert", "encrypted", "huge", "expired"])
def test_unusable_uploads_are_refused_without_echoing_them(case):
    """ASVS V5.1.3 · V12.1.1 · CWE-20 · CWE-400: a key of another certificate, garbage, a key in the certificate field, an encrypted key, an
    oversized upload or an expired certificate is refused (the expired one blocks the plan); no message repeats the input."""
    pem, kp = make_cert()
    if case == "expired":
        pem, kp = make_cert(days=-30)
        up = za.stash_upload(pem, kp, None)
        c, s = seeded()
        p = ao.plan(c, {"type": za.T_CERT, "upload_token": up["token"], "name": "old", "assign": []}, scope=ZPA)
        assert p["status"] == "blocked" and "expired" in p["blockers"][0]
        return
    args = {"mismatch": (pem, make_cert()[1]), "garbage": ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", kp),
            "key_in_cert": (pem + kp, kp), "encrypted": (pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"),
            "huge": (pem + "A" * (za.MAX_CERT_PEM + 1), kp)}[case]
    with pytest.raises(za.CertificateError) as e:
        za.stash_upload(*args, None)
    assert all(ln not in str(e.value) for ln in key_lines(kp))


def test_an_application_the_certificate_does_not_cover_is_excluded():
    """ASVS V9.2.1 · CWE-297: a certificate whose names do not cover the application's domain is not assigned (browsers would refuse it)."""
    c, s = seeded()
    pem, kp = make_cert(("other.example.org",))
    up = za.stash_upload(pem, kp, None)
    p = ao.plan(c, {"type": za.T_CERT, "upload_token": up["token"], "name": "c3", "assign": [{"segment_id": s["seg"]["id"], "app_id": "6001"}]}, scope=ZPA)
    ba = next(u for u in p["items"] if u["kind"] == "ba_app")
    assert ba["status"] == "excluded" and "does not cover" in ba["reason"]


def test_the_held_upload_is_single_use_bound_to_its_uploader_and_expires():
    """ASVS V3.3.1 · V4.2.1 · CWE-613 · CWE-639: another person cannot use or see an upload; it expires after ten minutes."""
    pem, kp = make_cert()
    up = za.stash_upload(pem, kp, "alice", now=1000.0)
    assert za.peek_upload(up["token"], "mallory", now=1001.0) is None
    assert za.peek_upload(up["token"], "alice", now=1000.0 + za.CERT_TTL + 1) is None
    for bad in ("", "x" * 500, "../x", None):
        assert za.peek_upload(bad, "alice") is None


def test_the_sdk_request_log_blocks_an_upload(monkeypatch):
    """ASVS V7.1.1 · CWE-532: with the SDK's request-body log on, the upload is blocked (the key would be logged)."""
    c, s = seeded()
    pem, kp = make_cert()
    up = za.stash_upload(pem, kp, None)
    monkeypatch.setenv("ZSCALER_SDK_LOG", "true")
    p = ao.plan(c, {"type": za.T_CERT, "upload_token": up["token"], "name": "c4", "assign": []}, scope=ZPA)
    assert p["status"] == "blocked" and any("ZSCALER_SDK_LOG" in b for b in p["blockers"])


def test_pointing_apps_at_an_existing_certificate_is_reversible():
    """ASVS V1.4.1 · CWE-841: payload oracle for the segment PUT (the segment as read, clientlessApps with the new certificateId)."""
    c, s = seeded()
    other = c.tenant.add("certificate", {"name": "wild", "validToInEpochSec": "4102444800", "san": ["*.example.com"]})
    p, r = apply(c, {"type": za.T_CERT, "certificate_id": other["id"], "assign": [{"segment_id": s["seg"]["id"], "app_id": "6001"}]})
    assert r["status"] == "applied"
    kw = next(x[3] for x in c.tenant.writes if x[1] == "segment")
    assert kw["domain_names"] == ["wiki.example.com"] and kw["server_group_ids"] == ["900"] and kw["segment_group_id"] == "500"
    assert kw["clientless_apps"][0]["certificateId"] == other["id"] and "certificateName" not in kw["clientless_apps"][0]
    assert r["inverse"]["restore"] == [{"segment_id": s["seg"]["id"], "app_id": "6001", "certificate_id": s["cert"]["id"], "from_id": other["id"]}]
    assert r["inverse"]["delete_certificate"] is None
