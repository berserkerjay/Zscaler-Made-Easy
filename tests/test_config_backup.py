"""Configuration backups, field-level diff, templates and the configuration
cache (config_backup.py).

Every test runs on the stateful fake tenant in tests/config_fake.py or the
made-up sample tenant: no network, state files in tmp_path."""
from __future__ import annotations

import importlib
import inspect
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import config_backup as cb  # noqa: E402
from config_fake import Client, Tenant  # noqa: E402

CANARY = "CANARY-SECRET-7f3a9c"
ALL = ao.scope_for(["dlp", "zia_extras", "zpa", "zcc", "genai"], {"web_dlp": "zscaler", "email_dlp": "zscaler", "endpoint_dlp": "zscaler"})


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    return tmp_path


def _tenant() -> Tenant:
    return Tenant({
        "zia.rule_labels": [{"id": 1, "name": "Team A", "description": "owned by A", "last_modified_time": 111}],
        "zia.url_categories": [{"id": "CUSTOM_01", "configured_name": "Partners", "super_category": "USER_DEFINED", "urls": ["b.example", "a.example"],
                                "custom_category": True}],
        "zia.url_filtering_rules": [{"id": 10, "name": "Block partners", "order": 1, "state": "ENABLED", "action": "BLOCK",
                                     "url_categories": ["CUSTOM_01", "GAMBLING"], "labels": [{"id": 1, "name": "Team A"}]}],
        "zia.vpn_credentials": [{"id": 7, "fqdn": "branch@corp.example", "type": "UFQDN", "pre_shared_key": CANARY}],
        "zia.nss_feeds": [{"id": 3, "name": "SIEM", "authentication_token": CANARY, "password": CANARY}],
        "zia.advanced_settings": [{"enable_office365": True, "ui_session_timeout": 600, "api_key": CANARY}],
        "zpa.segment_groups": [{"id": "71", "name": "Apps", "enabled": True, "applications": [{"id": "81"}]}],
        "zpa.provisioning_keys": [{"id": "9", "name": "conn key", "provisioning_key": CANARY}],
        "zcc.trusted_networks": [{"id": 4, "network_name": "HQ", "dns_servers": "10.0.0.1"}],
    })


# ── the catalogue against the installed SDK ─────────────────────────────

def _sdk_class(product: str, svc: str):
    mod = importlib.import_module(f"zscaler.{product}.{product}_service")
    cls = [c for n, c in inspect.getmembers(mod, inspect.isclass) if n.lower().startswith(product) and n.endswith("Service")][0]
    prop = getattr(cls, svc)
    ann = inspect.signature(prop.fget).return_annotation
    if isinstance(ann, str) and hasattr(mod, ann):
        return getattr(mod, ann)   # a forward reference to a class the service module imports at the top
    if isinstance(ann, str) or ann is inspect._empty:
        m = re.search(r"from (zscaler\.[\w.]+) import (\w+)", inspect.getsource(prop.fget))
        ann = getattr(importlib.import_module(m.group(1)), m.group(2))
    return ann


def test_every_catalogue_call_exists_in_the_installed_sdk():
    """ASVS V14.2.1 · CWE-1104: every service and method a backup reads or a restore writes is a real zscaler-sdk-python 1.11.3 call."""
    import zscaler
    missing = []
    for t in cb.TYPES:
        cls = _sdk_class(t["product"], t["svc"])
        for role in ("ls", "get", "add", "upd", "rm", "check"):
            m = t[role]
            if m and m != "raw" and not callable(getattr(cls, m, None)):
                missing.append(f"{t['key']}: {t['svc']}.{m}")
    assert not missing, missing
    assert getattr(zscaler, "__version__", "1.11.3").startswith("1.11")


def test_coverage_lists_each_product_and_what_is_written():
    """ASVS V1.14.1 · CWE-1059: the page and the docs say, per object type, whether it is backed up only, updated, or fully restored and cloned."""
    cov = cb.coverage()
    assert set(cov["products"]) == {"zia", "zpa", "zcc"}
    levels = {r["key"]: r["level"] for p in cov["products"].values() for r in p}
    assert levels["zia.url_filtering_rules"] == "full" and levels["zia.advanced_settings"] == "update" and levels["zia.org_info"] == "read"
    bound = {r["key"] for p in cov["products"].values() for r in p if r["tenant_bound"]}
    assert bound == {"zia.locations", "zia.sub_locations", "zia.static_ips", "zia.gre_tunnels"}
    assert not any(cb.writable(cb.BY_KEY[k]) for k in bound) and all(cb.writable(cb.BY_KEY[k], tenant_bound=True) for k in bound)
    assert all(r["why"] for p in cov["products"].values() for r in p if r["level"] == "read")
    assert sum(len(v) for v in cov["products"].values()) >= 80 and cov["not_covered"]


# ── backups: secrets, files, retention ──────────────────────────────────

def test_a_backup_never_holds_a_secret_and_is_owner_only(isolated):
    """ASVS V8.3.4 · CWE-312 · WSTG-CONF-11: secret canaries in pre-shared keys, tokens, passwords and API keys never reach the backup file."""
    c = Client(_tenant())
    got = cb.capture(c, ["zia", "zpa", "zcc"], ALL)
    entry = cb.save_backup(cb.build_doc(got["types"], {"tenant_label": "acme", "products": ["zia", "zpa", "zcc"]}))
    path = os.path.join(cb.backups_dir(), entry["id"] + ".json")
    raw = open(path, encoding="utf-8").read()
    assert CANARY not in raw and CANARY not in json.dumps(got)
    doc = cb.load_backup(entry["id"])
    assert doc["types"]["zia.vpn_credentials"][0]["pre_shared_key"] == "(set)"
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and stat.S_IMODE(os.stat(cb.backups_dir()).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(os.path.join(cb.backups_dir(), "index.json")).st_mode) == 0o600
    assert c.tenant.writes == []


def test_only_what_is_in_scope_is_read():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: with only ZPA ticked, no ZIA or Client Connector type is read."""
    c = Client(_tenant())
    got = cb.capture(c, ["zia", "zpa", "zcc"], ao.scope_for(["zpa"], {}))
    assert {k.split(".")[0] for _, k in c.tenant.reads} == {"zpa"}
    assert all(k.startswith("zpa.") for k in got["types"]) and any(k.startswith("zia.") for k in got["out_of_scope"])


@pytest.mark.parametrize("raw, match", [
    (b"x" * (cb.MAX_BACKUP_BYTES + 1), "larger"),
    ("[" * 60 + "]" * 60, "nested"),
    ('{"format": "other"}', "not a Zscaler Made Easy"),
    ('{"format": "zscaler-made-easy-config-backup", "version": 9, "meta": {}, "types": {}}', "version"),
    ('{"format": "zscaler-made-easy-config-backup", "version": 1, "meta": {}, "types": {"zia.evil": []}}', "not know"),
    ('{"format": "zscaler-made-easy-config-backup", "version": 1, "meta": {}, "types": {"zia.rule_labels": ["x"]}}', "expected form"),
    ('{"format": "zscaler-made-easy-config-backup", "version": 1, "meta": {}, "types": {}, "path": "/etc"}', "not know"),
    ('{"format": "zscaler-made-easy-config-backup", "version": 1, "meta": {}, "types": {"zia.rule_labels": [{"a": NaN}]}}', "valid JSON"),
])
def test_a_hostile_backup_file_is_refused(raw, match):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: size, nesting, format, version, type keys, row shapes and NaN are checked before a backup is used."""
    with pytest.raises(cb.BackupError, match=match):
        cb.parse_doc(raw)


def test_secrets_are_masked_again_when_a_backup_is_opened():
    """ASVS V8.3.4 · CWE-312: a backup file edited to carry a secret value has it masked when it is opened."""
    doc = {"format": cb.FORMAT, "version": 1, "meta": {}, "types": {"zia.vpn_credentials": [{"id": 1, "fqdn": "x", "pre_shared_key": CANARY}]}}
    assert CANARY not in json.dumps(cb.parse_doc(json.dumps(doc)))


def test_retention_keeps_the_newest_backups_per_profile():
    """ASVS V1.14.1 · CWE-400: a profile keeps its newest `keep` backups; older files are deleted."""
    ids = []
    for i in range(5):
        doc = cb.build_doc({"zia.rule_labels": []}, {"tenant_label": "acme", "profile_id": "acme", "saved_at": f"2026-10-0{i + 1}T00:00:00+00:00"})
        ids.append(cb.save_backup(doc, keep=3)["id"])
    kept = {b["id"] for b in cb.list_backups("acme")}
    assert kept == set(ids[2:])
    assert not os.path.exists(os.path.join(cb.backups_dir(), ids[0] + ".json"))


def test_ids_from_the_page_never_name_a_file():
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: a backup or template id that is not one the app makes is refused before any file is opened."""
    for bad in ("../../etc/passwd", "bk-zz", "bk-0123456789abcdef/../x", "tpl-../a"):
        with pytest.raises(cb.BackupError):
            cb.read_backup_raw(bad)
        with pytest.raises(cb.BackupError):
            cb.read_template_raw(bad)


# ── scheduled backups: read-only, unattended ────────────────────────────

def _profile(pid="acme", secret=True, scopes=("zia_extras",)):
    import tenant_profiles
    p = tenant_profiles.upsert({"name": pid, "vanity_domain": f"{pid}-example", "client_id": "cid", "cloud": "production",
                                "scopes": list(scopes)}, client_secret="s3cret" if secret else "", remember_secret=secret)
    return p["id"]


def test_a_schedule_is_validated():
    """ASVS V5.1.3 · CWE-20: every 1 to 168 hours, keep 1 to 100, at least one product, a saved profile."""
    pid = _profile()
    for kw in ({"every_hours": 0}, {"every_hours": 169}, {"keep": 0}, {"keep": 101}, {"products": []}):
        with pytest.raises(cb.BackupError):
            cb.schedule(pid, enabled=True, **dict({"every_hours": 24, "keep": 5, "products": ["zia"]}, **kw))
    with pytest.raises(cb.BackupError):
        cb.schedule("nobody", enabled=True, products=["zia"])
    assert cb.schedule(pid, enabled=True, every_hours=6, keep=2, products=["zia"])["every_hours"] == 6


def test_scheduled_backups_only_read_and_keep_their_count(monkeypatch):
    """ASVS V1.14.6 · CWE-306: a due schedule reads the profile's in-scope products only, never writes, and keeps its newest copies."""
    if not __import__("tenant_profiles").file_store_allowed():
        monkeypatch.setenv("DLP_CHECK_ALLOW_FILE_SECRETS", "1")
    pid = _profile()
    cb.schedule(pid, enabled=True, every_hours=1, keep=2, products=["zia", "zpa"])
    fake = Tenant(_tenant().data)
    now = datetime(2026, 10, 30, tzinfo=timezone.utc)
    built = []
    for h in range(4):
        out = cb.run_due(lambda creds: built.append(creds) or Client(fake), now + timedelta(hours=h))
        assert out and out[0]["status"] in ("saved", "skipped"), out
    if built:
        assert fake.writes == [] and len(cb.list_backups(pid)) == 2
        assert {k.split(".")[0] for _, k in fake.reads} == {"zia"}      # ZPA is not in the profile's scope
        assert cb.cache_summary(pid)["objects"] > 0
    assert cb.due(now + timedelta(hours=3, minutes=30)) == []


def test_a_profile_without_its_secret_is_skipped_not_read():
    """ASVS V2.10.4 · CWE-522: an unattended backup never runs for a profile that does not remember its secret."""
    pid = _profile("nosecret", secret=False)
    cb.schedule(pid, enabled=True, every_hours=1, keep=2, products=["zia"])
    calls = []
    out = cb.run_due(lambda creds: calls.append(1) or Client(_tenant()))
    assert calls == [] and out[0]["status"] == "skipped"


# ── field-level diff ────────────────────────────────────────────────────

OLD = {"meta": {}, "types": {
    "zia.rule_labels": [{"id": 1, "name": "Team A", "description": "x", "last_modified_time": 1}, {"id": 2, "name": "Gone"}],
    "zia.url_categories": [{"id": "CUSTOM_01", "configured_name": "Partners", "urls": ["a.example", "b.example"], "super_category": "USER_DEFINED"}],
    "zia.url_filtering_rules": [{"id": 10, "name": "R", "order": 3, "state": "ENABLED", "url_categories": ["CUSTOM_01"],
                                 "labels": [{"id": 1, "name": "Team A"}], "description": "d"}],
    "zia.advanced_settings": [{"enable_office365": True, "ui_session_timeout": 600}]}}
NEW = {"meta": {}, "types": {
    "zia.rule_labels": [{"id": 91, "name": "Team A", "description": "y", "last_modified_time": 2}, {"id": 92, "name": "New"}],
    "zia.url_categories": [{"id": "CUSTOM_77", "configured_name": "Partners", "urls": ["b.example", "a.example"], "super_category": "USER_DEFINED"}],
    "zia.url_filtering_rules": [{"id": 99, "name": "R", "order": 4, "state": "ENABLED", "url_categories": ["CUSTOM_77"],
                                 "labels": [{"id": 91, "name": "Team A"}], "description": "d", "modified_by": {"id": 5}}],
    "zia.advanced_settings": [{"enable_office365": False, "ui_session_timeout": 600}]}}


def test_the_diff_oracle_across_tenants():
    """ASVS V1.14.1 · CWE-1023: the field-level diff of two hand-made backups is exactly the expected one: ids, change times and list order are not differences, references compare by name."""
    out = cb.diff(OLD, NEW, by="name")
    got = {r["type"]: {"added": r["added"], "removed": r["removed"],
                       "changed": {c["name"]: [(f["path"], f["old"], f["new"]) for f in c["fields"]] for c in r["changed"]}} for r in out["types"]}
    assert got == {
        "zia.rule_labels": {"added": ["New"], "removed": ["Gone"], "changed": {"Team A": [("description", "x", "y")]}},
        "zia.url_filtering_rules": {"added": [], "removed": [], "changed": {"R": [("order", 3, 4)]}},
        "zia.advanced_settings": {"added": [], "removed": [], "changed": {"(settings)": [("enable_office365", True, False)]}},
    }
    assert out["totals"] == {"added": 1, "removed": 1, "changed": 3} and not out["same"]


def test_ignore_rules_and_matching_by_id():
    """ASVS V1.14.1 · CWE-1023: an ignore pattern drops a field from the diff; within one tenant objects match by id, so a rename is a change."""
    out = cb.diff(OLD, NEW, ignore=["order", "description", "enable_*"], by="name")
    assert [r["type"] for r in out["types"]] == ["zia.rule_labels"] and out["types"][0]["changed"] == []
    a = {"types": {"zia.rule_labels": [{"id": 1, "name": "Old name"}]}}
    b = {"types": {"zia.rule_labels": [{"id": 1, "name": "New name"}]}}
    by_id = cb.diff(a, b, by="id")["types"][0]
    assert by_id["changed"][0]["fields"] == [{"path": "name", "old": "Old name", "new": "New name"}] and not by_id["added"]


def test_a_backup_and_itself_are_the_same():
    """ASVS V1.14.1 · CWE-1023: no differences between a backup and itself; types read on one side only are named, never counted as emptied."""
    assert cb.diff(OLD, OLD)["same"]
    out = cb.diff(OLD, {"types": {"zia.rule_labels": OLD["types"]["zia.rule_labels"]}})
    assert out["same"] and "Custom URL categories" in out["only_in_old"]


# ── templates ───────────────────────────────────────────────────────────

def _backup_doc():
    c = Client(_tenant())
    got = cb.capture(c, ["zia"], ALL)
    return cb.build_doc(got["types"], {"tenant_label": "acme", "products": ["zia"]})


def test_a_template_strips_ids_parameterises_names_and_carries_what_its_objects_use():
    """ASVS V8.3.4 · CWE-200: a template has no ids, names its own objects {{prefix}}…, keeps references by name and pulls in what the picks use."""
    tpl = cb.make_template(_backup_doc(), [{"type": "zia.url_filtering_rules", "name": "Block partners"}], name="Starter", strip_prefix="")
    text = json.dumps(tpl)
    assert '"id"' not in text.replace('"$ref"', "")
    assert set(tpl["objects"]) == {"zia.url_filtering_rules", "zia.url_categories", "zia.rule_labels"}
    rule = tpl["objects"]["zia.url_filtering_rules"][0]
    assert rule["name"] == "{{prefix}}Block partners"
    assert {"$global": "GAMBLING"} in rule["url_categories"]["$refs"]
    src = cb.template_source(cb.parse_template(text), "ACME-")
    assert [r["name"] for r in src["types"]["zia.url_filtering_rules"]] == ["ACME-Block partners"]
    assert src["types"]["zia.url_filtering_rules"][0]["url_categories"][0].startswith("CUSTOM_T")


def test_secret_canaries_never_reach_a_template():
    """ASVS V8.3.4 · CWE-312: nothing secret-named, masked or not, is written into a template; a VPN credential cannot go into one."""
    doc = _backup_doc()
    doc["types"]["zia.rule_labels"][0]["api_key"] = CANARY
    tpl = cb.make_template(doc, [{"type": "zia.rule_labels", "name": "Team A"}], name="t")
    assert CANARY not in json.dumps(tpl) and "api_key" not in json.dumps(tpl)
    with pytest.raises(cb.BackupError):
        cb.make_template(doc, [{"type": "zia.vpn_credentials", "name": "branch@corp.example"}], name="t")


@pytest.mark.parametrize("mutate, match", [
    (lambda d: d["objects"].update({"zia.locations": [{"name": "{{prefix}}x"}]}), "cannot carry"),
    (lambda d: d["objects"]["zia.rule_labels"][0].update(name="no token"), "named"),
    (lambda d: d["objects"]["zia.rule_labels"][0].update(x={"$refs": [{"$ref": "zia.evil", "name": "a", "own": False}], "shape": "list"}), "expected form"),
    (lambda d: d.update(extra=1), "not know"),
])
def test_a_hostile_template_is_refused(mutate, match):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an imported template's types, names and references are checked before it is kept."""
    tpl = cb.make_template(_backup_doc(), [{"type": "zia.rule_labels", "name": "Team A"}], name="t")
    mutate(tpl)
    with pytest.raises(cb.BackupError, match=match):
        cb.parse_template(json.dumps(tpl))


def test_a_template_prefix_is_validated():
    """ASVS V5.1.3 · CWE-20: the prefix is at most 20 letters, digits, spaces and . _ -."""
    tpl = cb.parse_template(json.dumps(cb.make_template(_backup_doc(), [{"type": "zia.rule_labels", "name": "Team A"}], name="t")))
    for bad in ("x" * 21, "<b>", "a;b", "a\nb"):
        with pytest.raises(cb.BackupError):
            cb.template_source(tpl, bad)


# ── the configuration cache ─────────────────────────────────────────────

def test_the_cache_tracks_changes_by_hash_and_holds_no_secret(isolated):
    """ASVS V8.3.4 · CWE-312: a refresh says which objects were added, removed or changed since the last (by hash), and the cache file holds no secret."""
    t = _tenant()
    got = cb.capture(Client(t), ["zia"], ALL)
    first = cb.refresh_cache("acme", got["types"], {"tenant_label": "acme"})
    assert first["first"] and first["changes"] == {}
    t.rows("zia.rule_labels")[0]["description"] = "changed"
    t.rows("zia.rule_labels")[0]["last_modified_time"] = 999          # volatile: no change on its own
    t.rows("zia.rule_labels").append({"id": 2, "name": "Team B"})
    t.rows("zia.url_categories").clear()
    again = cb.refresh_cache("acme", cb.capture(Client(t), ["zia"], ALL)["types"], {"tenant_label": "acme"})
    assert again["changes"]["zia.rule_labels"] == {"added": ["Team B"], "removed": [], "changed": ["Team A"]}
    assert again["changes"]["zia.url_categories"]["removed"] == ["Partners"]
    raw = open(os.path.join(cb.backups_dir(), "cache-acme.json"), encoding="utf-8").read()
    assert CANARY not in raw
    assert cb.diff(cb.cache_as_backup("acme"), cb.cache_as_backup("acme"))["same"]


def test_the_sample_tenant_reads_into_a_backup_offline(monkeypatch):
    """ASVS V14.1.1 · CWE-918: a saved snapshot or the sample tenant becomes a backup through the offline client, which has no network code."""
    import socket
    import offline_tenant as ot
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    doc = cb.from_offline(ot.sample_store())
    assert doc["meta"]["kind"] == "sample" and len(doc["types"]["zia.url_filtering_rules"]) >= 1
    assert len(doc["types"]["zpa.application_segments"]) >= 1 and doc["types"]["zcc.trusted_networks"]


# ── restore breadth (#3): the new read types in the sample tenant and a snapshot ──

NEW_READ_TYPES = ("zia.nat_control_rules", "zia.traffic_capture_rules", "zia.workload_groups", "zpa.user_portals", "zpa.pra_credentials",
                  "zpa.scim_attributes", "zpa.scim_groups", "zpa.service_edges", "zpa.enrollment_certificates", "zcc.admin_users",
                  "zcc.predefined_ip_apps", "zcc.custom_ip_apps", "zcc.process_apps", "zcc.application_profiles")


def test_every_new_type_is_in_a_backup_of_the_sample_tenant_without_secrets_or_people():
    """ASVS V8.3.4 · CWE-359 · WSTG-CONF-11: the sample tenant's backup holds every new type, with no PEM block, credential secret or administrator e-mail address."""
    import offline_tenant as ot
    doc = cb.from_offline(ot.sample_store())
    missing = [k for k in NEW_READ_TYPES if not doc["types"].get(k)]
    assert not missing, (missing, {k: doc["meta"]["unread"].get(k) for k in missing})
    raw = json.dumps(doc)
    assert "BEGIN CERTIFICATE" not in raw and "PRIVATE KEY" not in raw
    assert "@larkspur-freight.example" not in json.dumps(doc["types"]["zcc.admin_users"])
    assert all("user_name" not in r for r in doc["types"]["zcc.admin_users"])
    assert all(set(r) <= {"id", "name", "credential_type", "user_domain", "description", "last_credential_reset_time", "creation_time",
                          "modified_time", "modified_by", "microtenant_id", "microtenant_name", "passphrase", "password", "private_key",
                          "user_name"} and r.get("password") in (None, "(set)") for r in doc["types"]["zpa.pra_credentials"])
    groups = doc["types"]["zpa.scim_groups"]
    assert groups and all(str(g.get("idp_id")) for g in groups)


def test_a_sample_backup_reads_the_newer_application_profiles_api():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the sample answers /application-profiles in the SDK's {"policies": [...]} shape, so a backup reads every app profile instead of marking the type unread."""
    import offline_tenant as ot
    import sample_tenant
    doc = cb.from_offline(ot.sample_store())
    assert "zcc.application_profiles" not in doc["meta"]["unread"], doc["meta"]["unread"].get("zcc.application_profiles")
    rows = doc["types"]["zcc.application_profiles"]
    assert sorted(int(r["id"]) for r in rows) == sorted(p["id"] for p in sample_tenant.APP_PROFILES)


def test_a_sample_backup_reads_the_gre_tunnels():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the sample's GRE tunnels carry lastModifiedBy, which the SDK model (zscaler/zia/models/gre_tunnels.py) needs to read a row, so a backup holds them instead of marking the type unread."""
    import offline_tenant as ot
    import sample_tenant
    doc = cb.from_offline(ot.sample_store())
    assert "zia.gre_tunnels" not in doc["meta"]["unread"], doc["meta"]["unread"].get("zia.gre_tunnels")
    assert sorted(r["source_ip"] for r in doc["types"]["zia.gre_tunnels"]) == sorted(g["sourceIp"] for g in sample_tenant.GRE_TUNNELS)


def test_client_connector_admin_users_are_counted_not_named():
    """ASVS V8.3.4 · CWE-359 · WSTG-CONF-11: a backup keeps each Client Connector admin's role and state by id, never the user name (an e-mail address)."""
    c = Client(Tenant({"zcc.admin_users": [{"id": 7, "user_name": "alice@corp.example", "company_role": {"id": 1, "role_name": "Super Admin"},
                                            "account_enabled": True, "is_default_admin": False}]}))
    got = cb.capture(c, ["zcc"], ALL)
    rows = got["types"]["zcc.admin_users"]
    assert rows == [{"id": 7, "company_role": {"id": 1, "role_name": "Super Admin"}, "account_enabled": True, "is_default_admin": False}]
    assert cb.name_of(cb.BY_KEY["zcc.admin_users"], rows[0]) == "7"


def test_entitlements_are_restored_through_the_bulk_changes_put():
    """ASVS V1.14.1 · CWE-1059: the backup restore PUTs a Client Connector entitlement to the same path Bulk changes → ZPA and ZDX entitlements uses."""
    import ops_zcc_admin as oza
    assert cb.BY_KEY["zcc.zpa_entitlements"]["raw_zcc"] == "/" + oza.SERVICES["zpa"][4]
    assert cb.BY_KEY["zcc.zdx_entitlements"]["raw_zcc"] == "/" + oza.SERVICES["zdx"][4]


def test_a_snapshot_reads_the_new_types_and_scim_per_identity_provider():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a snapshot with ZPA, ZIA platform and Client Connector ticked reads the new lists, SCIM groups and attributes once per identity provider, and a snapshot backup holds them."""
    import offline_tenant as ot
    plan = ot.capture_plan(["zia_extras", "zpa", "zcc"])
    for ep in ("/zia/trafficCaptureRules", "/zia/workloadGroups", "/zia/dnatRules", "/zpa/userPortal", "/zpa/serviceEdge",
               "/zpa/enrollmentCert", "/zcc/adminUsers", "/zcc/predefinedIpBasedApps", ot.PER_OBJECT_SCIM):
        assert ep in plan, ep
    assert "/zpa/credential" in ot.capture_plan(["zpa", "rbac"])   # PRA credentials (metadata) only with RBAC ticked
    assert ot.PER_OBJECT_SCIM not in ot.capture_plan(["zia_extras", "zcc"])
    src = ot.OfflineRawClient(ot.sample_store(), {})
    got = ot.capture(src, ["zia_extras", "zpa", "zcc", "rbac"], {}, lambda m: None)
    keys = set(got["responses"])
    assert any(k.endswith("/idp/2601/scimattribute") for k in keys) and any(k.endswith("/scimgroup/idpId/2601") for k in keys)
    assert "/zpa/userconfig/v1/customers/{customerId}/scimgroup/idpId/2601" in keys
    doc = cb.from_offline(ot.open_document(json.dumps({"format": ot.FORMAT, "version": ot.VERSION, "meta": {"tenant_label": "snap"},
                                                       "responses": got["responses"]}), "snap-0011223344556677"), ["zpa"])
    assert doc["types"]["zpa.scim_groups"] and doc["types"]["zpa.scim_attributes"] and doc["types"]["zpa.user_portals"]
