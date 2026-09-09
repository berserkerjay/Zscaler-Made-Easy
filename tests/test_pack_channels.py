"""
Endpoint / SaaS Security API (CASB) / Email DLP channels in the planner.

Extends the fake ZIA from test_pack_deploy with the four extra services
the channels touch (endpoint_dlp_rules, casb_dlp_rules,
outbound_email_dlp_rules, saas_security_api) plus notification templates
and rule labels, and checks that prerequisites are resolved, listed as
dependencies, and that missing ones block only the rules that need them.
"""
from __future__ import annotations

import itertools

import pytest

import pack_channels as pc
import pack_deploy as pd
from test_pack_deploy import (  # noqa: F401 — reuse the fake tenant, pack builders and the base_pack fixture
    PREDEF_SSN, FakeClient, FakeZia, Obj, _dict, _engine, _policy, write_pack, items_by, base_pack,
)

_pack_seq = itertools.count()


# ---------------------------------------------------------------------------
# Channel fakes
# ---------------------------------------------------------------------------

class FakeChannelRules:
    """endpoint_dlp_rules / outbound_email_dlp_rules shape: list_rules() + add_rule(**kw)."""
    def __init__(self, items=None, fail=False, start=8000):
        self.items = list(items or [])
        self.fail = fail
        self.added = []
        self._next = start

    def list_rules(self, query_params=None):
        if self.fail:
            return None, None, {"message": "FEATURE_NOT_ENABLED"}
        return list(self.items), None, None

    def add_rule(self, **kw):
        self.added.append(kw)
        self._next += 1
        obj = Obj(id=self._next, **kw)
        self.items.append(obj)
        return obj, None, None

    def update_rule(self, rule_id, **kw):
        self.updated = getattr(self, "updated", [])
        self.updated.append({"id": rule_id, **kw})
        for i, it in enumerate(self.items):
            if it.id == rule_id:
                self.items[i] = Obj(id=rule_id, **kw)
                return self.items[i], None, None
        return None, None, {"message": "not found"}


class FakeCasbRules(FakeChannelRules):
    def list_all_rules(self):
        return self.list_rules()

    def list_rules(self, rule_type=None, query_params=None):
        return super().list_rules()


class FakeSaaS:
    def __init__(self, tenants=None, fail=False):
        self.tenants = list(tenants or [])
        self.fail = fail

    def list_casb_tenant_lite(self, query_params=None):
        if self.fail:
            return None, None, {"message": "boom"}
        return list(self.tenants), None, None


class FakeNamed:
    def __init__(self, items=None):
        self.items = list(items or [])

    def list_dlp_templates(self, query_params=None):
        return list(self.items), None, None

    def list_labels(self, query_params=None):
        return list(self.items), None, None


# ---------------------------------------------------------------------------
# Containment channels (Cloud App Control, File Type Control, URL Filtering, SSL)
# ---------------------------------------------------------------------------

AVAILABLE = {
    "FILE_SHARE": ["ALLOW_FILE_SHARE_VIEW", "BLOCK_FILE_SHARE_VIEW", "ALLOW_FILE_SHARE_UPLOAD", "BLOCK_FILE_SHARE_UPLOAD",
                   "ALLOW_FILE_SHARE_SHARE", "BLOCK_FILE_SHARE_SHARE", "ISOLATE_FILE_SHARE_VIEW"],
    "WEBMAIL": ["ALLOW_WEBMAIL_VIEW", "BLOCK_WEBMAIL_VIEW", "ALLOW_WEBMAIL_SEND", "BLOCK_WEBMAIL_SEND",
                "ALLOW_WEBMAIL_ATTACHMENT_SEND", "BLOCK_WEBMAIL_ATTACHMENT_SEND"],
    "AI_ML": ["ALLOW_AI_ML_WEB_USE", "BLOCK_AI_ML_WEB_USE", "ALLOW_AI_ML_UPLOAD", "BLOCK_AI_ML_UPLOAD"],
}
APPS = {"FILE_SHARE": ["BOX", "DROPBOX", "GOOGLE_DRIVE"], "WEBMAIL": ["GMAIL", "YAHOO_WEBMAIL"], "AI_ML": ["CHATGPT_AI", "GEMINI"]}


class FakeCloudAppControl:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.added, self.updated, self.calls = [], [], []
        self._next = 9500

    def list_rules(self, rule_type, query_params=None):
        return [r for r in self.items if getattr(r, "type", None) == rule_type], None, None

    def list_available_actions(self, rule_type, cloud_apps):
        self.calls.append((rule_type, list(cloud_apps)))
        return list(AVAILABLE.get(rule_type, [])), None, None

    def add_rule(self, rule_type, **kw):
        self.added.append((rule_type, kw))
        self._next += 1
        obj = Obj(id=self._next, **kw)
        self.items.append(obj)
        return obj, None, None

    def update_rule(self, rule_type, rule_id, **kw):
        self.updated.append((rule_type, rule_id, kw))
        for i, it in enumerate(self.items):
            if it.id == rule_id:
                self.items[i] = Obj(id=rule_id, **kw)
                return self.items[i], None, None
        return None, None, {"message": "not found"}


class FakeClassApps:
    def list_cloud_app_policy(self, query_params=None):
        cls = (query_params or {}).get("app_class")
        return [Obj(app=a) for a in APPS.get(cls, [])], None, None


def add_control_services(client, cac_rules=None):
    """Give a fake client the four containment-channel services plus the
    cloud-application catalogue they scope by."""
    z = client.zia
    z.cloudappcontrol = FakeCloudAppControl(cac_rules)
    z.file_type_control_rule = FakeChannelRules(start=9600)
    z.url_filtering = FakeChannelRules(start=9700)
    z.ssl_inspection_rules = FakeChannelRules(start=9800)
    z.cloud_applications = FakeClassApps()
    return client



def tenant(name, app, tid):
    return Obj(tenant_id=tid, tenant_name=name, saas_application=app, status=["ACTIVE"])


def make_client(*, casb_tenants=None, casb_fail=False, endpoint_fail=False, email_fail=False,
                templates=None, labels=None, endpoint_rules=None, saas_rules=None, email_rules=None):
    client = FakeClient(dicts=[PREDEF_SSN])
    z = client.zia
    z.endpoint_dlp_rules = FakeChannelRules(endpoint_rules, fail=endpoint_fail, start=8000)
    z.casb_dlp_rules = FakeCasbRules(saas_rules, start=8500)
    z.outbound_email_dlp_rules = FakeChannelRules(email_rules, fail=email_fail, start=8800)
    z.saas_security_api = FakeSaaS(casb_tenants, fail=casb_fail)
    z.dlp_templates = FakeNamed(templates)
    z.rule_labels = FakeNamed(labels)
    return client


TENANTS = [tenant("Acme Box", "BOX", 501), tenant("Acme Google Workspace", "GOOGLE_DRIVE", 502),
           tenant("Acme M365 Mail", "OFFICE_365", 503), tenant("Acme Slack", "SLACK", 504)]


def multi_pack(tmp_path, **overrides):
    """One dictionary, one engine, and one rule per channel."""
    endpoint = dict(_policy("EP-Monitor", ["Alpha Engine"]), channel="endpoint", severity="RULE_SEVERITY_HIGH")
    saas = dict(_policy("SaaS-File-Monitor", ["Alpha Engine"], action="OFLCASB_DLP_REPORT_INCIDENT"),
                channel="saas", saas_type="OFLCASB_DLP_FILE")
    email = dict(_policy("Email-Monitor", ["Alpha Engine"]), channel="email")
    for k, v in overrides.items():
        {"endpoint": endpoint, "saas": saas, "email": email}[k].update(v)
    return write_pack(
        tmp_path / f"v{next(_pack_seq)}", "multi",
        dicts=[_dict("Alpha Dict")],
        engines=[_engine("Alpha Engine", "(D:Alpha Dict)")],
        policies=[_policy("Web-Monitor", ["Alpha Engine"]), endpoint, saas, email],
        meta={"name": "Multi", "confidence_tweaks": []},
    )


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def test_all_channels_plan_and_resolve_tenants(tmp_path):
    client = make_client(casb_tenants=TENANTS)
    rep = pd.preflight(client, [multi_pack(tmp_path)], writes_enabled=True)
    pol = items_by(rep, "policy")
    assert rep["status"] in ("ready", "warnings"), rep["blockers"]
    assert {n: p["status"] for n, p in pol.items()} == {
        "Web-Monitor": pd.CREATE, "EP-Monitor": pd.CREATE, "SaaS-File-Monitor": pd.CREATE, "Email-Monitor": pd.CREATE}
    assert pol["SaaS-File-Monitor"]["detail"]["channel"] == "saas"
    # FILE rules bind to file-storage apps only; email rules to mail apps only.
    assert pol["SaaS-File-Monitor"]["detail"]["tenants"] == ["Acme Box", "Acme Google Workspace"]
    assert pol["Email-Monitor"]["detail"]["tenants"] == ["Acme M365 Mail"]
    assert "resource:SaaS tenant: Acme Box" in pol["SaaS-File-Monitor"]["depends_on"]
    assert rep["summary"]["channels"] == {"web": {"create": 1}, "endpoint": {"create": 1}, "saas": {"create": 1}, "email": {"create": 1}}
    # Per-channel order shifts and a SaaS scope impact.
    kinds = {(i["type"], i.get("channel")) for i in rep["impacts"]}
    assert ("order_shift", "endpoint") in kinds and ("order_shift", "saas") in kinds and ("saas_scope", "email") in kinds
    assert any(i["type"] == "monitor_only" for i in rep["impacts"])


def test_dependencies_are_listed_per_channel(tmp_path):
    client = make_client(casb_tenants=TENANTS)
    rep = pd.preflight(client, [multi_pack(tmp_path)], writes_enabled=True)
    deps = rep["dependencies"]
    by_req = {(d["channel"], d["requirement"]): d for d in deps}
    assert {d["channel"] for d in deps} == {"web", "endpoint", "saas", "email"}
    saas_tenants = next(d for d in deps if d["channel"] == "saas" and "tenant" in d["requirement"])
    assert saas_tenants["status"] == "ok" and "Acme Box (BOX)" in saas_tenants["detail"]
    email_tenants = next(d for d in deps if d["channel"] == "email" and "tenant" in d["requirement"])
    assert email_tenants["status"] == "ok" and "Acme M365 Mail" in email_tenants["detail"]
    ep_api = next(d for d in deps if d["channel"] == "endpoint" and "API" in d["requirement"])
    assert ep_api["status"] == "ok" and ep_api["rules"] == ["EP-Monitor"]
    zcc = next(d for d in deps if d["channel"] == "endpoint" and "app profile" in d["requirement"])
    assert zcc["status"] == "info"
    assert all("rules" in d and d["rules"] for d in deps)


def test_no_saas_tenants_blocks_only_saas_and_email(tmp_path):
    client = make_client(casb_tenants=[])
    rep = pd.preflight(client, [multi_pack(tmp_path)], writes_enabled=True)
    pol = items_by(rep, "policy")
    assert pol["Web-Monitor"]["status"] == pd.CREATE
    assert pol["EP-Monitor"]["status"] == pd.CREATE
    assert pol["SaaS-File-Monitor"]["status"] == pd.BLOCKED_DEPENDENCY
    assert "SaaS Application Tenants" in pol["SaaS-File-Monitor"]["reason"]
    assert pol["Email-Monitor"]["status"] == pd.BLOCKED_DEPENDENCY
    assert rep["status"] == "warnings"  # still deployable for the other channels
    dep = next(d for d in rep["dependencies"] if d["channel"] == "saas" and "tenant" in d["requirement"])
    assert dep["status"] == "missing"


def test_tenant_type_mismatch_explains_and_names_can_pin(tmp_path):
    # Only a Slack tenant: a FILE rule can't bind to it...
    client = make_client(casb_tenants=[tenant("Acme Slack", "SLACK", 504)])
    rep = pd.preflight(client, [multi_pack(tmp_path)], writes_enabled=True)
    saas = items_by(rep, "policy")["SaaS-File-Monitor"]
    assert saas["status"] == pd.BLOCKED_DEPENDENCY
    assert "Acme Slack (SLACK)" in saas["reason"] and "pin tenants by name" in saas["reason"]
    # ...unless the pack pins it explicitly.
    rep = pd.preflight(client, [multi_pack(tmp_path, saas={"tenants": ["Acme Slack"]})], writes_enabled=True)
    saas = items_by(rep, "policy")["SaaS-File-Monitor"]
    assert saas["status"] == pd.CREATE and saas["detail"]["tenants"] == ["Acme Slack"]
    # A pinned name that isn't onboarded is a clear miss.
    rep = pd.preflight(client, [multi_pack(tmp_path, saas={"tenants": ["Nope"]})], writes_enabled=True)
    assert "not onboarded: Nope" in items_by(rep, "policy")["SaaS-File-Monitor"]["reason"]


def test_channel_api_failure_blocks_that_channel_only(tmp_path):
    client = make_client(casb_tenants=TENANTS, endpoint_fail=True)
    rep = pd.preflight(client, [multi_pack(tmp_path)], writes_enabled=True)
    pol = items_by(rep, "policy")
    assert pol["EP-Monitor"]["status"] == pd.BLOCKED_DEPENDENCY
    assert "not licensed" in pol["EP-Monitor"]["reason"]
    assert pol["SaaS-File-Monitor"]["status"] == pd.CREATE
    assert rep["tenant"]["channel_errors"]["endpoint"]
    dep = next(d for d in rep["dependencies"] if d["channel"] == "endpoint" and "API" in d["requirement"])
    assert dep["status"] == "error"


def test_template_and_labels_resolve_or_block(tmp_path):
    client = make_client(casb_tenants=TENANTS, templates=[Obj(id=77, name="DLP Notice")], labels=[Obj(id=9, name="Compliance")])
    pack = multi_pack(tmp_path, endpoint={"notification_template": "DLP Notice", "labels": ["Compliance"]},
                      email={"notification_template": "Missing Template"})
    rep = pd.preflight(client, [pack], writes_enabled=True)
    pol = items_by(rep, "policy")
    assert pol["EP-Monitor"]["status"] == pd.CREATE
    assert "resource:Notification template: DLP Notice" in pol["EP-Monitor"]["depends_on"]
    assert "resource:Label: Compliance" in pol["EP-Monitor"]["depends_on"]
    assert pol["Email-Monitor"]["status"] == pd.BLOCKED_DEPENDENCY
    assert "Missing Template" in pol["Email-Monitor"]["reason"]
    assert "missing:Notification template: Missing Template" in pol["Email-Monitor"]["depends_on"]
    dep = next(d for d in rep["dependencies"] if d["requirement"] == "Notification template: Missing Template")
    assert dep["status"] == "missing"


def test_existing_channel_rule_is_reused(tmp_path):
    client = make_client(casb_tenants=TENANTS, endpoint_rules=[Obj(id=1, name="EP-Monitor", order=1, action="ALLOW")],
                         email_rules=[Obj(id=2, name="Email-Monitor", order=1, action="BLOCK")])
    rep = pd.preflight(client, [multi_pack(tmp_path)], writes_enabled=True)
    pol = items_by(rep, "policy")
    assert pol["EP-Monitor"]["status"] == pd.REUSE
    assert pol["Email-Monitor"]["status"] == pd.REUSE_DIFFERS
    assert "Email DLP rule" in pol["Email-Monitor"]["reason"]


def test_invalid_saas_type_is_reported(tmp_path):
    client = make_client(casb_tenants=TENANTS)
    rep = pd.preflight(client, [multi_pack(tmp_path, saas={"saas_type": "OFLCASB_DLP_NOPE"})], writes_enabled=True)
    saas = items_by(rep, "policy")["SaaS-File-Monitor"]
    assert saas["status"] == pd.BLOCKED_DEPENDENCY and "unknown saas_type" in saas["reason"]


def test_enforcing_actions_per_channel():
    assert pc.is_enforcing("saas", "OFLCASB_DLP_QUARANTINE")
    assert not pc.is_enforcing("saas", "OFLCASB_DLP_REPORT_INCIDENT")
    assert pc.is_enforcing("email", "BLOCK") and not pc.is_enforcing("email", "ALLOW")
    assert pc.is_enforcing("endpoint", "CONFIRM") and not pc.is_enforcing("endpoint", "ALLOW")


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def test_apply_dispatches_each_channel_with_wire_shaped_payloads(tmp_path):
    client = make_client(casb_tenants=TENANTS, templates=[Obj(id=77, name="DLP Notice")], labels=[Obj(id=9, name="Compliance")])
    pack = multi_pack(tmp_path, endpoint={"notification_template": "DLP Notice", "labels": ["Compliance"],
                                          "file_types": ["FTCATEGORY_SQL"]},
                      saas={"components": ["COMPONENT_FILE_ATTACHMENTS"]})
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied", res
    z = client.zia
    engine_id = z.dlp_engine.items[-1].id

    ep = z.endpoint_dlp_rules.added[0]
    assert ep["name"] == "EP-Monitor" and ep["order"] == 1 and ep["action"] == "ALLOW"
    assert ep["dlp_engines"] == [{"id": engine_id}]
    assert ep["device_trust_levels"] == list(pc.ENDPOINT_TRUST_LEVELS)
    assert ep["notification_template"] == {"id": 77} and ep["labels"] == [{"id": 9}]
    assert ep["file_types"] == ["FTCATEGORY_SQL"] and ep["without_content_inspection"] is False

    saas = z.casb_dlp_rules.added[0]
    assert saas["type"] == "OFLCASB_DLP_FILE" and saas["action"] == "OFLCASB_DLP_REPORT_INCIDENT"
    assert saas["cloud_app_tenants"] == [{"id": 501}, {"id": 502}]
    assert saas["dlp_engines"] == [{"id": engine_id}]
    assert saas["collaboration_scope"] == ["ANY"] and saas["components"] == ["COMPONENT_FILE_ATTACHMENTS"]

    em = z.outbound_email_dlp_rules.added[0]
    assert em["email_tenants"] == [{"id": 503}] and em["action"] == "ALLOW" and "rank" not in em

    web = z.dlp_web_rules.added[0]
    assert web["name"] == "Web-Monitor" and web["dlp_engines"] == [engine_id]  # web service reshapes ids itself

    by = {(r["kind"], r["name"]): r for r in res["results"]}
    assert by[("policy", "EP-Monitor")]["channel"] == "endpoint"
    rules = res["verification"]["multi"]["rules"]
    assert rules == {"web": {"total": 1, "ok": 1, "missing": []}, "endpoint": {"total": 1, "ok": 1, "missing": []},
                     "saas": {"total": 1, "ok": 1, "missing": []}, "email": {"total": 1, "ok": 1, "missing": []}}
    assert res["verification"]["multi"]["all_good"]


def test_apply_skips_blocked_channel_rules_and_reports_them(tmp_path):
    client = make_client(casb_tenants=[])
    pack = multi_pack(tmp_path)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied"
    by = {(r["kind"], r["name"]): r for r in res["results"]}
    assert by[("policy", "SaaS-File-Monitor")]["status"] == "skipped"
    assert by[("policy", "Email-Monitor")]["status"] == "skipped"
    assert client.zia.casb_dlp_rules.added == [] and client.zia.outbound_email_dlp_rules.added == []
    assert client.zia.endpoint_dlp_rules.added[0]["name"] == "EP-Monitor"
    assert "saas" not in res["verification"]["multi"]["rules"]


def test_plan_hash_changes_when_saas_tenants_change(tmp_path):
    pack = multi_pack(tmp_path)
    a = pd.preflight(make_client(casb_tenants=TENANTS), [pack], writes_enabled=True)["plan_hash"]
    b = pd.preflight(make_client(casb_tenants=TENANTS[:1]), [pack], writes_enabled=True)["plan_hash"]
    assert a != b


def test_web_only_packs_never_touch_channel_services(tmp_path, base_pack):
    client = FakeClient(dicts=[PREDEF_SSN])  # no channel services at all
    rep = pd.preflight(client, [base_pack], writes_enabled=True)
    assert rep["status"] == "ready"
    assert rep["dependencies"] and {d["channel"] for d in rep["dependencies"]} == {"web"}
