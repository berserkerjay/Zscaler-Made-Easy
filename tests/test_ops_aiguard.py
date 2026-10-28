"""AI Guard builders on the Bulk changes engine (ops_aiguard) and the
read-only readiness check (ai_guard.readiness), against a fake tenant that
answers like ZIA and AI Guard where it matters: raw camelCase bodies behind
the SDK's (data, response, error) tuples, ids assigned on create, a
proxy gateway the API can only read, and a frozen mode in which any write
fails the test (a preview never writes)."""
from __future__ import annotations

import copy
import re
import threading

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import ai_guard as ag
import ops_aiguard as oa
import pack_channels as pc

PEM = "-----BEGIN CERTIFICATE-----\n" + ("MIIBszCCAVmgAwIBAgIUQ2VydGlmaWNhdGUgZm9yIHRlc3RzIG9ubHkwCgYIKoZIzj0E" * 3) + "\n-----END CERTIFICATE-----"


def _camel(k):
    p = str(k).split("_")
    return p[0] + "".join(x[:1].upper() + x[1:] for x in p[1:])


def _wire(v):
    """What the SDK sends: keys in camelCase, recursively."""
    if isinstance(v, dict):
        return {_camel(k): _wire(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_wire(x) for x in v]
    return v


class Resp:
    def __init__(self, body):
        self._body = copy.deepcopy(body)

    def get_body(self):
        return copy.deepcopy(self._body)

    def get_results(self):
        return copy.deepcopy(self._body) if isinstance(self._body, list) else []

    def has_next(self):
        return False


def ok(data):
    return copy.deepcopy(data), Resp(data), None


def refused(message, status=404):
    return None, None, {"status": status, "message": message}


class Tenant:
    def __init__(self):
        self.writes = []
        self.frozen = False
        self.next_id = 1000
        self.read_error = None

    def nid(self):
        self.next_id += 1
        return self.next_id

    def write(self, what):
        if self.frozen:
            raise AssertionError(f"write during a read-only step: {what}")
        self.writes.append(what)


class Store:
    """One object collection with list / get / add / update / delete under
    the SDK method names given."""

    def __init__(self, t, name, rows=(), name_key="name"):
        self.t, self.name, self.rows, self.name_key = t, name, [copy.deepcopy(r) for r in rows], name_key

    def _find(self, oid):
        return next((r for r in self.rows if str(r["id"]) == str(oid)), None)

    def list(self, *a, **k):
        if self.t.read_error:
            return refused(self.t.read_error, 403)
        return ok(self.rows)

    def get(self, oid):
        r = self._find(oid)
        return ok(r) if r else refused("not found", 404)

    def add(self, body):
        self.t.write((self.name, "add", body.get(self.name_key) or body.get("configuredName")))
        row = dict(_wire(body), id=self.t.nid())
        self.rows.append(row)
        return ok(row)

    def update(self, oid, body):
        self.t.write((self.name, "update", oid))
        r = self._find(oid)
        if r is None:
            return refused("not found", 404)
        r.update(_wire(body))
        r["id"] = r.get("id") if r.get("id") is not None else oid
        return ok(r)

    def delete(self, oid):
        self.t.write((self.name, "delete", oid))
        r = self._find(oid)
        if r is None:
            return refused("not found", 404)
        self.rows.remove(r)
        return None, Resp({}), None


class Svc:
    def __init__(self, **methods):
        self.__dict__.update(methods)


class Executor:
    """The SDK's request executor, for the calls the SDK has no method for:
    root certificates and activation."""

    def __init__(self, t, certs):
        self.t, self.certs = t, certs

    def create_request(self, method, url, body=None, headers=None, params=None):
        return {"method": method, "url": url, "body": body}, None

    def execute(self, req):
        m, url = req["method"], req["url"]
        if url.endswith("/status"):
            return Resp({"status": "ACTIVE"}), None
        if url.endswith("/status/activate"):
            self.t.write(("zia", "activate", None))
            return Resp({"status": "ACTIVE"}), None
        if "/rootCertificates" in url:
            if m == "GET":
                return Resp(self.certs.rows), None
            if m == "POST":
                return Resp(self.certs.add(req["body"])[0]), None
            if m == "DELETE":
                self.certs.delete(url.rsplit("/", 1)[1])
                return Resp({}), None
        return None, {"status": 404, "message": f"no such path {url}"}


class Fake:
    """A ZIA and AI Guard tenant with an AI Guard subscription but nothing
    built yet, apart from what the test adds."""

    def __init__(self, *, gateway=False, proxy=False, licensed=True, settings=None, ssl_rules=(), cac_rules=(), url_rules=(),
                 policies=(), match_rules=(), providers=("Default OpenAI Provider", "Default Anthropic Provider")):
        t = self.t = Tenant()
        certs = Store(t, "certs", [{"id": 11, "name": "AI Guard CA"}])
        proxies = Store(t, "proxies", [{"id": 21, "name": "AIG-Proxy", "type": "PROXYCHAIN", "address": ag.AI_GUARD_HOST, "port": 9443,
                                        "cert": {"id": 11, "name": "AI Guard CA"}}] if proxy else [])
        gws = Store(t, "gateways", [{"id": 31, "name": "AIG-Gateway", "primaryProxy": {"id": 21, "name": "AIG-Proxy"}, "failClosed": True}]
                    if gateway else [])
        groups = Store(t, "ipgroups")
        nws = Store(t, "nwservices", [{"id": 41, "name": "QUIC", "tag": "QUIC"}, {"id": 42, "name": "HTTPS"}])
        fw = Store(t, "firewall")
        ssl = Store(t, "ssl", ssl_rules)
        fwd = Store(t, "forwarding")
        cac = Store(t, "cac", cac_rules)
        url = Store(t, "url", url_rules)
        cats = Store(t, "categories", [], name_key="configured_name")
        self.settings = dict(settings if settings is not None else {"enableChatGptPrompt": False, "enableMicrosoftCoPilotPrompt": False,
                                                                     "enableGeminiPrompt": True, "enableClaudePrompt": False, "enableMsftO365": True,
                                                                     "enforceSafeSearch": True})
        subs = [{"id": "ZIA_BUS", "status": "ACTIVE", "subscribed": True}] + ([{"id": "ZS_DP_GEN_AI", "status": "ACTIVE", "subscribed": True}] if licensed else [])
        ex = Executor(t, certs)
        fake = self

        def settings_get():
            return None, Resp(fake.settings), None

        def settings_put(**kw):
            t.write(("settings", "update", None))
            fake.settings = _wire(kw)
            return ok(fake.settings)

        def rule_svc(s):
            return Svc(list_rules=s.list, get_rule=s.get, add_rule=lambda **kw: s.add(kw), update_rule=lambda rid, **kw: s.update(rid, kw),
                       delete_rule=s.delete, _request_executor=ex)

        def cac_add(rule_type, **kw):
            return cac.add(dict(kw, type=rule_type))
        self.stores = {"certs": certs, "proxies": proxies, "gateways": gws, "groups": groups, "firewall": fw, "ssl": ssl, "forwarding": fwd,
                       "cac": cac, "url": url, "categories": cats}
        self.zia = Svc(
            proxies=Svc(list_proxies=proxies.list, list_proxy_gateways=gws.list, get_proxy=proxies.get, add_proxy=lambda **kw: proxies.add(kw),
                        delete_proxy=proxies.delete, _request_executor=ex),
            endpoint_dlp_rules=Svc(_request_executor=ex),
            cloud_firewall=Svc(list_ip_destination_groups=groups.list, get_ip_destination_group=groups.get,
                               add_ip_destination_group=lambda **kw: groups.add(kw),
                               update_ip_destination_group=lambda gid, query_params=None, **kw: groups.update(gid, kw),
                               delete_ip_destination_group=groups.delete, list_network_services=nws.list),
            cloud_firewall_rules=rule_svc(fw), ssl_inspection_rules=rule_svc(ssl), forwarding_control=rule_svc(fwd),
            url_filtering=Svc(list_rules=url.list, get_rule=url.get, add_rule=lambda **kw: url.add(kw), update_rule=lambda rid, **kw: url.update(rid, kw),
                              delete_rule=url.delete, get_url_and_app_settings=settings_get, update_url_and_app_settings=settings_put),
            cloudappcontrol=Svc(list_rules=lambda rt: cac.list(), get_rule=lambda rt, rid: cac.get(rid), add_rule=cac_add,
                                update_rule=lambda rt, rid, **kw: cac.update(rid, kw), delete_rule=lambda rt, rid: cac.delete(rid)),
            url_categories=Svc(lookup=lambda urls: ([{"url": u, "urlClassifications": ["AI_ML_APPS"]} for u in urls], None),
                               list_categories=lambda query_params=None: cats.list(), get_category=cats.get,
                               add_url_category=lambda super_category=None, urls=None, configured_name=None, **kw: cats.add(
                                   dict(kw, super_category=super_category, urls=urls, configured_name=configured_name)),
                               update_url_category=lambda cid, action=None, **kw: cats.update(cid, kw), delete_category=cats.delete),
            organization_information=Svc(get_subscriptions=lambda: (None, Resp(subs), None)),
        )
        pol = Store(t, "aig_policies", policies)
        rules = Store(t, "aig_rules", match_rules)
        prov = Store(t, "aig_providers", [{"id": i + 1, "name": n} for i, n in enumerate(providers)])
        self.stores.update(aig_policies=pol, aig_rules=rules)
        self.aiguard = Svc(
            policies=Svc(list_policies=pol.list, get_policy=pol.get, add_policy=lambda **kw: pol.add(kw),
                         update_policy=lambda pid, **kw: pol.update(pid, kw), delete_policy=pol.delete),
            policy_match_rules=Svc(list_rules=rules.list, get_rule=rules.get, add_rule=lambda **kw: rules.add(kw),
                                   update_rule=lambda rid, **kw: rules.update(rid, kw), delete_rule=rules.delete),
            llm_providers=Svc(list_providers=prov.list))


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")


FULL = ao.scope_for(["zia_extras", "aiguard"], {"ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
ZIA_ONLY = ao.scope_for(["zia_extras"], {"ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
AIG_ONLY = ao.scope_for(["aiguard"], {})
NO_SSL = ao.scope_for(["zia_extras", "aiguard"], {"ssl_inspection": "alternative", "cloud_app_control": "alternative"})
ROUTE = {"type": "aiguard_routing", "apps": ["chatgpt", "claude", "m365copilot"], "cert": {"mode": "existing", "id": 11}}
POLICY = {"type": "aiguard_detection_policy", "profile": "HIPAA", "apps": ["chatgpt", "claude"]}


def preview(f, spec, scope=FULL):
    f.t.frozen = True
    try:
        return ao.plan(f, spec, scope=scope, tenant_label="acme")
    finally:
        f.t.frozen = False


def apply(f, spec, scope=FULL, prepared=None):
    p = prepared or preview(f, spec, scope)
    return ao.execute(f, spec, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor="Jane Doe", tenant_label="acme",
                      confirm_text=p.get("confirm_phrase") or "", settle_seconds=0)


def by_key(res):
    return {u["key"]: u for u in res["items"]}


# ── scope ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("spec,scope", [(ROUTE, ZIA_ONLY), (ROUTE, AIG_ONLY), (POLICY, ZIA_ONLY)],
                         ids=["routing-without-aiguard", "routing-without-zia", "policy-without-aiguard"])
def test_out_of_scope_is_refused_before_anything_is_read(spec, scope):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a builder outside the Scope page selection is refused before its plan reads anything."""
    # Arrange
    f = Fake()
    f.t.read_error = "must not be read"
    # Act / Assert
    with pytest.raises(ao.OperationError, match="not in scope"):
        ao.plan(f, spec, scope=scope)
    assert f.t.writes == []


def test_scope_key_is_known_to_the_scope_page_and_the_permissions_catalogue():
    """ASVS V4.1.3 · CWE-272: the AI Guard scope key is a Scope page key with a label and a permissions entry."""
    import data_flow
    import scope_permissions
    assert "aiguard" in data_flow.SCOPE_KEYS and data_flow.SCOPE_LABELS["aiguard"] == "AI Guard"
    assert scope_permissions.get_scope_permissions("aiguard")["label"] == "AI Guard"


# ── readiness ────────────────────────────────────────────────────────────

def test_readiness_on_an_empty_tenant_names_every_missing_part_and_the_portal_step():
    """ASVS V1.4.1 · CWE-1188: readiness reads only, says AI Guard is reachable and names the missing proxy, gateway (portal step) and rule."""
    # Arrange
    f = Fake()
    f.t.frozen = True
    # Act
    rd = ag.readiness(f)
    # Assert
    st = {c["id"]: c["status"] for c in rd["checks"]}
    assert st["aiguard.api"] == "pass" and st["zia.genai_license"] == "pass" and st["zia.root_ca"] == "pass"
    assert st["zia.proxy"] == "warn" and st["zia.gateway"] == "fail" and st["zia.forwarding"] == "warn"
    gw = next(c for c in rd["checks"] if c["id"] == "zia.gateway")
    assert "cannot create proxy gateways" in gw["detail"] and "Proxy Gateways" in gw["fix"]
    assert rd["ready"] is False and rd["zia"]["o365_one_click"] is True and rd["assumed"]


def test_readiness_finds_an_existing_proxy_and_gateway():
    """ASVS V1.4.1 · CWE-1188: an AI Guard proxy and its gateway already in ZIA are found and reported as ready."""
    f = Fake(proxy=True, gateway=True)
    rd = ag.readiness(f)
    st = {c["id"]: c["status"] for c in rd["checks"]}
    assert st["zia.proxy"] == "pass" and st["zia.gateway"] == "pass"
    assert rd["zia"]["proxies"][0]["gateway"] == "AIG-Gateway"


@pytest.mark.parametrize("err,words", [({"status": 403, "message": "Forbidden"}, "role"), ({"status": 404, "message": "Not Found"}, "not provisioned")])
def test_readiness_explains_an_unreachable_ai_guard(err, words):
    """ASVS V7.4.1 · CWE-209: an AI Guard refusal is explained in plain words without echoing the request."""
    f = Fake()
    f.aiguard.policies.list_policies = lambda: (None, None, err)
    rd = ag.readiness(f, zia=False)
    c = next(c for c in rd["checks"] if c["id"] == "aiguard.api")
    assert c["status"] == "fail" and words in c["detail"]


def test_readiness_reads_only_the_sides_in_scope():
    """ASVS V4.1.3 · CWE-272: with only AI Guard in scope, ZIA is not read (and the other way round)."""
    f = Fake()
    f.zia = None
    rd = ag.readiness(f, zia=False)
    assert rd["zia"]["read"] is False and rd["aiguard"]["read"] is True
    g = Fake()
    g.aiguard = None
    rd2 = ag.readiness(g, aiguard=False)
    assert rd2["aiguard"]["read"] is False and rd2["zia"]["read"] is True


def test_readiness_with_the_classic_api_sign_in_says_ai_guard_needs_oneapi():
    """ASVS V1.4.1 · CWE-1188: a client without AI Guard (classic ZIA API) is reported, never an exception."""
    f = Fake()
    del f.aiguard
    rd = ag.readiness(f, zia=False)
    assert "OneAPI" in rd["checks"][0]["detail"]


# ── routing: plan ────────────────────────────────────────────────────────

def test_routing_preview_writes_nothing_and_leaves_the_gateway_to_the_portal():
    """ASVS V1.4.1 · CWE-841: the routing preview reads only, plans each object, and leaves the gateway and the forwarding rule as a portal step."""
    # Arrange
    f = Fake()
    # Act
    p = preview(f, ROUTE)
    # Assert
    k = by_key(p)
    assert f.t.writes == [] and p["status"] == "ready" and len(p["plan_hash"]) == 64
    assert k["cert"]["status"] == "noop" and k["proxy"]["status"] == "change" and k["group"]["status"] == "change"
    assert k["gateway"]["status"] == "excluded" and "portal" in k["gateway"]["reason"]
    assert k["fwd"]["status"] == "excluded" and "gateway" in k["fwd"]["reason"]
    assert k["quic"]["status"] == "change" and k["ssl"]["status"] == "change" and k["prompt"]["status"] == "change"
    assert k["prompt"]["field"] == "enableChatGptPrompt, enableMicrosoftCoPilotPrompt, enableClaudePrompt"
    assert any("Proxy Gateways" in n for n in p["notes"]) and any("WebSocket" in w for w in p["warnings"])
    assert p["needs_activation"] is True


def test_routing_without_a_certificate_or_proxy_is_blocked():
    """ASVS V1.4.1 · CWE-20: no AI Guard proxy and no certificate chosen blocks the plan with the reason."""
    p = preview(Fake(), dict(ROUTE, cert={}))
    assert p["status"] == "blocked" and "root certificate" in p["blockers"][0]


@pytest.mark.parametrize("bad", [{"apps": ["notanapp"]}, {"prefix": "../x"}, {"proxy_host": "evil.example.com"},
                                 {"cert": {"mode": "upload", "pem": "not a pem"}}, {"cert": {"mode": "upload", "pem": PEM + "A" * 20000}},
                                 {"cert": {"mode": "existing", "id": "1; DROP"}}, {"cert": {"mode": "other"}}])
def test_routing_input_is_validated(bad):
    """ASVS V5.1.3 · CWE-20: unknown apps, a bad prefix, a non-AI Guard forwarder and a bad certificate are refused before any write."""
    f = Fake()
    with pytest.raises(ao.OperationError):
        preview(f, dict(ROUTE, **bad))
    assert f.t.writes == []


def test_ssl_and_cloud_app_control_out_of_scope_are_excluded_and_not_read():
    """ASVS V4.1.3 · CWE-272: SSL inspection and Cloud App Control not marked Zscaler are neither read nor changed."""
    f = Fake(cac_rules=[{"id": 5, "name": "Block AI", "type": "AI_ML", "order": 1, "state": "ENABLED", "actions": ["BLOCK_AI_ML_WEB_USE"]}])
    f.zia.ssl_inspection_rules = None
    f.zia.cloudappcontrol = None
    k = by_key(preview(f, ROUTE, NO_SSL))
    assert k["ssl"]["status"] == "excluded" and "not in scope" in k["ssl"]["reason"]
    assert k["allow"]["status"] == "excluded" and "not in scope" in k["allow"]["reason"]


def test_prompt_capture_is_left_off_without_the_licence_and_with_partial_settings():
    """ASVS V1.4.1 · CWE-1188: prompt capture is planned only with the Gen AI Security subscription and a complete settings object."""
    k = by_key(preview(Fake(licensed=False), ROUTE))
    assert k["prompt"]["status"] == "excluded" and "subscription" in k["prompt"]["reason"]
    f = Fake()
    f.zia.url_filtering.get_url_and_app_settings = lambda: ({"enableChatGptPrompt": False}, None, None)
    k = by_key(preview(f, ROUTE))
    assert k["prompt"]["status"] == "excluded" and "part of the settings" in k["prompt"]["reason"]


# ── routing: apply, read back, undo ──────────────────────────────────────

def test_routing_applies_in_order_activates_once_reads_back_and_undo_restores_the_tenant():
    """ASVS V1.4.1 · V11.1.1 · CWE-841: the routing applies through pack_ops in dependency order, activates once, is read back, and Undo deletes what it created and puts back what it changed."""
    # Arrange
    dni = {"id": 7, "name": "Office 365 One Click Rule", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "predefined": True}
    f = Fake(proxy=True, gateway=True, ssl_rules=[dni],
             cac_rules=[{"id": 5, "name": "Caution AI", "type": "AI_ML", "order": 1, "state": "ENABLED", "actions": ["CAUTION_AI_ML_WEB_USE"]}],
             url_rules=[{"id": 9, "name": "Block AI", "order": 1, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["AI_ML_APPS"]}])
    before_settings = dict(f.settings)
    # Act
    res = apply(f, ROUTE)
    # Assert
    k = by_key(res)
    assert res["status"] == "applied", [(u["key"], u["status"], u.get("reason"), u.get("error")) for u in res["items"]]
    assert [w for w in f.t.writes if w[1] == "activate"] == [("zia", "activate", None)] or res["activation"]["activated"]
    order = [w[0] for w in f.t.writes if w[1] == "add"]
    assert order.index("ipgroups") < order.index("ssl") and order.index("ipgroups") < order.index("forwarding")
    assert order.index("categories") < order.index("url")
    assert k["proxy"]["status"] == "noop" and k["fwd"]["status"] == "applied" and k["allow"]["status"] == "applied"
    ssl = next(r for r in f.stores["ssl"].rows if r["name"] == "AIG-Inspect")
    assert ssl["order"] == 1 and ssl["action"]["type"] == "DECRYPT" and "By Jane Doe." in ssl["description"]
    fwd = f.stores["forwarding"].rows[0]
    assert fwd["forwardMethod"] == "PROXYCHAIN" and fwd["proxyGateway"]["id"] == 31
    assert fwd["destIpGroups"][0]["id"] == f.stores["groups"].rows[0]["id"]
    assert f.settings["enableChatGptPrompt"] is True and f.settings["enforceSafeSearch"] is True
    assert res["verification"]["confirmed"] == res["verification"]["checked"] > 0 and not res["verification"]["mismatched"]
    inv = res["inverse"]
    assert inv["action"] == "undo" and inv["steps"][0]["op"] == "delete"
    # Undo: previewed and applied like any other operation
    rec = ao.record(res, by="Jane Doe")
    assert rec and rec["inverse"] == inv
    undo = apply(f, inv)
    assert undo["status"] == "applied", [(u["key"], u["status"], u.get("reason")) for u in undo["items"]]
    assert undo["verification"]["confirmed"] == undo["verification"]["checked"] > 0, undo["verification"]
    for s in ("groups", "firewall", "forwarding", "categories"):
        assert f.stores[s].rows == [], s
    assert [r["name"] for r in f.stores["ssl"].rows] == ["Office 365 One Click Rule"]
    assert [r["name"] for r in f.stores["cac"].rows] == ["Caution AI"] and [r["name"] for r in f.stores["url"].rows] == ["Block AI"]
    assert f.settings == before_settings
    assert undo["inverse"] is None


def test_routing_creates_the_certificate_and_proxy_when_uploading():
    """ASVS V1.4.1 · CWE-841: an uploaded certificate is created first and the new proxy names its id."""
    f = Fake()
    res = apply(f, dict(ROUTE, cert={"mode": "upload", "pem": PEM}, block_quic=False, ssl_inspect=False, prompt_capture=False, allow_in_zia=False))
    assert res["status"] == "applied"
    cert = next(c for c in f.stores["certs"].rows if c["name"] == "AIG-CA")
    assert cert["certTypes"] == ["PROXY_CHAINING"]
    proxy = f.stores["proxies"].rows[0]
    assert proxy["cert"]["id"] == cert["id"] and proxy["address"] == ag.AI_GUARD_HOST and proxy["port"] == 9443


def test_a_second_run_changes_nothing():
    """ASVS V1.4.1 · CWE-841: applying the same routing twice is a no-op the second time (idempotent)."""
    f = Fake(proxy=True, gateway=True)
    assert apply(f, ROUTE)["status"] == "applied"
    p = preview(f, ROUTE)
    assert p["status"] == "nothing_to_do", [(u["key"], u["status"]) for u in p["items"]]


def test_the_plan_is_refused_when_the_tenant_moved_and_a_changed_object_is_a_conflict():
    """ASVS V1.4.1 · V11.1.1 · CWE-367: a different plan hash writes nothing; an object changed between the plan and its write is skipped."""
    f = Fake(proxy=True, gateway=True)
    p = preview(f, ROUTE)
    stale = ao.execute(f, ROUTE, plan_hash="0" * 64, scope=FULL, writes_enabled=True, assessor="Jane Doe", settle_seconds=0)
    assert stale["status"] == "plan_changed" and f.t.writes == []
    with pytest.raises(PermissionError):
        ao.execute(f, ROUTE, plan_hash=p["plan_hash"], scope=FULL, writes_enabled=False)
    real_add = f.stores["ssl"].add

    def add_then_someone_else(body):   # an admin turns ChatGPT capture on between the plan and its write
        f.settings["enableChatGptPrompt"] = True
        return real_add(body)
    f.stores["ssl"].add = add_then_someone_else
    f.zia.ssl_inspection_rules.add_rule = lambda **kw: f.stores["ssl"].add(kw)
    res = apply(f, ROUTE, prepared=p)
    k = by_key(res)
    assert k["prompt"]["status"] == "conflict" and ("settings", "update", None) not in f.t.writes
    assert k["ssl"]["status"] == "applied" and res["status"] == "partial"


# ── the detection policy ────────────────────────────────────────────────

def test_monitor_policy_detects_and_blocks_nothing():
    """ASVS V1.4.1 · CWE-1188: the default (Monitor) policy has no BLOCK action anywhere."""
    body = oa.build_policy("AIG-Policy", "HIPAA", "monitor")
    actions = re.findall(r"'action': '(\w+)'", str(body))
    assert "BLOCK" not in actions and "DETECT" in actions
    blocked = oa.build_policy("AIG-Policy", "PCI", "block")
    ents = {e["entityType"]: e["action"] for d in blocked["inputDetectorPolicies"] if d["detector"] == "pii" for e in d["configuration"]["entities"]}
    assert ents["CREDIT_CARD"] == "BLOCK" and ents["PERSON"] == "DETECT" and ents["US_PASSPORT"] == "DISABLE"


@pytest.mark.parametrize("profile", sorted(ag.PROFILES))
def test_every_profile_builds_both_detector_sides(profile):
    """ASVS V5.1.3 · CWE-20: every compliance profile builds input and output detectors (AI Guard refuses a one-sided policy)."""
    body = oa.build_policy("AIG-Policy", profile, "monitor")
    assert body["inputDetectorPolicies"] and body["outputDetectorPolicies"]


def test_policy_applies_reads_back_and_undo_deletes_both():
    """ASVS V1.4.1 · V11.1.1 · CWE-841: the policy and its match rule are created (rule after the tenant's rules, matching the apps' providers), read back, and undone."""
    f = Fake(match_rules=[{"id": 3, "name": "Theirs", "policyId": 1, "ruleOrder": 4, "enabled": True,
                           "matchCriteria": {"type": "APPLICATION", "llmProviders": [{"llmProvider": "Default OpenAI Provider"}]}}])
    p = preview(f, POLICY, AIG_ONLY)
    assert p["needs_activation"] is False and any("AI Guard applies each change" in n for n in p["notes"])
    assert any("Theirs" in w for w in p["warnings"])
    res = apply(f, POLICY, AIG_ONLY, prepared=p)
    assert res["status"] == "applied" and res["activation"] is None
    pol = next(x for x in f.stores["aig_policies"].rows if x["name"] == "AIG-Policy")
    rule = next(x for x in f.stores["aig_rules"].rows if x["name"] == "AIG-Policy-Apps")
    assert rule["policyId"] == pol["id"] and rule["ruleOrder"] == 5
    assert [x["llmProvider"] for x in rule["matchCriteria"]["llmProviders"]] == ["Default OpenAI Provider", "Default Anthropic Provider"]
    assert res["verification"]["confirmed"] == 2
    undo = apply(f, res["inverse"], AIG_ONLY)
    assert undo["status"] == "applied" and [x["name"] for x in f.stores["aig_rules"].rows] == ["Theirs"] and f.stores["aig_policies"].rows == []


def test_switching_to_block_updates_the_policy_and_undo_puts_monitor_back():
    """ASVS V1.4.1 · CWE-841: an existing policy is updated (only its detectors) and Undo restores the earlier detectors."""
    f = Fake()
    assert apply(f, POLICY, AIG_ONLY)["status"] == "applied"
    before = copy.deepcopy(f.stores["aig_policies"].rows[0])
    res = apply(f, dict(POLICY, mode="block"), AIG_ONLY)
    k = by_key(res)
    assert k["policy"]["status"] == "applied" and k["rule"]["status"] == "noop"
    assert "BLOCK" in str(f.stores["aig_policies"].rows[0]["inputDetectorPolicies"])
    undo = apply(f, res["inverse"], AIG_ONLY)
    assert undo["status"] == "applied"
    assert oa.canon(f.stores["aig_policies"].rows[0]["inputDetectorPolicies"], "input_detector_policies") == \
        oa.canon(before["inputDetectorPolicies"], "input_detector_policies")


def test_no_matching_provider_excludes_the_rule():
    """ASVS V1.4.1 · CWE-1188: apps without an AI Guard provider leave the match rule out with the reason."""
    k = by_key(preview(Fake(providers=()), POLICY, AIG_ONLY))
    assert k["rule"]["status"] == "excluded" and "provider" in k["rule"]["reason"]


@pytest.mark.parametrize("bad", [{"profile": "NOPE"}, {"mode": "enforce"}, {"apps": "chatgpt"}])
def test_policy_input_is_validated(bad):
    """ASVS V5.1.3 · CWE-20: an unknown profile, mode or a non-list of apps is refused."""
    with pytest.raises(ao.OperationError):
        preview(Fake(), dict(POLICY, **bad), AIG_ONLY)


# ── Undo input is untrusted ─────────────────────────────────────────────

@pytest.mark.parametrize("steps", [
    [{"kind": "zia_proxy", "op": "delete", "id": 21, "name": "Customer proxy"}],                    # not made by this builder
    [{"kind": "ssl_rule", "op": "update", "id": 7, "name": "AIG-Inspect", "set": {"name": "x"}, "expect": {"name": "y"}}],   # a field it never sets
    [{"kind": "dlp_rule", "op": "delete", "id": 1, "name": "AIG-x"}],                               # an unknown kind
    [{"kind": "aiguard_policy", "op": "delete", "id": 1, "name": "AIG-Policy"}],                     # the other product
    [{"kind": "zia_proxy", "op": "create", "id": 1, "name": "AIG-x"}],                              # only delete or update
    [],
])
def test_an_undo_spec_cannot_widen_what_the_builder_may_change(steps):
    """ASVS V4.2.1 · V5.1.3 · CWE-639 · CWE-20: a crafted Undo cannot delete or change objects this builder did not make or fields it does not set."""
    f = Fake(proxy=True)
    with pytest.raises(ao.OperationError):
        preview(f, {"type": "aiguard_routing", "action": "undo", "steps": steps})


def test_undo_keeps_an_object_renamed_or_changed_since():
    """ASVS V1.4.1 · CWE-367: Undo deletes only an object that still has the name it was given, and restores only fields still as written."""
    f = Fake(proxy=True, gateway=True)
    res = apply(f, dict(ROUTE, ssl_inspect=False, allow_in_zia=False, block_quic=False))
    f.stores["groups"].rows[0]["name"] = "Renamed by admin"
    f.settings["enableClaudePrompt"] = False
    k = by_key(preview(f, res["inverse"]))
    assert any(u["status"] == "excluded" and "renamed" in u["reason"] for u in k.values())
    assert any(u["status"] == "excluded" and "someone else" in u["reason"] for u in k.values())


# ── the page and the catalogue ──────────────────────────────────────────

def test_both_builders_are_in_the_catalogue_with_their_form():
    """ASVS V14.3.3 · CWE-200: the Bulk changes catalogue lists both AI Guard builders and their form script, nothing callable."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    for t in ("aiguard_routing", "aiguard_detection_policy"):
        assert cat[t]["script"] == "ops_aiguard.js" and cat[t]["group"] == "Build new"


def test_genai_findings_link_to_the_builder():
    """WCAG 2.2 SC 2.4.4 · ASVS V1.4.1: GenAI findings that AI Guard addresses carry a link to the Bulk changes builder; a pass carries none."""
    import zscaler_genai_checks as g
    link = g.tool_link("AI.6", "FAIL")
    assert link["href"].startswith("/report/operations?build=aiguard_routing") and link["build"] == "aiguard_routing" and link["label"]
    assert g.tool_link("AI.13", "REVIEW")["href"].endswith("aiguard_detection_policy")
    assert g.tool_link("AI.6", "PASS") is None and g.tool_link("AI.16", "FAIL") is None


def test_the_form_script_is_served():
    """ASVS V14.4.1 · CWE-116: the builder form is a static script the page loads from /static."""
    import dlp_api_server as srv
    r = TestClient(srv.app).get("/static/ops_aiguard.js")
    assert r.status_code == 200 and "OPS_PLUGINS.register" in r.text
