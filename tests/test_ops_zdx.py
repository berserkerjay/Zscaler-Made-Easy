"""ZDX probe setup (ops_zdx): three operation types on the Bulk changes
engine, tested against a fake ZDX configuration API that sits where the
SDK's request executor sits (create_request / execute), so the exact
request paths, bodies and order are what is checked. No tenant, no
network, no clock."""
from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import ops_zdx as oz
import pack_ops as ops

BASE = "/zdx/v1/config"
SCOPE = ao.scope_for(["zdx"], {})
NO_ZDX = ao.scope_for(["dlp", "zpa"], {"web_dlp": "zscaler"})
SUPPORTED = [{"provider": "MICROSOFT_LOGIN", "name": "Microsoft Login", "host": "login.microsoftonline.com"},
             {"provider": "MICROSOFT_TEAMS", "name": "Microsoft Teams", "host": "teams.microsoft.com"},
             {"provider": "ZOOM", "name": "Zoom", "host": "<prefix>.zoom.us"},
             {"provider": "BOX", "name": "Box", "host": "app.box.com"}]


class ApiError(Exception):
    """The shape of the SDK's ZscalerAPIError (status_code, error_code, error_message)."""

    def __init__(self, status, code, message):
        super().__init__(f"HTTP {status} {code} {message}")
        self.status_code, self.error_code, self.error_message = status, code, message


class Resp:
    def __init__(self, body):
        self._body = body

    def get_body(self):
        return copy.deepcopy(self._body)


class FakeZdx:
    """The ZDX configuration API as ops_zdx assumes it behaves: custom apps
    are created off into a collection; a predefined app gets ZDX's own Web
    and CloudPath probes (off); a CloudPath probe follows a Web probe that
    must exist; an active follower blocks turning off or deleting its Web
    probe; a predefined app cannot be deleted; an app with probes cannot be
    deleted. `frozen` makes any write an assertion error (a preview)."""

    def __init__(self):
        self.apps, self.mons, self.cols = [], [], []
        self.supported = copy.deepcopy(SUPPORTED)
        self.requests, self.writes = [], []
        self.frozen = False
        self.refused_hosts = set()
        self.fail = {}          # (method, path suffix) -> ApiError
        self.next_id = 1000
        self.on_read = None

    # the SDK request executor's interface
    def create_request(self, method, endpoint, body=None, headers=None, params=None):
        return {"method": method, "url": endpoint, "json": copy.deepcopy(body), "params": dict(params or {})}, None

    def execute(self, req):
        m, path = req["method"], unquote(req["url"])
        assert path.startswith(BASE), path
        p = path[len(BASE):]
        self.requests.append((m, p, req["params"]))
        if m != "GET":
            if self.frozen:
                raise AssertionError(f"write during a preview: {m} {p}")
            self.writes.append((m, p, req["json"]))
        elif self.on_read:
            self.on_read(p)
        for (fm, fp), err in list(self.fail.items()):
            if fm == m and p.endswith(fp):
                return None, err
        try:
            return Resp(self._route(m, p, req["json"], req["params"])), None
        except ApiError as e:
            return None, e

    # helpers
    def _id(self):
        self.next_id += 1
        return self.next_id

    def _app(self, key):
        return next((a for a in self.apps if str(a["id"]) == str(key) or (a["type"] == "PREDEFINED" and a.get("provider") == key)), None)

    def add_app(self, name, typ="CUSTOM", active=True, provider=None, prefix=None, col=None):
        a = {"id": self._id(), "name": name, "type": typ, "active": active, "collection": col or {"id": 1, "name": "Custom Apps Collection"}}
        if provider:
            a["provider"], a["prefix"] = provider, prefix
        self.apps.append(a)
        return a

    def add_mon(self, app, name, typ="WEB", active=True, url="", host="", follows=None, klass="CUSTOM"):
        m = {"id": self._id(), "name": name, "type": typ, "active": active, "class": klass, "application": {"id": app["id"], "name": app["name"]},
             "frequencyInSeconds": 300}
        if typ == "WEB":
            m["url"] = url
        else:
            m["host"] = host
            m["followWebMonitor"] = {"id": follows}
        self.mons.append(m)
        return m

    def _route(self, m, p, body, params):
        parts = [x for x in p.split("/") if x]
        if parts == ["applications"] and m == "GET":
            return {"items": self.apps}
        if parts == ["applications", "supported"]:
            assert params.get("type") == "PREDEFINED"
            return self.supported
        if parts == ["monitors"]:
            return self.mons
        if parts == ["collections"] and m == "GET":
            return self.cols
        if parts == ["collections"] and m == "POST":
            c = {"id": self._id(), "name": body["name"], "type": body["type"]}
            self.cols.append(c)
            return c
        if parts == ["applications"] and m == "POST":
            col = body.get("collection") or {}
            if not any(c["id"] == col.get("id") for c in self.cols):
                raise ApiError(400, "INVALID_COLLECTION", "collection is required")
            if body["type"] == "CUSTOM":
                assert body["active"] is False, "custom apps are created off"
                a = self.add_app(body["name"], active=False, col=col)
                return a
            a = self.add_app(body["name"], "PREDEFINED", active=False, provider=body["provider"], prefix=body.get("prefix"), col=col)
            sup = next(s for s in self.supported if s["provider"] == body["provider"])
            host = sup["host"].replace("<prefix>", body.get("prefix") or "")
            w = self.add_mon(a, f"{body['name']} Web Probe", url=f"https://{host}/", active=False, klass="ZSCALER")
            self.add_mon(a, f"{body['name']} CloudPath Probe", "TRACERT", host=host, follows=w["id"], active=False, klass="ZSCALER")
            return a
        app = self._app(parts[1]) if len(parts) > 1 and parts[0] == "applications" else None
        if parts[0] == "applications" and app is None:
            raise ApiError(404, "NOT_FOUND", "application not found")
        if len(parts) == 2 and m == "GET":
            return app
        if len(parts) == 3 and parts[2] in ("activate", "deactivate"):
            app["active"] = parts[2] == "activate"
            return app
        if len(parts) == 2 and m == "DELETE":
            if app["type"] == "PREDEFINED":
                raise ApiError(403, "FORBIDDEN", "predefined applications cannot be deleted")
            if any(x["application"]["id"] == app["id"] for x in self.mons):
                raise ApiError(409, "HAS_MONITORS", "delete the monitors first")
            self.apps.remove(app)
            return {}
        if parts[2] == "monitors" and len(parts) == 3 and m == "GET":
            return [x for x in self.mons if x["application"]["id"] == app["id"]]
        if parts[2] == "monitors" and len(parts) == 3 and m == "POST":
            if body["type"] == "WEB":
                host = oz.host_of(body["url"])
            else:
                host = body["host"]
                fid = (body.get("followWebMonitor") or {}).get("id")
                if not any(x["id"] == fid for x in self.mons):
                    raise ApiError(400, "INVALID_FOLLOW", "followWebMonitor must name a Web monitor")
            if host in self.refused_hosts:
                raise ApiError(400, "INVALID_HOST", f"The host {host} is not allowed")
            mon = self.add_mon(app, body["name"], body["type"], active=body["active"], url=body.get("url", ""), host=body.get("host", ""),
                               follows=(body.get("followWebMonitor") or {}).get("id"))
            mon["_body"] = body
            return mon
        mon = next((x for x in self.mons if str(x["id"]) == parts[3] and x["application"]["id"] == app["id"]), None)
        if mon is None:
            raise ApiError(404, "NOT_FOUND", "monitor not found")
        followers = [x for x in self.mons if x.get("followWebMonitor", {}).get("id") == mon["id"]]
        if len(parts) == 5:
            if parts[4] == "deactivate" and any(f["active"] for f in followers):
                raise ApiError(409, "FOLLOWED", "an active CloudPath monitor follows this monitor")
            mon["active"] = parts[4] == "activate"
            return mon
        if m == "DELETE":
            if followers:
                raise ApiError(409, "FOLLOWED", "a CloudPath monitor follows this monitor")
            self.mons.remove(mon)
            return {}
        raise AssertionError(f"unexpected {m} {p}")


def client_for(fake):
    return SimpleNamespace(zdx=SimpleNamespace(_request_executor=fake), zia=None, zpa=None)


@pytest.fixture
def zdx(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    fake = FakeZdx()
    return fake, client_for(fake)


def preview(fake, client, spec, scope=SCOPE):
    fake.frozen = True
    try:
        return ao.plan(client, spec, scope=scope, tenant_label="acme (zscalertwo)")
    finally:
        fake.frozen = False


def apply(fake, client, spec, prepared=None, **kw):
    prepared = prepared or preview(fake, client, spec)
    kw.setdefault("confirm_text", prepared.get("confirm_phrase") or "")
    return ao.execute(client, spec, plan_hash=prepared["plan_hash"], scope=SCOPE, writes_enabled=True, assessor="Jane Doe",
                      tenant_label="acme (zscalertwo)", **kw)


BEST = {"type": "zdx_probes", "template": "best_practice", "interval_minutes": 5, "protocol": "ADAPTIVE",
        "predefined": [{"provider": "MICROSOFT_LOGIN", "web": True, "cloudpath": True}],
        "custom": [{"name": "Intranet", "url": "https://intranet.example.com/home", "cloudpath": True}]}


def _writes(fake):
    return [(m, p) for m, p, _b in fake.writes]


# ── Scope ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("scopes", [[], ["dlp", "zpa", "zcc"], ["ZDX"], ["zdx "]], ids=["nothing", "others", "upper-case", "padded"])
def test_zdx_out_of_scope_is_refused_before_anything_is_read(zdx, scopes):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZDX ticked on the Scope page every ZDX type and its object list is refused before any request."""
    fake, client = zdx
    scope = ao.scope_for(scopes, {})
    for t in ("zdx_probes", "zdx_probe_state", "zdx_probe_delete"):
        with pytest.raises(ao.OperationError, match="ZDX is not ticked"):
            ao.plan(client, dict(BEST, type=t), scope=scope)
    with pytest.raises(ao.OperationError, match="ZDX is not ticked"):
        ao.read_objects(client, "zdx_apps", scope)
    assert fake.requests == []


# ── Plan: the template, the tenant's state, the exact ordered steps ─────

def test_best_practice_on_a_new_tenant_plans_collections_then_apps_in_zdx_order_and_writes_nothing(zdx):
    """ASVS V1.4.1 · CWE-841: the preview lists every step in the order it is written (collections, predefined app and its probes, custom app off, Web, CloudPath, app on) and sends no write."""
    fake, client = zdx
    p = preview(fake, client, BEST)
    assert p["status"] == "ready" and len(p["plan_hash"]) == 64 and fake.writes == []
    steps = [(u["kind"], u["object"]["name"], u["field"], u["after"]) for u in p["items"] if u["status"] == "change"]
    assert steps == [
        ("zdx_collection", "Predefined Apps Collection", "exists", True),
        ("zdx_app", "Microsoft 365 sign-in", "exists", True),
        ("zdx_probe_state", "Microsoft 365 sign-in Web probe (ZDX creates it)", "state", "on"),
        ("zdx_probe_state", "Microsoft 365 sign-in CloudPath probe (ZDX creates it)", "state", "on"),
        ("zdx_app_state", "Microsoft 365 sign-in", "state", "on"),
        ("zdx_collection", "Custom Apps Collection", "exists", True),
        ("zdx_app", "Intranet", "exists", True),
        ("zdx_probe", "Intranet Web probe", "exists", True),
        ("zdx_probe", "Intranet CloudPath probe", "exists", True),
        ("zdx_app_state", "Intranet", "state", "on"),
    ]
    assert any("In the tenant now: 0 ZDX app(s)" in n for n in p["notes"])
    assert any("assumed" in n for n in p["notes"]) and any("ZDX applies each change" in n for n in p["notes"])
    assert {r[0] for r in fake.requests} == {"GET"}
    assert ("GET", "/applications/supported", {"type": "PREDEFINED"}) in fake.requests


def test_apply_creates_and_turns_on_everything_in_order_reads_back_and_offers_undo(zdx):
    """ASVS V1.4.1 · V11.1.1 · CWE-841: apply writes through the shared path in ZDX's order, the CloudPath probe follows the new Web probe, and the read-back confirms every step."""
    fake, client = zdx
    res = apply(fake, client, BEST)
    assert res["status"] == "applied", res.get("logs")
    w = _writes(fake)
    pre = next(a for a in fake.apps if a["type"] == "PREDEFINED")
    cus = next(a for a in fake.apps if a["type"] == "CUSTOM")
    web = next(m for m in fake.mons if m["application"]["id"] == cus["id"] and m["type"] == "WEB")
    path = next(m for m in fake.mons if m["application"]["id"] == cus["id"] and m["type"] == "TRACERT")
    assert w[0] == ("POST", "/collections") and w[1] == ("POST", "/applications")
    assert w[-4:] == [("POST", "/applications"), ("POST", f"/applications/{cus['id']}/monitors"),
                      ("POST", f"/applications/{cus['id']}/monitors"), ("PUT", f"/applications/{cus['id']}/activate")]
    assert ("PUT", "/applications/MICROSOFT_LOGIN/activate") in w
    assert path["followWebMonitor"] == {"id": web["id"]} and path["_body"]["protocol"] == "ADAPTIVE"
    assert web["_body"]["frequencyInSeconds"] == 300 and web["_body"]["onUsers"] == [] and web["_body"]["excludedGroups"] == []
    assert cus["active"] and pre["active"] and all(m["active"] for m in fake.mons)
    body = next(b for m, p, b in fake.writes if p == "/applications" and b["type"] == "CUSTOM")
    assert body["description"] == "ZDX probe setup by Jane Doe" and "Zscaler Made Easy" not in json.dumps(fake.writes)
    v = res["verification"]
    assert v["checked"] == v["confirmed"] and v["checked"] >= 8 and not v["mismatched"]
    inv = res["inverse"]
    assert inv["type"] == "zdx_probe_delete" and inv["targets"] == [{"app": str(cus["id"]), "probe": None, "name": "Intranet"}]
    assert {t["app"] for t in inv["turn_off"]} == {"MICROSOFT_LOGIN"} and inv["turn_off"][-1]["probe"] is None


def test_existing_apps_are_skipped_or_get_only_their_missing_probes(zdx):
    """ASVS V1.4.1 · CWE-841: an app already on with its probes is skipped; an existing custom app gets only the CloudPath probe it lacks; nothing else is touched."""
    fake, client = zdx
    fake.cols = [{"id": 1, "name": "Custom Apps Collection"}, {"id": 2, "name": "Predefined Apps Collection"}]
    pre = fake.add_app("Microsoft Login", "PREDEFINED", provider="MICROSOFT_LOGIN", col={"id": 2, "name": "Predefined Apps Collection"})
    w = fake.add_mon(pre, "ML Web", url="https://login.microsoftonline.com/", klass="ZSCALER")
    fake.add_mon(pre, "ML Path", "TRACERT", host="login.microsoftonline.com", follows=w["id"], klass="ZSCALER")
    intra = fake.add_app("Intranet")
    web = fake.add_mon(intra, "Intranet Web probe", url="https://intranet.example.com/")
    p = preview(fake, client, BEST)
    changes = [u for u in p["items"] if u["status"] == "change"]
    assert [(u["kind"], u["object"]["name"]) for u in changes] == [("zdx_probe", "Intranet CloudPath probe")]
    assert {u["reason"] for u in p["items"] if u["status"] == "noop"} >= {"already set up", "already on"}
    res = apply(fake, client, BEST, p)
    assert res["status"] == "applied" and _writes(fake) == [("POST", f"/applications/{intra['id']}/monitors")]
    assert fake.writes[0][2]["followWebMonitor"] == {"id": web["id"]}
    assert res["inverse"] == {"type": "zdx_probe_delete", "targets": [
        {"app": str(intra["id"]), "probe": str(fake.mons[-1]["id"]), "name": "Intranet CloudPath probe"}], "turn_off": []}


def test_a_custom_app_with_the_same_name_probing_another_url_is_blocked(zdx):
    """ASVS V5.1.3 · CWE-20: an existing custom app with that name but another URL blocks the plan instead of mixing two sites."""
    fake, client = zdx
    a = fake.add_app("Intranet")
    fake.add_mon(a, "Intranet Web probe", url="https://other.example.org/")
    p = preview(fake, client, dict(BEST, predefined=[]))
    assert p["status"] == "blocked" and "probes https://other.example.org/" in p["blockers"][0]


def test_a_refused_host_is_shown_in_zdx_words_and_the_half_created_app_is_removed(zdx):
    """ASVS V7.4.1 · V11.1.1 · CWE-460: when ZDX refuses the CloudPath host, the error says so plainly and the custom app and its Web probe are deleted again, probes first."""
    fake, client = zdx
    fake.cols = [{"id": 1, "name": "Custom Apps Collection"}, {"id": 2, "name": "Predefined Apps Collection"}]
    fake.refused_hosts.add("intranet.example.com")
    fake.fail = {}
    spec = dict(BEST, custom=[{"name": "Intranet", "url": "https://intranet.example.com/", "cloudpath": True},
                              {"name": "Wiki", "url": "https://wiki.example.net/", "cloudpath": False}])
    # The Web probe is accepted; ZDX refuses the host only for the CloudPath probe.
    real = fake._route

    def route(m, p, body, params):
        if m == "POST" and p.endswith("/monitors") and body["type"] == "WEB":
            fake.refused_hosts.discard("intranet.example.com")
            try:
                return real(m, p, body, params)
            finally:
                fake.refused_hosts.add("intranet.example.com")
        return real(m, p, body, params)
    fake._route = route
    res = apply(fake, client, spec)
    assert res["status"] == "partial"
    failed = next(u for u in res["items"] if u["status"] == "failed")
    assert failed["error"].startswith("HTTP 400 · INVALID_HOST: The host intranet.example.com is not allowed")
    assert "refused the host or URL" in failed["explanation"]
    assert not any(a["name"] == "Intranet" for a in fake.apps), "the half-created app was removed"
    dels = [p for m, p in _writes(fake) if m == "DELETE"]
    assert len(dels) == 2 and "/monitors/" in dels[0] and "/monitors/" not in dels[1]
    assert any(u["status"] == "rolled_back" for u in res["items"])
    assert any(a["name"] == "Wiki" and a["active"] for a in fake.apps), "the other apps still went ahead"
    assert any("Removed what was created for 'Intranet'" in line for line in res["logs"])


def test_a_predefined_app_that_needs_a_prefix_is_left_out_without_one_and_refused_with_a_bad_one(zdx):
    """ASVS V5.1.3 · CWE-20: a predefined app whose host needs the customer's prefix is left out (said so) without one, and a malformed prefix blocks the plan."""
    fake, client = zdx
    spec = dict(BEST, custom=[], predefined=[{"provider": "ZOOM"}])
    p = preview(fake, client, spec)
    assert p["status"] == "nothing_to_do" and "left out: enter the customer's prefix" in p["items"][0]["reason"]
    p = preview(fake, client, dict(spec, predefined=[{"provider": "ZOOM", "prefix": "-bad-"}]))
    assert p["status"] == "blocked" and "not a tenant prefix" in p["blockers"][0]
    p = preview(fake, client, dict(spec, predefined=[{"provider": "ZOOM", "prefix": "acme"}]))
    assert p["status"] == "ready" and p["items"][1]["object"]["host"] == "acme.zoom.us"


def test_an_app_zdx_does_not_offer_is_excluded(zdx):
    """ASVS V5.1.3 · CWE-20: a provider outside the tenant's predefined catalogue is excluded with the reason."""
    fake, client = zdx
    p = preview(fake, client, dict(BEST, custom=[], predefined=[{"provider": "WEBEX", "prefix": "acme"}]))
    assert p["items"][0]["status"] == "excluded" and "does not offer" in p["items"][0]["reason"]


@pytest.mark.parametrize("change,needle", [
    ({"interval_minutes": 7}, "interval must be one of 5, 10, 15, 30"),
    ({"interval_minutes": 4}, "interval must be one of"),
    ({"protocol": "HTTP"}, "protocol must be one of Adaptive, ICMP, TCP, UDP"),
    ({"predefined": [], "custom": []}, "at least one"),
    ({"custom": [{"name": f"a{i}", "url": "https://x.example.com/"} for i in range(21)]}, "At most"),
    ({"predefined": [{"provider": "../x"}]}, "provider"),
    ({"custom": [{"name": "x", "url": "https://x.example.com/", "cloudpath": "yes"}]}, "true or false"),
], ids=["interval-7", "interval-below", "protocol", "empty", "too-many", "bad-provider", "bool"])
def test_bad_requests_are_refused_before_anything_is_read(zdx, change, needle):
    """ASVS V5.1.3 · V5.1.4 · CWE-20: a malformed setup (interval, protocol, limits, field types) is a 400 before any request to ZDX."""
    fake, client = zdx
    with pytest.raises(ao.OperationError, match=needle):
        ao.plan(client, dict(BEST, **change), scope=SCOPE)
    assert fake.requests == []


@pytest.mark.parametrize("url,why", [
    ("ftp://x.example.com/", "must start with https:// or http://"),
    ("https://user:pw@x.example.com/", "user name or password"),
    ("https://x example.com/", "spaces"),
    ("https://localhost/", "not a valid host name"),
    ("https://" + "a" * 1020 + ".com/", "longer than"),
    ("", "enter the app's URL"),
], ids=["ftp", "credentials", "space", "single-label", "too-long", "empty"])
def test_custom_app_urls_are_checked_in_the_plan(zdx, url, why):
    """ASVS V5.1.3 · V5.1.5 · CWE-20: a custom app URL that is not an http(s) URL with a valid host (or carries credentials) blocks the plan, with the reason."""
    fake, client = zdx
    p = preview(fake, client, dict(BEST, predefined=[], custom=[{"name": "X", "url": url}]))
    assert p["status"] == "blocked" and why in " ".join(p["blockers"]) and fake.writes == []


def test_the_tenant_moving_after_the_preview_writes_nothing(zdx):
    """ASVS V11.1.1 · CWE-367: someone creating the same app between preview and apply changes the plan hash: plan_changed, nothing written."""
    fake, client = zdx
    p = preview(fake, client, BEST)
    fake.add_app("Intranet")
    res = ao.execute(client, BEST, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor="Jane Doe")
    assert res["status"] == "plan_changed" and fake.writes == []


def test_an_app_created_between_the_re_plan_and_its_write_is_a_conflict_not_a_duplicate(zdx):
    """ASVS V11.1.1 · CWE-367: the re-read right before the create finds the app someone just made and skips it, never creating a second."""
    fake, client = zdx
    fake.cols = [{"id": 1, "name": "Custom Apps Collection"}]
    spec = dict(BEST, predefined=[])
    p = preview(fake, client, spec)
    reads = {"n": 0}

    def sneak(path):
        reads["n"] += 1
        if path == "/applications" and reads["n"] == 4:   # the handler's re-read, after the re-plan's three reads
            fake.add_app("Intranet")
    fake.on_read = sneak
    res = apply(fake, client, spec, p)
    assert fake.writes == [] and {u["status"] for u in res["items"]} == {"conflict"}
    assert "created since the preview" in res["items"][0]["reason"]


# ── On and off ──────────────────────────────────────────────────────────

def _tenant_with_app(fake, active=True):
    fake.cols = [{"id": 1, "name": "Custom Apps Collection"}]
    a = fake.add_app("Intranet", active=active)
    w = fake.add_mon(a, "Intranet Web probe", url="https://intranet.example.com/", active=active)
    c = fake.add_mon(a, "Intranet CloudPath probe", "TRACERT", host="intranet.example.com", follows=w["id"], active=active)
    return a, w, c


def test_turning_off_sends_cloudpath_before_web_before_the_app_and_undo_turns_them_back_on(zdx):
    """ASVS V1.4.1 · V11.1.1 · CWE-841: off goes CloudPath, Web, app (ZDX refuses a Web probe off under an active follower); the undo is the opposite change."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    spec = {"type": "zdx_probe_state", "targets": [{"app": a["id"], "to": "off"}, {"app": a["id"], "probe": w["id"], "to": "off"},
                                                   {"app": a["id"], "probe": c["id"], "to": "off"}]}
    res = apply(fake, client, spec)
    assert res["status"] == "applied", res["logs"]
    assert _writes(fake) == [("PUT", f"/applications/{a['id']}/monitors/{c['id']}/deactivate"),
                             ("PUT", f"/applications/{a['id']}/monitors/{w['id']}/deactivate"), ("PUT", f"/applications/{a['id']}/deactivate")]
    assert res["verification"]["confirmed"] == 3
    inv = res["inverse"]
    assert inv["type"] == "zdx_probe_state" and {t["to"] for t in inv["targets"]} == {"on"}
    fake.writes.clear()
    back = apply(fake, client, inv)
    assert back["status"] == "applied" and [p for _m, p in _writes(fake)][0] == f"/applications/{a['id']}/activate"
    assert a["active"] and w["active"] and c["active"]


def test_state_change_warns_about_a_follower_left_on_and_skips_what_is_already_so(zdx):
    """ASVS V1.4.1 · CWE-841: turning a Web probe off while its CloudPath follower stays on is warned about; a target already off is a no-op."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    p = preview(fake, client, {"type": "zdx_probe_state", "targets": [{"app": a["id"], "probe": w["id"], "to": "off"},
                                                                      {"app": a["id"], "probe": "999999", "to": "off"}]})
    assert any("follows 'Intranet Web probe' and stays on" in x for x in p["warnings"])
    assert [u["status"] for u in p["items"]] == ["excluded", "change"] or [u["status"] for u in p["items"]] == ["change", "excluded"]
    a["active"] = False
    p = preview(fake, client, {"type": "zdx_probe_state", "targets": [{"app": a["id"], "to": "off"}]})
    assert p["status"] == "nothing_to_do" and p["items"][0]["status"] == "noop"


def test_a_probe_renamed_after_the_re_plan_is_left_alone(zdx):
    """ASVS V11.1.1 · CWE-367: the re-read before a state write finds the probe renamed and does not touch it."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    spec = {"type": "zdx_probe_state", "targets": [{"app": a["id"], "probe": c["id"], "to": "off"}]}
    p = preview(fake, client, spec)
    n = {"reads": 0}

    def rename(path):
        n["reads"] += 1
        if n["reads"] == 3:
            c["name"] = "Renamed"
    fake.on_read = rename
    res = apply(fake, client, spec, p)
    assert fake.writes == [] and res["items"][0]["status"] == "conflict" and "now called 'Renamed'" in res["items"][0]["reason"]


# ── Delete ──────────────────────────────────────────────────────────────

def test_delete_needs_the_exact_name_and_goes_probes_first_cloudpath_before_web(zdx):
    """ASVS V4.2.2 · V11.1.1 · CWE-352 · CWE-841: a delete whose typed name does not match excludes the app and writes nothing; the exact name deletes CloudPath, Web, then the app."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    wrong = {"type": "zdx_probe_delete", "targets": [{"app": a["id"], "name": "intranet"}]}
    p = preview(fake, client, wrong)
    assert p["status"] == "nothing_to_do" and p["items"][0]["status"] == "excluded" and "exact name" in p["items"][0]["reason"]
    right = {"type": "zdx_probe_delete", "targets": [{"app": a["id"], "name": "Intranet"}]}
    res = apply(fake, client, right)
    assert res["status"] == "applied" and fake.apps == [] and fake.mons == []
    assert _writes(fake) == [("DELETE", f"/applications/{a['id']}/monitors/{c['id']}"), ("DELETE", f"/applications/{a['id']}/monitors/{w['id']}"),
                             ("DELETE", f"/applications/{a['id']}")]
    assert res["inverse"] is None and res["verification"]["confirmed"] == 3


def test_predefined_apps_zscaler_probes_and_followed_web_probes_are_not_deleted(zdx):
    """ASVS V4.1.3 · CWE-284: a predefined app, one of Zscaler's own probes and a Web probe a CloudPath probe follows are excluded with the way out."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    pre = fake.add_app("Microsoft Login", "PREDEFINED", provider="MICROSOFT_LOGIN")
    zp = fake.add_mon(pre, "ML Web", url="https://login.microsoftonline.com/", klass="ZSCALER")
    p = preview(fake, client, {"type": "zdx_probe_delete", "targets": [{"app": "MICROSOFT_LOGIN", "name": "Microsoft Login"},
                                                                       {"app": "MICROSOFT_LOGIN", "probe": zp["id"], "name": "ML Web"},
                                                                       {"app": a["id"], "probe": w["id"], "name": "Intranet Web probe"}]})
    reasons = [u["reason"] for u in p["items"]]
    assert p["status"] == "nothing_to_do" and all(u["status"] == "excluded" for u in p["items"])
    assert "turn it off instead" in reasons[0] and "Zscaler's own probes" in reasons[1] and "delete the CloudPath probe first" in reasons[2]
    both = preview(fake, client, {"type": "zdx_probe_delete", "targets": [{"app": a["id"], "probe": w["id"], "name": "Intranet Web probe"},
                                                                          {"app": a["id"], "probe": c["id"], "name": "Intranet CloudPath probe"}]})
    assert both["status"] == "ready" and [u["object"]["name"] for u in both["items"]] == ["Intranet CloudPath probe", "Intranet Web probe"]


def test_a_probe_added_after_the_preview_stops_the_app_delete(zdx):
    """ASVS V11.1.1 · CWE-367: deleting an app re-reads its probes; one added since the preview stops the delete and nothing is removed."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    spec = {"type": "zdx_probe_delete", "targets": [{"app": a["id"], "name": "Intranet"}]}
    p = preview(fake, client, spec)
    n = {"reads": 0}

    def add(path):
        n["reads"] += 1
        if path.endswith("/monitors") and path.startswith("/applications/"):
            if not any(m["name"] == "Late probe" for m in fake.mons):
                fake.add_mon(a, "Late probe", url="https://intranet.example.com/late")
    fake.on_read = add
    res = apply(fake, client, spec, p)
    assert fake.writes == [] and "got the probe 'Late probe'" in res["items"][0]["reason"]


def test_undo_of_a_setup_deletes_what_it_created_and_turns_off_the_predefined_app(zdx):
    """ASVS V1.4.1 · V11.1.1 · CWE-841: Undo previews and applies the inverse: the new custom app goes (probes first), the predefined app ZDX keeps is turned off."""
    fake, client = zdx
    res = apply(fake, client, BEST)
    inv = res["inverse"]
    fake.writes.clear()
    p = preview(fake, client, inv)
    assert p["status"] == "ready" and p["title"] == "Undo a ZDX probe setup"
    back = apply(fake, client, inv, p)
    assert back["status"] == "applied", back["logs"]
    assert [a["name"] for a in fake.apps] == ["Microsoft 365 sign-in"] and not fake.apps[0]["active"]
    assert all(not m["active"] for m in fake.mons)
    w = _writes(fake)
    assert w.index(("PUT", "/applications/MICROSOFT_LOGIN/deactivate")) < w.index(next(x for x in w if x[0] == "DELETE"))


# ── Errors and run control ──────────────────────────────────────────────

def test_a_permission_refusal_stops_the_run_in_zdx_words(zdx):
    """ASVS V7.4.1 · V8.3.4 · CWE-209: a 403 on a ZDX write stops the remaining writes and says what to change, in ZDX's terms (not ZIA's DLP policy)."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    fake.fail[("PUT", "/deactivate")] = ApiError(403, "FORBIDDEN", "Forbidden")
    spec = {"type": "zdx_probe_state", "targets": [{"app": a["id"], "probe": c["id"], "to": "off"}, {"app": a["id"], "to": "off"}]}
    res = apply(fake, client, spec)
    assert res["status"] == "failed" and len(fake.writes) == 1
    assert "change ZDX configuration" in res["stopped"] and "DLP policy" not in res["stopped"]
    assert res["items"][0]["explanation"].startswith("ZDX refused it")
    assert res["items"][1]["status"] == "skipped"


def test_the_zdx_configuration_api_not_answering_blocks_the_plan_with_the_reason(zdx):
    """ASVS V7.4.1 · CWE-755: a ZDX configuration API that answers 404 blocks the plan with what ZDX said and why, instead of planning blind."""
    fake, client = zdx
    fake.fail[("GET", "/applications")] = ApiError(404, "NOT_FOUND", "no such API")
    p = preview(fake, client, BEST)
    assert p["status"] == "blocked" and "HTTP 404 · NOT_FOUND: no such API" in p["blockers"][0] and "not available" in p["blockers"][0]


def test_a_classic_api_sign_in_has_no_zdx_access_and_says_so(zdx):
    """ASVS V7.4.1 · CWE-755: a client without a OneAPI request executor (the classic ZIA sign-in) gets a blocked plan, not a crash."""
    p = ao.plan(SimpleNamespace(zia=None), BEST, scope=SCOPE)
    assert p["status"] == "blocked" and "OneAPI" in p["blockers"][0]


def test_stop_during_the_preview_reads_nothing_more(zdx):
    """ASVS V11.1.4 · CWE-400: Stop during the preview ends the reads at once and nothing is planned."""
    fake, client = zdx
    ev = threading.Event()
    fake.on_read = lambda path: ev.set()
    with pytest.raises(ao.Stopped):
        ao.plan(client, BEST, scope=SCOPE, cancel=ev)
    assert len(fake.requests) == 1 and fake.writes == []


def test_every_zdx_write_leaves_an_audit_entry_without_the_body(zdx, tmp_path, monkeypatch):
    """ASVS V7.1.3 · V7.2.1 · CWE-778: every ZDX create, update and delete is one object_write audit entry (type, name, result), never the request body."""
    fake, client = zdx
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    apply(fake, client, dict(BEST, predefined=[]))
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    writes = [r for r in rows if r.get("event") == "object_write"]
    assert {r["object_type"] for r in writes} == {"zdx_collection", "zdx_app", "zdx_probe"} and len(writes) == len(fake.writes)
    assert all(r["result"] == "ok" for r in writes) and "intranet.example.com/home" not in log.read_text()


def test_sdk_error_objects_and_plain_words():
    """ASVS V7.4.1 · CWE-209: what ZDX said is kept (status, code, message) and explained by status, including a refused host."""
    parts = oz.error_parts(ApiError(400, "INVALID_HOST", "host not allowed"))
    assert oz.describe(parts) == "HTTP 400 · INVALID_HOST: host not allowed"
    assert "host or URL" in oz.explain(400, "INVALID_HOST", "host not allowed")
    assert "sign-in" in oz.explain(401) and "conflict" in oz.explain(409) and "rate limit" in oz.explain(429) and "busy" in oz.explain(503)
    assert oz.error_parts({"status": "403", "message": "x"}) == {"status": 403, "code": None, "message": "x"}


def test_the_sdk_executor_routes_zdx_config_paths_to_oneapi_and_keeps_the_body_as_sent():
    """SSDF PW.4.1 · CWE-1357: the installed SDK's request executor (the verified part) sends /zdx/v1/config/... as a ZDX request and leaves camelCase ZDX bodies untouched."""
    from zscaler.request_executor import RequestExecutor
    ex = RequestExecutor.__new__(RequestExecutor)
    ex.use_legacy_client, ex.zdx_legacy_client, ex.ztb_legacy_client = False, None, None
    assert ex.get_service_type("/zdx/v1/config/applications") == "zdx"
    body = {"frequencyInSeconds": 300, "followWebMonitor": {"id": 1}, "onUsers": []}
    assert ex._prepare_body("/zdx/v1/config/applications/1/monitors", dict(body)) == body


# ── The form's data and the endpoints ───────────────────────────────────

def test_read_objects_lists_every_app_and_probe_with_what_may_be_deleted(zdx):
    """ASVS V1.4.1 · CWE-200: the object list has every app and probe with its state, which may be deleted, the predefined catalogue with the tenant's state, templates and choices."""
    fake, client = zdx
    a, w, c = _tenant_with_app(fake)
    pre = fake.add_app("Microsoft Login", "PREDEFINED", provider="MICROSOFT_LOGIN", active=False)
    fake.add_mon(pre, "ML Web", url="https://login.microsoftonline.com/", klass="ZSCALER")
    out = ao.read_objects(client, "zdx_apps", SCOPE)["zdx"]
    assert [x["name"] for x in out["apps"]] == ["Microsoft Login", "Intranet"]
    assert out["apps"][0]["deletable"] is False and out["apps"][0]["probes"][0]["deletable"] is False
    assert out["apps"][1]["deletable"] and [p["kind"] for p in out["apps"][1]["probes"]] == ["web", "cloudpath"]
    ml = next(x for x in out["catalogue"] if x["provider"] == "MICROSOFT_LOGIN")
    assert ml["configured"] and not ml["active"] and next(x for x in out["catalogue"] if x["provider"] == "ZOOM")["needs_prefix"]
    assert [t["id"] for t in out["templates"]] == ["best_practice", "microsoft_365", "empty"]
    assert out["intervals"] == [5, 10, 15, 30] and out["protocols"] == ["ADAPTIVE", "ICMP", "TCP", "UDP"]
    assert fake.writes == []


BODY = {"scopes": ["zdx"], "channels": {}, "from_page": True, "client_id": "cid", "client_secret": "s3cret-value", "vanity_domain": "acme",
        "cloud": "zscalertwo", "assessor": "Jane Doe"}


def test_endpoints_preview_apply_record_and_undo_through_the_bulk_changes_routes(zdx, monkeypatch):
    """ASVS V1.4.1 · V4.1.3 · V7.1.3 · CWE-841: the ZDX types use the Bulk changes routes: the scope gate before sign-in, preview, apply with every gate, the record and its Undo."""
    import dlp_api_server as srv
    fake, client = zdx
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    c = TestClient(srv.app)
    assert any(p["type"] == "zdx_probes" and p["script"] == "ops_zdx.js" for p in c.get("/api/operations/plugins").json()["plugins"])
    r = c.post("/api/operations/preview", json=dict(BODY, scopes=["dlp"], operation=BEST))
    assert r.status_code == 400 and "ZDX is not ticked" in r.json()["detail"] and fake.requests == []
    r = c.post("/api/operations/objects", json=dict(BODY, family="zdx_apps"))
    assert r.status_code == 200 and "zdx" in r.json()
    r = c.post("/api/operations/preview", json=dict(BODY, operation=BEST))
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["counts"]["change"] == 10 and p["confirm_phrase"] == "" and fake.writes == [] and "s3cret" not in r.text
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    r = c.post("/api/operations/apply", json=dict(BODY, operation=BEST, plan_hash=p["plan_hash"], confirm=True))
    assert r.status_code == 403 and fake.writes == []
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    assert c.post("/api/operations/apply", json=dict(BODY, operation=BEST, plan_hash=p["plan_hash"], confirm=True, assessor="")).status_code == 400
    r = c.post("/api/operations/apply", json=dict(BODY, operation=BEST, plan_hash=p["plan_hash"], confirm=True))
    assert r.status_code == 200 and r.json()["status"] == "applied", r.text
    op_id = r.json()["operation_id"]
    rec = c.get(f"/api/operations/{op_id}").json()
    assert rec["type"] == "zdx_probes" and rec["product"] == "zdx" and rec["inverse"]["type"] == "zdx_probe_delete"
    u = c.post(f"/api/operations/{op_id}/undo/preview", json=BODY).json()
    assert u["undo_of"] == op_id and u["counts"]["change"] >= 3
    r = c.post("/api/operations/apply", json=dict(BODY, operation=u["operation"], plan_hash=u["plan_hash"], confirm=True, undo_of=op_id))
    assert r.status_code == 200 and r.json()["status"] == "applied"
    assert not any(a["type"] == "CUSTOM" for a in fake.apps)


def test_the_form_script_registers_the_three_types_with_the_page():
    """WCAG 2.2 SC 1.3.1 · 3.3.2 · ASVS V5.3.3 · CWE-79: static/ops_zdx.js registers each ZDX type with the Bulk changes page, labels its inputs and escapes tenant text."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "ops_zdx.js"), encoding="utf-8").read()
    for t in ("zdx_probes", "zdx_probe_state", "zdx_probe_delete"):
        assert f"type: '{t}'" in js
    assert "window.OPS_PLUGINS.register" in js and "aria-label" in js and "H.E(" in js
    assert "innerHTML" in js and not __import__("re").search(r"#[0-9a-fA-F]{3,6}\b", js)
