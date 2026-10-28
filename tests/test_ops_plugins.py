"""Operation plugins (admin_ops.register): a builder is one more operation
type on the Bulk changes engine, so it inherits the scope check before any
read, the plan hash, the re-plan before writing, the write-mode refusal,
read-back verification and an inverse for Undo."""
from __future__ import annotations

import pytest

import admin_ops as ao
import pack_ops as ops


class Box:
    """A fake product holding named objects; records every write."""

    def __init__(self):
        self.objects = {}
        self.writes = []


class Client:
    def __init__(self):
        self.zpa = Box()
        self.zia = None


def _plan(client, spec, scope, say, cancel):
    names = [str(n) for n in spec.get("names") or []]
    if not names:
        raise ao.OperationError("Name at least one object.")
    items, groups = [], []
    for i, n in enumerate(names):
        exists = n in client.zpa.objects
        items.append(ao._unit(f"o{i}", f"g{i}", "demo_object", {"name": n, "type": "demo"}, "exists", exists, True,
                              status="noop" if exists else "change", reason="already there" if exists else ""))
        groups.append({"key": f"g{i}", "handler": "demo_create", "target": {"name": n}})
    return {"type": "demo_build", "product": "zpa", "title": f"Create {len(names)} demo objects", "spec": spec,
            "items": items, "groups": groups}


def _create(run, group, units):
    name = group["target"]["name"]
    run.client.zpa.objects[name] = {"name": name}
    run.client.zpa.writes.append(("create", name))
    run.outcome(units, ops.Outcome(ok=True, id=name), "create")


def _verify(run):
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    ok = [u for u in applied if u["object"]["name"] in run.client.zpa.objects]
    for u in applied:
        u["verified"] = u in ok
    return {"checked": len(applied), "confirmed": len(ok), "mismatched": [], "unread": []}


def _inverse(result):
    made = [u["object"]["name"] for u in result.get("items") or [] if u.get("status") == "applied"]
    return {"type": "demo_build", "names": made, "action": "delete"} if made else None


@pytest.fixture
def demo_plugin(monkeypatch):
    monkeypatch.setattr(ao, "PLUGINS", {})
    monkeypatch.setattr(ao, "PLUGIN_FAMILIES", {})
    monkeypatch.setattr(ao, "PLUGIN_HANDLERS", {})
    monkeypatch.setattr(ao, "_plugins_loaded", True)
    ao.register("demo_build", family="demo_objects", product="zpa", label="Create demo objects", hint="A test builder.",
                in_scope=lambda scope: None if scope.get("zpa") else "ZPA is not ticked on the Scope page.",
                plan=_plan, read_objects=lambda client, scope, say, cancel: {"objects": sorted(client.zpa.objects)},
                handlers={"demo_create": _create}, verify=_verify, inverse=_inverse, script="ops_demo_build.js")
    return ao


ZPA_SCOPE = ao.scope_for(["zpa"], {})
NO_ZPA = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})


def test_a_plugin_out_of_scope_is_refused_before_anything_is_read(demo_plugin):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a plugin type outside the Scope page selection is refused before its plan reads anything."""
    client = Client()
    with pytest.raises(ao.OperationError, match="ZPA is not ticked"):
        ao.plan(client, {"type": "demo_build", "names": ["a"]}, scope=NO_ZPA)
    with pytest.raises(ao.OperationError, match="ZPA is not ticked"):
        ao.read_objects(client, "demo_objects", NO_ZPA)
    assert client.zpa.writes == []


def test_a_plugin_plan_is_hashed_and_never_writes(demo_plugin):
    """ASVS V1.4.1 · CWE-841: a plugin's preview carries a plan hash and counts, and writes nothing."""
    client = Client()
    client.zpa.objects["b"] = {"name": "b"}
    p = ao.plan(client, {"type": "demo_build", "names": ["a", "b"]}, scope=ZPA_SCOPE, tenant_label="acme")
    assert p["status"] == "ready" and len(p["plan_hash"]) == 64 and p["counts"] == {"change": 1, "noop": 1, "excluded": 0, "total": 2}
    assert client.zpa.writes == []


def test_a_plugin_applies_through_the_shared_gates_and_reads_back(demo_plugin):
    """ASVS V1.4.1 · V11.1.1 · CWE-841: apply refuses without write mode, re-plans against the hash, writes, verifies and offers an inverse."""
    client = Client()
    spec = {"type": "demo_build", "names": ["a"]}
    p = ao.plan(client, spec, scope=ZPA_SCOPE)
    with pytest.raises(PermissionError):
        ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZPA_SCOPE, writes_enabled=False)
    assert client.zpa.writes == []
    stale = ao.execute(client, spec, plan_hash="0" * 64, scope=ZPA_SCOPE, writes_enabled=True, assessor="Jane Doe")
    assert stale["status"] == "plan_changed" and client.zpa.writes == []
    res = ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZPA_SCOPE, writes_enabled=True, assessor="Jane Doe")
    assert res["status"] == "applied" and client.zpa.writes == [("create", "a")]
    assert res["verification"]["confirmed"] == 1
    assert res["inverse"] == {"type": "demo_build", "names": ["a"], "action": "delete"}


def test_plugin_names_and_scripts_are_validated(demo_plugin):
    """ASVS V5.1.3 · CWE-20: a plugin cannot take a built-in name, a malformed name, a taken handler or a script outside static/ops_*.js."""
    base = dict(family="fam_x", product="zpa", label="x", hint="x", in_scope=lambda s: None, plan=_plan,
                read_objects=lambda *a: {}, handlers={"h_x": _create})
    with pytest.raises(ValueError):
        ao.register("rule_state", **base)
    with pytest.raises(ValueError):
        ao.register("Bad Name", **base)
    with pytest.raises(ValueError):
        ao.register("good_name", **dict(base, script="../x.js"))
    with pytest.raises(ValueError):
        ao.register("good_name", **dict(base, handlers={"rule_state": _create}))


def test_the_catalog_lists_plugins_without_callables(demo_plugin):
    """ASVS V14.3.3 · CWE-200: the page's catalog of plugin types carries names and labels only."""
    cat = ao.plugin_catalog()
    assert cat == [{"type": "demo_build", "family": "demo_objects", "product": "zpa", "label": "Create demo objects",
                    "hint": "A test builder.", "group": "Build new", "script": "ops_demo_build.js"}]
    assert "demo_build" in ao.types()


def test_the_plugins_endpoint_serves_the_catalog(demo_plugin, monkeypatch, tmp_path):
    """ASVS V4.1.1 · CWE-200: GET /api/operations/plugins answers the catalog (behind the app's token like every /api route)."""
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    r = TestClient(srv.app).get("/api/operations/plugins")
    assert r.status_code == 200 and r.json()["plugins"][0]["type"] == "demo_build"
