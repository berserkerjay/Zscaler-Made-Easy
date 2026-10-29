"""A stateful fake ZPA tenant for the ZPA builder tests and browser checks:
the SDK services ops_zpa reads and pack_ops writes, with the SDK's
(data, response, error) answers, pages, ZPA's refusal to delete an object
something still uses, and a provisioning key value on every read of a key
(as ZPA answers it), so a test can prove the value never leaks."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

CANARY_KEY = "3|CANARY-PROVISIONING-KEY-q9Zx7Lm2Vt8Rb4Nw|do-not-leak"
RULE_TYPES = ("access", "timeout", "inspection", "isolation")


def _camel(k: str) -> str:
    return re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k)


class Tenant:
    def __init__(self) -> None:
        self.n = 72058304855000000
        self.rows: Dict[str, Dict[str, Dict[str, Any]]] = {k: {} for k in (
            "connector_group", "provisioning_key", "segment_group", "server_group", "segment", "inspection_profile", "pra_console",
            "isolation_profile", "pra_portal", "certificate", "enrollment") + tuple(f"rule:{t}" for t in RULE_TYPES)}
        self.writes: List[tuple] = []
        self.reads: List[str] = []
        self.add("enrollment", {"name": "Connector"})
        self.add("enrollment", {"name": "Service Edge"})
        self.versions = ["OWASP_CRS/3.3.0", "OWASP_CRS/4.8.0", "OWASP_CRS/4.10.0"]

    def nid(self) -> str:
        self.n += 1
        return str(self.n)

    def add(self, kind: str, row: Dict[str, Any]) -> Dict[str, Any]:
        row = dict(row, id=row.get("id") or self.nid())
        self.rows[kind][row["id"]] = row
        return row

    def by_name(self, kind: str, name: str) -> Optional[Dict[str, Any]]:
        return next((r for r in self.rows[kind].values() if r.get("name") == name), None)

    def names(self, kind: str) -> List[str]:
        return sorted(r["name"] for r in self.rows[kind].values())


def _page(rows: List[Dict[str, Any]], q: Optional[dict]) -> List[Dict[str, Any]]:
    q = q or {}
    size = int(q.get("page_size") or 20)
    page = int(q.get("page") or 1)
    return [dict(r) for r in rows[(page - 1) * size: page * size]]


def _body(kw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in kw.items():
        if k == "server_group_ids":
            out["serverGroups"] = [{"id": str(x)} for x in v]
        elif k == "app_connector_group_ids":
            out["appConnectorGroups"] = [{"id": str(x)} for x in v]
        elif k in ("component_id", "zcomponent_id"):
            out["zcomponentId"] = str(v)
        elif k == "clientless_app_ids":
            out["clientlessApps"] = v
        elif k == "conditions":
            out["conditions"] = [{"operator": "OR", "operands": [{"objectType": c[0].upper(), "lhs": c[1], "rhs": c[2]} for c in v]}] if v else []
        else:
            out[_camel(k)] = v
    return out


class _Svc:
    def __init__(self, t: Tenant, kind: str):
        self.t, self.kind = t, kind

    def _list(self, q=None, kind=None):
        k = kind or self.kind
        self.t.reads.append(f"list:{k}")
        return _page(list(self.t.rows[k].values()), q), None, None

    def _get(self, oid, kind=None):
        k = kind or self.kind
        self.t.reads.append(f"get:{k}")
        r = self.t.rows[k].get(str(oid))
        return (dict(r), None, None) if r else (None, None, "HTTP 404: resource.not.found")

    def _add(self, kw, kind=None, **extra):
        k = kind or self.kind
        b = _body(kw)
        b.update(extra)
        if self.t.by_name(k, b.get("name")) is not None:
            return None, None, "HTTP 409: duplicate name"
        r = self.t.add(k, b)
        self.t.writes.append(("create", k, r["name"]))
        return dict(r), None, None

    def _update(self, oid, kw, kind=None):
        k = kind or self.kind
        r = self.t.rows[k].get(str(oid))
        if r is None:
            return None, None, "HTTP 404"
        r.update(_body(kw))
        self.t.writes.append(("update", k, r["name"]))
        return dict(r), None, None

    def _delete(self, oid, kind=None, used_by=None):
        k = kind or self.kind
        r = self.t.rows[k].get(str(oid))
        if r is None:
            return None, None, "HTTP 404: resource.not.found"
        if used_by:
            return None, None, f"HTTP 400: in use by {used_by}"
        del self.t.rows[k][str(oid)]
        self.t.writes.append(("delete", k, r["name"]))
        return None, None, None


def _ids(v):
    return [str(x.get("id")) for x in v or []]


class ConnectorGroups(_Svc):
    def list_connector_groups(self, query_params=None):
        return self._list(query_params)

    def get_connector_group(self, gid, query_params=None):
        return self._get(gid)

    def add_connector_group(self, **kw):
        return self._add(kw, connectors=[])

    def update_connector_group(self, gid, **kw):
        return self._update(gid, kw)

    def delete_connector_group(self, gid, microtenant_id=None):
        r = self.t.rows[self.kind].get(str(gid)) or {}
        used = [s["name"] for s in self.t.rows["server_group"].values() if str(gid) in _ids(s.get("appConnectorGroups"))] + (["connectors"] if r.get("connectors") else [])
        return self._delete(gid, used_by=", ".join(used))


class Provisioning(_Svc):
    def list_provisioning_keys(self, key_type, query_params=None):
        assert key_type == "connector"
        return self._list(query_params)

    def get_provisioning_key(self, key_id, key_type, query_params=None):
        return self._get(key_id)

    def add_provisioning_key(self, key_type, **kw):
        assert key_type == "connector" and kw.get("enrollment_cert_id")
        return self._add(kw, provisioningKey=CANARY_KEY, usageCount="0")

    def update_provisioning_key(self, key_id, key_type, **kw):
        return self._update(key_id, kw)

    def delete_provisioning_key(self, key_id, key_type, microtenant_id=None):
        return self._delete(key_id)


class Enrollment(_Svc):
    def list_enrolment(self, query_params=None):
        rows = [r for r in self.t.rows["enrollment"].values() if (query_params or {}).get("search", "") in r["name"]]
        return _page(rows, query_params), None, None


class Groups(_Svc):
    def list_groups(self, query_params=None):
        return self._list(query_params)

    def get_group(self, gid, query_params=None):
        return self._get(gid)

    def add_group(self, **kw):
        return self._add(kw)

    def update_group(self, gid, **kw):
        return self._update(gid, kw)

    def delete_group(self, gid, microtenant_id=None):
        if self.kind == "segment_group":
            used = [s["name"] for s in self.t.rows["segment"].values() if str(s.get("segmentGroupId")) == str(gid)]
        else:
            used = [s["name"] for s in self.t.rows["segment"].values() if str(gid) in _ids(s.get("serverGroups"))]
        return self._delete(gid, used_by=", ".join(used))


class Segments(_Svc):
    def list_segments(self, query_params=None):
        return self._list(query_params)

    def get_segment(self, sid, query_params=None):
        return self._get(sid)

    def add_segment(self, **kw):
        return self._add(kw)

    def update_segment(self, sid, **kw):
        return self._update(sid, kw)

    def delete_segment(self, sid, force_delete=False, microtenant_id=None):
        r = self.t.rows["segment"].get(str(sid)) or {}
        pra = set(_ids(r.get("praApps")))
        used = [x["name"] for t in RULE_TYPES for x in self.t.rows[f"rule:{t}"].values() if str(sid) in _rule_apps(x)]
        used += [c["name"] for c in self.t.rows["pra_console"].values() if str((c.get("praApplication") or {}).get("id")) in pra]
        return self._delete(sid, used_by=", ".join(used))


class PraSegments(_Svc):
    def add_segment_pra(self, **kw):
        dto = kw.pop("common_apps_dto", None) or {}
        return self._add(kw, kind="segment", praApps=[{"id": self.t.nid(), "name": c.get("name")} for c in dto.get("apps_config") or []])


class AppProtection(_Svc):
    def list_profiles(self, query_params=None):
        return self._list(query_params)

    def get_profile(self, pid, **kw):
        return self._get(pid)

    def add_profile(self, **kw):
        assert kw.get("predefined_controls_version") in self.t.versions
        return self._add(kw)

    def delete_profile(self, pid):
        used = [x["name"] for x in self.t.rows["rule:inspection"].values() if str(x.get("zpnInspectionProfileId")) == str(pid)]
        return self._delete(pid, used_by=", ".join(used))

    def list_predef_control_versions(self):
        self.t.reads.append("versions")
        return list(self.t.versions), None, None


class Simple(_Svc):
    def __getattr__(self, name):
        if name.startswith("list_"):
            return lambda query_params=None, **k: self._list(query_params)
        raise AttributeError(name)


class Consoles(_Svc):
    def list_consoles(self, query_params=None):
        return self._list(query_params)

    def get_console(self, cid, query_params=None):
        return self._get(cid)

    def add_console(self, **kw):
        app, portals = kw.pop("pra_application_id"), kw.pop("pra_portal_ids")
        return self._add(kw, praApplication={"id": str(app)}, praPortals=[{"id": str(p)} for p in portals])

    def update_console(self, cid, **kw):
        kw.pop("pra_application_id", None)
        kw.pop("pra_portal_ids", None)
        return self._update(cid, kw)

    def delete_console(self, cid, microtenant_id=None):
        return self._delete(cid)


def _rule_apps(r):
    return [str(o.get("rhs")) for c in r.get("conditions") or [] for o in c.get("operands") or [] if o.get("objectType") == "APP"]


class Policies(_Svc):
    def list_rules(self, policy_type, query_params=None):
        return self._list(query_params, kind=f"rule:{policy_type}")

    def get_rule(self, policy_type, rule_id, query_params=None):
        return self._get(rule_id, kind=f"rule:{policy_type}")

    def _rule(self, t, kw):
        kw = dict(kw)
        if "action" in kw:
            kw["action"] = str(kw["action"]).upper()
        return self._add(kw, kind=f"rule:{t}")

    def add_access_rule(self, name, action, **kw):
        return self._rule("access", dict(kw, name=name, action=action))

    def add_timeout_rule(self, **kw):
        return self._rule("timeout", kw)

    def add_app_protection_rule(self, name, action, zpn_inspection_profile_id=None, **kw):
        return self._rule("inspection", dict(kw, name=name, action=action, zpn_inspection_profile_id=zpn_inspection_profile_id))

    def add_isolation_rule(self, name, action, zpn_isolation_profile_id=None, **kw):
        return self._rule("isolation", dict(kw, name=name, action=action, zpn_isolation_profile_id=zpn_isolation_profile_id))

    def _upd(self, t, rid, kw):
        kw = dict(kw)
        if "action" in kw:
            kw["action"] = str(kw["action"]).upper()
        return self._update(rid, kw, kind=f"rule:{t}")

    def update_access_rule(self, rule_id, **kw):
        return self._upd("access", rule_id, kw)

    def update_timeout_rule(self, rule_id, **kw):
        return self._upd("timeout", rule_id, kw)

    def update_app_protection_rule(self, rule_id, **kw):
        return self._upd("inspection", rule_id, kw)

    def update_isolation_rule(self, rule_id, **kw):
        return self._upd("isolation", rule_id, kw)

    def delete_rule(self, policy_type, rule_id, microtenant_id=None):
        return self._delete(rule_id, kind=f"rule:{policy_type}")


class Zpa:
    def __init__(self, t: Tenant):
        self.app_connector_groups = ConnectorGroups(t, "connector_group")
        self.provisioning = Provisioning(t, "provisioning_key")
        self.enrollment_certificates = Enrollment(t, "enrollment")
        self.segment_groups = Groups(t, "segment_group")
        self.server_groups = Groups(t, "server_group")
        self.application_segment = Segments(t, "segment")
        self.app_segments_pra = PraSegments(t, "segment")
        self.app_protection = AppProtection(t, "inspection_profile")
        self.cbi_zpa_profile = Simple(t, "isolation_profile")
        self.pra_portal = Simple(t, "pra_portal")
        self.certificates = Simple(t, "certificate")
        self.pra_console = Consoles(t, "pra_console")
        self.policies = Policies(t, "rule:access")


class Client:
    """What _build_sdk_client returns: a ZPA namespace over the fake tenant (no ZIA)."""

    def __init__(self, t: Optional[Tenant] = None):
        self.tenant = t or Tenant()
        self.zpa = Zpa(self.tenant)
        self.zia = None

    def close(self) -> None:
        pass
