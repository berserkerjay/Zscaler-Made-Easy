"""A stateful fake ZIA / ZPA / Client Connector tenant for the configuration
backup, restore and clone tests (config_backup.py, ops_config_restore.py).

The fake answers the SDK calls the catalogue names (config_backup.TYPES):
every service and method is generated from the catalogue, so a call the
catalogue does not name does not exist here either. Answers are the SDK's
(data, response, error) tuples with plain snake_case dicts. Nothing here
opens a socket.

`Tenant.fail_on` makes the n-th write (1-based) fail; `Tenant.before_write`
runs a callback right before each write (a colleague changing an object
meanwhile). `reads` and `writes` record what was asked; `calls` records the
SDK keyword arguments of every write (what the real SDK would be given).

ZPA policy rules: the list, get and delete calls take the policy type first
and are routed by it; an add or update is stored the way ZPA would answer
(app_connector_group_ids → app_connector_groups, the v1 condition blocks or,
for a _v2 call, the blocks the SDK's own _create_conditions_v2 builds from the
tuples). `Tenant.foreign_ips` are static IP addresses another organisation
holds: check_static_ip refuses them (HTTP 409), as it refuses one the tenant
already has. A Client Connector entitlement PUT updates the stored one.

Sub-locations live with the locations (zia.locations rows with a parent_id),
as in ZIA: list_sub_locations(location_id) answers that location's ones, and
get_location / add_location / delete_location serve both. A SaaS Security API
rule's get and delete take the rule type after the id (`args` records the
positional arguments of every get and delete)."""
from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List, Optional, Tuple

import config_backup as cb


class Tenant:
    def __init__(self, data: Optional[Dict[str, List[Dict[str, Any]]]] = None):
        self.data: Dict[str, List[Dict[str, Any]]] = {k: [copy.deepcopy(r) for r in v] for k, v in (data or {}).items()}
        self.reads: List[Tuple[str, str]] = []
        self.writes: List[Tuple[str, str, str]] = []
        self.sent: List[Dict[str, Any]] = []
        self.fail_on: Optional[int] = None
        self.before_write: Optional[Callable[["Tenant", str, str], None]] = None
        self.activations = 0
        self.next_id = 5000
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []
        self.foreign_ips: set = set()
        self.args: List[Tuple[str, str, Tuple[Any, ...]]] = []

    def rows(self, key: str) -> List[Dict[str, Any]]:
        return self.data.setdefault(key, [])

    def by_name(self, key: str, name: str) -> Optional[Dict[str, Any]]:
        t = cb.BY_KEY[key]
        return next((r for r in self.rows(key) if cb.name_of(t, r) == name), None)

    def names(self, key: str) -> List[str]:
        t = cb.BY_KEY[key]
        return sorted(cb.name_of(t, r) for r in self.rows(key))

    def new_id(self, key: str) -> Any:
        self.next_id += 1
        if key == "zia.url_categories":
            return f"CUSTOM_{self.next_id}"
        return str(self.next_id) if key.startswith("zpa.") else self.next_id

    def _write(self, op: str, key: str, name: str, body: Any = None) -> Optional[str]:
        if self.before_write:
            self.before_write(self, op, key)
        self.writes.append((op, key, name))
        if body is not None:
            self.sent.append(copy.deepcopy(body))
        if self.fail_on is not None and len(self.writes) == self.fail_on:
            return '{"status": 400, "code": "INVALID_INPUT_ARGUMENT", "message": "Refused by the fake tenant"}'
        return None


class _Answer:
    def __init__(self, body: Any):
        self._body = body

    def get_body(self) -> Any:
        return self._body


class _Exec:
    """The SDK request executor's shape for the raw ZIA calls pack_channels
    makes (activation, its status, root certificates)."""

    def __init__(self, tenant: Tenant):
        self._t = tenant

    def create_request(self, method: str, url: str, body: Any = None, headers: Any = None, params: Any = None) -> Any:
        return {"method": method, "url": url, "body": body}, None

    def execute(self, req: Dict[str, Any], *a: Any) -> Any:
        t, path, method = self._t, str(req["url"]).replace("/zia/api/v1", ""), req["method"]
        if path == "/status/activate" and method == "POST":
            t.activations += 1
            return _Answer({"status": "ACTIVE"}), None
        if path == "/status":
            return _Answer({"status": "ACTIVE"}), None
        zcc = {"/zcc/papi/public/v1/updateZpaGroupEntitlement": "zcc.zpa_entitlements",
               "/zcc/papi/public/v1/updateZdxGroupEntitlement": "zcc.zdx_entitlements"}
        if method == "PUT" and str(req["url"]) in zcc:
            key = zcc[str(req["url"])]
            body = {_snake(k): v for k, v in (req["body"] or {}).items()}
            err = t._write("update", key, cb.BY_KEY[key]["label"], body)
            if err:
                return None, err
            t.rows(key)[:1] = [body]
            return _Answer(copy.deepcopy(body)), None
        key, rt = "zia.root_certificates", cb.BY_KEY["zia.root_certificates"]
        if path == rt["raw"] and method == "GET":
            t.reads.append(("list", key))
            if key not in t.data:
                return None, "HTTP 404 not found"
            return _Answer(copy.deepcopy(t.rows(key))), None
        if path == rt["raw"] and method == "POST":
            err = t._write("create", key, str((req["body"] or {}).get("name")), req["body"])
            if err:
                return None, err
            obj = dict(copy.deepcopy(req["body"] or {}), id=t.new_id(key))
            t.rows(key).append(obj)
            return _Answer(copy.deepcopy(obj)), None
        if path.startswith(rt["raw"] + "/") and method == "DELETE":
            oid = path.rsplit("/", 1)[-1]
            hit = next((r for r in t.rows(key) if str(r.get("id")) == oid), None)
            err = t._write("delete", key, cb.name_of(rt, hit) if hit else oid)
            if err:
                return None, err
            if hit:
                t.rows(key).remove(hit)
            return _Answer({}), None
        return None, f"HTTP 404 {path} not modelled"


def _snake(k: str) -> str:
    import re
    return re.sub(r"(?<!^)(?=[A-Z])", "_", str(k)).lower()


_CAP_WORDS = {"clipboard_copy": "CLIPBOARD_COPY", "clipboard_paste": "CLIPBOARD_PASTE", "file_download": "FILE_DOWNLOAD",
              "file_upload": "FILE_UPLOAD", "inspect_file_download": "INSPECT_FILE_DOWNLOAD", "inspect_file_upload": "INSPECT_FILE_UPLOAD",
              "monitor_session": "MONITOR_SESSION", "record_session": "RECORD_SESSION", "share_session": "SHARE_SESSION"}


def _zpa_rule_store(t: Dict[str, Any], kw: Dict[str, Any]) -> Dict[str, Any]:
    """A ZPA rule as ZPA answers it, from the SDK call's keyword arguments."""
    body = {k: copy.deepcopy(v) for k, v in kw.items() if k not in ("conditions", "app_connector_group_ids", "app_server_group_ids",
                                                                   "service_edge_group_ids", "credential_id", "credential_pool_id",
                                                                   "privileged_capabilities")}
    if "app_connector_group_ids" in kw:
        body["app_connector_groups"] = [{"id": str(i)} for i in kw["app_connector_group_ids"]]
    if "app_server_group_ids" in kw:
        body["app_server_groups"] = [{"id": str(i)} for i in kw["app_server_group_ids"]]
    if "service_edge_group_ids" in kw:
        body["service_edge_groups"] = [{"id": str(i)} for i in kw["service_edge_group_ids"]]
    if kw.get("credential_id"):
        body["credential"] = {"id": str(kw["credential_id"])}
    if kw.get("credential_pool_id"):
        body["credential_pool"] = {"id": str(kw["credential_pool_id"])}
    if "privileged_capabilities" in kw:
        body["privileged_capabilities"] = {"capabilities": sorted(_CAP_WORDS[k] for k, v in kw["privileged_capabilities"].items() if v)}
    conds = kw.get("conditions") or []
    if t["v2"]:
        from zscaler.zpa.policies import PolicySetControllerAPI
        built = PolicySetControllerAPI._create_conditions_v2(None, copy.deepcopy(conds))
        blocks = []
        for b in built:
            ops = []
            for o in b.get("operands") or []:
                for v in o.get("values") or []:
                    ops.append({"object_type": o["objectType"], "lhs": "id", "rhs": str(v)})
                for ev in o.get("entryValues") or []:
                    ops.append({"object_type": o["objectType"], "lhs": str(ev["lhs"]), "rhs": str(ev["rhs"])})
            blocks.append({"operator": b.get("operator", "OR"), "negated": False, "operands": ops})
    else:
        for b in conds:
            assert isinstance(b, dict), "the v1 calls are given dict blocks"
        blocks = [{"operator": b.get("operator", "OR"), "negated": bool(b.get("negated")),
                   "operands": [dict({"object_type": o["objectType"], "lhs": o["lhs"], "rhs": o["rhs"]},
                                     **({"idp_id": o["idp_id"]} if o.get("idp_id") else {})) for o in b.get("operands") or []]}
                  for b in conds]
    body["conditions"] = blocks
    body["policy_type"] = t["zpa_policy"]
    return body


class _Service:
    def __init__(self, tenant: Tenant, product: str, svc: str):
        self._t, self._product, self._svc = tenant, product, svc
        self._request_executor = _Exec(tenant)
        self._methods: Dict[str, Tuple[str, str]] = {}
        self._policy: Dict[str, str] = {}
        for t in cb.TYPES:
            if t["product"] == product and t["svc"] == svc:
                if t["zpa_policy"]:
                    self._policy[t["zpa_policy"]] = t["key"]
                for role in ("ls", "get", "add", "upd", "rm", "check"):
                    m = t[role]
                    if m and m != "raw":
                        self._methods.setdefault(m, (t["key"], role))

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_") or name not in self._methods:
            raise AttributeError(name)
        key, role = self._methods[name]
        if self._policy and role in ("ls", "get", "rm"):
            # policies.list_rules / get_rule / delete_rule take the policy type first
            return lambda *a, **kw: self._call(self._policy[a[0]], role, a[1:], kw)
        return lambda *a, **kw: self._call(key, role, a, kw, method=name)

    def _call(self, key: str, role: str, a: Tuple[Any, ...], kw: Dict[str, Any], method: str = "") -> Any:
        tenant, t = self._t, cb.BY_KEY[key]
        if role == "check":
            ip = str(a[0])
            if ip in tenant.foreign_ips or any(str(r.get("ip_address")) == ip for r in tenant.rows(key)):
                return False, None, "HTTP 409 DUPLICATE_ITEM: the IP address already exists"
            return True, None, None
        if role in ("add", "upd"):
            tenant.calls.append((method, key, copy.deepcopy(kw)))
            if t["zpa_policy"]:
                kw = _zpa_rule_store(t, kw)
            elif t["app_kind"] and role == "add" and "common_apps_dto" in kw:
                kw = dict(kw)
                apps = [{k: v for k, v in x.items() if k != "app_types"} for x in kw.pop("common_apps_dto").get("apps_config") or []]
                kw["pra_apps" if t["app_kind"] == "pra" else "inspection_apps"] = apps
        if role == "ls" and t["per_parent"]:
            tenant.reads.append(("list", key))
            if t["per_parent"] not in tenant.data:
                return None, None, f"HTTP 404 {key} not found"
            return copy.deepcopy([r for r in tenant.rows(t["per_parent"]) if str(r.get("parent_id") or "0") == str(a[0])]), None, None
        if role in ("get", "rm"):
            tenant.args.append((key, role, tuple(a)))
        if role == "ls":
            tenant.reads.append(("list", key))
            if key not in tenant.data:
                return None, None, f"HTTP 404 {key} not found"
        rows = tenant.rows(key)
        if role == "ls":
            out = rows
            if t["per_type"] and a:
                out = [r for r in rows if r.get("type") == a[0]]
            if t["per_idp"] and a:
                out = [r for r in rows if str(r.get("idp_id")) == str(a[0])]
            return copy.deepcopy(out), None, None
        if role == "get" and t["singleton"]:
            tenant.reads.append(("get", key))
            return (copy.deepcopy(rows[0]), None, None) if rows else (None, None, "HTTP 404 not found")
        if role == "get":
            oid = a[0] if t["type_arg"] else a[-1]
            tenant.reads.append(("get", key))
            hit = next((r for r in rows if str(r.get("id")) == str(oid)), None)
            return (copy.deepcopy(hit), None, None) if hit else (None, None, "HTTP 404 NOT_FOUND: no such object")
        body = dict(kw)
        lead = list(a)
        if t["per_type"] and lead:
            body["type"] = lead.pop(0)
        if role == "rm":
            oid = lead[0] if t["type_arg"] else lead[-1]
            hit = next((r for r in rows if str(r.get("id")) == str(oid)), None)
            err = tenant._write("delete", key, cb.name_of(t, hit) if hit else str(oid))
            if err:
                return None, None, err
            if hit is None:
                return None, None, "HTTP 404 not found"
            rows.remove(hit)
            return None, None, None
        if role == "upd" and t["singleton"]:
            err = tenant._write("update", key, t["label"], body)
            if err:
                return None, None, err
            rows[0].update(copy.deepcopy(body))
            return copy.deepcopy(rows[0]), None, None
        if role == "upd" and t["upd_body"]:
            oid = body.get("id")
        elif role == "upd":
            oid = lead.pop(0)
        else:
            oid = None
        if role == "add" or (role == "upd" and oid in (None, "") and t["add_via_upd"]):
            for i, k in enumerate(t["add_pos"]):
                if i < len(lead) and lead[i] is not None:
                    body[k] = lead[i]
            err = tenant._write("create", key, cb.name_of(t, body), body)
            if err:
                return None, None, err
            obj = copy.deepcopy(body)
            obj["id"] = tenant.new_id(key)
            if key == "zia.url_categories":
                obj["custom_category"] = True
            rows.append(obj)
            return copy.deepcopy(obj), None, None
        hit = next((r for r in rows if str(r.get("id")) == str(oid)), None)
        err = tenant._write("update", key, cb.name_of(t, hit) if hit else str(oid), body)
        if err:
            return None, None, err
        if hit is None:
            return None, None, "HTTP 404 not found"
        new = copy.deepcopy(body)
        new["id"] = hit["id"]
        rows[rows.index(hit)] = new
        return copy.deepcopy(new), None, None


class _Activate:
    def __init__(self, tenant: Tenant):
        self._t = tenant

    def activate(self) -> Any:
        self._t.activations += 1
        return {"status": "ACTIVE"}, None, None

    def status(self) -> Any:
        return {"status": "ACTIVE"}, None, None


class _Root:
    def __init__(self, tenant: Tenant, product: str):
        self._tenant, self._product = tenant, product
        self._services: Dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        if name == "activate" and self._product == "zia":
            return _Activate(self._tenant)
        if not any(t["product"] == self._product and t["svc"] == name for t in cb.TYPES) and \
                not (self._product == "zia" and name in ("dlp_web_rules", "proxies")):
            raise AttributeError(name)
        if name not in self._services:
            self._services[name] = _Service(self._tenant, self._product, name)
        return self._services[name]


class Client:
    """The SDK client's shape (.zia, .zpa, .zcc) over a Tenant."""

    def __init__(self, tenant: Optional[Tenant] = None):
        self.tenant = tenant or Tenant()
        self.zia = _Root(self.tenant, "zia")
        self.zpa = _Root(self.tenant, "zpa")
        self.zcc = _Root(self.tenant, "zcc")


def state(tenant: Tenant, keys: List[str]) -> Dict[str, Dict[str, Any]]:
    """The tenant's configuration by name, comparable across ids: what an
    exact Undo must give back (references by name)."""
    idx = cb.index(tenant.data)
    out = {}
    for k in keys:
        t = cb.BY_KEY[k]
        out[k] = {cb.name_of(t, r): cb.normal(t, r, idx) for r in tenant.rows(k)}
    return out
