"""Stateful fakes for the day-to-day admin operations (ops_zpa_admin,
ops_zcc_admin, ops_zdx_trace): the SDK services those modules read and
write, with the SDK's (data, response, error) answers, a request executor for
the calls the SDK lacks, every write recorded with the exact keyword
arguments it got (the payload oracles), and secret canaries in the answers a
real tenant would put them in (a provisioning key on every read of a key, a
device's one-time passwords, a certificate blob echoed back). No network."""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Optional, Tuple

CANARY_PROV_KEY = "3|CANARY-ADMIN-PROVKEY-zz81Qw|never-show-me"
CANARY_OTP = "CANARY-DEVICE-OTP-77x1"
CANARY_ECHO = "CANARY-ECHO-OF-THE-REQUEST"


class Resp:
    def __init__(self, body: Any):
        self.body = body

    def get_body(self) -> Any:
        return copy.deepcopy(self.body)

    def get_results(self) -> Any:
        return copy.deepcopy(self.body if isinstance(self.body, list) else [self.body])


def _camel(k: str) -> str:
    return re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k)


# ── ZPA ─────────────────────────────────────────────────────────────────

class ZpaTenant:
    KINDS = ("connector", "connector_group", "service_edge", "service_edge_group", "key:connector", "key:service_edge", "certificate",
             "segment", "enrollment", "pra_portal", "pra_console", "user_portal")

    def __init__(self) -> None:
        self.n = 72058304855100000
        self.rows: Dict[str, Dict[str, Dict[str, Any]]] = {k: {} for k in self.KINDS}
        self.writes: List[Tuple[str, str, str, Dict[str, Any]]] = []   # (verb, kind, id, kwargs)
        self.reads: List[str] = []
        self.fail: Dict[Tuple[str, str], str] = {}   # (verb, kind) -> error text
        self.add("enrollment", {"name": "Connector"})
        self.add("enrollment", {"name": "Service Edge"})

    def nid(self) -> str:
        self.n += 1
        return str(self.n)

    def add(self, kind: str, row: Dict[str, Any]) -> Dict[str, Any]:
        row = dict(row, id=row.get("id") or self.nid())
        self.rows[kind][row["id"]] = row
        return row

    def seed(self) -> Dict[str, Dict[str, Any]]:
        """A small tenant: two connector groups, three connectors, a Service
        Edge group with one edge, a key per group, a certificate used by a
        Browser Access application, PRA portal, console and user portal."""
        g1 = self.add("connector_group", {"name": "HQ connectors", "enabled": True, "upgradeDay": "SUNDAY", "upgradeTimeInSecs": "66600",
                                          "versionProfileId": "0", "overrideVersionProfile": False, "location": "San Jose, CA, USA",
                                          "enrollmentCertId": "11", "serverGroups": [{"id": "900"}]})
        g2 = self.add("connector_group", {"name": "DR connectors", "enabled": True, "upgradeDay": "SATURDAY", "upgradeTimeInSecs": "7200",
                                          "versionProfileId": "0", "overrideVersionProfile": False})
        c1 = self.add("connector", {"name": "hq-ac-1", "enabled": True, "appConnectorGroupId": g1["id"], "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED",
                                    "currentVersion": "24.1", "expectedVersion": "24.2", "lastBrokerConnectTime": "1730000000000", "description": "rack 4"})
        c2 = self.add("connector", {"name": "hq-ac-2", "enabled": True, "appConnectorGroupId": g1["id"], "controlChannelStatus": "ZPN_STATUS_DISCONNECTED",
                                    "currentVersion": "24.2", "expectedVersion": "24.2"})
        c3 = self.add("connector", {"name": "old-ac", "enabled": False, "appConnectorGroupId": g2["id"], "controlChannelStatus": "ZPN_STATUS_DISCONNECTED"})
        sg = self.add("service_edge_group", {"name": "PSE Frankfurt", "enabled": True, "upgradeDay": "MONDAY", "upgradeTimeInSecs": "3600",
                                             "versionProfileId": "1", "overrideVersionProfile": True, "isPublic": False,
                                             "trustedNetworks": [{"id": "77"}]})
        se = self.add("service_edge", {"name": "pse-fra-1", "enabled": True, "serviceEdgeGroupId": sg["id"], "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"})
        self.rows["service_edge_group"][sg["id"]]["serviceEdges"] = [{"id": se["id"]}]
        k1 = self.add("key:connector", {"name": "hq-key", "enabled": True, "zcomponentId": g1["id"], "usageCount": "2", "maxUsage": "5",
                                        "provisioningKey": CANARY_PROV_KEY})
        cert = self.add("certificate", {"name": "wiki-cert", "cName": "wiki.example.com", "validToInEpochSec": "4102444800", "san": ["wiki.example.com"],
                                        "certificate": "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----"})
        seg = self.add("segment", {"name": "Wiki", "enabled": True, "domainNames": ["wiki.example.com"], "segmentGroupId": "500",
                                   "serverGroups": [{"id": "900"}], "tcpPortRanges": ["443", "443"],
                                   "clientlessApps": [{"id": "6001", "appId": "", "name": "wiki.example.com", "domain": "wiki.example.com",
                                                       "applicationPort": "443", "applicationProtocol": "HTTPS", "certificateId": cert["id"],
                                                       "certificateName": "wiki-cert", "enabled": True}]})
        self.rows["segment"][seg["id"]]["clientlessApps"][0]["appId"] = seg["id"]
        up = self.add("user_portal", {"name": "Contractors", "enabled": True, "domain": "portal.example.com", "certificateId": cert["id"]})
        pp = self.add("pra_portal", {"name": "Ops PRA", "enabled": True, "domain": "pra.example.com", "certificateId": cert["id"], "userPortalGid": up["id"]})
        pc = self.add("pra_console", {"name": "jump-rdp", "enabled": True, "praApplication": {"id": "7001", "name": "jump"},
                                      "praPortals": [{"id": pp["id"]}]})
        lone = self.add("pra_portal", {"name": "Spare PRA", "enabled": False, "domain": "spare.example.com"})
        return {"g1": g1, "g2": g2, "c1": c1, "c2": c2, "c3": c3, "sg": sg, "se": se, "k1": k1, "cert": cert, "seg": seg, "up": up, "pp": pp,
                "pc": pc, "lone": lone}


def _pages(rows: List[Dict[str, Any]], q: Optional[dict]) -> List[Dict[str, Any]]:
    q = q or {}
    size, page = int(q.get("page_size") or 20), int(q.get("page") or 1)
    return [copy.deepcopy(r) for r in rows[(page - 1) * size: page * size]]


def _wire_body(kind: str, kw: Dict[str, Any]) -> Dict[str, Any]:
    """What ZPA would store for a write's kwargs (the SDK's camelCase)."""
    out: Dict[str, Any] = {}
    for k, v in kw.items():
        if k == "service_edge_ids":
            out["serviceEdges"] = [{"id": str(x)} for x in v]
        elif k == "trusted_network_ids":
            out["trustedNetworks"] = [{"id": str(x)} for x in v]
        elif k == "component_id":
            out["zcomponentId"] = str(v)
        elif k == "server_group_ids":
            out["serverGroups"] = [{"id": str(x)} for x in v]
        else:
            out[_camel(k)] = v
    return out


class _ZSvc:
    def __init__(self, t: ZpaTenant, kind: str):
        self.t, self.kind = t, kind

    def _list(self, q=None, kind=None):
        k = kind or self.kind
        self.t.reads.append(f"list:{k}")
        return _pages(list(self.t.rows[k].values()), q), None, None

    def _get(self, oid, kind=None):
        k = kind or self.kind
        self.t.reads.append(f"get:{k}")
        r = self.t.rows[k].get(str(oid))
        return (copy.deepcopy(r), Resp(copy.deepcopy(r)), None) if r else (None, None, "HTTP 404: resource.not.found")

    def _fail(self, verb, kind=None):
        return self.t.fail.get((verb, kind or self.kind))

    def _update(self, oid, kw, kind=None):
        k = kind or self.kind
        self.t.writes.append(("update", k, str(oid), copy.deepcopy(kw)))
        if self._fail("update", k):
            return None, None, self._fail("update", k)
        r = self.t.rows[k].get(str(oid))
        if r is None:
            return None, None, "HTTP 404"
        r.update(_wire_body(k, kw))
        return copy.deepcopy(r), None, None

    def _delete(self, oid, kind=None):
        k = kind or self.kind
        self.t.writes.append(("delete", k, str(oid), {}))
        if self._fail("delete", k):
            return None, None, self._fail("delete", k)
        if self.t.rows[k].pop(str(oid), None) is None:
            return None, None, "HTTP 404: resource.not.found"
        return None, None, None


def _svc(kind: str, list_name: str, get_name: str, update_name: str, delete_name: str):
    def lst(self, query_params=None):
        return self._list(query_params)

    def get(self, oid, query_params=None, **kw):
        return self._get(oid)

    def upd(self, oid, **kw):
        return self._update(oid, kw)

    def dele(self, oid, microtenant_id=None, **kw):
        return self._delete(oid)

    return type(f"Fake_{kind}", (_ZSvc,), {list_name: lst, get_name: get, update_name: upd, delete_name: dele})


Connectors = _svc("connector", "list_connectors", "get_connector", "update_connector", "delete_connector")
ConnectorGroups = _svc("connector_group", "list_connector_groups", "get_connector_group", "update_connector_group", "delete_connector_group")
Edges = _svc("service_edge", "list_service_edges", "get_service_edge", "update_service_edge", "delete_service_edge")
EdgeGroups = _svc("service_edge_group", "list_service_edge_groups", "get_service_edge_group", "update_service_edge_group", "delete_service_edge_group")
PraPortals = _svc("pra_portal", "list_portals", "get_portal", "update_portal", "delete_portal")
PraConsoles = _svc("pra_console", "list_consoles", "get_console", "update_console", "delete_console")
UserPortals = _svc("user_portal", "list_user_portals", "get_user_portal", "update_user_portal", "delete_user_portal")


class Certificates(_ZSvc):
    def list_certificates(self, query_params=None):
        return self._list(query_params)

    def get_certificate(self, cid, query_params=None):
        return self._get(cid)

    def add_certificate(self, **kw):
        self.t.writes.append(("create", "certificate", "", copy.deepcopy(kw)))
        if self._fail("create"):
            # an error answer that quotes the request it refused (as a gateway might)
            return None, None, f"HTTP 400: {CANARY_ECHO} invalid certificate, the request ended: {kw.get('cert_blob', '')[-400:]}"
        r = self.t.add("certificate", {"name": kw.get("name"), "description": kw.get("description"), "cName": "wiki.example.com",
                                       "validToInEpochSec": "4102444800", "san": ["wiki.example.com", "*.example.com"]})
        # ZPA echoes the blob back in the create's answer
        return dict(r, certBlob=kw.get("cert_blob")), Resp(dict(r, certBlob=kw.get("cert_blob"))), None

    def delete_certificate(self, cid, microtenant_id=None):
        return self._delete(cid)


class Segments(_ZSvc):
    def list_segments(self, query_params=None):
        return self._list(query_params)

    def get_segment(self, sid, query_params=None):
        return self._get(sid)

    def update_segment(self, sid, **kw):
        self.t.writes.append(("update", "segment", str(sid), copy.deepcopy(kw)))
        r = self.t.rows["segment"].get(str(sid))
        if r is None:
            return None, None, "HTTP 404"
        if "clientless_apps" in kw:
            r["clientlessApps"] = copy.deepcopy(kw["clientless_apps"])
        return copy.deepcopy(r), None, None


class Provisioning(_ZSvc):
    def list_provisioning_keys(self, key_type, query_params=None):
        assert key_type in ("connector", "service_edge")
        return self._list(query_params, kind=f"key:{key_type}")

    def get_provisioning_key(self, key_id, key_type, query_params=None):
        return self._get(key_id, kind=f"key:{key_type}")

    def add_provisioning_key(self, key_type, **kw):
        k = f"key:{key_type}"
        self.t.writes.append(("create", k, "", copy.deepcopy(kw)))
        if self._fail("create", k):
            return None, None, self._fail("create", k)
        b = {"name": kw.get("name"), "maxUsage": kw.get("max_usage"), "enrollmentCertId": kw.get("enrollment_cert_id"),
             "zcomponentId": kw.get("component_id"), "enabled": kw.get("enabled"), "usageCount": "0", "provisioningKey": CANARY_PROV_KEY}
        r = self.t.add(k, b)
        return copy.deepcopy(r), Resp(copy.deepcopy(r)), None

    def delete_provisioning_key(self, key_id, key_type, microtenant_id=None):
        return self._delete(key_id, kind=f"key:{key_type}")


class Enrollment(_ZSvc):
    def list_enrolment(self, query_params=None):
        rows = [r for r in self.t.rows["enrollment"].values() if (query_params or {}).get("search", "") in r["name"]]
        return [copy.deepcopy(r) for r in rows], None, None


class ZpaNs:
    def __init__(self, t: ZpaTenant):
        self.app_connectors = Connectors(t, "connector")
        self.app_connector_groups = ConnectorGroups(t, "connector_group")
        self.service_edges = Edges(t, "service_edge")
        self.service_edge_group = EdgeGroups(t, "service_edge_group")
        self.certificates = Certificates(t, "certificate")
        self.application_segment = Segments(t, "segment")
        self.provisioning = Provisioning(t, "key:connector")
        self.enrollment_certificates = Enrollment(t, "enrollment")
        self.pra_portal = PraPortals(t, "pra_portal")
        self.pra_console = PraConsoles(t, "pra_console")
        self.user_portal_controller = UserPortals(t, "user_portal")


class ZpaClient:
    def __init__(self, t: Optional[ZpaTenant] = None):
        self.tenant = t or ZpaTenant()
        self.zpa = ZpaNs(self.tenant)
        self.zia = None


# ── Client Connector ───────────────────────────────────────────────────

class ZccTenant:
    def __init__(self) -> None:
        self.devices: List[Dict[str, Any]] = []
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.profiles: Dict[str, List[Dict[str, Any]]] = {p: [] for p in ("ios", "android", "windows", "macos", "linux")}
        self.ent = {"zpa": {"zpaEnableForAll": True, "groupList": ["Engineering"], "deviceGroupList": [], "machineTunEnabledForAll": False},
                    "zdx": {"upmEnableForAll": False, "upmGroupList": ["IT"], "upmDeviceGroupList": [], "collectZdxLocation": True}}
        self.writes: List[Tuple[str, str, Any]] = []
        self.reads: List[str] = []
        self.fail: Dict[str, str] = {}
        self.n = 600

    def seed(self) -> None:
        self.devices = [
            {"udid": "VMW-1:AAA", "user": "jdoe@acme.com", "machineHostname": "JDOE-LT", "osVersion": "Windows 11", "type": "3",
             "agentVersion": "4.5.0", "registrationState": "Registered", "deviceOtpArray": [CANARY_OTP], "last_seen_time": "2026-10-30"},
            {"udid": "MAC-2:BBB", "user": "jdoe@acme.com", "machineHostname": "JDOE-MBP", "osVersion": "macOS 15", "type": "4",
             "agentVersion": "4.4.1", "registrationState": "Removal Pending"},
            {"udid": "VMW-9:ZZZ", "user": "other@acme.com", "machineHostname": "OTHER", "registrationState": "Registered"},
        ]
        self.apps = {"501": {"id": 501, "appName": "Teams media", "active": True,
                             "appDataBlob": [{"proto": "UDP", "port": "3478-3481", "ipaddr": "52.112.0.0/14", "fqdn": ""}], "appDataBlobV6": [],
                             "createdBy": "admin"},
                     "502": {"id": 502, "appName": "Old VoIP", "active": False,
                             "appDataBlob": [{"proto": "TCP", "port": "5060", "ipaddr": "10.9.0.0/16", "fqdn": ""}], "appDataBlobV6": []}}
        self.profiles["windows"] = [{"id": 1, "name": "Default Windows", "bypassCustomAppIds": [501], "active": "1"}]


class _Dev:
    def __init__(self, t: ZccTenant):
        self.t = t

    def list_devices(self, query_params=None):
        q = query_params or {}
        self.t.reads.append(f"devices:{q.get('username')}")
        mine = [d for d in self.t.devices if q.get("username") in (None, d["user"])]
        size = int(q.get("page_size") or 50)
        page = int(q.get("page") or 1)
        rows = [copy.deepcopy(d) for d in mine[(page - 1) * size: page * size]]
        return rows, Resp(rows), None

    def _remove(self, kind, kw):
        self.t.writes.append((kind, "device", copy.deepcopy(kw)))
        if self.t.fail.get(kind):
            return None, Resp({"errorMsg": self.t.fail[kind], "devicesRemoved": 0}), None
        n = 0
        for d in list(self.t.devices):
            if d["udid"] in kw.get("udids", []):
                n += 1
                if kind == "force_remove":
                    self.t.devices.remove(d)
                else:
                    d["registrationState"] = "Removal Pending"
        return [], Resp({"devicesRemoved": n, "errorMsg": ""}), None

    def remove_devices(self, query_params=None, **kw):
        return self._remove("remove", kw)

    def force_remove_devices(self, query_params=None, **kw):
        return self._remove("force_remove", kw)


class _CustomApps:
    def __init__(self, t: ZccTenant):
        self.t = t

    def get_custom_ip_base_apps(self):
        self.t.reads.append("custom-ip-based-apps")
        body = {"customAppContracts": [copy.deepcopy(a) for a in self.t.apps.values()]}
        return [], Resp(body), None


class _WebPolicy:
    def __init__(self, t: ZccTenant):
        self.t = t

    def list_by_company(self, query_params=None):
        q = query_params or {}
        if self.t.fail.get("profiles"):
            return None, None, self.t.fail["profiles"]
        rows = copy.deepcopy(self.t.profiles.get(q.get("device_type"), [])) if int(q.get("page") or 1) == 1 else []
        return rows, Resp(rows), None


class Executor:
    """The SDK's request executor for the raw ZCC calls: every request kept."""

    def __init__(self, t: ZccTenant):
        self.t = t
        self.sent: List[Dict[str, Any]] = []

    def create_request(self, method, endpoint, body=None, headers=None, params=None):
        return {"method": method, "endpoint": endpoint, "body": copy.deepcopy(body), "params": params}, None

    def execute(self, req):
        self.sent.append(req)
        m, path, body = req["method"], req["endpoint"], req["body"]
        base = "/zcc/papi/public/v1"
        assert path.startswith(base), path
        p = path[len(base):]
        if self.t.fail.get(f"{m} {p}"):
            return None, self.t.fail[f"{m} {p}"]
        if m == "GET" and p in ("/getZpaGroupEntitlements", "/getZdxGroupEntitlements"):
            self.t.reads.append(p)
            return Resp(copy.deepcopy(self.t.ent["zpa" if "Zpa" in p else "zdx"])), None
        if m == "PUT" and p in ("/updateZpaGroupEntitlement", "/updateZdxGroupEntitlement"):
            self.t.writes.append(("put", p, copy.deepcopy(body)))
            self.t.ent["zpa" if "Zpa" in p else "zdx"] = copy.deepcopy(body)
            return Resp({"success": "true"}), None
        if m == "POST" and p == "/custom-ip-based-apps":
            self.t.writes.append(("post", p, copy.deepcopy(body)))
            self.t.n += 1
            self.t.apps[str(self.t.n)] = dict(copy.deepcopy(body), id=self.t.n)
            return Resp({"id": self.t.n, "success": "true"}), None
        mm = re.fullmatch(r"/custom-ip-based-apps/(\d+)", p)
        if mm and m == "PUT":
            self.t.writes.append(("put", p, copy.deepcopy(body)))
            self.t.apps[mm.group(1)] = dict(copy.deepcopy(body), id=int(mm.group(1)))
            return Resp({"success": "true"}), None
        if mm and m == "DELETE":
            self.t.writes.append(("delete", p, None))
            if self.t.apps.pop(mm.group(1), None) is None:
                return None, "HTTP 404"
            return Resp({"success": "true"}), None
        return None, f"HTTP 404 {m} {p}"


class ZccNs:
    def __init__(self, t: ZccTenant, ex: Executor):
        self.devices = _Dev(t)
        self.custom_ip_base_apps = _CustomApps(t)
        self.web_policy = _WebPolicy(t)
        self._request_executor = ex


class ZccClient:
    def __init__(self, t: Optional[ZccTenant] = None):
        self.tenant = t or ZccTenant()
        self.executor = Executor(self.tenant)
        self.zcc = ZccNs(self.tenant, self.executor)
        self.zia = None


# ── ZDX ─────────────────────────────────────────────────────────────────

class ZdxTenant:
    def __init__(self) -> None:
        self.devices = {"132559212": {"id": 132559212, "name": "JDOE-LT", "user": "jdoe@acme.com"}}
        self.apps = {"3": {"id": 3, "name": "Microsoft 365", "score": 71}}
        self.web_probes = {("132559212", "3"): [{"id": 41, "name": "M365 web"}]}
        self.path_probes = {("132559212", "3"): [{"id": 42, "name": "M365 path"}]}
        self.traces: Dict[str, Dict[str, Dict[str, Any]]] = {"132559212": {}}
        self.status_script: List[str] = []   # statuses a trace answers, one per read, then the last one forever
        self.writes: List[Tuple[str, str, Any]] = []
        self.reads: List[str] = []
        self.n = 342941739947000


class _ZdxDevices:
    def __init__(self, t: ZdxTenant):
        self.t = t

    def list_devices(self, query_params=None):
        self.t.reads.append("devices")
        emails = (query_params or {}).get("emails") or []
        rows = [d for d in self.t.devices.values() if d["user"] in emails]
        return rows, Resp({"devices": copy.deepcopy(rows)}), None

    def get_device(self, device_id, query_params=None):
        self.t.reads.append("device")
        d = self.t.devices.get(str(device_id))
        return (d, Resp(copy.deepcopy(d)), None) if d else (None, None, "HTTP 404: not found")

    def get_device_apps(self, device_id, query_params=None):
        rows = list(self.t.apps.values())
        return rows, Resp(copy.deepcopy(rows)), None

    def get_device_app(self, device_id, app_id, query_params=None):
        body = {"id": int(app_id), "name": "Microsoft 365", "score": 71, "metrics": [{"metric": "pft", "datapoints": [{"value": 812}]}]}
        return body, Resp(body), None

    def get_health_metrics(self, device_id, query_params=None):
        body = [{"category": "cpu", "instances": [{"metric": "cpu_total", "datapoints": [{"value": 12}]}]}]
        return body, Resp(body), None

    def get_web_probes(self, device_id, app_id, query_params=None):
        rows = self.t.web_probes.get((str(device_id), str(app_id)), [])
        return rows, Resp(copy.deepcopy(rows)), None

    def list_cloudpath_probes(self, device_id, app_id, query_params=None):
        rows = self.t.path_probes.get((str(device_id), str(app_id)), [])
        return rows, Resp(copy.deepcopy(rows)), None


class _ZdxApps:
    def __init__(self, t: ZdxTenant):
        self.t = t

    def list_apps(self, query_params=None):
        rows = list(self.t.apps.values())
        return rows, Resp(copy.deepcopy(rows)), None

    def get_app_score(self, app_id, query_params=None):
        body = {"metric": "score", "datapoints": [{"timestamp": 1, "value": 70}]}
        return body, Resp(body), None


class _ZdxUsers:
    def __init__(self, t: ZdxTenant):
        self.t = t

    def list_users(self, query_params=None):
        rows = [{"id": 1, "name": "Jane Doe", "email": "jdoe@acme.com", "devices": [{"id": 132559212, "name": "JDOE-LT"}]},
                {"id": 2, "name": "Someone Else", "email": "x@acme.com", "devices": []}]
        return rows, Resp({"users": rows}), None


class _Troubleshooting:
    def __init__(self, t: ZdxTenant):
        self.t = t

    def list_deeptraces(self, device_id):
        self.t.reads.append("traces")
        rows = list(self.t.traces.get(str(device_id), {}).values())
        return rows, Resp(copy.deepcopy(rows)), None

    def get_deeptrace(self, device_id, trace_id):
        self.t.reads.append("trace")
        r = self.t.traces.get(str(device_id), {}).get(str(trace_id))
        if r is None:
            return None, None, "HTTP 404: not found"
        if self.t.status_script:
            r["status"] = self.t.status_script.pop(0) if len(self.t.status_script) > 1 else self.t.status_script[0]
        return [r], Resp(copy.deepcopy(r)), None

    def start_deeptrace(self, device_id, **kw):
        self.t.writes.append(("start", str(device_id), copy.deepcopy(kw)))
        self.t.n += 1
        tid = str(self.t.n)
        self.t.traces.setdefault(str(device_id), {})[tid] = {"trace_id": tid, "status": "in_progress", "trace_details": dict(kw)}
        return None, Resp({"trace_id": tid, "status": "in_progress"}), None

    def delete_deeptrace(self, device_id, trace_id):
        self.t.writes.append(("delete", str(device_id), str(trace_id)))
        if self.t.traces.get(str(device_id), {}).pop(str(trace_id), None) is None:
            return None, None, "HTTP 404: not found"
        return None, Resp({}), None

    def _metric(self, device_id, trace_id):
        return [{"metric": "pft", "datapoints": [{"value": 1}]}], Resp([{"metric": "pft", "datapoints": [{"value": 1}]}]), None

    get_deeptrace_webprobe_metrics = get_deeptrace_cloudpath_metrics = get_deeptrace_cloudpath = _metric
    get_deeptrace_health_metrics = get_deeptrace_events = _metric


class ZdxNs:
    def __init__(self, t: ZdxTenant):
        self.devices = _ZdxDevices(t)
        self.troubleshooting = _Troubleshooting(t)
        self.apps = _ZdxApps(t)
        self.users = _ZdxUsers(t)


class ZdxClient:
    def __init__(self, t: Optional[ZdxTenant] = None):
        self.tenant = t or ZdxTenant()
        self.zdx = ZdxNs(self.tenant)
        self.zia = None
