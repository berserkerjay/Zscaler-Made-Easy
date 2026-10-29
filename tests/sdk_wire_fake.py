"""A stateful fake tenant at the SDK's wire level, for the builder lifecycle
tests (tests/test_qa6_builders_lifecycle.py).

The app's code talks to the installed zscaler-sdk-python 1.11.3 service and
model classes, exactly as it does against a live tenant; only the executor
under them is replaced (offline_tenant.OfflineExecutor, which has no network
code). On top of the sample tenant's answers this store:

* replaces an object on PUT, as ZIA and ZPA do (the sample merges), so a
  write that leaves a field out is seen to clear it;
* keeps ZIA rule orders contiguous: a rule created or moved to order n
  pushes the others down, the default rule never moves;
* answers ZPA's PUT and DELETE with 204, as ZPA does;
* checks every POST / PUT body against the SDK model the service method
  names for the answer (`execute(request, Model)`): a field the model does
  not know, at any depth the model describes, is recorded in `violations`;
* refuses (400 NOT_MODELLED, recorded) any write to a path it does not hold,
  so a call to an endpoint the SDK does not have fails the test;
* models what the API does on its own: a custom URL category's incremental
  ADD_TO_LIST / REMOVE_FROM_LIST update, ZPA's policy rules written under
  /policySet/{id}/rule and listed by policy type, the PRA applications ZPA
  adds to a segment, and Client Connector's edit and delete endpoints.

A field sent back exactly as the tenant answered it (a re-read object
written whole) is recorded in `echoed`, not as a violation; a Client
Connector field outside the SDK model is recorded in `assumed` (the module
sends the portal's own payload, ops_zcc.ASSUMED).

Deterministic: ids count up from a fixed base, no clock, no randomness."""
from __future__ import annotations

import copy
import importlib
import inspect
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

import offline_tenant as ot
import sample_tenant

ZIA = "/zia/api/v1"
ZPA1 = "/zpa/mgmtconfig/v1/admin/customers/{customerId}"
ZPA2 = "/zpa/mgmtconfig/v2/admin/customers/{customerId}"
ZCC = "/zcc/papi/public/v1"
ZCC_FWD = f"{ZCC}/webForwardingProfile/listByCompany"
ZCC_APPS = (f"{ZCC}/web/policy/listByCompany", f"{ZCC}/application-profiles")

# Fields the API takes that SDK 1.11.3's models leave out (commented out in
# the model), each with why it is still sent. Anything else unknown fails.
ACCEPTED_OUTSIDE_MODEL: Dict[str, Set[str]] = {
    # zscaler/zia/models/sandboxrules.py comments out cbiProfile; the service
    # passes it through (utils.reformat_params maps cbi_profile) and ZIA's
    # sandboxRules API takes it for the QUARANTINE_ISOLATE first-time action.
    "SandboxRules": {"cbiProfile"},
    # zscaler/zpa/provisioning.py add_provisioning_key/update_provisioning_key
    # read component_id and add zcomponentId but leave component_id in the
    # body too: the SDK sends both (the app passes component_id as documented).
    "ProvisioningKey": {"componentId"},
    # ai_guard.py ASSUMED: a policy match rule of type APPLICATION names
    # llmProviders, which SDK 1.11.3's MatchCriteria model does not list.
    "MatchCriteria": {"llmProviders"},
    # A predefined dictionary's clone names its template: ZIA's own answer
    # carries dictTemplateId (pack_export reads it from the raw answer), the
    # SDK 1.11.3 DLPDictionary model leaves it out.
    "DLPDictionary": {"dictTemplateId"},
    # ai_guard.py (documented there): prompt-capture switches the SDK 1.11.3
    # model does not declare are sent only when the tenant's own settings
    # already carry them, i.e. ZIA answered with them.
    "AdvancedUrlFilterAndCloudAppSettings": {"enableClaudePrompt", "enableGrokPrompt", "enableMistralAIPrompt"},
}

_CFG_KEY = re.compile(r'config(?:\["|\.get\(\s*")([A-Za-z0-9_]+)"')
_FORMAT_KEY = re.compile(r'^\s*"([A-Za-z0-9_]+)":\s*self\.', re.M)
_NESTED = (re.compile(r'([A-Za-z_][A-Za-z0-9_.]*)\(\s*config\["([A-Za-z0-9_]+)"\]\s*\)'),
           re.compile(r'\[\s*([A-Za-z_][A-Za-z0-9_.]*)\(\s*\w+\s*\)\s*for\s+\w+\s+in\s+config\["([A-Za-z0-9_]+)"\]'),
           re.compile(r'form_list\(\s*config\["([A-Za-z0-9_]+)"\]\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)'))
_SCHEMAS: Dict[type, Tuple[Set[str], Dict[str, type]]] = {}


def _resolve(module, dotted: str) -> Optional[type]:
    obj: Any = module
    for part in dotted.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj if inspect.isclass(obj) else None


def model_schema(cls: type) -> Tuple[Set[str], Dict[str, type]]:
    """(camelCase keys the model reads, {key: nested model class}), from the
    model's own source with commented-out lines left out."""
    if cls in _SCHEMAS:
        return _SCHEMAS[cls]
    try:
        src = inspect.getsource(cls)
    except (OSError, TypeError):
        _SCHEMAS[cls] = (set(), {})
        return _SCHEMAS[cls]
    live = "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))
    keys = set(_CFG_KEY.findall(live)) | set(_FORMAT_KEY.findall(live))
    module = sys.modules.get(cls.__module__) or importlib.import_module(cls.__module__)
    nested: Dict[str, type] = {}
    for rx in _NESTED:
        for a, b in rx.findall(live):
            name, key = (b, a) if rx is _NESTED[2] else (a, b)
            sub = _resolve(module, name)
            if sub is not None and sub is not cls and hasattr(sub, "as_dict"):
                nested.setdefault(key, sub)
    _SCHEMAS[cls] = (keys, nested)
    return _SCHEMAS[cls]


def unknown_fields(body: Any, cls: type, path: str = "") -> List[str]:
    """Every field of `body` (camelCase, as sent) the SDK model `cls` does not
    know, as dotted paths."""
    keys, nested = model_schema(cls)
    if not keys or not isinstance(body, dict):
        return []
    ok = keys | ACCEPTED_OUTSIDE_MODEL.get(cls.__name__, set())
    out = []
    for k, v in body.items():
        here = f"{path}{k}"
        if k not in ok:
            out.append(f"{cls.__name__}.{here}")
            continue
        sub = nested.get(k)
        if sub is None:
            continue
        for x in (v if isinstance(v, list) else [v]):
            out.extend(unknown_fields(x, sub, here + "."))
    return out


def _is_zia_rules(path: str, items: List[Any]) -> bool:
    if not path.startswith(ZIA):
        return False
    return (any(isinstance(x, dict) and "order" in x for x in items) or path.rsplit("/", 1)[-1].endswith(("Rules", "rules"))
            or "/webApplicationRules/" in path)


def _order(x: Dict[str, Any]) -> int:
    try:
        return int(x.get("order") or 0)
    except (TypeError, ValueError):
        return 0


def _default(x: Dict[str, Any]) -> bool:
    return bool(x.get("defaultRule") or x.get("default_rule")) or _order(x) < 0


class WireStore(ot.OfflineStore):
    """The sample tenant's answers (plus `extra`), with real write semantics."""

    def __init__(self, extra: Optional[Dict[str, Any]] = None, *, drop: Tuple[str, ...] = ()):
        # One deepcopy of the whole table: paths the sample serves from one
        # list (casbDlpRules and casbDlpRules/all, the two app profile
        # listings) stay one list, as the API's are one collection.
        responses = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in copy.deepcopy(sample_tenant.responses()).items()}
        for p in drop:
            responses.pop(ot.normalize_path(p), None)
        for p, b in (extra or {}).items():
            responses[ot.normalize_path(p)] = {"status": 200, "body": copy.deepcopy(b)}
        super().__init__("sample", ot.SAMPLE, responses, sample_tenant.meta(), writable=True)
        self.log: List[Tuple[str, str, Any]] = []
        self.violations: List[str] = []
        self.assumed: List[str] = []
        self.echoed: List[str] = []
        self.next_id = 950000
        # ZPA writes a policy's rules under /policySet/{id}/rule and lists them
        # under /policySet/rules/policyType/{TYPE}: one collection, two paths.
        self.aliases: Dict[str, str] = {}
        for t in ("ACCESS_POLICY", "TIMEOUT_POLICY", "CLIENT_FORWARDING_POLICY", "INSPECTION_POLICY", "ISOLATION_POLICY",
                  "CREDENTIAL_POLICY", "CAPABILITIES_POLICY", "REDIRECTION_POLICY"):
            sid = str(9100 + len(self.aliases))
            listing = ot.normalize_path(f"{ZPA1}/policySet/rules/policyType/{t}")
            self.responses.setdefault(listing, {"status": 200, "body": {"list": [], "totalPages": "1"}})
            self.responses.setdefault(ot.normalize_path(f"{ZPA1}/policySet/policyType/{t}"),
                                      {"status": 200, "body": {"id": sid, "name": t.title(), "policyType": t, "enabled": True}})
            self.aliases[ot.normalize_path(f"{ZPA1}/policySet/{sid}/rule")] = listing

    def _lookup(self, path: str) -> Optional[Dict[str, Any]]:
        return super()._lookup(self.aliases.get(path, path))

    # -- what a test compares ------------------------------------------------
    def state(self, *prefixes: str) -> Dict[str, Any]:
        """{path: body} of every answer (or those under `prefixes`), copied."""
        return {p: copy.deepcopy(e.get("body")) for p, e in sorted(self.responses.items())
                if not prefixes or p.startswith(prefixes)}

    def write_log(self) -> List[Tuple[str, str]]:
        return [(m, p) for m, p, _ in self.log if m != "POST" or not p.endswith("/status/activate")]

    def rows(self, path: str) -> List[Dict[str, Any]]:
        entry = self._lookup(ot.normalize_path(path))
        return copy.deepcopy(ot._items(entry["body"]) or []) if entry else []

    def by_name(self, path: str, name: str) -> Optional[Dict[str, Any]]:
        return next((r for r in self.rows(path) if r.get("name") == name), None)

    # -- the API's write semantics ---------------------------------------------
    def check_body(self, url: str, body: Any, model: Any) -> None:
        if inspect.isclass(model) and isinstance(body, dict):
            path = ot.normalize_path(url)
            item, _, _ = self._item(path)
            if item is None:
                entry = self._lookup(path)
                item = entry.get("body") if entry and isinstance(entry.get("body"), dict) else None
            for f in unknown_fields(body, model):
                top = f.split(".", 2)[1]
                if isinstance(item, dict) and top in item:
                    # Sent back as the tenant answered it (a re-read object
                    # written whole): the tenant's field, not one the app made up.
                    self.echoed.append(f"{path}: {f}")
                elif path.startswith("/zcc/"):
                    # Client Connector bodies are the portal's own payload: fields
                    # the SDK model does not declare are assumed (ops_zcc.ASSUMED).
                    self.assumed.append(f"{path}: {f}")
                else:
                    self.violations.append(f"{path}: {f}")

    def _zcc_write(self, method: str, path: str, body: Any) -> Optional[Tuple[int, Any]]:
        """ZCC's portal-style endpoints: one edit path creates (no id, or id
        -1) or replaces; /{id}/delete deletes (assumed, ops_zcc.ASSUMED)."""
        def colls(p: str) -> List[List[Any]]:
            return [ot._items(self.responses[x]["body"]) for x in ((ZCC_FWD,) if "Forwarding" in p else ZCC_APPS) if x in self.responses]
        m = re.fullmatch(re.escape(ZCC) + r"/(webForwardingProfile|web/policy)/(?:edit|(\d+)/delete)", path)
        if not m:
            return None
        lists = colls(path)
        if not lists:
            return None
        if m.group(2):
            if method != "DELETE":
                return None
            hit = False
            for items in lists:
                for i, x in enumerate(list(items)):
                    if str(x.get("id")) == m.group(2):
                        items.pop(i)
                        hit = True
                        break
            if not hit:
                return 404, {"success": "false", "error": "not found"}
            self.writes += 1
            return 200, {"success": "true"}
        obj = copy.deepcopy(body) if isinstance(body, dict) else {}
        oid = str(obj.get("id") or "")
        if oid in ("", "-1", "0"):
            self.next_id += 1
            obj["id"] = str(self.next_id)
            for items in lists:
                items.append(copy.deepcopy(obj))
        else:
            for items in lists:
                for i, x in enumerate(items):
                    if str(x.get("id")) == oid:
                        items[i] = copy.deepcopy(obj)
        self.writes += 1
        return 200, {"success": "true", "id": obj["id"]}

    def _derive(self, collection: str, obj: Dict[str, Any], old: Optional[Dict[str, Any]] = None) -> None:
        """What the API adds to an object itself (assumed, as the portal shows
        it): ZIA flags a dictionary made through the API as custom; ZPA adds
        a PRA application per SECURE_REMOTE_ACCESS entry of a segment's
        commonAppsDto.appsConfig, kept across updates."""
        if collection.endswith("/dlpDictionaries"):
            obj.setdefault("custom", True)   # ZIA marks a dictionary made through the API as custom
            return
        if not collection.endswith("/application"):
            return
        cfg = ((obj.get("commonAppsDto") or {}).get("appsConfig") or [])
        pra = [c for c in cfg if isinstance(c, dict) and "SECURE_REMOTE_ACCESS" in (c.get("appTypes") or [])]
        if not pra:
            return
        kept = {str(a.get("name")): a for a in ((old or {}).get("praApps") or []) if isinstance(a, dict)}
        out = []
        for c in pra:
            name = str(c.get("name") or c.get("domain") or "")
            if name not in kept:
                self.next_id += 1
                kept[name] = {"id": str(self.next_id), "name": name, "applicationProtocol": c.get("applicationProtocol")}
            out.append(kept[name])
        obj["praApps"] = out

    def answer_write(self, method: str, url: str, body: Any = None) -> Tuple[int, Any]:
        method = str(method or "").upper()
        path = ot.normalize_path(url)
        self.log.append((method, path, copy.deepcopy(body)))
        zpa = path.startswith("/zpa/")
        with self._lock:
            if method == "POST" and path.endswith("/status/activate"):
                return 200, {"status": "ACTIVE"}
            if method == "POST" and path.endswith("/urlLookup"):   # a read the API asks for with a POST
                self.log.pop()
                return 200, sample_tenant.url_lookup(body if isinstance(body, list) else [])
            zcc = self._zcc_write(method, path, body) if path.startswith(ZCC) else None
            if zcc is not None:
                return zcc
            entry = self._lookup(path)
            items = ot._items(entry["body"]) if entry else None
            if method == "POST" and items is not None:
                obj = copy.deepcopy(body) if isinstance(body, dict) else {}
                self.next_id += 1
                obj["id"] = str(self.next_id) if zpa else self.next_id
                if _is_zia_rules(path, items) and _order(obj) > 0:
                    live = [x for x in items if isinstance(x, dict) and not _default(x)]
                    if _order(obj) > len(live) + 1:
                        self.violations.append(f"{path}: POST order {_order(obj)} is past the end ({len(live)} rules)")
                    for x in live:
                        if _order(x) >= _order(obj):
                            x["order"] = _order(x) + 1
                self._derive(path, obj)
                items.append(obj)
                self.writes += 1
                return 200, copy.deepcopy(obj)
            item, coll, idx = self._item(path)
            action = str((getattr(self, "params", None) or {}).get("action") or "")
            if method == "PUT" and item is not None and "/urlCategories/" in path and action in ("ADD_TO_LIST", "REMOVE_FROM_LIST"):
                # ZIA's incremental URL update: only the named URLs are added or removed
                urls = [u for u in (item.get("urls") or []) if u not in ((body or {}).get("urls") or [])]
                if action == "ADD_TO_LIST":
                    urls += list((body or {}).get("urls") or [])
                item["urls"] = urls
                self.writes += 1
                return 200, copy.deepcopy(item)
            if method in ("PUT", "PATCH") and item is not None:
                new = copy.deepcopy(body) if isinstance(body, dict) else {}
                if method == "PATCH":
                    new = dict(copy.deepcopy(item), **new)
                new["id"] = item.get("id")
                if _is_zia_rules(path.rsplit("/", 1)[0], coll) and not _default(item) and _order(new) > 0 and _order(new) != _order(item):
                    old, to = _order(item), _order(new)
                    for x in coll:
                        if x is item or not isinstance(x, dict) or _default(x):
                            continue
                        o = _order(x)
                        if old < o <= to:
                            x["order"] = o - 1
                        elif to <= o < old:
                            x["order"] = o + 1
                self._derive(path.rsplit("/", 1)[0], new, item)
                coll[idx] = new
                self.writes += 1
                return (204, {}) if zpa else (200, copy.deepcopy(new))
            if method == "DELETE" and item is not None:
                coll.pop(idx)
                self.writes += 1
                if _is_zia_rules(path.rsplit("/", 1)[0], coll) and not _default(item):
                    for x in coll:
                        if isinstance(x, dict) and not _default(x) and _order(x) > _order(item) > 0:
                            x["order"] = _order(x) - 1
                return 204, {}
            if method in ("PUT", "PATCH") and entry is not None and isinstance(entry.get("body"), dict) and items is None:
                new = copy.deepcopy(body) if isinstance(body, dict) else {}
                entry["body"] = dict(entry["body"], **new) if method == "PATCH" else new
                self.writes += 1
                return 200, copy.deepcopy(entry["body"])
        self.violations.append(f"{method} {path}: not a path this tenant holds")
        return 400, {"code": "NOT_MODELLED", "message": f"The wire fake holds no {path} ({method}); nothing was written."}


class WireExecutor(ot.OfflineExecutor):
    @staticmethod
    def get_service_type(url: str) -> str:
        # as the SDK's own executor: AI Guard lists come in {"items": [...]}
        return "aiguard" if "/aiguard/" in str(url or "") else ot.OfflineExecutor.get_service_type(url)

    def fire_request(self, request: Dict[str, Any]):
        self._store.params = dict(request.get("params") or {})
        return super().fire_request(request)

    def create_request(self, *a: Any, **k: Any):
        req, err = super().create_request(*a, **k)
        if req is not None:
            req["service_type"] = self.get_service_type(req.get("url", ""))
        return req, err

    def execute(self, request: Dict[str, Any], response_type: Any = None, return_raw_response: bool = False):
        if str(request.get("method") or "").upper() in ("POST", "PUT", "PATCH"):
            model = response_type
            if model is None and "/webApplicationRules/" in str(request.get("url") or ""):
                # the SDK's cloudappcontrol.update_rule names no answer model: check against the rule's own
                from zscaler.zia.models.cloudappcontrol import CloudApplicationControl as model
            self._store.check_body(request.get("url", ""), request.get("json"), model)
        return super().execute(request, response_type, return_raw_response)


class WireClient(ot.OfflineSdkClient):
    """The SDK client (.zia, .zpa, .zcc, .zdx ...) over a WireStore."""

    def __init__(self, store: WireStore):
        super().__init__(store, {"vanity_domain": "larkspur"})
        self._request_executor = WireExecutor(store)
        self.store = store

    @property
    def aiguard(self):
        from zscaler.aiguard.aiguard_service import AIGuardService
        return self._svc("aiguard", lambda: AIGuardService(self._request_executor))


# ── What a builder reads that the sample tenant does not carry ───────────

def _zl(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"list": items, "totalPages": "1"}


def zia_catalogues() -> Dict[str, Any]:
    """Every URL category, network application, cloud application and
    Cloud App Control rule type the ZIA baseline names, the Trusted Resolver
    gateway and two ready-to-use intermediate certificates."""
    import ops_zia_baseline as zb
    cats = sorted({c for r in zb.CATALOG for c in r["fields"].get("url_categories", [])})
    nw = sorted({a for r in zb.CATALOG for a in r["fields"].get("nw_applications", [])})
    cloud = sorted({a for r in zb.CATALOG for a in r["fields"].get("applications", []) if r["area"] == "cac"})
    out = {f"{ZIA}/urlCategories/lite": [{"id": c} for c in cats] + [{"id": "CUSTOM_01"}],
           f"{ZIA}/networkApplications": [{"id": a} for a in nw],
           f"{ZIA}/cloudApplications/policy": [{"app": a} for a in cloud],
           f"{ZIA}/dnsGateways": [{"id": 9, "name": "Zscaler Trusted Resolver", "natZtrGateway": True}],
           f"{ZIA}/intermediateCaCertificate/readyToUse": [
               {"id": 50, "name": "Zscaler Intermediate CA", "defaultCertificate": True, "status": "ENABLED", "type": "ZSCALER"},
               {"id": 52, "name": "New CA 2026", "status": "ENABLED", "type": "CUSTOM"}]}
    for t in sorted({r["fields"]["type"] for r in zb.CATALOG if r["area"] == "cac"} | {"AI_ML"}):
        out[f"{ZIA}/webApplicationRules/{t}"] = []
    return out


def zpa_builder_lists() -> Dict[str, Any]:
    """The ZPA lists the ZPA builder reads that the sample has no answer for."""
    certs = [{"id": "8001", "name": "Connector"}, {"id": "8002", "name": "Service Edge"}]
    controls = [{"id": "70001", "name": "Preprocessors", "defaultGroup": True, "predefinedInspectionControls": [
                    {"id": "70011", "name": "Multipart request body failed strict validation", "action": "BLOCK", "defaultAction": "BLOCK",
                     "controlType": "PREDEFINED", "protocolType": "HTTP", "paranoiaLevel": "1", "severity": "CRITICAL"}]},
                {"id": "70002", "name": "Environment and port scanners", "defaultGroup": True, "predefinedInspectionControls": [
                    {"id": "70021", "name": "Found User-Agent associated with security scanner", "action": "BLOCK", "defaultAction": "BLOCK",
                     "controlType": "PREDEFINED", "protocolType": "HTTP", "paranoiaLevel": "1", "severity": "CRITICAL"}]}]
    return {f"{ZPA1}/associationType/CONNECTOR_GRP/provisioningKey": _zl([]),
            f"{ZPA1}/associationType/SERVICE_EDGE_GRP/provisioningKey": _zl([]),
            f"{ZPA1}/enrollmentCert": _zl(copy.deepcopy(certs)), f"{ZPA2}/enrollmentCert": _zl(copy.deepcopy(certs)),
            f"{ZPA1}/inspectionProfile": _zl([]),
            f"{ZPA1}/inspectionControls/predefined/versions": ["OWASP_CRS/3.3.0", "OWASP_CRS/4.8.0"],
            f"{ZPA1}/inspectionControls/predefined": controls,
            f"{ZPA1}/praConsole": _zl([]), f"{ZPA1}/praPortal": _zl([{"id": "6101", "name": "pra.corp.example.com"}]),
            f"{ZPA1}/clientlessCertificate/issued": _zl([{"id": "6001", "name": "web.corp.example.com"}]),
            f"{ZPA2}/clientlessCertificate/issued": _zl([{"id": "6001", "name": "web.corp.example.com"}]),
            f"{ZPA1}/isolation/profiles": _zl([{"id": "6201", "name": "Default isolation"}])}


AIG = "/aiguard/v1"


def aiguard_lists(*, proxy: bool = False, gateway: bool = False, licensed: bool = True) -> Dict[str, Any]:
    """ZIA's proxy-chaining objects and AI Guard's detection lists."""
    import ai_guard as ag
    out = {f"{ZIA}/rootCertificates": [{"id": 11, "name": "AI Guard CA"}],
           f"{ZIA}/proxies": [{"id": 21, "name": "AIG-Proxy", "type": "PROXYCHAIN", "address": ag.AI_GUARD_HOST, "port": 9443,
                               "cert": {"id": 11, "name": "AI Guard CA"}}] if proxy else [],
           f"{ZIA}/proxyGateways": [{"id": 31, "name": "AIG-Gateway", "primaryProxy": {"id": 21, "name": "AIG-Proxy"}, "failClosed": True}] if gateway else [],
           f"{ZIA}/forwardingRules": [],
           f"{ZIA}/networkServices": [{"id": 41, "name": "QUIC", "tag": "QUIC"}, {"id": 42, "name": "HTTPS"}],
           f"{ZIA}/advancedUrlFilterAndCloudAppSettings": {"enableChatGptPrompt": False, "enableMicrosoftCoPilotPrompt": False,
                                                            "enableGeminiPrompt": True, "enableClaudePrompt": False, "enableMsftO365": True,
                                                            "enforceSafeSearch": True},
           f"{ZIA}/subscriptions": [{"id": "ZIA_BUS", "status": "ACTIVE", "subscribed": True}]
           + ([{"id": "ZS_DP_GEN_AI", "status": "ACTIVE", "subscribed": True}] if licensed else []),
           f"{AIG}/detections/policies": {"items": []},
           f"{AIG}/detections/policy-match-rules": {"items": []},
           f"{AIG}/llm-providers": {"items": [{"id": 1, "name": "Default OpenAI Provider"}, {"id": 2, "name": "Default Anthropic Provider"}]}}
    out.update({k: v for k, v in zia_catalogues().items() if "/webApplicationRules/" in k})
    return out


def semantic(state: Any) -> Any:
    """A state with what the API treats as unset (None, False, 0, "", [], {})
    left out, at every depth: an object written back whole by the SDK's
    model carries such defaults where the original simply had no field."""
    if isinstance(state, dict):
        out = {k: semantic(v) for k, v in state.items()}
        return {k: v for k, v in out.items() if v not in (None, False, 0, "", [], {})}
    if isinstance(state, list):
        return [semantic(v) for v in state]
    return state
