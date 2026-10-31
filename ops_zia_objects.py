"""The objects around the rule editor, on the Bulk changes engine
(admin_ops.register): the same scope check before any read, preview with
a plan hash, the four gates, the re-plan, a re-read right before each
write, writes through pack_ops (audited, with the actor), read-back and a
recorded, previewed Undo.

zpa_segment_edit    Edit one ZPA application segment's settings (name,
                    description, bypass, health reporting, ICMP, double
                    encryption, ports, ...) and enable or disable it.
                    Domains move with "ZPA segment domains". ZPA applies
                    each change as it is saved, so every edit of an enabled
                    segment needs the typed phrase. SDK 1.11.3
                    zpa/application_segment.py get_segment / update_segment
                    (PUT /application/{id}); a PUT clears ports it is not
                    given, so the body is the segment as read
                    (admin_ops.segment_body) with the changed fields set.

app_object_edit     Cloud application instances and tenancy restriction
                    profiles: browse them (read-only) and create or edit
                    one. SDK 1.11.3 zia/cloud_app_instances.py
                    (list_ / get_ / add_ / update_ / delete_cloud_app_instances,
                    /cloudApplicationInstances; the id is instanceId) and
                    zia/tenancy_restriction_profile.py (list_ / get_ / add_ /
                    update_ / delete_restriction_profile,
                    /tenancyRestrictionProfile). Undo of a create deletes it.

proxy_chain_edit    Proxy chaining: create or edit a third-party proxy
                    (zia/proxies.py list_proxies / get_proxy / add_proxy /
                    update_proxy, /proxies) and list the proxy gateways
                    (list_proxy_gateways, /proxyGateways). The SDK cannot
                    create or change a gateway, so a gateway is a manual
                    step: the preview and the result carry a report of
                    what to do in the ZIA Admin Portal, and the forwarding
                    rule that uses it can then be made in "Edit a rule".

Scope: ZPA segments when ZPA is ticked; the ZIA objects when ZIA platform
is ticked. New proxies and objects are not live until a rule uses them.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import pack_channels as pc
import pack_ops as ops
import rule_editor as R

SEG_TYPE, SEG_FAMILY = "zpa_segment_edit", "zpa_segment_editor"
OBJ_TYPE, OBJ_FAMILY = "app_object_edit", "app_objects"
PROXY_TYPE, PROXY_FAMILY = "proxy_chain_edit", "proxy_chaining"
NAME_MAX = 255           # assumed for these objects (the API refuses longer)

INSTANCE_TYPES = ("SHAREPOINTONLINE", "ONEDRIVE", "BOXNET", "OKTA", "APPSPACE", "BITBUCKET", "GITHUB", "SLACK", "QUICK_BASE", "ZEPLIN",
                  "SOURCEFORGE", "ZOOM", "WORKDAY", "GDRIVE", "GOOGLE_WEBMAIL", "WINDOWS_LIVE_HOTMAIL", "MSTEAM")   # SDK docstring
IDENTIFIER_TYPES = ("URL", "REFURL", "KEYWORD")                                                                    # SDK docstring
TR_APPS = ("YOUTUBE", "GOOGLE", "MSLOGINSERVICES", "SLACK", "BOX", "FACEBOOK", "AWS", "DROPBOX", "WEBEX_LOGIN_SERVICES", "AMAZON_S3",
           "ZOHO_LOGIN_SERVICES", "GOOGLE_CLOUD_PLATFORM", "ZOOM", "IBMSMARTCLOUD", "GITHUB", "CHATGPT_AI")            # SDK docstring
TR_ITEMS = ("TENANT_RESTRICTION_TEAM_ID", "TENANT_RESTRICTION_ALLOWED_WORKSPACE_ID", "TENANT_RESTRICTION_DOMAIN",
            "TENANT_RESTRICTION_TENANT_NAME", "TENANT_RESTRICTION_TENANT_DIRECTORY", "TENANT_RESTRICTION_CHANNEL_ID",
            "TENANT_RESTRICTION_CATEGORY_ID", "TENANT_RESTRICTION_SCHOOL_ID", "TENANT_RESTRICTION_REQUEST_WORKSPACE_ID",
            "TENANT_RESTRICTION_EXP_BUCKET_OWNERID", "TENANT_RESTRICTION_EXP_BUCKET_SRC_OWNERID", "TENANT_RESTRICTION_RESTRICT_MSA",
            "TENANT_RESTRICTION_TENANT_POLICY_ID", "TENANT_RESTRICTION_ACCOUNT_ID", "TENANT_RESTRICTION_TENANT_ORG_ID",
            "TENANT_RESTRICTION_POLICY_LABEL", "TENANT_RESTRICTION_ENTERPRISE_SLUG", "TENANT_RESTRICTION_WORKSPACE_ID")       # SDK docstring


def _f(kind: str, label: str, **kw: Any) -> Dict[str, Any]:
    return dict(kind=kind, label=label, **kw)


# Each object kind: label, SDK service and read methods, the id field, the pack_ops kind it is written as, its form.
OBJECTS: Dict[str, Dict[str, Any]] = {
    "segment": {"label": "ZPA application segment", "id": "id", "name": "name", "fields": {
        "name": _f("text", "Name", required=True),
        "description": _f("longtext", "Description"),
        "enabled": _f("bool", "Enabled"),
        "bypass_type": _f("enum", "Client Connector bypass", values=("NEVER", "ALWAYS", "ON_NET")),
        "health_reporting": _f("enum", "Health reporting", values=("NONE", "ON_ACCESS", "CONTINUOUS")),
        "icmp_access_type": _f("enum", "ICMP access", values=("NONE", "PING", "PING_TRACEROUTING")),
        "double_encrypt": _f("bool", "Double encryption"),
        "is_cname_enabled": _f("bool", "Resolve CNAMEs on the connector"),
        "passive_health_enabled": _f("bool", "Passive health monitoring"),
        "select_connector_close_to_app": _f("bool", "Pick the connector closest to the app"),
        "ip_anchored": _f("bool", "Source IP anchoring"),
        "tcp_keep_alive": _f("flag01", "TCP keep-alive"),
        "tcp_ports": _f("ports", "TCP ports (e.g. 443, 8000-8080)"),
        "udp_ports": _f("ports", "UDP ports"),
    }},
    "instance": {"label": "Cloud application instance", "id": "instance_id", "name": "instance_name", "kind": "cloud_app_instance",
                 "service": "cloud_app_instances", "list": "list_cloud_app_instances", "get": "get_cloud_app_instances", "fields": {
                     "instance_name": _f("text", "Name", required=True),
                     "instance_type": _f("enum", "Application", values=INSTANCE_TYPES, required=True),
                     "instance_identifiers": _f("identifiers", "Identifiers (one per line: URL, REFURL or KEYWORD, then the value)",
                                                required=True),
                 }},
    "tenancy": {"label": "Tenancy restriction profile", "id": "id", "name": "name", "kind": "tenancy_profile",
                "service": "tenancy_restriction_profile", "list": "list_restriction_profile", "get": "get_restriction_profile", "fields": {
                    "name": _f("text", "Name", required=True),
                    "description": _f("longtext", "Description"),
                    "app_type": _f("enum", "Application", values=TR_APPS, required=True),
                    "item_type_primary": _f("enum", "Primary item type", values=TR_ITEMS),
                    "item_data_primary": _f("lines", "Primary items (one per line: tenant IDs, domains...)"),
                    "item_type_secondary": _f("enum", "Secondary item type", values=TR_ITEMS),
                    "item_data_secondary": _f("lines", "Secondary items (one per line)"),
                    "restrict_personal_o365_domains": _f("bool", "Restrict personal Microsoft 365 domains"),
                    "allow_google_consumers": _f("bool", "Allow Google consumer accounts"),
                    "allow_google_visitors": _f("bool", "Allow Google visitors"),
                    "ms_login_services_tr_v2": _f("bool", "Microsoft login services v2"),
                    "allow_gcp_cloud_storage_read": _f("bool", "Allow Google Cloud Storage reads"),
                }},
    "proxy": {"label": "Proxy (proxy chaining)", "id": "id", "name": "name", "kind": "zia_proxy",
              "service": "proxies", "list": "list_proxies", "get": "get_proxy", "fields": {
                  "name": _f("text", "Name", required=True),
                  "description": _f("longtext", "Description"),
                  "address": _f("host", "Address (IP address or host name)", required=True),
                  "port": _f("int", "Port", required=True, min=1, max=65535),
                  "insert_xau_header": _f("bool", "Add the X-Authenticated-User header"),
                  "base64_encode_xau_header": _f("bool", "Base64-encode that header"),
              }},
}
OBJ_KINDS = ("instance", "tenancy")


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

def _ranges_text(ranges: Sequence[Tuple[int, int]]) -> List[str]:
    return [str(a) if a == b else f"{a}-{b}" for a, b in sorted(set(ranges))]


def canon(f: Dict[str, Any], v: Any) -> Any:
    k = f["kind"]
    if k == "bool":
        return v is True or str(v).strip().lower() in ("true", "1", "yes")
    if k == "flag01":
        return str(v).strip() in ("1", "true", "True")
    if k == "int":
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    if k in ("lines", "ports"):
        return sorted({str(x).strip() for x in (v or []) if str(x).strip()})
    if k == "identifiers":
        out = []
        for x in v or []:
            if isinstance(x, dict):
                out.append(f"{str(x.get('identifier_type') or x.get('identifierType') or x.get('instance_type') or '').upper()} "
                           f"{str(x.get('instance_identifier') or x.get('instanceIdentifier') or '').strip()}")
            else:
                out.append(str(x).strip())
        return sorted({o for o in out if o.strip()})
    return "" if v is None else str(v)


def current(obj: str, row: Dict[str, Any]) -> Dict[str, Any]:
    row = row or {}
    out = {}
    for k, f in OBJECTS[obj]["fields"].items():
        if k in ("tcp_ports", "udp_ports"):
            out[k] = _ranges_text(ao._ranges(row, k[:3]))
        else:
            out[k] = canon(f, pc._field(row, k, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k)))
    return out


def _ports(v: Any, label: str) -> List[str]:
    vals = v if isinstance(v, list) else re.split(r"[\s,]+", str(v or ""))
    out = []
    for x in [str(x).strip() for x in vals if str(x).strip()][:200]:
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", x)
        a, b = (int(m.group(1)), int(m.group(2) or m.group(1))) if m else (0, 0)
        if not m or not (1 <= a <= b <= 65535):
            raise ao.OperationError(f"{label}: '{x[:20]}' is not a port (1-65535) or a range like 8000-8080.")
        out.append((a, b))
    return _ranges_text(out)


def validate(obj: str, fields: Any, *, partial: bool) -> Dict[str, Any]:
    if not isinstance(fields, dict):
        raise ao.OperationError("The fields must be an object.")
    specs = OBJECTS[obj]["fields"]
    unknown = [str(k)[:40] for k in fields if k not in specs]
    if unknown:
        raise ao.OperationError(f"A {OBJECTS[obj]['label']} has no field {', '.join(unknown[:5])} in this editor.")
    out: Dict[str, Any] = {}
    try:
        for k, f in specs.items():
            if k not in fields:
                continue
            v, lab, kind = fields[k], f["label"], f["kind"]
            if kind == "text":
                out[k] = R._text(v, lab, NAME_MAX, name=True)
            elif kind == "longtext":
                out[k] = R._text(v, lab, R.DESC_MAX)
            elif kind == "enum":
                s = str(v or "").strip().upper()
                if s and s not in f["values"]:
                    raise ao.OperationError(f"{lab}: '{s[:40]}' is not one of {', '.join(f['values'])}.")
                out[k] = s
            elif kind in ("bool", "flag01"):
                if v not in (True, False, None, ""):
                    raise ao.OperationError(f"{lab} must be yes or no.")
                out[k] = v is True
            elif kind == "int":
                try:
                    n = int(v)
                except (TypeError, ValueError):
                    raise ao.OperationError(f"{lab} must be a whole number.")
                if not f["min"] <= n <= f["max"]:
                    raise ao.OperationError(f"{lab} must be between {f['min']} and {f['max']}.")
                out[k] = n
            elif kind == "host":
                s = str(v or "").strip().lower()
                try:
                    s = str(ipaddress.ip_address(s))
                except ValueError:
                    if not R._HOST.match(s) or s.startswith("*."):
                        raise ao.OperationError(f"{lab}: '{s[:60]}' is not an IP address or a host name.")
                out[k] = s
            elif kind == "ports":
                out[k] = _ports(v, lab)
            elif kind == "lines":
                vals = R._list(v if isinstance(v, list) else [x for x in re.split(r"[\r\n]+", str(v or ""))], lab)
                vals = [str(x).strip() for x in vals if str(x).strip()]
                bad = [x for x in vals if len(x) > 255 or R._UNSAFE_NAME.search(x) or " " in x]
                if bad:
                    raise ao.OperationError(f"{lab}: {', '.join(repr(b[:40]) for b in bad[:3])} is not a valid entry (no spaces, < > or control characters).")
                out[k] = sorted(set(vals))
            elif kind == "identifiers":
                vals = R._list(v if isinstance(v, list) else re.split(r"[\r\n]+", str(v or "")), lab)
                got = []
                for x in [str(x).strip() for x in vals if str(x).strip()]:
                    parts = x.split(None, 1)
                    t, val = (parts[0].upper(), parts[1].strip()) if len(parts) == 2 else ("", "")
                    if t not in IDENTIFIER_TYPES or not val or len(val) > 255 or R._UNSAFE_NAME.search(val) or " " in val:
                        raise ao.OperationError(f"{lab}: '{x[:60]}' must be URL, REFURL or KEYWORD, a space, then the value.")
                    got.append(f"{t} {val}")
                out[k] = sorted(set(got))
    except R.FormError as e:
        raise ao.OperationError(str(e))
    if not partial:
        miss = [specs[k]["label"] for k, f in specs.items() if f.get("required") and out.get(k) in (None, "", [])]
        if miss:
            raise ao.OperationError("Fill in: " + ", ".join(miss) + ".")
    return out


def wire(obj: str, values: Dict[str, Any]) -> Dict[str, Any]:
    """Fields as the SDK's add_ / update_ call takes them."""
    out: Dict[str, Any] = {}
    for k, v in values.items():
        f = OBJECTS[obj]["fields"][k]
        if f["kind"] == "identifiers":
            out[k] = [{"identifier_type": x.split(" ", 1)[0], "instance_identifier": x.split(" ", 1)[1],
                       "instance_identifier_name": x.split(" ", 1)[1]} for x in v]
        elif f["kind"] == "flag01":
            out[k] = "1" if v else "0"
        elif f["kind"] == "int":
            out[k] = str(v) if obj == "proxy" and k == "port" else v   # proxies.add_proxy: port (str)
        else:
            out[k] = v
    return out


def show(obj: str, k: str, v: Any) -> str:
    f = OBJECTS[obj]["fields"][k]
    if f["kind"] in ("bool", "flag01"):
        return "yes" if v else "no"
    if v in (None, "", []):
        return "—"
    return ", ".join(str(x) for x in v[:12]) + (f" and {len(v) - 12} more" if len(v) > 12 else "") if isinstance(v, list) else str(v)


# ---------------------------------------------------------------------------
# Reading (GET only)
# ---------------------------------------------------------------------------

def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {str(e)[:200]}"


def read_list(client, obj: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if obj == "segment":
        return ao.read_segments(getattr(client, "zpa", None))
    o = OBJECTS[obj]
    fn = getattr(getattr(getattr(client, "zia", None), o["service"], None), o["list"], None)
    if not callable(fn):
        return [], f"the installed zscaler-sdk-python has no {o['service']}.{o['list']}"
    try:
        return ao._rows(fn())
    except Exception as e:  # noqa: BLE001
        return [], _err(e)


def get_one(client, obj: str, oid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if obj == "segment":
        return ao.get_segment(getattr(client, "zpa", None), oid)
    o = OBJECTS[obj]
    fn = getattr(getattr(getattr(client, "zia", None), o["service"], None), o["get"], None)
    if not callable(fn):
        return None, f"the installed zscaler-sdk-python has no {o['service']}.{o['get']}"
    try:
        return ao._one(fn(oid))
    except Exception as e:  # noqa: BLE001
        return None, _err(e)


def read_gateways(client) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    fn = getattr(getattr(getattr(client, "zia", None), "proxies", None), "list_proxy_gateways", None)
    if not callable(fn):
        return [], "the installed zscaler-sdk-python has no proxies.list_proxy_gateways"
    try:
        ret = fn()
        if ret is None:    # SDK 1.11.3 list_proxy_gateways returns None (not a tuple) on an error
            return [], "the proxy gateways could not be read"
        return ao._rows(ret)
    except Exception as e:  # noqa: BLE001
        return [], _err(e)


def _oid(obj: str, row: Dict[str, Any]) -> Any:
    return pc._field(row, OBJECTS[obj]["id"], "instanceId" if obj == "instance" else "id")


def _oname(obj: str, row: Dict[str, Any]) -> str:
    return str(pc._field(row, OBJECTS[obj]["name"], "instanceName" if obj == "instance" else "name", default="") or "")


def summary_row(obj: str, row: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": _oid(obj, row), "name": _oname(obj, row), "values": current(obj, row)}


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def _seg_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if scope.get("zpa") else (scope.get("not_in_scope") or {}).get("zpa_segments") or \
        "Not in scope: ZPA is not ticked on the Scope page, so the application segments are not read."


def _zia_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if "zia_extras" in set(scope.get("scopes") or []) else \
        "Not in scope: ZIA platform is not ticked on the Scope page, so these ZIA objects are not read or changed. Nothing was read."


# ---------------------------------------------------------------------------
# Planning (one object per operation; Undo restores or deletes it)
# ---------------------------------------------------------------------------

def _ref(obj: str, oid: Any, name: str) -> Dict[str, Any]:
    return {"type": obj, "policy_label": OBJECTS[obj]["label"], "id": oid, "name": name}


def _norm(spec: Dict[str, Any], kinds: Sequence[str], type_name: str) -> Dict[str, Any]:
    act = str(spec.get("action") or "").strip().lower()
    obj = str(spec.get("object") or kinds[0])
    if obj not in kinds:
        raise ao.OperationError(f"Pick what to change: {', '.join(OBJECTS[k]['label'] for k in kinds)}.")
    if act == "revert":
        if not isinstance(spec.get("fields"), dict) and spec.get("op") != "delete":
            raise ao.OperationError("An undo names what to put back.")
        return {"type": type_name, "action": "revert", "object": obj, "op": "delete" if spec.get("op") == "delete" else "restore",
                "id": spec.get("id"), "name": str(spec.get("name") or "")[:255], "fields": spec.get("fields") or {},
                "expect": spec.get("expect") or {}}
    allowed = ("update",) if obj == "segment" else ("create", "update")
    if act not in allowed:
        raise ao.OperationError(f"A {OBJECTS[obj]['label']} can be {' or '.join(a + 'd' for a in allowed)} here.")
    n = {"type": type_name, "action": act, "object": obj, "fields": validate(obj, spec.get("fields"), partial=act == "update")}
    if act == "update":
        oid = str(spec.get("id") or "").strip()
        if not re.fullmatch(r"[0-9]{1,24}", oid):
            raise ao.OperationError("Pick the object from the list (its id is missing).")
        n["id"] = oid
    return n


def _taken(rows: List[Dict[str, Any]], obj: str, name: str, but: Any = None) -> bool:
    want = " ".join(name.split()).casefold()
    return any(" ".join(_oname(obj, r).split()).casefold() == want and str(_oid(obj, r)) != str(but) for r in rows)


def _plan_object(client, spec: Dict[str, Any], kinds: Sequence[str], type_name: str, product: str, say) -> Dict[str, Any]:
    n = _norm(spec, kinds, type_name)
    obj, act = n["object"], n["action"]
    o = OBJECTS[obj]
    say(f"Reading the {o['label']}s…")
    rows, err = read_list(client, obj)
    if err:
        raise ao.OperationError(f"The {o['label']}s could not be read, so nothing can be planned: {err}")
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    notes: List[str] = []
    live = False
    gk = f"obj:{obj}:{act}:{n.get('id', 'new')}"
    if act == "create":
        vals = n["fields"]
        name = vals.get(o["name"]) or ""
        if _taken(rows, obj, name):
            blockers.append(f"A {o['label']} named '{name}' already exists. Pick another name.")
        items.append(ao._unit(gk + ":object", gk, "object_create", _ref(obj, None, name), "object", "absent",
                              "; ".join(f"{OBJECTS[obj]['fields'][k]['label'].split(' (')[0]}: {show(obj, k, v)}" for k, v in vals.items())))
        groups.append({"key": gk, "handler": "zo_create", "target": {"object": obj, "name": name, "values": vals}})
        title = f"Create {o['label']} '{name}'"
        notes.append(f"A new {o['label'].lower()} changes nothing for users until a rule uses it.")
    elif act == "update":
        row = next((r for r in rows if str(_oid(obj, r)) == n["id"]), None)
        if row is None:
            raise ao.OperationError(f"That {o['label']} is not in the tenant now: read again.")
        have = current(obj, row)
        name = _oname(obj, row)
        changes = {k: v for k, v in n["fields"].items() if v != have.get(k)}
        after = dict(have, **changes)
        if obj == "segment" and not after["tcp_ports"] and not after["udp_ports"]:
            raise ao.OperationError("ZPA needs at least one TCP or UDP port in a segment.")
        if o["name"] in changes and _taken(rows, obj, changes[o["name"]], but=n["id"]):
            blockers.append(f"A {o['label']} named '{changes[o['name']]}' already exists. Pick another name.")
        ref = _ref(obj, _oid(obj, row), name)
        for k, v in changes.items():
            items.append(ao._unit(f"{gk}:{k}", gk, "object_field", ref, k, show(obj, k, have.get(k)), show(obj, k, v)))
        if not changes:
            items.append(ao._unit(gk + ":object", gk, "object_field", ref, "object", "as asked", "as asked", status="noop",
                                  reason="every field is already as the form says"))
        else:
            groups.append({"key": gk, "handler": "zo_update", "target": {"object": obj, "id": _oid(obj, row), "name": name, "changes": changes,
                                                                        "expect": {k: have.get(k) for k in changes}}})
        if obj == "segment":
            live = have.get("enabled") or after.get("enabled")
            if changes.get("enabled") is False:
                warnings.append("Disabling the segment stops ZPA access to its applications at once (ZPA has no activation step).")
            if changes.get("enabled") is True:
                warnings.append("Enabling the segment lets the access rules that name it reach its applications at once.")
            if "tcp_ports" in changes or "udp_ports" in changes:
                warnings.append("The segment's ports change: users lose access on a port that is taken away.")
        title = f"Edit {o['label']} '{name}'"
    else:   # revert: put fields back, or delete what was created (only while unchanged)
        row = next((r for r in rows if str(_oid(obj, r)) == str(n["id"])), None)
        ref = _ref(obj, n["id"], n["name"])
        title = f"Undo: {o['label']} '{n['name']}'"
        if n["op"] == "delete":
            if row is None:
                items.append(ao._unit(gk + ":object", gk, "object_delete", ref, "object", "absent", "absent", status="noop", reason="already gone"))
            else:
                have = current(obj, row)
                want = {k: v for k, v in (n["fields"] or {}).items() if k in o["fields"] and v not in (None, "", [], False)}
                if _oname(obj, row) != n["name"] or any(have.get(k) != v for k, v in want.items()):
                    items.append(ao._unit(gk + ":object", gk, "object_delete", ref, "object", "exists", "deleted", status="excluded",
                                          reason="changed in the tenant since it was created here; left as it is"))
                else:
                    items.append(ao._unit(gk + ":object", gk, "object_delete", ref, "object", "exists", "deleted"))
                    groups.append({"key": gk, "handler": "zo_delete", "target": {"object": obj, "id": n["id"], "name": n["name"]}})
        elif row is None:
            items.append(ao._unit(gk + ":object", gk, "object_field", ref, "object", "absent", "restored", status="excluded", reason="no longer in the tenant"))
        else:
            have = current(obj, row)
            changes, expect = {}, {}
            for k, before in n["fields"].items():
                if k not in o["fields"]:
                    raise ao.OperationError(f"Unknown field in the undo: {str(k)[:40]}.")
                now = have.get(k)
                if now == before:
                    items.append(ao._unit(f"{gk}:{k}", gk, "object_field", ref, k, show(obj, k, now), show(obj, k, before), status="noop",
                                          reason="already as before"))
                elif now != n["expect"].get(k):
                    items.append(ao._unit(f"{gk}:{k}", gk, "object_field", ref, k, show(obj, k, now), show(obj, k, before), status="excluded",
                                          reason="changed in the tenant since it was edited here; left as it is"))
                else:
                    items.append(ao._unit(f"{gk}:{k}", gk, "object_field", ref, k, show(obj, k, now), show(obj, k, before)))
                    changes[k], expect[k] = before, now
            if changes:
                groups.append({"key": gk, "handler": "zo_update", "target": {"object": obj, "id": n["id"], "name": _oname(obj, row),
                                                                            "changes": changes, "expect": expect}})
            live = obj == "segment" and (have.get("enabled") or changes.get("enabled"))
    nchg = sum(1 for u in items if u["status"] == "change")
    return {"type": type_name, "product": product, "spec": n, "items": items, "groups": groups, "title": title, "warnings": warnings,
            "blockers": blockers, "notes": notes,
            "confirm_always": f"APPLY {nchg} CHANGE{'' if nchg == 1 else 'S'}" if live and nchg else ""}


def _plan_segment(client, spec, scope, say, cancel):
    p = _plan_object(client, spec, ("segment",), SEG_TYPE, "zpa", say)
    p["apply_note"] = "ZPA applies the change as it is saved; there is no activation step."
    return p


def _plan_app(client, spec, scope, say, cancel):
    return _plan_object(client, spec, OBJ_KINDS, OBJ_TYPE, "zia", say)


GATEWAY_STEPS = [
    "In the ZIA Admin Portal, go to Administration, Proxies & Gateways, and add a Gateway for Proxies: give it a name, pick the proxy "
    "as the Primary Proxy (and a second proxy as the Secondary Proxy if you have one), and decide Fail Close (on: traffic is dropped "
    "when no proxy answers; off: it goes out directly).",
    "If the proxy inspects TLS, add its root certificate under Administration, Root Certificates, so ZIA trusts it (the API client "
    "cannot upload it through this SDK).",
    "Activate the change in the portal.",
    "Then, in Bulk changes, Edit a rule: create a Forwarding control rule with Forward method PROXYCHAIN and the new gateway (read the "
    "tenant again so the gateway is listed). It is created disabled; enable it after review.",
]


def gateway_report(proxies: List[Dict[str, Any]], gateways: List[Dict[str, Any]], err: Optional[str], proxy_name: str = "") -> Dict[str, Any]:
    """Which gateways use which proxy, and the manual steps a new proxy needs."""
    names = {str(pc._field(p, "id")): str(pc._field(p, "name", default="")) for p in proxies}
    rows = []
    for g in gateways:
        prim, sec = pc._field(g, "primary_proxy", "primaryProxy") or {}, pc._field(g, "secondary_proxy", "secondaryProxy") or {}
        rows.append({"id": pc._field(g, "id"), "name": str(pc._field(g, "name", default="")),
                     "primary": names.get(str(pc._field(prim, "id")), str(pc._field(prim, "name", default="") or "")),
                     "secondary": names.get(str(pc._field(sec, "id")), str(pc._field(sec, "name", default="") or "")),
                     "fail_closed": bool(pc._field(g, "fail_closed", "failClosed", default=False))})
    used = {r["primary"] for r in rows} | {r["secondary"] for r in rows}
    steps = list(GATEWAY_STEPS) if not proxy_name or proxy_name not in used else []
    if proxy_name and proxy_name in used:
        steps.append(f"'{proxy_name}' is already in a gateway: nothing more to do in the portal for it.")
    return {"gateways": rows, "error": err, "manual_steps": steps,
            "why_manual": "zscaler-sdk-python 1.11.3 can list proxy gateways (proxies.list_proxy_gateways) but has no call to create or "
                          "change one, so a gateway is set up in the ZIA Admin Portal."}


def _plan_proxy(client, spec, scope, say, cancel):
    p = _plan_object(client, spec, ("proxy",), PROXY_TYPE, "zia", say)
    if p["spec"]["action"] in ("create", "update"):
        rows, _ = read_list(client, "proxy")
        gws, gerr = read_gateways(client)
        nm = (p["spec"].get("fields") or {}).get("name") or next((u["object"]["name"] for u in p["items"]), "")
        p["gateway_report"] = gateway_report(rows, gws, gerr, nm)
        p["notes"] = list(p.get("notes") or []) + [p["gateway_report"]["why_manual"]]
    return p


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def _seg_body(fresh: Dict[str, Any], changes: Dict[str, Any]) -> Dict[str, Any]:
    body = ao.segment_body(fresh)
    for k, v in changes.items():
        if k in ("tcp_ports", "udp_ports"):
            rngs = [(int(x.split("-")[0]), int(x.split("-")[-1])) for x in v]
            body[f"{k[:3]}_port_ranges"] = ao._flat(rngs)
        elif k == "tcp_keep_alive":
            body[k] = "1" if v else "0"
        else:
            body[k] = v
    return body


def _object_body(obj: str, fresh: Dict[str, Any], changes: Dict[str, Any]) -> Dict[str, Any]:
    if obj == "segment":
        return _seg_body(fresh, changes)
    # An update replaces the object: everything is sent back as read, the changed fields as the form says.
    body = {k: v for k, v in fresh.items() if v is not None and k not in ("id", "instance_id", "last_modified_by", "last_modified_time",
                                                                          "modified_at", "modified_by")}
    body.update(wire(obj, changes))
    if obj == "proxy":
        body.setdefault("type", "PROXYCHAIN")
    return body


def _target_client(run, obj: str):
    return run.zpa if obj == "segment" else run.zia


def _h_create(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    obj, o = t["object"], OBJECTS[t["object"]]
    rows, err = read_list(run.client, obj)
    if err:
        run.halt = ao._read_halt(err)
        run.mark(units, "skipped" if run.halt else "failed", f"not attempted: {run.halt}" if run.halt else "",
                 **({} if run.halt else {"error": f"could not read the {o['label']}s again before the change: {err}"}))
        if not run.halt:
            run.counts["failed"] += 1
        return
    if _taken(rows, obj, t["name"]):
        run.mark(units, "conflict", "one with this name appeared in the tenant since the preview; left as it is")
        return
    body = wire(obj, t["values"])
    if obj == "proxy":
        body["type"] = "PROXYCHAIN"
    out = ops.create(run.zia, o["kind"], body, name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        oid = out.id if out.id is not None else pc._field(out.data, "instance_id", "instanceId")
        for u in units:
            u["object"]["id"] = oid
        run.created.append({"type": obj, "id": oid, "name": t["name"]})
        run.log(f"[{o['label']}] {t['name']}: created")


def _h_update(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    obj, o = t["object"], OBJECTS[t["object"]]
    fresh, err = get_one(run.client, obj, t["id"])
    if fresh is None:
        run.halt = ao._read_halt(err)
        if run.halt:
            run.mark(units, "skipped", f"not attempted: {run.halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read it again before the change: {err}")
            run.counts["failed"] += 1
        return
    have = current(obj, fresh)
    ok = []
    for u in units:
        if have.get(u["field"]) != t["expect"].get(u["field"]):
            run.mark([u], "conflict", f"changed in the tenant since the preview: {u['field']} is {show(obj, u['field'], have.get(u['field']))} now; left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    body = _object_body(obj, fresh, {u["field"]: t["changes"][u["field"]] for u in ok})
    kind = "zpa_segment" if obj == "segment" else o["kind"]
    out = ops.update(_target_client(run, obj), kind, t["id"], body, name=t["name"], log=run.log)
    if run.outcome(ok, out, "update"):
        run.wrote_zia = run.wrote_zia or obj != "segment"
        run.log(f"[{o['label']}] {t['name']}: updated {', '.join(u['field'] for u in ok)}")


def _h_delete(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    obj, o = t["object"], OBJECTS[t["object"]]
    fresh, err = get_one(run.client, obj, t["id"])
    if fresh is None:
        run.mark(units, "noop", "already gone")
        return
    if _oname(obj, fresh) != t["name"]:
        run.mark(units, "conflict", f"renamed since the preview (now '{_oname(obj, fresh)}'); left as it is")
        return
    out = ops.delete(run.zia, {"kind": o["kind"], "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[{o['label']}] {t['name']}: deleted")


def _verify(run) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    groups = {g["key"]: g for g in run.p["groups"]}
    for u in [x for x in run.p["items"] if x["status"] == "applied"]:
        out["checked"] += 1
        t = (groups.get(u["group"]) or {}).get("target") or {}
        obj = t["object"]
        row, err = get_one(run.client, obj, u["object"].get("id")) if u["object"].get("id") is not None else (None, "no id")
        if u["kind"] == "object_delete":
            ok, err = row is None, None
        elif row is None:
            ok = False
        elif u["kind"] == "object_create":
            have = current(obj, row)
            ok = all(have.get(k) == v for k, v in t["values"].items() if v not in (None, "", [], False))
        else:
            ok = current(obj, row).get(u["field"]) == t["changes"].get(u["field"])
        if not ok and err and u["kind"] != "object_delete":
            out["unread"].append(f"{u['object'].get('name')}: {err}")
            u["verified"] = None
            continue
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['object'].get('name')}: {u['field']} is not as written when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    groups = {g["key"]: g for g in result.get("groups") or []}
    t = (groups.get(applied[0]["group"]) or {}).get("target") or {}
    o = applied[0]["object"]
    if applied[0]["kind"] == "object_create" and o.get("id") is not None:
        return {"type": result["type"], "action": "revert", "object": t["object"], "op": "delete", "id": o["id"], "name": o.get("name"),
                "fields": t.get("values") or {}}
    if applied[0]["kind"] == "object_field":
        f = [u["field"] for u in applied]
        return {"type": result["type"], "action": "revert", "object": t["object"], "op": "restore", "id": o.get("id"), "name": o.get("name"),
                "fields": {k: (t.get("expect") or {}).get(k) for k in f}, "expect": {k: (t.get("changes") or {}).get(k) for k in f}}
    return None


# ---------------------------------------------------------------------------
# Object pickers (read-only browse)
# ---------------------------------------------------------------------------

def _forms(kinds: Sequence[str]) -> Dict[str, Any]:
    return {k: {"label": OBJECTS[k]["label"], "fields": [dict(key=fk, kind=f["kind"], label=f["label"], values=list(f.get("values") or []),
                                                               required=bool(f.get("required")), min=f.get("min"), max=f.get("max"))
                                                          for fk, f in OBJECTS[k]["fields"].items()]} for k in kinds}


def _read_segments(client, scope, say, cancel) -> Dict[str, Any]:
    say("Reading the ZPA application segments…")
    rows, err = read_list(client, "segment")
    say(f"{len(rows)} application segments.")
    return {"forms": _forms(("segment",)), "errors": {"segments": err} if err else {},
            "objects": {"segment": [dict(summary_row("segment", r), domains=ao._domains(r)[:20])
                                    for r in sorted(rows, key=lambda r: _oname("segment", r).lower())]}}


def _read_apps(client, scope, say, cancel) -> Dict[str, Any]:
    out: Dict[str, Any] = {"forms": _forms(OBJ_KINDS), "errors": {}, "objects": {}}
    for k in OBJ_KINDS:
        ao._check_stop(cancel)
        say(f"Reading the {OBJECTS[k]['label']}s…")
        rows, err = read_list(client, k)
        if err:
            out["errors"][OBJECTS[k]["label"]] = err
        out["objects"][k] = [summary_row(k, r) for r in sorted(rows, key=lambda r: _oname(k, r).lower())]
    return out


def _read_proxies(client, scope, say, cancel) -> Dict[str, Any]:
    say("Reading the proxies and the proxy gateways…")
    rows, err = read_list(client, "proxy")
    gws, gerr = read_gateways(client)
    out = {"forms": _forms(("proxy",)), "errors": {}, "objects": {"proxy": [summary_row("proxy", r) for r in rows]},
           "gateway_report": gateway_report(rows, gws, gerr)}
    if err:
        out["errors"]["Proxies"] = err
    if gerr:
        out["errors"]["Proxy gateways"] = gerr
    return out


ao.register(SEG_TYPE, family=SEG_FAMILY, product="zpa", label="Edit a ZPA application segment",
            hint="Change one segment's settings (name, bypass, health reporting, ICMP, ports, ...) or enable or disable it. ZPA applies "
                 "it as it is saved, so you type a confirmation for any change to an enabled segment.",
            in_scope=_seg_scope, plan=_plan_segment, read_objects=_read_segments,
            handlers={"zo_update": _h_update, "zo_create": _h_create, "zo_delete": _h_delete},
            verify=_verify, inverse=_inverse, script="ops_rule_editor.js")
ao.register(OBJ_TYPE, family=OBJ_FAMILY, product="zia", label="Cloud app instances and tenancy restrictions",
            hint="Browse the cloud application instances and tenancy restriction profiles, and create or edit one. Nothing changes for "
                 "users until a Cloud App Control rule uses it.",
            in_scope=_zia_scope, plan=_plan_app, read_objects=_read_apps,
            handlers={"zo_update": _h_update, "zo_create": _h_create, "zo_delete": _h_delete},
            verify=_verify, inverse=_inverse, script="ops_rule_editor.js")
ao.register(PROXY_TYPE, family=PROXY_FAMILY, product="zia", label="Proxy chaining",
            hint="Create or edit a third-party proxy and see the proxy gateways that use each one. A gateway is a portal step: the "
                 "preview lists what to do there.",
            in_scope=_zia_scope, plan=_plan_proxy, read_objects=_read_proxies,
            handlers={"zo_update": _h_update, "zo_create": _h_create, "zo_delete": _h_delete},
            verify=_verify, inverse=_inverse, script="ops_rule_editor.js")
