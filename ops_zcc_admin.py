"""Client Connector day-to-day administration on the Bulk changes engine
(admin_ops.register).

Three operation types on /report/operations, under "Day-to-day admin",
each planned from the tenant as it is now, previewed item by item, approved
by its plan hash and applied through the engine's gates (write mode, a
writer, the assessor, the typed confirmation), with a re-read right before
every write, a read-back, the change record, the audit log and Undo where
one exists (every preview says when there is none):

  zcc_device_remove   remove devices from the Client Connector Portal, by
                      device id (udid) and user: Remove (the portal marks the
                      device Removal Pending; Client Connector unenrolls at
                      its next check-in) or Force remove (the portal drops
                      the device at once, without waiting for it). The typed
                      confirmation always names the count and the kind of
                      removal. No Undo: the user enrolls again.
  zcc_device_bulk_remove
                      the same removal from a pasted or uploaded list of
                      users, host names, device ids, user + host name pairs
                      or @domains, matched against one paged read of the
                      enrolled devices (ambiguous and unmatched entries are
                      shown for the operator to resolve first), up to
                      BULK_MAX devices by explicit device id, in batches,
                      after an hourly budget check against Client
                      Connector's limit of 100 API calls an hour
                      (zscaler/zcc/legacy.py); a verification re-read
                      afterwards; the plan and the result as CSV.
  zcc_bypass_app      list, create, edit and delete custom IP-based bypass
                      applications (protocol, port and an IP address, a
                      subnet or a host name per entry). A new one is created
                      off unless the operator turns it on; one that an app
                      profile bypasses (bypassCustomAppIds) is never deleted.
                      Undo deletes what was created and puts back what was
                      edited; a delete has no Undo.
  zcc_entitlements    the ZPA and ZDX service entitlements: on for every
                      user, or for the groups listed. Narrowing them (turning
                      "all users" off, or taking a group out) always asks for
                      the typed confirmation. Undo puts back the setting and
                      the exact group list as read.

Device lookups (read-only, by user name) answer the page's search: the
fleet is never listed whole. Device rows carry only the device id, user,
host name, platform, version, state and last seen time; anything else a
device answer holds (the one-time passwords of a device, for example) is
never read into a result.

SDK calls, verified against the installed zscaler-sdk-python 1.11.3
(zscaler/zcc):

  devices.list_devices          GET  /zcc/papi/public/v1/getDevices (username, page, page_size)
  devices.remove_devices        POST /zcc/papi/public/v1/removeDevices (udids)
  devices.force_remove_devices  POST /zcc/papi/public/v1/forceRemoveDevices (udids)
  custom_ip_base_apps.get_custom_ip_base_apps / get_custom_ip_base_app
                                GET  /zcc/papi/public/v1/custom-ip-based-apps[/{id}]
                                (customAppContracts: appName, active, appDataBlob
                                and appDataBlobV6 entries of proto, port, ipaddr, fqdn)
  entitlements                  GET  /getZpaGroupEntitlements, /getZdxGroupEntitlements
                                (zpaEnableForAll, groupList, deviceGroupList;
                                upmEnableForAll, upmGroupList, upmDeviceGroupList)
  web_policy.list_by_company    the app profiles' bypassCustomAppIds (ops_zcc.read_apps)

ASSUMED (not in the SDK, or not checkable without a tenant; see ASSUMED):
the SDK has no write for custom IP-based apps, so create, edit and delete
use the request executor on POST /custom-ip-based-apps, PUT
/custom-ip-based-apps/{id} and DELETE /custom-ip-based-apps/{id}; the SDK's
update_zpa_group_entitlement / update_zdx_group_entitlement send an empty
body, so the update is a PUT of the entitlement as read, with the setting
and the groups changed, to the SDK's own path (/updateZpaGroupEntitlement,
/updateZdxGroupEntitlement); the registration states' words; and that ZCC
answers a refused removal with errorMsg or devicesRemoved 0.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import ops_zcc
import pack_ops as ops

FAMILY = "zcc_admin"
T_REMOVE, T_BYPASS, T_ENT, T_BULK = "zcc_device_remove", "zcc_bypass_app", "zcc_entitlements", "zcc_device_bulk_remove"
GROUP = "Day-to-day admin"
BASE = "/zcc/papi/public/v1"
NOT_IN_SCOPE = "Not in scope: tick ZCC (Client Connector) on the Scope page, then try again. Nothing was read."
MAX_DEVICES = 25
MAX_LOOKUP = 200
MAX_ENTRIES = 100
MAX_GROUPS = 200
PAGE_SIZE = 100
MAX_PAGES = 10
_UDID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._\-]{0,255}$")
_USER_RE = re.compile(r"^[^\s\x00-\x1f\x7f<>\"']{1,254}$")
_APP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,63}$")
_GROUP_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,128}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PROTOCOLS = ("TCP", "UDP")
SERVICES = {"zpa": ("ZPA", "zpaEnableForAll", "groupList", "getZpaGroupEntitlements", "updateZpaGroupEntitlement"),
            "zdx": ("ZDX", "upmEnableForAll", "upmGroupList", "getZdxGroupEntitlements", "updateZdxGroupEntitlement")}
# zscaler/utils.py zcc_param_map["reg_type"]: the numbers ZCC uses for registration states
REG_STATES = {"1": "registered", "3": "removal pending", "4": "unregistered", "5": "removed", "6": "quarantined"}

ASSUMED = [
    "The SDK has no write for custom IP-based apps: create, edit and delete are POST /custom-ip-based-apps, PUT and DELETE "
    "/custom-ip-based-apps/{id} through the SDK's request executor; assumed.",
    "The SDK's entitlement updates send an empty body: the update is a PUT of the entitlement as read, with the setting and the groups "
    "changed, to /updateZpaGroupEntitlement or /updateZdxGroupEntitlement; assumed.",
    "An app profile bypasses a custom IP-based app by listing its id in bypassCustomAppIds; assumed (the field is in the SDK's model).",
    "Remove marks a device Removal Pending until Client Connector checks in; Force remove drops it at once; the state words; assumed.",
]


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """Client Connector is read and changed only when ZCC is ticked on the Scope page."""
    return None if "zcc" in (scope.get("scopes") or []) else NOT_IN_SCOPE


# ---------------------------------------------------------------------------
# The raw API (for the calls the SDK lacks) and the reads
# ---------------------------------------------------------------------------

def _seg(v: Any) -> str:
    s = str(v)
    if not re.fullmatch(r"\d{1,24}", s):
        raise _err("An id is not a Client Connector id (digits only); nothing was sent.")
    return s


class ZccRaw:
    """Client Connector calls through the signed-in client's request
    executor (the SDK's own signing and gateway routing). Reads are paced."""

    def __init__(self, client: Any) -> None:
        svc = getattr(client, "zcc", None)
        self.ex = getattr(svc, "_request_executor", None) if svc is not None else None
        if self.ex is None:
            self.ex = getattr(client, "_request_executor", None)

    def send(self, method: str, path: str, body: Any = None, params: Optional[Dict[str, Any]] = None) -> Tuple[Any, Any, Any]:
        """(data, response, error): the SDK's answer shape."""
        if self.ex is None:
            return None, None, "this sign-in has no Client Connector access (it needs a OneAPI API client)"
        if method == "GET":
            import zia_rate
            zia_rate.wait("GET", "", what="Client Connector read")
        try:
            made = self.ex.create_request(method, BASE + path, body if body is not None else {}, {}, params=params or {})
            req, err = (made[0], made[1]) if isinstance(made, tuple) and len(made) >= 2 else (made, None)
            if err:
                return None, None, err
            got = self.ex.execute(req)
            resp, err = (got[0], got[1]) if isinstance(got, tuple) and len(got) >= 2 else (got, None)
            if err:
                return None, resp, err
        except Exception as e:  # noqa: BLE001 — one failed request is reported, never raised
            return None, None, f"{type(e).__name__}: {str(e)[:240]}"
        data = resp.get_body() if resp is not None and hasattr(resp, "get_body") else resp
        if isinstance(data, (bytes, str)):
            try:
                data = json.loads(data) if data else {}
            except ValueError:
                data = {}
        return (data if data is not None else {}), resp, None

    def get_entitlement(self, service: str):
        return self.send("GET", "/" + SERVICES[service][3])

    def put_entitlement(self, service: str, body: Dict[str, Any]):
        return self.send("PUT", "/" + SERVICES[service][4], body)

    def create_app(self, body: Dict[str, Any]):
        return self.send("POST", "/custom-ip-based-apps", body)

    def update_app(self, aid: Any, body: Dict[str, Any]):
        return self.send("PUT", f"/custom-ip-based-apps/{_seg(aid)}", body)

    def delete_app(self, aid: Any):
        return self.send("DELETE", f"/custom-ip-based-apps/{_seg(aid)}")


def raw_for(client: Any) -> ZccRaw:
    api = getattr(client, "_zcc_raw", None)
    if isinstance(api, ZccRaw):
        return api
    api = ZccRaw(client)
    try:
        setattr(client, "_zcc_raw", api)
    except Exception:  # noqa: BLE001
        pass
    return api


def _zcc(client: Any) -> Any:
    return ops_zcc._zcc(client)


def _check_stop(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise ao.Stopped("You clicked Stop: nothing more was read and nothing was written.")


def _get(row: Any, *keys: str) -> Any:
    """The first of `keys` the row has (any casing: camelCase or snake_case)."""
    for k in keys:
        v = ops_zcc._get(row, k)
        if v is not None:
            return v
    return None


def _norm_state(v: Any) -> str:
    s = str(v if v is not None else "").strip()
    if s in REG_STATES:
        return REG_STATES[s]
    s = re.sub(r"[_\s]+", " ", s).lower()
    return s or "unknown"


def device_row(d: Dict[str, Any]) -> Dict[str, Any]:
    """The fields of a device this app shows: nothing else is kept."""
    g = lambda *k: _get(d, *k)  # noqa: E731
    return {"udid": str(g("udid") or "")[:256], "user": str(g("user") or g("username") or "")[:254],
            "hostname": str(g("machineHostname") or g("machine_hostname") or "")[:128], "os": str(g("osVersion") or g("os_version") or "")[:80],
            "type": str(g("type") or "")[:10], "version": str(g("agentVersion") or g("agent_version") or "")[:40],
            "state": _norm_state(g("registrationState") or g("registration_state") or g("state")),
            "last_seen": str(g("last_seen_time") or g("lastSeenTime") or "")[:40]}


def check_user(v: Any) -> str:
    s = str(v or "").strip() if isinstance(v, str) else ""
    if not _USER_RE.match(s):
        raise _err("The user must be the enrolled user name (an email address), without spaces or control characters.")
    return s


def check_udid(v: Any) -> str:
    s = str(v or "").strip() if isinstance(v, str) else ""
    if not _UDID_RE.match(s):
        raise _err("A device id (udid) must be letters, digits and : . _ - (at most 256).")
    return s


def devices_of(client: Any, user: str, cancel: Optional[threading.Event] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """The user's devices (only the shown fields); (rows, error)."""
    z = _zcc(client)
    note_calls(client)
    rows, err = ops_zcc._read_all(z.devices.list_devices, {"username": user}, cancel)
    out = [device_row(r) for r in rows if isinstance(r, dict)]
    # The portal's username filter is assumed to match exactly; anything else it answers is not this user's.
    return [r for r in out if not r["user"] or r["user"].lower() == user.lower()], err


def read_apps(client: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every custom IP-based app as read (raw body); (rows, error)."""
    z = _zcc(client)
    try:
        ret = z.custom_ip_base_apps.get_custom_ip_base_apps()
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"
    data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        return [], ops_zcc._err_text(err)
    body = ops_zcc._wire(resp)
    if isinstance(body, dict) and isinstance(body.get("customAppContracts"), list):
        return [dict(x) for x in body["customAppContracts"] if isinstance(x, dict)], None
    return [ops_zcc._plain(x) for x in (data or [])], None


def _entries(row: Dict[str, Any]) -> List[Dict[str, str]]:
    out = []
    for key in ("appDataBlob", "appDataBlobV6", "app_data_blob", "app_data_blob_v6"):
        for e in row.get(key) or []:
            if isinstance(e, dict):
                out.append({"proto": str(e.get("proto") or "").upper(), "port": str(e.get("port") or ""),
                            "ipaddr": str(e.get("ipaddr") or ""), "fqdn": str(e.get("fqdn") or "").lower()})
    return sorted(out, key=lambda e: (e["proto"], e["port"], e["ipaddr"], e["fqdn"]))


def app_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": str(_get(row, "id") or ""), "name": str(_get(row, "appName", "app_name") or "")[:64],
            "active": _truthy(_get(row, "active")), "entries": _entries(row)[:MAX_ENTRIES]}


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes", "on")


def read_entitlement(client: Any, service: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    data, _resp, err = raw_for(client).get_entitlement(service)
    if err:
        return None, ops_zcc._err_text(err)
    if isinstance(data, list):
        data = data[0] if data and isinstance(data[0], dict) else {}
    return (dict(data) if isinstance(data, dict) else {}), None


def _group_label(g: Any) -> str:
    if isinstance(g, dict):
        return str(g.get("name") or g.get("groupName") or g.get("id") or "")[:128]
    return str(g)[:128]


def ent_summary(service: str, row: Dict[str, Any]) -> Dict[str, Any]:
    label, all_key, groups_key = SERVICES[service][:3]
    dev_key = "deviceGroupList" if service == "zpa" else "upmDeviceGroupList"
    return {"service": service, "label": label, "enable_for_all": _truthy(row.get(all_key)),
            "groups": sorted({_group_label(g) for g in row.get(groups_key) or [] if _group_label(g)}, key=str.lower)[:MAX_GROUPS],
            "device_groups": sorted({_group_label(g) for g in row.get(dev_key) or [] if _group_label(g)}, key=str.lower)[:MAX_GROUPS]}


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Read-only: the custom IP-based bypass apps and the ZPA and ZDX
    entitlements. Devices are looked up per user (lookup), never listed whole."""
    errors: Dict[str, str] = {}
    say("Reading the Client Connector custom bypass apps…")
    _check_stop(cancel)
    apps, err = read_apps(client)
    if err:
        errors["custom bypass apps"] = err
    ents = {}
    for svc in SERVICES:
        _check_stop(cancel)
        say(f"Reading the {SERVICES[svc][0]} entitlements…")
        row, err = read_entitlement(client, svc)
        if err:
            errors[f"{SERVICES[svc][0]} entitlements"] = err
        ents[svc] = ent_summary(svc, row or {}) if row is not None else None
    return {"bypass_apps": [app_summary(a) for a in apps][:2000], "entitlements": ents, "protocols": list(PROTOCOLS),
            "errors": errors, "assumed": list(ASSUMED), "limits": {"devices": MAX_DEVICES, "entries": MAX_ENTRIES}}


def lookup(client: Any, what: str, query: Dict[str, Any], cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read-only answers to the page's searches: a user's devices, or a list
    matched against one paged read of the enrolled devices."""
    if what == "match":
        entries = parse_list(query.get("text"))
        mode = "force" if query.get("mode") == "force" else "remove"
        dom = str(query.get("domain") or "").strip().lower()
        if dom and not _DOMAIN_RE.match(dom):
            raise _err("The domain filter must be a domain like acme.com.")
        inv, _pages, err = inventory(client, cancel)
        if err:
            return {"error": err, "counts": {}, "planned": []}
        out = match_list(inv, entries, mode=mode, domain=dom)
        out["budget"] = budget(client)
        out["planned"] = out["planned"][:BULK_MAX]
        return out
    if what != "devices":
        raise _err("Unknown lookup.")
    user = check_user(query.get("user"))
    rows, err = devices_of(client, user, cancel)
    return {"devices": rows[:MAX_LOOKUP], "truncated": len(rows) > MAX_LOOKUP, "error": err}


# ---------------------------------------------------------------------------
# Writes through pack_ops.call, one audit entry each
# ---------------------------------------------------------------------------

def _write(fn: Callable[..., Any], *args: Any, op: str, kind: str, name: str, log, oid: Any = None, kw: Optional[Dict[str, Any]] = None,
           check: Optional[Callable[[Any, Any], Optional[str]]] = None) -> ops.Outcome:
    """One write: pacing, retries, Stop and the run's fatal refusals
    (pack_ops.call), ZCC's success "false" (or `check`) read as a refusal,
    the answer reduced to its id, and one object_write audit entry."""
    def sdk_call(*a: Any, **k: Any) -> Any:
        ret = fn(*a, **k)
        data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
        if err:
            return (None, resp, err)
        why = ops_zcc._rejected(resp, data) or (check(resp, data) if check else None)
        if why:
            return (None, resp, why)
        body = ops_zcc._wire(resp)
        rid = _get(body, "id") if isinstance(body, dict) else (_get(data, "id") if isinstance(data, dict) else None)
        return ({"id": rid}, resp, None)

    out = ops.call(sdk_call, *args, op=op, kind=kind, name=name, log=log, kw=kw)
    out.data = None
    ops._audit_write(op, kind, out.id if op == "create" else oid, name, None, out)
    return out


def _read_fail(run: Any, units: List[Dict[str, Any]], err: Optional[str], what: str) -> None:
    ops_zcc._read_fail(run, units, str(err or "not readable"), what)


def _done(t: str, title: str, spec: Dict[str, Any], items: List[Dict[str, Any]], groups: List[Dict[str, Any]], *, undo: str,
          warnings: Sequence[str] = (), blockers: Sequence[str] = (), notes: Sequence[str] = (), **extra: Any) -> Dict[str, Any]:
    return dict({"type": t, "product": "zcc", "title": title, "spec": spec, "items": items, "groups": groups, "undo_note": undo,
                 "warnings": list(dict.fromkeys(warnings)), "blockers": list(blockers),
                 "notes": [undo] + list(notes)},
                apply_note="Client Connector applies each change as it is saved; devices pick it up at their next policy refresh. "
                           "There is no activation step.", **extra)


# ── zcc_device_remove ──────────────────────────────────────────────────

def plan_remove(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    mode = str(spec.get("mode") or "")
    if mode not in ("remove", "force"):
        raise _err("Pick Remove or Force remove.")
    raw = spec.get("devices")
    if not isinstance(raw, list) or not raw or len(raw) > MAX_DEVICES or not all(isinstance(d, dict) for d in raw):
        raise _err(f"Pick 1 to {MAX_DEVICES} devices.")
    devs = [{"udid": check_udid(d.get("udid")), "user": check_user(d.get("user"))} for d in raw]
    if len({d["udid"] for d in devs}) != len(devs):
        raise _err("Each device may appear once.")
    nspec = {"type": T_REMOVE, "mode": mode, "devices": devs}
    _zcc(client)
    seen: Dict[str, List[Dict[str, Any]]] = {}
    for user in sorted({d["user"] for d in devs}):
        _check_stop(cancel)
        say(f"Reading the devices of {user}…")
        rows, err = devices_of(client, user, cancel)
        if err:
            raise _err(f"The devices of {user} could not be read, so nothing was planned: {err}")
        seen[user] = rows
    items, groups = [], []
    after = "removal pending" if mode == "remove" else "removed (forced)"
    for d in devs:
        row = next((r for r in seen[d["user"]] if r["udid"] == d["udid"]), None)
        key = f"dev:{d['udid']}"
        o = {"type": "zcc_device", "kind": "device", "label": "Client Connector device", "id": d["udid"],
             "name": f"{row['hostname'] or d['udid'][:24]} ({d['user']})" if row else d["udid"][:40]}
        if row is None:
            items.append(ao._unit(key, key, "device", o, "registration", "", after, status="excluded", reason="no such device for this user now"))
            continue
        st = row["state"]
        if st == "removed" or (mode == "remove" and st == "removal pending"):
            items.append(ao._unit(key, key, "device", o, "registration", st, after, status="noop", reason=f"already {st}"))
            continue
        call = "POST /removeDevices (devices.remove_devices)" if mode == "remove" else "POST /forceRemoveDevices (devices.force_remove_devices)"
        items.append(ao._unit(key, key, "device", o, "registration", st, after, reason=f"{call}, by its udid."))
        groups.append({"key": key, "handler": "zcc_adm_remove", "target": {"udid": d["udid"], "user": d["user"], "mode": mode, "before": st,
                                                                          "name": o["name"]}})
    n = len(groups)
    phrase = (f"{'FORCE ' if mode == 'force' else ''}REMOVE {n} DEVICE{'' if n == 1 else 'S'}") if n else ""
    warnings = (["Force remove takes the device off the portal at once, without waiting for it to check in. Use it for a lost, wiped or "
                 "retired device; the user must enroll again to get protection back."] if mode == "force" else
                ["The device is marked Removal Pending: at its next check-in Client Connector unenrolls and the user is signed out."])
    return _done(T_REMOVE, f"{'Force remove' if mode == 'force' else 'Remove'} {len(devs)} Client Connector device{'' if len(devs) == 1 else 's'}",
                 nspec, items, groups, warnings=warnings, confirm_always=phrase,
                 undo="No Undo: a removed device comes back only when its user enrolls Client Connector again.",
                 notes=["You type the confirmation whatever the count: a removal always asks for it.", ASSUMED[3]])


def _removed_check(resp: Any, data: Any) -> Optional[str]:
    """ZCC's answer to a removal: errorMsg, or devicesRemoved 0, is a refusal (assumed)."""
    body = ops_zcc._wire(resp)
    for b in ([body] if isinstance(body, dict) else body if isinstance(body, list) else []):
        if not isinstance(b, dict):
            continue
        msg = _get(b, "errorMsg", "error_msg")
        if msg:
            return f"Client Connector refused the removal: {str(msg)[:200]}"
        n = _get(b, "devicesRemoved", "devices_removed")
        if n is not None and str(n).strip() in ("0", "0.0"):
            return "Client Connector removed no device (devicesRemoved 0)"
    return None


def _h_remove(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    rows, err = devices_of(run.client, t["user"])
    if err:
        _read_fail(run, units, err, "the user's devices")
        return
    row = next((r for r in rows if r["udid"] == t["udid"]), None)
    if row is None or row["state"] != t["before"]:
        run.mark(units, "conflict", f"the device changed since the preview (now {row['state'] if row else 'gone'}); left as it is")
        return
    z = _zcc(run.client)
    fn = z.devices.remove_devices if t["mode"] == "remove" else z.devices.force_remove_devices
    note_calls(run.client)
    out = _write(fn, op="delete", kind=f"zcc_device_{t['mode']}", name=t["name"], log=run.log, oid=t["udid"], kw={"udids": [t["udid"]]},
                 check=_removed_check)
    if run.outcome(units, out, "delete"):
        run.log(f"[Client Connector device] {t['name']}: {'force removed' if t['mode'] == 'force' else 'marked for removal'}")


# ── zcc_device_bulk_remove: removal from a list, batched ───────────────
#
# A list of users (email), host names, device ids (udid), user + host name
# pairs or @domains is matched against ONE paged read of the enrolled devices:
# a device id first (exact), then a user + host name pair, a user, a host
# name, a domain. A host name enrolled more than once is ambiguous and never
# removed until the operator picks the device; an entry that matches nothing
# is listed. The plan then carries explicit device ids only (never criteria),
# in batches of BATCH_DEFAULT (1 to BATCH_MAX) per call, after an hourly
# budget check against Client Connector's API limit (ZCC_CALLS_PER_HOUR,
# zscaler/zcc/legacy.py: 100 calls an hour); the typed confirmation names the
# count and the kind. After the writes a verification re-read (after
# VERIFY_DELAY seconds) checks every device, and devices still not removed are
# looked up again by user.

BULK_MAX = 2000                  # devices in one batched removal (a hard cap)
BATCH_DEFAULT, BATCH_MAX = 25, 100
MAX_LIST_BYTES = 1024 * 1024     # a pasted or uploaded list
MAX_LIST_ENTRIES = 5000
INVENTORY_PAGE = 5000            # the SDK's documented getDevices maximum (zcc_fleet.DEVICE_PAGE_SIZE)
INVENTORY_PAGES = 40
ZCC_CALLS_PER_HOUR = 100         # zscaler/zcc/legacy.py RATE_LIMIT: 100 calls an hour (per endpoint and source)
VERIFY_DELAY = 10.0
LEFTOVER_LOOKUPS = 10
_LEDGER: Dict[str, List[float]] = {}
_LEDGER_LOCK = threading.Lock()


def _tenant(client: Any) -> str:
    try:
        import zia_rate
        k = zia_rate.key_of(client)
        if k:
            return str(k)
    except Exception:  # noqa: BLE001
        pass
    return f"client-{id(client)}"


def note_calls(client: Any, n: int = 1, now: Optional[float] = None) -> None:
    """Count Client Connector calls this app made for the tenant (the hourly budget)."""
    t = time.time() if now is None else now
    with _LEDGER_LOCK:
        _LEDGER.setdefault(_tenant(client), []).extend([t] * max(0, int(n)))


def budget(client: Any, now: Optional[float] = None) -> Dict[str, Any]:
    """{used, remaining, limit, resets_in_seconds} over the last hour."""
    now = time.time() if now is None else now
    with _LEDGER_LOCK:
        recent = [x for x in _LEDGER.get(_tenant(client), []) if now - x < 3600]
        _LEDGER[_tenant(client)] = recent
    left = max(0, ZCC_CALLS_PER_HOUR - len(recent))
    return {"used": len(recent), "remaining": left, "limit": ZCC_CALLS_PER_HOUR,
            "resets_in_seconds": int(3600 - (now - min(recent))) + 1 if recent else 0}


def inventory(client: Any, cancel: Optional[threading.Event] = None) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
    """Every enrolled device (the shown fields only), paged; (rows, pages read, error)."""
    z = _zcc(client)
    rows: List[Dict[str, Any]] = []
    for page in range(1, INVENTORY_PAGES + 1):
        _check_stop(cancel)
        note_calls(client)
        try:
            ret = z.devices.list_devices(query_params={"page": page, "page_size": INVENTORY_PAGE})
        except Exception as e:  # noqa: BLE001
            return rows, page, f"{type(e).__name__}: {str(e)[:200]}"
        items, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
        if err:
            return rows, page, ops_zcc._err_text(err)
        batch = ops_zcc._wire_items(ops_zcc._wire(resp))
        if batch is None:
            batch = [ops_zcc._plain(x) for x in (items or [])]
        rows.extend(device_row(r) for r in batch if isinstance(r, dict))
        if len(batch) < INVENTORY_PAGE:
            return rows, page, None
    return rows, INVENTORY_PAGES, f"more than {INVENTORY_PAGES * INVENTORY_PAGE:,} devices: the list could not be read completely"


_DOMAIN_RE = re.compile(r"^@?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$", re.I)


def parse_list(text: Any) -> List[Dict[str, str]]:
    """Entries of a pasted or uploaded list (text or CSV: one entry a line;
    "user,hostname" is a pair; a header line is skipped). Pure; capped."""
    if not isinstance(text, str):
        raise _err("Paste the list, or choose a .txt or .csv file.")
    if len(text.encode("utf-8", "ignore")) > MAX_LIST_BYTES:
        raise _err(f"The list is larger than {MAX_LIST_BYTES // 1024} KB.")
    out: List[Dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip().strip("﻿")
        if not line or line.startswith("#"):
            continue
        cells = [c.strip().strip('"').strip() for c in re.split(r"[,;\t]", line) if c.strip().strip('"').strip()]
        if not cells or (len(out) == 0 and all(c.lower() in ("user", "username", "email", "hostname", "host", "udid", "device", "device id",
                                                               "machine hostname", "domain") for c in cells)):
            continue
        if any(re.search(r"[\x00-\x1f\x7f<>]", c) or len(c) > 256 for c in cells):
            out.append({"entry": line[:120], "kind": "invalid"})
            continue
        if len(cells) >= 2 and "@" in cells[0] and "@" not in cells[1]:
            out.append({"entry": f"{cells[0]}, {cells[1]}", "kind": "pair", "user": cells[0].lower(), "host": cells[1].lower()})
        else:
            for c in cells:
                low = c.lower()
                if low.startswith("@") and _DOMAIN_RE.match(low):
                    out.append({"entry": c, "kind": "domain", "domain": low.lstrip("@")})
                elif "@" in low and _USER_RE.match(c):
                    out.append({"entry": c, "kind": "user", "user": low})
                else:
                    out.append({"entry": c, "kind": "name", "value": low})
        if len(out) > MAX_LIST_ENTRIES:
            raise _err(f"At most {MAX_LIST_ENTRIES} entries in one list.")
    return out


def _domain_of(user: str) -> str:
    return user.rsplit("@", 1)[1].lower() if "@" in user else ""


def match_list(devices: List[Dict[str, Any]], entries: List[Dict[str, str]], *, mode: str = "remove", domain: str = "") -> Dict[str, Any]:
    """Match the list against the inventory (pure): exact device ids first,
    then a user + host name pair, a user, a host name, a domain. Categories:
    planned (devices to remove), ambiguous (a host name enrolled more than
    once: the operator picks), not_found, already_removed, filtered (outside
    the domain filter), invalid."""
    by_udid = {d["udid"].lower(): d for d in devices if d["udid"]}
    by_user: Dict[str, List[Dict[str, Any]]] = {}
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for d in devices:
        by_user.setdefault(d["user"].lower(), []).append(d)
        if d["hostname"]:
            by_host.setdefault(d["hostname"].lower(), []).append(d)
    dom = domain.lower().lstrip("@")
    planned: Dict[str, Dict[str, Any]] = {}
    out: Dict[str, List[Dict[str, Any]]] = {"ambiguous": [], "not_found": [], "already_removed": [], "filtered": [], "invalid": []}

    def take(d: Dict[str, Any], entry: str) -> None:
        if dom and _domain_of(d["user"]) != dom:
            out["filtered"].append({"entry": entry, "udid": d["udid"], "user": d["user"], "hostname": d["hostname"]})
            return
        if d["state"] == "removed" or (mode == "remove" and d["state"] == "removal pending"):
            out["already_removed"].append({"entry": entry, "udid": d["udid"], "user": d["user"], "hostname": d["hostname"], "state": d["state"]})
            return
        planned.setdefault(d["udid"], dict(d, entry=entry))

    for e in entries:
        k = e["kind"]
        if k == "invalid":
            out["invalid"].append({"entry": e["entry"]})
            continue
        if k == "pair":
            hits = [d for d in by_user.get(e["user"], []) if d["hostname"].lower() == e["host"]]
        elif k == "user":
            hits = by_user.get(e["user"], [])
        elif k == "domain":
            hits = [d for d in devices if _domain_of(d["user"]) == e["domain"]]
        else:
            v = e["value"]
            if v in by_udid:
                hits = [by_udid[v]]
            else:
                hits = by_host.get(v, [])
                if len(hits) > 1:
                    out["ambiguous"].append({"entry": e["entry"], "candidates": [{k2: d[k2] for k2 in ("udid", "user", "hostname", "state", "last_seen")}
                                                                                for d in hits][:20]})
                    continue
        if not hits:
            out["not_found"].append({"entry": e["entry"]})
            continue
        for d in hits:
            take(d, e["entry"])
    per_domain: Dict[str, int] = {}
    for d in planned.values():
        per_domain[_domain_of(d["user"]) or "(none)"] = per_domain.get(_domain_of(d["user"]) or "(none)", 0) + 1
    return {"planned": list(planned.values()), **out, "per_domain": dict(sorted(per_domain.items(), key=lambda x: (-x[1], x[0]))),
            "counts": {"planned": len(planned), **{k: len(v) for k, v in out.items()}}}


def plan_bulk(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    mode = str(spec.get("mode") or "")
    if mode not in ("remove", "force"):
        raise _err("Pick Remove or Force remove.")
    bs = spec.get("batch_size", BATCH_DEFAULT)
    if isinstance(bs, bool) or not isinstance(bs, int) or not 1 <= bs <= BATCH_MAX:
        raise _err(f"The batch size must be a whole number from 1 to {BATCH_MAX}.")
    raw = spec.get("devices")
    if not isinstance(raw, list) or not raw or len(raw) > BULK_MAX or not all(isinstance(d, dict) for d in raw):
        raise _err(f"Pick 1 to {BULK_MAX} devices (match a list first).")
    devs = [{"udid": check_udid(d.get("udid")), "user": check_user(d.get("user")), "entry": re.sub(r"[\x00-\x1f\x7f<>]", "", str(d.get("entry") or ""))[:120]}
            for d in raw]
    if len({d["udid"] for d in devs}) != len(devs):
        raise _err("Each device may appear once.")
    nspec = {"type": T_BULK, "mode": mode, "batch_size": bs, "devices": devs}
    _zcc(client)
    say("Reading the enrolled devices (one paged read)…")
    inv, pages, err = inventory(client, cancel)
    if err:
        raise _err(f"The enrolled devices could not be read completely, so nothing was planned: {err}")
    by = {d["udid"]: d for d in inv}
    items, groups, batch = [], [], []
    after = "removal pending" if mode == "remove" else "removed (forced)"
    for d in devs:
        row = by.get(d["udid"])
        key = f"dev:{d['udid']}"
        o = {"type": "zcc_device", "kind": "device", "label": "Client Connector device", "id": d["udid"], "user": d["user"], "entry": d["entry"],
             "hostname": row["hostname"] if row else "", "name": f"{(row or {}).get('hostname') or d['udid'][:24]} ({d['user']})"}
        if row is None or row["user"].lower() != d["user"].lower():
            items.append(ao._unit(key, "", "device", o, "registration", "", after, status="excluded", reason="no such device for this user now"))
            continue
        if row["state"] == "removed" or (mode == "remove" and row["state"] == "removal pending"):
            items.append(ao._unit(key, "", "device", o, "registration", row["state"], after, status="noop", reason=f"already {row['state']}"))
            continue
        batch.append((key, d["udid"], row["state"]))
        items.append(ao._unit(key, f"batch:{len(groups) + 1}", "device", o, "registration", row["state"], after,
                              reason=f"In batch {len(groups) + 1}: POST /{'removeDevices' if mode == 'remove' else 'forceRemoveDevices'} with its udid."))
        if len(batch) == bs:
            groups.append({"key": f"batch:{len(groups) + 1}", "handler": "zcc_adm_bulk_remove",
                           "target": {"mode": mode, "udids": [b[1] for b in batch], "before": {b[1]: b[2] for b in batch}}})
            batch = []
    if batch:
        groups.append({"key": f"batch:{len(groups) + 1}", "handler": "zcc_adm_bulk_remove",
                       "target": {"mode": mode, "udids": [b[1] for b in batch], "before": {b[1]: b[2] for b in batch}}})
    for u in items:   # an item outside every batch keeps a group of its own name (never written)
        if not u["group"]:
            u["group"] = u["key"]
    n = sum(len(g["target"]["udids"]) for g in groups)
    b = budget(client)
    need = len(groups) + 2 * pages + LEFTOVER_LOOKUPS   # the re-read before the writes, the batches, the verification and leftovers
    blockers = []
    if groups and need > b["remaining"]:
        blockers.append(f"Client Connector allows {ZCC_CALLS_PER_HOUR} API calls an hour; this needs about {need} and {b['remaining']} are left "
                        f"this hour (this app counted {b['used']}). Wait {max(1, b['resets_in_seconds'] // 60)} minute(s), or use larger batches.")
    phrase = (f"{'FORCE ' if mode == 'force' else ''}REMOVE {n} DEVICE{'' if n == 1 else 'S'}") if n else ""
    warnings = [f"{n} device(s) in {len(groups)} batch(es) of up to {bs}; about {need} of the {b['remaining']} Client Connector API calls left "
                "this hour.", "The plan and the result hold user names and host names: the CSV download is personal data (a counts-only "
                "download is offered)."]
    if mode == "force":
        warnings.append("Force remove drops each device at once; the users must enroll again.")
    return _done(T_BULK, f"{'Force remove' if mode == 'force' else 'Remove'} {n} Client Connector devices in batches", nspec, items, groups,
                 warnings=warnings, blockers=blockers, confirm_always=phrase, budget=dict(b, needed=need),
                 undo="No Undo: removed devices come back only when their users enroll Client Connector again.",
                 notes=["You type the confirmation naming the count whatever the count.", ASSUMED[3]])


def _h_bulk(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    inv = getattr(run, "_zcc_inventory", None)
    if inv is None:   # one re-read right before the first batch, shared by the batches
        rows, _pages, err = inventory(run.client)
        if err:
            _read_fail(run, units, err, "the enrolled devices")
            return
        inv = run._zcc_inventory = {d["udid"]: d for d in rows}
    ok = []
    for u in units:
        now = inv.get(u["object"]["id"])
        if now is None or now["state"] != t["before"].get(u["object"]["id"]):
            run.mark([u], "conflict", f"the device changed since the preview (now {now['state'] if now else 'gone'}); left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    z = _zcc(run.client)
    fn = z.devices.remove_devices if t["mode"] == "remove" else z.devices.force_remove_devices
    udids = [u["object"]["id"] for u in ok]
    note_calls(run.client)
    out = _write(fn, op="delete", kind=f"zcc_device_{t['mode']}", name=f"{g['key']} ({len(udids)} devices)", log=run.log, oid=g["key"],
                 kw={"udids": udids}, check=_removed_check)
    if out.ok:
        run.mark(ok, "applied", "")
        run.counts["deleted"] += 1
        run.log(f"[Client Connector] {g['key']}: {len(udids)} device(s) {'force removed' if t['mode'] == 'force' else 'marked for removal'}")
    else:
        run.outcome(ok, out, "delete")


def verify_bulk(run: Any) -> Dict[str, Any]:
    """One re-read of the inventory after VERIFY_DELAY seconds; devices still
    not removed are looked up again by user (at most LEFTOVER_LOOKUPS users)."""
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    if not applied:
        return out
    if VERIFY_DELAY > 0:
        time.sleep(VERIFY_DELAY)
    rows, _pages, err = inventory(run.client)
    if err:
        for u in applied:
            u["verified"] = None
        out["checked"] = len(applied)
        out["unread"].append(f"the enrolled devices: {err}")
        return out
    by = {d["udid"]: d for d in rows}
    mode = run.p["spec"]["mode"]
    good = ("removal pending", "removed") if mode == "remove" else ("removed",)
    left = [u for u in applied if by.get(u["object"]["id"]) is not None and by[u["object"]["id"]]["state"] not in good]
    for user in sorted({u["object"]["user"] for u in left})[:LEFTOVER_LOOKUPS]:
        note_calls(run.client)
        again, e2 = devices_of(run.client, user)
        if not e2:
            for d in again:
                by[d["udid"]] = d
            known = {d["udid"] for d in again}
            for u in left:
                if u["object"]["user"] == user and u["object"]["id"] not in known:
                    by.pop(u["object"]["id"], None)
    for u in applied:
        out["checked"] += 1
        d = by.get(u["object"]["id"])
        ok = d is None or d["state"] in good
        u["verified"] = ok
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['object']['name']}: still {d['state']}")
    return out


def plan_csv(result: Dict[str, Any], *, counts_only: bool = False) -> str:
    """A plan or a result of a device removal as CSV (cells made safe for
    spreadsheets). counts_only: per status and user domain, no names."""
    import csv_safe
    import io
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    items = [u for u in result.get("items") or [] if (u.get("object") or {}).get("type") == "zcc_device"]
    if counts_only:
        tally: Dict[Tuple[str, str], int] = {}
        for u in items:
            k = (u.get("status") or "", _domain_of(str(u["object"].get("user") or "")) or "(none)")
            tally[k] = tally.get(k, 0) + 1
        w.writerow(["status", "user domain", "devices"])
        for (st, dom), n in sorted(tally.items()):
            w.writerow([st, dom, n])
        return buf.getvalue()
    w.writerow(["entry", "user", "hostname", "udid", "before", "after", "status", "reason", "read back"])
    for u in items:
        o = u["object"]
        w.writerow([o.get("entry") or "", o.get("user") or "", o.get("hostname") or "", o.get("id") or "", u.get("before") or "", u.get("after") or "",
                    u.get("status") or "", " — ".join(str(x) for x in (u.get("reason"), u.get("error")) if x),
                    {True: "yes", False: "no"}.get(u.get("verified"), "")])
    return buf.getvalue()


# ── zcc_bypass_app ─────────────────────────────────────────────────────

def check_app_name(v: Any) -> str:
    s = re.sub(r"\s+", " ", v).strip() if isinstance(v, str) else ""
    if not _APP_NAME_RE.match(s):
        raise _err("The app's name: 1 to 64 letters, digits, spaces and . _ ( ) -, starting with a letter or digit.")
    return s


def _port(v: Any) -> str:
    s = str(v if v is not None else "").strip()
    m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", s)
    if not m:
        raise _err(f"A port must be a number or a range like 8000-8080 (not {s[:20]!r}).")
    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
    if not 1 <= a <= b <= 65535:
        raise _err("Ports run from 1 to 65535, the lower one first.")
    return f"{a}-{b}" if b != a else str(a)


def clean_entries(raw: Any) -> List[Dict[str, str]]:
    """The app's entries, validated (pure): protocol, port, and an IP address,
    a subnet or a host name each."""
    if not isinstance(raw, list) or not raw or len(raw) > MAX_ENTRIES or not all(isinstance(e, dict) for e in raw):
        raise _err(f"List 1 to {MAX_ENTRIES} entries (protocol, port, and an address or a host name).")
    out = []
    for e in raw:
        proto = str(e.get("proto") or "").strip().upper()
        if proto not in PROTOCOLS:
            raise _err("Each entry's protocol must be TCP or UDP.")
        port = _port(e.get("port"))
        addr = str(e.get("address") or e.get("ipaddr") or e.get("fqdn") or "").strip().lower()
        if not addr or len(addr) > 253 or re.search(r"[\s\x00-\x1f]", addr):
            raise _err("Each entry needs an IP address, a subnet (10.0.0.0/8) or a host name.")
        ip, fqdn = "", ""
        try:
            net = ipaddress.ip_network(addr, strict=False)
            if net.prefixlen == 0:
                raise _err("An entry for every address (0.0.0.0/0 or ::/0) would bypass everything: list the real subnets.")
            ip = str(net) if "/" in addr else str(net.network_address)
        except ValueError:
            if not _HOST_RE.match(addr):
                raise _err(f"{addr[:60]!r} is neither an IP address, a subnet nor a host name.")
            fqdn = addr
        out.append({"proto": proto, "port": port, "ipaddr": ip, "fqdn": fqdn})
    uniq = {tuple(sorted(x.items())) for x in out}
    if len(uniq) != len(out):
        raise _err("Each entry may appear once.")
    return sorted(out, key=lambda e: (e["proto"], e["port"], e["ipaddr"], e["fqdn"]))


def _is_v6(e: Dict[str, str]) -> bool:
    try:
        return bool(e["ipaddr"]) and ipaddress.ip_network(e["ipaddr"], strict=False).version == 6
    except ValueError:
        return False


def app_body(name: str, active: bool, entries: List[Dict[str, str]], base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The portal-shaped body of a custom IP-based app (the SDK model's field
    names); an edit starts from the app as read."""
    body = copy.deepcopy(base) if base else {}
    for k in ("createdBy", "editedBy", "editedTimestamp", "zappDataBlob", "zappDataBlobV6", "uid"):
        body.pop(k, None)
    body.update(appName=name, active=active,
                appDataBlob=[{k: e[k] for k in ("proto", "port", "ipaddr", "fqdn")} for e in entries if not _is_v6(e)],
                appDataBlobV6=[{k: e[k] for k in ("proto", "port", "ipaddr", "fqdn")} for e in entries if _is_v6(e)])
    return body


def _bypass_users(client: Any, cancel) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """{app id: [app profile names that bypass it]} on every platform; errors per platform."""
    rows, errors = ops_zcc._app_rows_everywhere(client, cancel)
    used: Dict[str, List[str]] = {}
    for plat, profiles in rows.items():
        for p in profiles:
            for aid in _get(p, "bypassCustomAppIds", "bypass_custom_app_ids") or []:
                used.setdefault(str(aid), []).append(f"{ops_zcc._name(p)} ({plat})")
    return used, errors


def plan_bypass(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    action = str(spec.get("action") or "")
    if action not in ("create", "update", "delete"):
        raise _err("Create, edit or delete a custom bypass app.")
    undo = spec.get("undo") is True
    nspec: Dict[str, Any] = {"type": T_BYPASS, "action": action}
    if undo:
        nspec["undo"] = True
    if action in ("update", "delete"):
        nspec["id"] = _seg(spec.get("id"))
    if action == "delete":
        nspec["name"] = check_app_name(spec.get("name"))
    if action == "create":
        nspec["name"] = check_app_name(spec.get("name"))
        nspec["entries"] = clean_entries(spec.get("entries"))
        a = spec.get("active", False)
        if not isinstance(a, bool):
            raise _err("Turn it on: true or false.")
        nspec["active"] = a
    if action == "update":
        for k in ("name", "entries", "active"):
            if k in spec:
                nspec[k] = check_app_name(spec[k]) if k == "name" else clean_entries(spec[k]) if k == "entries" else spec[k]
        if "active" in nspec and not isinstance(nspec["active"], bool):
            raise _err("Turn it on: true or false.")
        if not any(k in nspec for k in ("name", "entries", "active")):
            raise _err("Say what to change: its name, its entries or whether it is on.")
    _zcc(client)
    say("Reading the custom bypass apps…")
    apps, err = read_apps(client)
    if err:
        raise _err(f"The custom bypass apps could not be read, so nothing was planned: {err}")
    items, groups, warnings, blockers = [], [], [], []
    obj = lambda oid, name: {"type": "zcc_bypass_app", "kind": "bypass_app", "label": "Custom bypass app", "id": oid, "name": name}  # noqa: E731
    if action == "create":
        key = f"app:{nspec['name']}"
        if any(app_summary(a)["name"].lower() == nspec["name"].lower() for a in apps):
            items.append(ao._unit(key, key, "bypass_app", obj(None, nspec["name"]), "exists", True, True, status="excluded",
                                  reason="a custom bypass app with this name exists: edit it instead"))
        else:
            items.append(ao._unit(key, key, "bypass_app", obj(None, nspec["name"]), "exists", False, True,
                                  value=f"{len(nspec['entries'])} entr{'y' if len(nspec['entries']) == 1 else 'ies'}, {'on' if nspec['active'] else 'off'}",
                                  reason="Creates it: POST /custom-ip-based-apps (assumed; not in the SDK)."))
            groups.append({"key": key, "handler": "zcc_adm_app_create", "target": {"name": nspec["name"], "body": app_body(nspec["name"], nspec["active"], nspec["entries"])}})
            warnings.append("Traffic to these addresses and ports skips the Zscaler tunnel once an app profile bypasses this app: nothing "
                            "inspects it. List only what must bypass (voice and video media, for example).")
        undo_note = "Undo: deletes the new app, previewed first."
    else:
        row = next((a for a in apps if str(_get(a, "id")) == nspec["id"]), None)
        cur = app_summary(row) if row else None
        name = cur["name"] if cur else nspec.get("name") or nspec["id"]
        key = f"app:{nspec['id']}"
        if cur is None:
            items.append(ao._unit(key, key, "bypass_app", obj(nspec["id"], name), "exists", False, action != "delete",
                                  status="noop" if action == "delete" else "excluded", reason="already gone" if action == "delete" else "not in Client Connector now"))
        elif action == "delete":
            used, errs = _bypass_users(client, cancel)
            if errs:
                blockers.append("The app profiles could not all be read (" + "; ".join(f"{k}: {v}" for k, v in errs.items())[:300] +
                                "), so it is not known whether one bypasses this app: nothing is deleted.")
            if cur["name"] != nspec["name"]:
                items.append(ao._unit(key, key, "bypass_app", obj(nspec["id"], cur["name"]), "exists", True, True, status="excluded",
                                      reason=f"its name is '{cur['name']}' now, not '{nspec['name']}': read again and pick it"))
            elif used.get(nspec["id"]):
                items.append(ao._unit(key, key, "bypass_app", obj(nspec["id"], name), "exists", True, True, status="excluded",
                                      reason=f"app profile {used[nspec['id']][0]} bypasses it: take it out of the profile first"))
            else:
                items.append(ao._unit(key, key, "bypass_app", obj(nspec["id"], name), "exists", True, False,
                                      reason="Deletes it: DELETE /custom-ip-based-apps/{id} (assumed; not in the SDK)."))
                groups.append({"key": key, "handler": "zcc_adm_app_delete", "target": {"id": nspec["id"], "name": name, "before": cur}})
        else:
            want = {"name": nspec.get("name", cur["name"]), "active": nspec.get("active", cur["active"]), "entries": nspec.get("entries", cur["entries"])}
            if want["name"].lower() != cur["name"].lower() and any(app_summary(a)["name"].lower() == want["name"].lower() for a in apps):
                blockers.append(f"Another custom bypass app is named '{want['name']}'.")
            changed = []
            for f in ("name", "active", "entries"):
                b, a = cur[f], want[f]
                show = (lambda v: "on" if v else "off") if f == "active" else (lambda v: "; ".join(f"{e['proto']} {e['port']} {e['ipaddr'] or e['fqdn']}" for e in v) or "(none)") \
                    if f == "entries" else str
                if b == a:
                    items.append(ao._unit(f"{key}:{f}", key, "bypass_app", obj(nspec["id"], name), f, show(b), show(a), status="noop", reason="already as asked"))
                else:
                    changed.append(f)
                    items.append(ao._unit(f"{key}:{f}", key, "bypass_app", obj(nspec["id"], name), f, show(b), show(a),
                                          reason="Edits it: PUT /custom-ip-based-apps/{id} (assumed; not in the SDK)."))
            if changed:
                groups.append({"key": key, "handler": "zcc_adm_app_update", "target": {"id": nspec["id"], "name": name, "want": want,
                                                                                      "before": {f: cur[f] for f in ("name", "active", "entries")}}})
        undo_note = ("No Undo: a deleted app is gone (create it again with the same entries)." if action == "delete"
                     else "Undo: puts the name, the entries and on or off back as read, previewed first.")
    title = {"create": "Create", "update": "Edit", "delete": "Delete"}[action] + f" custom bypass app '{nspec.get('name') or (items[0]['object']['name'] if items else '')}'"
    extra = {}
    if action == "delete" and groups:
        nm = items[-1]["object"]["name"]
        extra["confirm_always"] = f"DELETE {nm.upper()}"
    return _done(T_BYPASS, ("Undo: " if undo else "") + title, nspec, items, groups, warnings=warnings, blockers=blockers, undo=undo_note,
                 notes=[ASSUMED[0]] + ([ASSUMED[2]] if action == "delete" else []), **extra)


def _fresh_app(run: Any, aid: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    apps, err = read_apps(run.client)
    if err:
        return None, err
    return next((a for a in apps if str(_get(a, "id")) == aid), None), None


def _h_app_create(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    apps, err = read_apps(run.client)
    if err:
        _read_fail(run, units, err, "the custom bypass apps")
        return
    if any(app_summary(a)["name"].lower() == t["name"].lower() for a in apps):
        run.mark(units, "conflict", "an app with this name now exists (made since the preview); nothing was created")
        return
    out = _write(raw_for(run.client).create_app, t["body"], op="create", kind="zcc_bypass_app", name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        oid = str(out.id or "")
        if not oid:   # an answer without the id: found by its name
            again, _e = read_apps(run.client)
            oid = next((str(_get(a, "id")) for a in again or [] if app_summary(a)["name"].lower() == t["name"].lower()), "")
        for u in units:
            u["object"] = dict(u["object"], id=oid or None)
        run.created.append({"type": "zcc_bypass_app", "id": oid, "name": t["name"]})
        run.log(f"[Client Connector bypass app] {t['name']}: created")


def _h_app_update(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    row, err = _fresh_app(run, t["id"])
    if row is None:
        if err:
            _read_fail(run, units, err, "the custom bypass app")
        else:
            run.mark(units, "conflict", "deleted since the preview; nothing was changed")
        return
    cur = app_summary(row)
    if any(cur[f] != v for f, v in t["before"].items()):
        run.mark(units, "conflict", "changed in Client Connector since the preview; left as it is")
        return
    w = t["want"]
    out = _write(raw_for(run.client).update_app, t["id"], app_body(w["name"], w["active"], w["entries"], base=row), op="update",
                 kind="zcc_bypass_app", name=t["name"], log=run.log, oid=t["id"])
    if run.outcome(units, out, "update"):
        run.log(f"[Client Connector bypass app] {t['name']}: edited")


def _h_app_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    row, err = _fresh_app(run, t["id"])
    if row is None:
        if err:
            _read_fail(run, units, err, "the custom bypass app")
        else:
            run.mark(units, "noop", "already gone")
        return
    if app_summary(row) != t["before"]:
        run.mark(units, "conflict", "changed in Client Connector since the preview, so it is kept")
        return
    used, errs = _bypass_users(run.client, None)
    if errs or used.get(t["id"]):
        run.mark(units, "conflict", "an app profile bypasses it now (or the profiles could not be read), so it is kept")
        return
    out = _write(raw_for(run.client).delete_app, t["id"], op="delete", kind="zcc_bypass_app", name=t["name"], log=run.log, oid=t["id"])
    if run.outcome(units, out, "delete"):
        run.log(f"[Client Connector bypass app] {t['name']}: deleted")


# ── zcc_entitlements ───────────────────────────────────────────────────

def _clean_groups(raw: Any, what: str) -> List[str]:
    if raw in (None, []):
        return []
    if not isinstance(raw, list) or len(raw) > MAX_GROUPS:
        raise _err(f"{what}: a list of at most {MAX_GROUPS} group names.")
    out = []
    for g in raw:
        s = re.sub(r"\s+", " ", g).strip() if isinstance(g, str) else ""
        if not _GROUP_RE.match(s):
            raise _err(f"{what}: each group name is 1 to 128 characters, without control characters or < >.")
        out.append(s)
    return list(dict.fromkeys(out))


def plan_entitlements(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    service = str(spec.get("service") or "")
    if service not in SERVICES:
        raise _err("Pick the ZPA or the ZDX entitlement.")
    label, all_key, groups_key = SERVICES[service][:3]
    undo = spec.get("undo") is True
    nspec: Dict[str, Any] = {"type": T_ENT, "service": service}
    if "enable_for_all" in spec:
        if not isinstance(spec["enable_for_all"], bool):
            raise _err("On for every user: true or false.")
        nspec["enable_for_all"] = spec["enable_for_all"]
    if undo:
        nspec["undo"] = True
        if not isinstance(spec.get("set_groups"), list) or len(spec["set_groups"]) > MAX_GROUPS:
            raise _err("The Undo names the groups as they were.")
        nspec["set_groups"] = spec["set_groups"]   # the exact entries read before (strings or {id, name}); compared, never interpreted
        for g in nspec["set_groups"]:
            if not isinstance(g, (str, dict)) or len(json.dumps(g)) > 400:
                raise _err("The Undo names the groups as they were.")
    else:
        nspec["add_groups"] = _clean_groups(spec.get("add_groups"), "Groups to add")
        nspec["remove_groups"] = _clean_groups(spec.get("remove_groups"), "Groups to take out")
        if set(g.lower() for g in nspec["add_groups"]) & set(g.lower() for g in nspec["remove_groups"]):
            raise _err("A group cannot be added and taken out at once.")
        if "enable_for_all" not in nspec and not nspec["add_groups"] and not nspec["remove_groups"]:
            raise _err("Say what to change: on for every user, or the groups.")
    _zcc(client)
    _check_stop(cancel)
    say(f"Reading the {label} entitlements…")
    row, err = read_entitlement(client, service)
    if row is None:
        raise _err(f"The {label} entitlements could not be read, so nothing was planned: {err}")
    cur = ent_summary(service, row)
    raw_groups = list(row.get(groups_key) or [])
    o = {"type": "zcc_entitlement", "kind": "entitlement", "label": f"{label} entitlement", "id": service, "name": f"{label} entitlement"}
    items, groups, warnings = [], [], []
    key = f"ent:{service}"
    want_all = nspec.get("enable_for_all", cur["enable_for_all"])
    items.append(ao._unit(f"{key}:all", key, "entitlement", o, "on for every user", "on" if cur["enable_for_all"] else "off",
                          "on" if want_all else "off", status="change" if want_all != cur["enable_for_all"] else "noop",
                          reason="Updates it: PUT /" + SERVICES[service][4] + " (the entitlement as read, assumed body)." if want_all != cur["enable_for_all"]
                          else "already as asked"))
    labels_now = {_group_label(g).lower(): g for g in raw_groups}
    if undo:
        new_groups = list(nspec["set_groups"])
    else:
        new_groups = [g for g in raw_groups if _group_label(g).lower() not in {x.lower() for x in nspec["remove_groups"]}]
        as_dict = bool(raw_groups) and all(isinstance(g, dict) for g in raw_groups)
        for name in nspec["add_groups"]:
            if name.lower() not in labels_now:
                new_groups.append({"name": name} if as_dict else name)
    before_set = {_group_label(g).lower() for g in raw_groups}
    after_set = {_group_label(g).lower() for g in new_groups}
    for lab in sorted(before_set | after_set):
        shown = next((_group_label(g) for g in list(raw_groups) + list(new_groups) if _group_label(g).lower() == lab), lab)
        b, a = lab in before_set, lab in after_set
        items.append(ao._unit(f"{key}:group:{lab}", key, "entitlement", o, "group", "listed" if b else "not listed", "listed" if a else "not listed",
                              value=shown, status="change" if a != b else "noop", reason="" if a != b else "already as asked"))
    if not undo:
        for name in nspec["remove_groups"]:
            if name.lower() not in before_set:
                items.append(ao._unit(f"{key}:missing:{name.lower()}", key, "entitlement", o, "group", "not listed", "not listed", value=name,
                                      status="noop", reason="not listed now"))
    changes = [u for u in items if u["status"] == "change"]
    if changes:
        groups.append({"key": key, "handler": "zcc_adm_entitlement", "target": {"service": service, "enable_for_all": want_all, "groups": new_groups,
                                                                               "before": {"enable_for_all": cur["enable_for_all"], "groups": raw_groups}}})
    narrows = (cur["enable_for_all"] and not want_all) or bool(before_set - after_set)
    if narrows:
        warnings.append(f"This narrows who gets {label}: users outside the listed groups lose {label} on their devices at the next Client "
                        "Connector policy refresh.")
    if not want_all and not after_set:
        warnings.append(f"With 'on for every user' off and no group listed, no user is entitled to {label}.")
    extra = {"confirm_always": f"CHANGE {label} ENTITLEMENTS"} if narrows and changes else {}
    return _done(T_ENT, ("Undo: " if undo else "") + f"{label} entitlements", nspec, items, groups, warnings=warnings,
                 undo="Undo: puts 'on for every user' and the exact group list back as read, previewed first.", notes=[ASSUMED[1]], **extra)


def _h_entitlement(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    label, all_key, groups_key = SERVICES[t["service"]][:3]
    row, err = read_entitlement(run.client, t["service"])
    if row is None:
        _read_fail(run, units, err, f"the {label} entitlements")
        return
    if _truthy(row.get(all_key)) != t["before"]["enable_for_all"] or json.dumps(row.get(groups_key) or [], sort_keys=True) != \
            json.dumps(t["before"]["groups"], sort_keys=True):
        run.mark(units, "conflict", f"the {label} entitlements changed since the preview; left as they are")
        return
    body = dict(row)
    body[all_key] = t["enable_for_all"] if isinstance(row.get(all_key), bool) or row.get(all_key) is None else (1 if t["enable_for_all"] else 0)
    body[groups_key] = t["groups"]
    out = _write(raw_for(run.client).put_entitlement, t["service"], body, op="update", kind=f"zcc_{t['service']}_entitlement",
                 name=f"{label} entitlement", log=run.log, oid=t["service"])
    if run.outcome(units, out, "update"):
        run.log(f"[Client Connector] {label} entitlements updated")


HANDLERS = {"zcc_adm_remove": _h_remove, "zcc_adm_bulk_remove": _h_bulk, "zcc_adm_app_create": _h_app_create, "zcc_adm_app_update": _h_app_update,
            "zcc_adm_app_delete": _h_app_delete, "zcc_adm_entitlement": _h_entitlement}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    if run.p.get("type") == T_BULK:
        return verify_bulk(run)
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        t, h = g["target"], g["handler"]
        out["checked"] += len(applied)
        ok, err = False, None
        if h == "zcc_adm_remove":
            rows, err = devices_of(run.client, t["user"])
            row = next((r for r in rows if r["udid"] == t["udid"]), None)
            ok = err is None and (row is None or row["state"] in (("removal pending", "removed") if t["mode"] == "remove" else ("removed",)))
        elif h in ("zcc_adm_app_create", "zcc_adm_app_update", "zcc_adm_app_delete"):
            oid = t.get("id") or applied[0]["object"].get("id")
            apps, err = read_apps(run.client)
            row = next((a for a in apps if str(_get(a, "id")) == str(oid)), None) if not err else None
            if h == "zcc_adm_app_delete":
                ok = err is None and row is None
            elif h == "zcc_adm_app_create":
                body = t["body"]
                s = app_summary(row) if row else None
                ok = s is not None and s["name"] == body["appName"] and s["active"] == body["active"]
            else:
                s = app_summary(row) if row else None
                ok = s is not None and all(s[f] == v for f, v in t["want"].items())
        elif h == "zcc_adm_entitlement":
            row, err = read_entitlement(run.client, t["service"])
            label, all_key, groups_key = SERVICES[t["service"]][:3]
            ok = row is not None and _truthy(row.get(all_key)) == t["enable_for_all"] and \
                {_group_label(x).lower() for x in row.get(groups_key) or []} == {_group_label(x).lower() for x in t["groups"]}
        if not ok and err:
            out["unread"].append(f"{t.get('name') or h}: {err}")
            for u in applied:
                u["verified"] = None
            continue
        for u in applied:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(applied)
        else:
            out["mismatched"].append(f"{t.get('name') or t.get('service')}: not as expected when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The Undo (None for a removal or a delete: there is none)."""
    t = result.get("type")
    items = result.get("items") or []
    done = lambda g: any(u.get("group") == g["key"] and u.get("status") == "applied" for u in items)  # noqa: E731
    for g in result.get("groups") or []:
        if not done(g):
            continue
        tg = g["target"]
        if g["handler"] == "zcc_adm_app_create":
            made = next((c for c in result.get("created") or [] if c.get("type") == "zcc_bypass_app" and c.get("id")), None)
            return {"type": T_BYPASS, "action": "delete", "undo": True, "id": made["id"], "name": made["name"]} if made else None
        if g["handler"] == "zcc_adm_app_update":
            b = tg["before"]
            return {"type": T_BYPASS, "action": "update", "undo": True, "id": tg["id"], "name": b["name"], "active": b["active"],
                    "entries": [{"proto": e["proto"], "port": e["port"], "address": e["ipaddr"] or e["fqdn"]} for e in b["entries"]]}
        if g["handler"] == "zcc_adm_entitlement" and t == T_ENT:
            return {"type": T_ENT, "service": tg["service"], "undo": True, "enable_for_all": tg["before"]["enable_for_all"],
                    "set_groups": tg["before"]["groups"]}
    return None


_COMMON = dict(family=FAMILY, product="zcc", in_scope=in_scope, read_objects=read_objects, verify=verify, inverse=inverse,
               script="ops_admin.js", group=GROUP)

ao.register(T_REMOVE, label="Remove Client Connector devices", plan=plan_remove, handlers=HANDLERS,
            hint="Find a user's devices and remove them (marked Removal Pending) or force remove them (dropped at once). You type the "
                 "confirmation every time. No Undo: the user enrolls again.", **_COMMON)
ao.register(T_BULK, label="Remove Client Connector devices from a list", plan=plan_bulk, handlers=HANDLERS,
            hint="Paste or upload users, host names, device ids or @domains; resolve ambiguous and unmatched entries, then remove or force "
                 f"remove up to {BULK_MAX} devices in batches, within Client Connector's hourly API budget. Plan and result as CSV. No Undo.",
            **_COMMON)
ao.register(T_BYPASS, label="Client Connector custom bypass apps", plan=plan_bypass, handlers=HANDLERS,
            hint="List, create, edit or delete custom IP-based bypass apps (protocol, port, address or host name). New ones start off; an app a "
                 "profile bypasses is never deleted. Undo for create and edit.", **_COMMON)
ao.register(T_ENT, label="ZPA and ZDX entitlements", plan=plan_entitlements, handlers=HANDLERS,
            hint="Who gets ZPA and ZDX in Client Connector: on for every user, or the groups listed. Narrowing asks for the typed "
                 "confirmation. Undo puts it back.", **_COMMON)
