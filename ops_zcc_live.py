"""Client Connector live changes on the Bulk changes engine (admin_ops plugins).

Two operation types on /report/operations. Both change what enrolled
devices do as soon as they are saved (Client Connector has no activation
step), so the typed confirmation is always asked for: the app profile's
name.

  zcc_app_profile_state     turn app profiles on or off (at most
                            MAX_TARGETS per operation), on any platform.
  zcc_app_profile_settings  change one app profile's DNS and tunnel
                            settings from an allowlist (SETTINGS): split
                            DNS, DNS exclusions first, the DNS search order,
                            DNS route exclusion, large UDP DNS answers, DNS
                            through the UDP proxy, and the packet tunnel's
                            exclusion list. Passwords and every other
                            secret the API accepts are never offered,
                            read or sent.

The engine (admin_ops) supplies the scope check (ZCC ticked) before any
read, the plan hash and the re-plan before writing, write mode, the writer,
assessor and typed-confirmation gates, the record, the audit log and Undo.
Each profile is read again right before the change (a value someone else
changed meanwhile is a conflict, left alone), read back after, and Undo
puts every applied value back, previewed and confirmed like any change.

API calls (zscaler-sdk-python 1.11.3, zscaler/zcc), verified there:

    web_policy.list_by_company                  GET   /zcc/papi/public/v1/web/policy/listByCompany (device_type)
    web_policy.activate_web_policy              PUT   /zcc/papi/public/v1/web/policy/activate (device_type, policy_id)
    application_profiles.get_application_profile
                                                GET   /zcc/papi/public/v1/application-profiles/{id}
    application_profiles.update_application_profile
                                                PATCH /zcc/papi/public/v1/application-profiles/{id} (allowlisted
                                                      fields; the SDK adds policyId)

Assumed (ASSUMED): see the list below; every applied value is read back,
so a wrong assumption shows as a mismatch, never as a silent success.
"""
from __future__ import annotations

import ipaddress
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao
import ops_zcc
import sdk_read

STATE = "zcc_app_profile_state"
SETTINGS_TYPE = "zcc_app_profile_settings"
FAMILY = "zcc_app_profile_live"
MAX_TARGETS = 10
EXCLUDE_MAX = 4000
LIVE_NOTE = ("Client Connector applies this change to enrolled devices as soon as it is saved (there is no activation step): "
             "you type the app profile's name to confirm.")
ASSUMED = [
    "PUT /web/policy/activate with device_type and policy_id switches the app profile's state (the SDK documents it as "
    "'enables or disables'): it is sent only when the state differs from the one asked for, and the state is read back.",
    "PATCH /application-profiles/{id} accepts the SDK's documented keyword names (sent camelCase by the SDK) and stores them "
    "in the profile's policyExtension, where GET answers them; every value is read back.",
    "ZCC answers HTTP 200 with success \"false\" when it rejects a body; that answer is treated as a refusal.",
]

# key: (SDK keyword, policyExtension wire key, label, kind, what it does)
SETTINGS: Dict[str, Tuple[str, str, str, str]] = {
    "enforce_split_dns": ("enforceSplitDNS", "Enforce split DNS", "flag",
                          "Names the company resolves internally are sent to its own DNS servers only, never to a public resolver."),
    "prioritize_dns_exclusions": ("prioritizeDnsExclusions", "Apply DNS exclusions first", "flag",
                                  "Domains excluded from ZPA's DNS are decided before the inclusions, so an exclusion always wins."),
    "update_dns_search_order": ("updateDnsSearchOrder", "Update the DNS search order", "flag",
                                "Client Connector puts its own DNS suffixes first on the device."),
    "disable_dns_route_exclusion": ("disableDNSRouteExclusion", "Turn off the DNS route exclusion", "flag",
                                    "DNS servers are no longer excluded from the tunnel's routes; DNS goes through the tunnel."),
    "truncate_large_udpdns_response": ("truncateLargeUDPDNSResponse", "Truncate large UDP DNS answers", "flag",
                                       "Very large DNS answers are cut so the client retries over TCP (helps on networks that drop big UDP packets)."),
    "bypass_dns_traffic_using_udp_proxy": ("bypassDNSTrafficUsingUDPProxy", "Send DNS through the UDP proxy", "flag",
                                           "DNS that bypasses the tunnel is sent through Client Connector's UDP proxy instead of straight out."),
    "packet_tunnel_exclude_list": ("packetTunnelExcludeList", "Packet tunnel exclusions", "list",
                                   "Addresses that leave the device outside the tunnel, uninspected. Keep it as short as possible."),
}
_ID = re.compile(r"^\d{1,19}$")
_HOST = re.compile(r"^(?=.{1,253}$)(\*\.)?([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """Client Connector is read and changed only when ZCC is ticked on the Scope page."""
    return ops_zcc.in_scope(scope)


def _txt(v: Any, n: int = 120) -> str:
    return "".join(ch for ch in ("" if v is None else str(v)) if ch.isprintable())[:n]


def _platform(v: Any) -> str:
    p = _txt(v, 20).strip().lower()
    if p not in ops_zcc.ALL_DEVICE_TYPES:
        raise ao.OperationError("The platform must be one of: " + ", ".join(ops_zcc.ALL_DEVICE_TYPES) + ".")
    return p


def _apps_everywhere(sdk: Any, cancel: Optional[threading.Event]) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    rows, errors = {}, {}
    for plat in ops_zcc.ALL_DEVICE_TYPES:
        if cancel is not None and cancel.is_set():
            raise ao.Stopped(ops_zcc.STOPPED_REASON)
        r, err = ops_zcc.read_apps(sdk, plat, cancel)
        rows[plat] = r
        if err:
            errors[plat] = err
    return rows, errors


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """The app profiles on every platform (name, id, on or off) and the settings this page can change. No secret is read."""
    say("Reading the app profiles on every platform…")
    rows, errors = _apps_everywhere(client, cancel)
    profiles = []
    for plat, rs in rows.items():
        for r in rs:
            if _ID.match(ops_zcc._id(r)):
                profiles.append({"id": ops_zcc._id(r), "name": _txt(ops_zcc._name(r), 128), "platform": plat, "active": ops_zcc._active(r)})
    profiles.sort(key=lambda p: (p["platform"], p["name"].lower()))
    return {"profiles": profiles, "max_targets": MAX_TARGETS,
            "settings": [{"key": k, "label": v[1], "kind": v[2], "explain": v[3]} for k, v in SETTINGS.items()],
            "errors": {f"zcc_app_{k}": v for k, v in errors.items()}}


# ── on / off ───────────────────────────────────────────────────────────

def _norm_to(v: Any) -> bool:
    s = _txt(v, 10).strip().lower()
    if s in ("on", "1", "true", "enable", "enabled"):
        return True
    if s in ("off", "0", "false", "disable", "disabled"):
        return False
    raise ao.OperationError("Say whether to turn each profile on or off.")


def normalize_state(spec: Any) -> Dict[str, Any]:
    raw = spec.get("targets") if isinstance(spec, dict) else None
    if not isinstance(raw, list) or not raw:
        raise ao.OperationError("Pick at least one app profile.")
    if len(raw) > MAX_TARGETS:
        raise ao.OperationError(f"At most {MAX_TARGETS} app profiles per operation; this one names {len(raw)}. Split it.")
    out, seen = [], set()
    for t in raw:
        if not isinstance(t, dict):
            raise ao.OperationError("Each target is an object with id, platform and to.")
        pid = _txt(t.get("id"), 20).strip()
        if not _ID.match(pid):
            raise ao.OperationError("An app profile id is digits only.")
        key = (pid, _platform(t.get("platform")))
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": pid, "platform": key[1], "to": "on" if _norm_to(t.get("to")) else "off"})
    return {"type": STATE, "targets": out}


def plan_state(client: Any, spec: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    spec = normalize_state(spec)
    rows: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    for plat in sorted({t["platform"] for t in spec["targets"]}):
        say(f"Reading the {plat} app profiles…")
        rows[plat], err = ops_zcc.read_apps(client, plat, cancel)
        if err:
            errors[plat] = err
    items, groups, names = [], [], []
    for i, t in enumerate(spec["targets"]):
        key = f"s{i}"
        row = next((r for r in rows.get(t["platform"], []) if ops_zcc._id(r) == t["id"]), None)
        obj = {"type": "zcc_app_profile", "id": t["id"], "platform": t["platform"], "name": _txt(ops_zcc._name(row), 128) if row else ""}
        if row is None:
            why = f"the {t['platform']} app profiles could not be read: {errors[t['platform']]}" if t["platform"] in errors else "no such app profile on that platform now"
            items.append(ao._unit(key, key, "zcc_app_profile_state", obj, "state", None, t["to"], status="excluded", reason=why))
            continue
        before = "on" if ops_zcc._active(row) else "off"
        names.append(obj["name"])
        if before == t["to"]:
            items.append(ao._unit(key, key, "zcc_app_profile_state", obj, "state", before, t["to"], status="noop", reason=f"already {before}"))
            continue
        items.append(ao._unit(key, key, "zcc_app_profile_state", obj, "state", before, t["to"]))
        groups.append({"key": key, "handler": "zcc_live_state", "target": dict(obj, to=t["to"])})
    n = len(groups)
    changed = [g["target"]["name"] for g in groups]
    warnings = [f"{p}: {e}" for p, e in errors.items()]
    if any(g["target"]["to"] == "off" for g in groups):
        warnings.append("Devices on a profile that is turned off move to the next profile that matches them (or the default): check what they get.")
    return {"type": STATE, "product": "zcc", "title": f"Turn {n} app profile{'s' if n != 1 else ''} on or off", "spec": spec,
            "items": items, "groups": groups, "warnings": warnings, "blockers": [],
            "notes": [f"PUT {ops_zcc.BASE}/web/policy/activate (SDK zcc.web_policy.activate_web_policy) with the platform and the profile's id.", LIVE_NOTE,
                      "Each profile is read again right before its change; one changed by someone else meanwhile is left alone."],
            "confirm_always": changed[0] if len(changed) == 1 else (f"CHANGE {n} PROFILES" if n else ""),
            "apply_note": "Client Connector applies each change as it is saved; there is no activation step."}


def _h_state(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    rows, err = ops_zcc.read_apps(run.client, t["platform"])
    if err:
        return ops_zcc._read_fail(run, units, err, "the app profile")
    row = next((r for r in rows if ops_zcc._id(r) == t["id"]), None)
    if row is None:
        run.mark(units, "conflict", "the app profile is gone since the preview; nothing was sent")
        return
    now = "on" if ops_zcc._active(row) else "off"
    if now == t["to"]:
        run.mark(units, "noop", "already as asked (someone made the same change)")
        return
    if now != units[0]["before"]:
        run.mark(units, "conflict", "changed in the tenant since the preview; left as it is")
        return
    out = ops_zcc._call(ops_zcc._zcc(run.client).web_policy.activate_web_policy, op="update", kind="zcc_app_profile", name=t["name"],
                        log=run.log, kw={"device_type": ops_zcc.ALL_DEVICE_TYPES[t["platform"]], "policy_id": int(t["id"])})
    if run.outcome(units, out, "update"):
        run.log(f"[Client Connector] app profile \"{t['name']}\" ({t['platform']}): {now} → {t['to']}")


def verify_state(run: Any) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    cache: Dict[str, Tuple[List[Dict[str, Any]], Optional[str]]] = {}
    for u in [u for u in run.p["items"] if u["status"] == "applied"]:
        o = u["object"]
        if o["platform"] not in cache:
            cache[o["platform"]] = ops_zcc.read_apps(run.client, o["platform"])
        rows, err = cache[o["platform"]]
        out["checked"] += 1
        row = next((r for r in rows if ops_zcc._id(r) == o["id"]), None)
        if err or row is None:
            u["verified"] = None
            out["unread"].append(f"{o['name']}: {err or 'not listed'}")
            continue
        u["verified"] = ("on" if ops_zcc._active(row) else "off") == u["after"]
        if u["verified"]:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o['name']}: still {u['before']}")
    return out


def inverse_state(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied" and u.get("kind") == "zcc_app_profile_state"]
    if not applied:
        return None
    return {"type": STATE, "targets": [{"id": u["object"]["id"], "platform": u["object"]["platform"], "to": u["before"]} for u in applied]}


# ── settings ───────────────────────────────────────────────────────────

def clean_exclude_list(raw: Any) -> str:
    """The packet tunnel exclusion list as ZCC stores it (comma-separated), each entry an address, a range or a host name."""
    if not isinstance(raw, str):
        raise ao.OperationError("Packet tunnel exclusions: give them as text, separated by commas.")
    if len(raw) > EXCLUDE_MAX:
        raise ao.OperationError(f"Packet tunnel exclusions: at most {EXCLUDE_MAX} characters.")
    out, seen = [], set()
    for part in re.split(r"[\s,;]+", raw.strip()):
        if not part:
            continue
        ok = False
        try:
            ipaddress.ip_network(part, strict=False)
            ok = True
        except ValueError:
            ok = bool(_HOST.match(part))
        if not ok:
            raise ao.OperationError(f"Packet tunnel exclusions: {part[:60]!r} is not an address, a range or a host name.")
        if part.lower() not in seen:
            seen.add(part.lower())
            out.append(part)
    return ",".join(out)


def _flag_value(v: Any) -> int:
    s = _txt(v, 10).strip().lower()
    if s in ("1", "true", "on", "yes"):
        return 1
    if s in ("0", "false", "off", "no"):
        return 0
    raise ao.OperationError("A setting is turned on (1) or off (0).")


def normalize_settings(spec: Any) -> Dict[str, Any]:
    if not isinstance(spec, dict):
        raise ao.OperationError("The operation must be an object.")
    pid = _txt(spec.get("profile"), 20).strip()
    if not _ID.match(pid):
        raise ao.OperationError("Pick the app profile.")
    raw = spec.get("settings")
    if not isinstance(raw, dict) or not raw:
        raise ao.OperationError("Pick at least one setting to change.")
    unknown = [k for k in raw if k not in SETTINGS]
    if unknown:
        raise ao.OperationError("These settings cannot be changed here: " + ", ".join(_txt(k, 40) for k in unknown[:5]) + ".")
    vals = {k: (clean_exclude_list(v) if SETTINGS[k][2] == "list" else _flag_value(v)) for k, v in raw.items()}
    return {"type": SETTINGS_TYPE, "profile": pid, "platform": _platform(spec.get("platform") or "windows"), "settings": dict(sorted(vals.items()))}


def read_profile(sdk: Any, pid: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    body, err = sdk_read.call(ops_zcc._zcc(sdk).application_profiles.get_application_profile, pid)
    if err:
        return None, err
    return (body if isinstance(body, dict) else None), (None if isinstance(body, dict) else "no such app profile")


def current(profile: Dict[str, Any], key: str) -> Any:
    wire_key, _label, kind, _x = SETTINGS[key]
    pe = profile.get("policyExtension") if isinstance(profile.get("policyExtension"), dict) else {}
    v = pe.get(wire_key, profile.get(wire_key))
    if kind == "list":
        return ",".join(x for x in re.split(r"[\s,;]+", str(v or "")) if x)
    if v in (None, ""):
        return 0
    try:
        return 1 if int(float(str(v))) else 0
    except ValueError:
        return 1 if str(v).strip().lower() == "true" else 0


def plan_settings(client: Any, spec: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    spec = normalize_settings(spec)
    say("Reading the app profile…")
    prof, err = read_profile(client, spec["profile"])
    if prof is None:
        raise ao.OperationError(f"The app profile could not be read: {err}.")
    name = _txt(prof.get("name") or spec["profile"], 128)
    obj = {"type": "zcc_app_profile", "id": spec["profile"], "platform": spec["platform"], "name": name}
    items, changes = [], {}
    for k, want in spec["settings"].items():
        before = current(prof, k)
        label = SETTINGS[k][1]
        if before == want:
            items.append(ao._unit(f"v:{k}", "g0", "zcc_app_profile_setting", dict(obj, setting=label), k, before, want, status="noop", reason="already as asked"))
        else:
            items.append(ao._unit(f"v:{k}", "g0", "zcc_app_profile_setting", dict(obj, setting=label), k, before, want))
            changes[k] = want
    groups = [{"key": "g0", "handler": "zcc_live_settings", "target": dict(obj, changes=changes)}] if changes else []
    warnings = []
    if "packet_tunnel_exclude_list" in changes and len(str(changes["packet_tunnel_exclude_list"])) > len(str(current(prof, "packet_tunnel_exclude_list"))):
        warnings.append("The packet tunnel exclusion list grows: every address added leaves devices uninspected.")
    return {"type": SETTINGS_TYPE, "product": "zcc", "title": f"Change {len(changes)} setting{'s' if len(changes) != 1 else ''} of \"{name}\"",
            "spec": spec, "items": items, "groups": groups, "warnings": warnings, "blockers": [],
            "notes": [f"PATCH {ops_zcc.BASE}/application-profiles/{spec['profile']} (SDK zcc.application_profiles.update_application_profile) "
                      "with only the settings that change.", LIVE_NOTE,
                      "No password or other secret is read, shown or sent by this operation."],
            "confirm_always": name, "apply_note": "Client Connector applies the change as it is saved; there is no activation step."}


def _h_settings(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    prof, err = read_profile(run.client, t["id"])
    if prof is None:
        return ops_zcc._read_fail(run, units, err or "no such app profile", "the app profile")
    send, ready = {}, []
    for u in units:
        now = current(prof, u["field"])
        if now == u["after"]:
            run.mark([u], "noop", "already as asked (someone made the same change)")
        elif now != u["before"]:
            run.mark([u], "conflict", "changed in the tenant since the preview; left as it is")
        else:
            send[u["field"]] = u["after"]
            ready.append(u)
    if not ready:
        return
    out = ops_zcc._call(ops_zcc._zcc(run.client).application_profiles.update_application_profile, t["id"], op="update",
                        kind="zcc_app_profile", name=t["name"], log=run.log, kw=send)
    if run.outcome(ready, out, "update"):
        run.log(f"[Client Connector] app profile \"{t['name']}\": {len(ready)} setting(s) changed")


def verify_settings(run: Any) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    if not applied:
        return out
    prof, err = read_profile(run.client, applied[0]["object"]["id"])
    for u in applied:
        out["checked"] += 1
        if prof is None:
            u["verified"] = None
            out["unread"].append(f"{u['object']['name']}: {err}")
            continue
        u["verified"] = current(prof, u["field"]) == u["after"]
        if u["verified"]:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['object']['setting']}: not as asked")
    return out


def inverse_settings(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied" and u.get("kind") == "zcc_app_profile_setting"]
    if not applied:
        return None
    o = applied[0]["object"]
    return {"type": SETTINGS_TYPE, "profile": o["id"], "platform": o["platform"], "settings": {u["field"]: u["before"] for u in applied}}


_common = dict(family=FAMILY, product="zcc", in_scope=in_scope, read_objects=read_objects, script="ops_zcc_live.js")
ao.register(STATE, label="Turn Client Connector app profiles on or off", plan=plan_state, handlers={"zcc_live_state": _h_state},
            verify=verify_state, inverse=inverse_state,
            hint=("Turn app profiles on or off on any platform; enrolled devices get the change at once, so you type the profile's name. "
                  "Needs ZCC ticked on the Scope page."), **_common)
ao.register(SETTINGS_TYPE, label="Change a Client Connector app profile's DNS and tunnel settings", plan=plan_settings,
            handlers={"zcc_live_settings": _h_settings}, verify=verify_settings, inverse=inverse_settings,
            hint=("Split DNS, DNS exclusions first, the DNS search order and the packet tunnel exclusions of one app profile, from an allowlist "
                  "(never a password); enrolled devices get the change at once, so you type the profile's name. Needs ZCC ticked on the Scope page."),
            **_common)
