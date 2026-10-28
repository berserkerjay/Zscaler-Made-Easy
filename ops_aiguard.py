"""AI Guard builders on the Bulk changes engine (admin_ops.register).

Two operation types, planned from the tenant as it is now, previewed item
by item, applied through the shared gates and pack_ops, read back and
reversible with Undo, exactly like every other bulk change:

  aiguard_routing           send chosen GenAI apps (ChatGPT, Microsoft 365
                            Copilot, Claude, Gemini, ...) through AI Guard by
                            proxy chaining: the root certificate (reused or
                            uploaded), the AI Guard proxy (reused or created),
                            a destination group of the apps' domains, a QUIC
                            block, an SSL Inspect rule at the top of SSL
                            inspection (above every Do Not Decrypt bypass),
                            GenAI prompt capture when licensed, the forwarding
                            rule to the proxy gateway, and an Allow in ZIA for
                            the apps above any Block, Caution or Isolate rule.
                            The proxy gateway is a ZIA portal step: the API
                            cannot create it, so the plan says how and leaves
                            the forwarding rule out until it exists.
  aiguard_detection_policy  a compliance profile (HIPAA, HITRUST, PCI, GDPR,
                            CJIS, FERPA, SOX, general) as an AI Guard detection
                            policy plus a policy match rule for the apps' LLM
                            providers. Monitor (detect only) by default.

Each write is one step (a group's target): create, update (only the named
fields, on the object read again right before the write; a field someone
changed since the preview is a conflict, never overwritten) or delete (an
Undo only, and only of an object that still carries the name this builder
gave it). The inverse of a run deletes what it created and puts back the
fields it changed. ai_guard.py holds the catalogue, the readers and the
readiness check; what is verified against the SDK and what is assumed is
listed there.
"""
from __future__ import annotations

import json
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao
import ai_guard as ag
import pack_channels as pc
import pack_ops as ops

ROUTING = "aiguard_routing"
POLICY = "aiguard_detection_policy"
HANDLER = "aiguard_step"
MARK = "AIG-"                      # every name this builder gives carries it; Undo deletes nothing without it
MAX_PEM = 16_384
MAX_UNDO_STEPS = 40
_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,11}$")
_PEM = re.compile(r"^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]{64,}-----END CERTIFICATE-----\s*$")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# What each object kind is: its label, product, the pack_ops kind and channel
# it is written through, and the only fields an update (or an Undo) may set.
KINDS: Dict[str, Dict[str, Any]] = {
    "root_certificate": {"label": "Root certificate", "product": "zia", "ops": "root_certificate", "fields": ()},
    "zia_proxy": {"label": "Proxy", "product": "zia", "ops": "zia_proxy", "fields": ()},
    "proxy_gateway": {"label": "Proxy gateway", "product": "zia", "ops": "", "fields": ()},
    "ip_destination_group": {"label": "Destination group", "product": "zia", "ops": "ip_destination_group", "fields": ("addresses",)},
    "firewall_rule": {"label": "Cloud Firewall rule", "product": "zia", "ops": "policy", "channel": "firewall",
                      "fields": ("state", "action", "nw_services")},
    "ssl_rule": {"label": "SSL inspection rule", "product": "zia", "ops": "policy", "channel": pc.SSL,
                 "fields": ("state", "action", "dest_ip_groups", "order")},
    "url_app_settings": {"label": "GenAI prompt capture", "product": "zia", "ops": "url_app_settings", "fields": ("*Prompt",)},
    "forwarding_rule": {"label": "Forwarding rule", "product": "zia", "ops": "forwarding_rule",
                        "fields": ("state", "forward_method", "proxy_gateway", "dest_ip_groups")},
    "cac_rule": {"label": "Cloud App Control rule", "product": "zia", "ops": "policy", "channel": pc.CLOUD_APP,
                 "fields": ("state", "actions", "applications", "order")},
    "url_category": {"label": "URL category", "product": "zia", "ops": "url_category", "fields": ("urls",)},
    "url_rule": {"label": "URL filtering rule", "product": "zia", "ops": "policy", "channel": pc.URL,
                 "fields": ("state", "action", "url_categories", "order")},
    "aiguard_policy": {"label": "AI Guard detection policy", "product": "aiguard", "ops": "aiguard_policy",
                       "fields": ("input_detector_policies", "output_detector_policies", "description")},
    "aiguard_rule": {"label": "AI Guard policy match rule", "product": "aiguard", "ops": "aiguard_rule",
                     "fields": ("policy_id", "enabled", "match_criteria")},
}
_BOOKKEEPING = {"last_modified_time", "last_modified_by", "create_time_millis", "update_time_millis", "creation_time", "created_by",
                "modified_time", "modified_by", "rule_type"}


def names(prefix: str) -> Dict[str, str]:
    """Object names (ZIA allows 31 characters)."""
    def nm(suffix: str) -> str:
        return (f"{prefix}-{MARK}{suffix}" if prefix else f"{MARK}{suffix}")[:31]
    return {"cert": nm("CA"), "proxy": nm("Proxy"), "gateway": nm("Gateway"), "group": nm("Apps"), "quic": nm("NoQUIC"),
            "ssl": nm("Inspect"), "fwd": nm("Forward"), "allow": nm("Allow-AI"), "allow_url": nm("Allow-URL"),
            "policy": nm("Policy"), "policy_rule": nm("Policy-Apps")}


# ── comparison ───────────────────────────────────────────────────────────
def _det_sig(v: Any) -> List[Dict[str, Any]]:
    """A detector list as far as this builder sets it: AI Guard adds its own
    fields and disabled entity types, which are not a difference."""
    out = []
    for d in v if isinstance(v, list) else []:
        if not isinstance(d, dict):
            continue
        c = ag.get(d, "configuration") or {}
        ents = sorted(f"{ag.get(e, 'entity_type')}:{ag.get(e, 'action')}" for e in (ag.get(c, "entities") or [])
                      if isinstance(e, dict) and str(ag.get(e, "action") or "").upper() != "DISABLE")
        thr = ag.get(c, "threshold")
        out.append({"detector": str(ag.get(d, "detector")), "enabled": bool(ag.get(d, "enabled")), "severity": str(ag.get(d, "severity")),
                    "action": str(ag.get(c, "action")), "default_action": str(ag.get(c, "default_action")),
                    "threshold": round(float(thr), 3) if isinstance(thr, (int, float)) or re.fullmatch(r"[0-9.]+", str(thr or "")) else None,
                    "entities": ents})
    return sorted(out, key=lambda x: x["detector"])


def canon(v: Any, path: str = "") -> Any:
    """A value in a form two answers can be compared in: references by id,
    lists sorted, empty fields dropped, keys in snake_case."""
    if path.endswith("detector_policies"):
        return _det_sig(v)
    if isinstance(v, dict):
        if "id" in v and v.get("id") is not None:
            return str(v["id"])
        return {ag._snake(k): canon(x) for k, x in sorted(v.items()) if x not in (None, "", [], {})}
    if isinstance(v, (list, tuple)):
        return sorted((canon(x) for x in v), key=lambda x: json.dumps(x, sort_keys=True, default=str))
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, float):
        return str(round(v, 4))
    return str(v)


def _same(row: Optional[Dict[str, Any]], want: Dict[str, Any]) -> bool:
    return row is not None and all(canon(ag.get(row, p), p) == canon(v, p) for p, v in want.items())


def _resolve(v: Any, ids: Dict[str, Any]) -> Any:
    """Replace {"$ref": key} with the id an earlier step of this run created."""
    if isinstance(v, dict):
        if set(v) == {"$ref"}:
            if v["$ref"] not in ids:
                raise KeyError(v["$ref"])
            return ids[v["$ref"]]
        return {k: _resolve(x, ids) for k, x in v.items()}
    if isinstance(v, list):
        return [_resolve(x, ids) for x in v]
    return v


def _ref(key: str) -> Dict[str, str]:
    return {"$ref": key}


# ── readers per kind ─────────────────────────────────────────────────────
def _aig(client: Any) -> Any:
    svc, _why = ag.aiguard_service(client)
    return svc


def _full(ret: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One object as the tenant sent it (every field), top-level keys in snake_case."""
    body = ag.raw_body(ret)
    if isinstance(body, dict) and body:
        return ag._plain(body), None
    return ag.one(ret)


def fetch(client: Any, kind: str, oid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One object of `kind`, read fresh; (None, why) when it cannot be read or is gone."""
    z = getattr(client, "zia", None)
    try:
        if kind == "root_certificate":
            certs, err = ag.read_root_certs(z)
            if err:
                return None, err
            hit = next((c for c in certs if str(c["id"]) == str(oid)), None)
            return (hit, None) if hit else (None, "not found")
        if kind == "url_app_settings":
            settings, complete, err = ag.read_app_settings(z)
            if err or not complete:
                return None, err or "only part of the settings could be read, so they are not written back"
            return settings, None
        if kind == "aiguard_policy":
            return _full(_aig(client).policies.get_policy(oid))
        if kind == "aiguard_rule":
            return _full(_aig(client).policy_match_rules.get_rule(oid))
        getter = {"zia_proxy": lambda: z.proxies.get_proxy(oid),
                  "ip_destination_group": lambda: z.cloud_firewall.get_ip_destination_group(oid),
                  "firewall_rule": lambda: z.cloud_firewall_rules.get_rule(oid),
                  "ssl_rule": lambda: z.ssl_inspection_rules.get_rule(oid),
                  "forwarding_rule": lambda: z.forwarding_control.get_rule(oid),
                  "cac_rule": lambda: z.cloudappcontrol.get_rule("AI_ML", oid),
                  "url_category": lambda: z.url_categories.get_category(oid),
                  "url_rule": lambda: z.url_filtering.get_rule(oid)}[kind]
        return _full(getter())
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def listing(client: Any, kind: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every object of `kind` (snake_case rows)."""
    z = getattr(client, "zia", None)
    if kind == "root_certificate":
        return ag.read_root_certs(z)
    if kind == "zia_proxy":
        return ag.read_proxies(z)
    if kind == "proxy_gateway":
        return ag.read_gateways(z)
    if kind in ("aiguard_policy", "aiguard_rule"):
        a = _aig(client)
        return ag.rows(ag._call(lambda: a.policies.list_policies() if kind == "aiguard_policy" else a.policy_match_rules.list_rules()))
    fn = {"ip_destination_group": lambda: z.cloud_firewall.list_ip_destination_groups(),
          "firewall_rule": lambda: z.cloud_firewall_rules.list_rules(),
          "ssl_rule": lambda: z.ssl_inspection_rules.list_rules(),
          "forwarding_rule": lambda: z.forwarding_control.list_rules(),
          "cac_rule": lambda: z.cloudappcontrol.list_rules("AI_ML"),
          "url_category": lambda: z.url_categories.list_categories(query_params={"custom_only": True}),
          "url_rule": lambda: z.url_filtering.list_rules()}[kind]
    return ag.rows(ag._call(fn))


def name_of(kind: str, row: Dict[str, Any]) -> str:
    return str(ag.get(row, "configured_name") if kind == "url_category" else ag.get(row, "name") or "")


def _by_name(rows: List[Dict[str, Any]], kind: str, name: str) -> Optional[Dict[str, Any]]:
    return next((r for r in rows if name_of(kind, r) == name), None)


# ── planning ─────────────────────────────────────────────────────────────
class _Plan:
    def __init__(self, type_name: str, product: str, title: str, spec: Dict[str, Any]):
        self.p: Dict[str, Any] = {"type": type_name, "product": product, "title": title, "spec": spec, "items": [], "groups": [],
                                  "warnings": [], "blockers": [], "notes": [], "impact": []}

    def unit(self, key: str, kind: str, name: str, *, status: str = "change", reason: str = "", before: str = "", after: str = "",
             field: str = "object", oid: Any = None, depends: Tuple[str, ...] = (), step: Optional[Dict[str, Any]] = None) -> None:
        obj = {"type": KINDS[kind]["label"], "kind": kind, "name": name, "id": oid}
        self.p["items"].append(ao._unit(key, f"g_{key}", kind, obj, field, before, after, status=status, reason=reason,
                                        depends_on=[d for d in depends if any(u["key"] == d for u in self.p["items"])]))
        if status == "change" and step is not None:
            self.p["groups"].append({"key": f"g_{key}", "handler": HANDLER, "target": dict(step, kind=kind, name=name, key=key)})

    def status_of(self, key: str) -> Optional[str]:
        return next((u["status"] for u in self.p["items"] if u["key"] == key), None)


def _bool(spec: Dict[str, Any], key: str, default: bool = True) -> bool:
    v = spec.get(key, default)
    return v is True or str(v).strip().lower() in ("true", "1", "yes", "on")


def _prefix(spec: Dict[str, Any]) -> str:
    p = str(spec.get("prefix") or "").strip()
    if p and not _PREFIX.match(p):
        raise ao.OperationError("The name prefix may have up to 12 letters, digits, '-' or '_' (for example ACME).")
    return p


def _apps(spec: Dict[str, Any]) -> List[str]:
    raw = spec.get("apps")
    if raw is not None and not isinstance(raw, list):
        raise ao.OperationError("apps must be a list of app ids.")
    unknown = [str(x) for x in (raw or []) if str(x).strip().lower() not in ag.APPS_BY_ID]
    if unknown:
        raise ao.OperationError(f"Unknown app(s): {', '.join(unknown[:5])[:200]}. Use: {', '.join(ag.APPS_BY_ID)}.")
    return ag.app_ids(raw)


def _scope_parts(scope: Dict[str, Any]) -> Dict[str, bool]:
    import data_flow
    sc = [str(s) for s in scope.get("scopes") or []]
    read = data_flow.path_scope(sorted(sc), scope.get("channels") or {})["read"] if sc else []
    return {"zia": "zia_extras" in sc, "aiguard": ag.SCOPE_KEY in sc, "ssl": "ssl" in read, "cac": "cac" in read, "url": "url" in read}


def _in_scope_routing(scope: Dict[str, Any]) -> Optional[str]:
    s = _scope_parts(scope)
    if not s["zia"] or not s["aiguard"]:
        miss = " and ".join(x for x, on in (("ZIA platform", s["zia"]), (ag.SCOPE_LABEL, s["aiguard"])) if not on)
        return f"AI Guard routing is not in scope: on the Scope page tick {miss}. Nothing was read."
    return None


def _in_scope_policy(scope: Dict[str, Any]) -> Optional[str]:
    if not _scope_parts(scope)["aiguard"]:
        return f"The AI Guard detection policy is not in scope: on the Scope page tick {ag.SCOPE_LABEL}. Nothing was read."
    return None


def _desc(text: str) -> str:
    return text[:200]


def _plan_routing(client, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    if spec.get("action") == "undo":
        return _plan_undo(client, spec, ROUTING, "zia", say, cancel)
    prefix, apps = _prefix(spec), _apps(spec)
    n = names(prefix)
    parts = _scope_parts(scope)
    z = getattr(client, "zia", None)
    if z is None:
        raise ao.OperationError("This sign-in has no ZIA service, so AI Guard routing cannot be planned.")
    domains = ag.domains_for(apps)
    host = str(spec.get("proxy_host") or ag.AI_GUARD_HOST).strip().lower()
    if not ag.AIG_HOST.match(host):
        raise ao.OperationError(f"'{host[:80]}' is not an AI Guard forwarder (for example {ag.AI_GUARD_HOST}).")
    cert = spec.get("cert") if isinstance(spec.get("cert"), dict) else {}
    mode = str(cert.get("mode") or "")
    if mode == "upload":
        pem = str(cert.get("pem") or "").strip()
        if len(pem) > MAX_PEM or not _PEM.match(pem + "\n"):
            raise ao.OperationError("The AI Guard certificate must be one PEM certificate (-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----, "
                                    "at most 16 KB). Download it in the AI Guard portal: Tenant Settings > Integrations.")
    elif mode == "existing":
        if not _ID.match(str(cert.get("id") or "")):
            raise ao.OperationError("Pick the AI Guard root certificate already in ZIA.")
    elif mode:
        raise ao.OperationError("cert.mode must be 'existing' or 'upload'.")
    P = _Plan(ROUTING, "zia", f"Send {len(apps)} GenAI app(s) through AI Guard", spec)
    P.p["apply_note"] = "ZIA keeps every change pending until it is activated: the app activates once, after the last write."
    picked = ", ".join(ag.APPS_BY_ID[a]["name"] for a in apps)

    say("Reading the proxy-chaining root certificates, the proxies and the proxy gateways…")
    certs, cerr = ag.read_root_certs(z)
    proxies, perr = ag.read_proxies(z)
    gws, gerr = ag.read_gateways(z)
    for what, e in (("root certificates", cerr), ("proxies", perr), ("proxy gateways", gerr)):
        if e and what != "root certificates":
            P.p["blockers"].append(f"The {what} could not be read ({e}), so the plan cannot tell what already exists.")
    # 1-2. an AI Guard proxy already in ZIA is reused (one using the chosen
    # certificate first); otherwise the certificate is reused or uploaded and
    # the proxy is created with it
    aig = [p for p in proxies if ag.is_aiguard_proxy(p)]
    mine = _by_name(proxies, "zia_proxy", n["proxy"])
    reuse = None
    if aig:
        if mode == "existing":
            reuse = next((p for p in aig if str(ag.get(p, "cert.id")) == str(cert["id"])), None)
        reuse = reuse or (mine if mine in aig else aig[0])
    cert_id: Any = None
    if reuse is not None:
        cert_id = ag.get(reuse, "cert.id")
        if mode:
            P.unit("cert", "root_certificate", str(ag.get(reuse, "cert.name") or cert_id or "certificate"), status="noop", oid=cert_id,
                   reason="the AI Guard proxy already in ZIA carries its certificate: nothing to upload", before="in ZIA", after="reused")
    elif mode == "existing":
        hit = next((c for c in certs if str(c["id"]) == str(cert["id"])), None)
        if hit is None and not cerr:
            P.p["blockers"].append("The chosen root certificate is no longer in ZIA: read again and pick one.")
        cert_id = cert["id"]
        P.unit("cert", "root_certificate", hit["name"] if hit else str(cert["id"]), status="noop", oid=cert_id,
               reason="already in ZIA: reused", before="in ZIA", after="reused")
    elif mode == "upload":
        same = _by_name(certs, "root_certificate", n["cert"])
        if same:
            cert_id = same["id"]
            P.unit("cert", "root_certificate", n["cert"], status="noop", oid=cert_id, reason="uploaded earlier: reused", before="in ZIA", after="reused")
        else:
            P.unit("cert", "root_certificate", n["cert"], before="not in ZIA", after="uploaded (proxy chaining)",
                   step={"op": "create", "ref": "cert", "payload": {"name": n["cert"], "cert": pem, "certTypes": [ag.CERT_TYPE]},
                         "check": {"name": n["cert"]}})
    ao._check_stop(cancel)
    proxy_id: Any = None
    if reuse is not None:
        proxy_id = ag.get(reuse, "id")
        P.unit("proxy", "zia_proxy", name_of("zia_proxy", reuse), status="noop", oid=proxy_id,
               reason=f"an AI Guard proxy already in ZIA ({ag.get(reuse, 'address')}:{ag.get(reuse, 'port')}): reused",
               before="in ZIA", after="reused")
    elif mine is not None:
        P.p["blockers"].append(f"ZIA already has a proxy named {n['proxy']} that does not point at AI Guard. Rename it, or choose another name prefix.")
        P.unit("proxy", "zia_proxy", n["proxy"], status="excluded", reason="a proxy with this name exists and is not an AI Guard proxy")
    elif not mode:
        P.p["blockers"].append("ZIA has no AI Guard proxy yet: pick the AI Guard root certificate already in ZIA, or upload it, so the proxy can be created.")
        P.unit("proxy", "zia_proxy", n["proxy"], status="excluded", reason="needs the root certificate")
    else:
        P.unit("proxy", "zia_proxy", n["proxy"], before="not in ZIA", after=f"created: {host}:{ag.AI_GUARD_PORT}", depends=("cert",),
               step={"op": "create", "ref": "proxy",
                     "payload": {"name": n["proxy"], "type": "PROXYCHAIN", "address": host, "port": ag.AI_GUARD_PORT,
                                 "cert": {"id": cert_id if cert_id is not None else _ref("cert")}, "insertXauHeader": True,
                                 "base64EncodeXauHeader": False, "description": _desc("Proxy chaining to Zscaler AI Guard.")},
                     "check": {"address": host, "type": "PROXYCHAIN"}})
    # 3. the proxy gateway: a portal step
    gw = ag.gateway_for(gws, proxy_id) if proxy_id is not None else None
    gw = gw or _by_name(gws, "proxy_gateway", n["gateway"])
    gw_id = ag.get(gw, "id") if gw else None
    if gw is not None:
        fc = ag.get(gw, "fail_closed")
        P.unit("gateway", "proxy_gateway", name_of("proxy_gateway", gw), status="noop", oid=gw_id,
               reason="exists" + ("" if fc is not False else "; Fail Close is off"), before="in ZIA", after="used")
        if fc is False:
            P.p["warnings"].append(f"Proxy gateway {name_of('proxy_gateway', gw)} has Fail Close off: if AI Guard is unreachable, GenAI prompts go out uninspected.")
    else:
        P.unit("gateway", "proxy_gateway", n["gateway"], status="excluded",
               reason="a ZIA portal step: the Zscaler API cannot create proxy gateways", before="not in ZIA", after="create it in the portal")
        P.p["warnings"].append(f"The proxy gateway is a portal step (the API cannot create it). Create {n['gateway']} with Primary Proxy "
                               f"{name_of('zia_proxy', reuse) if reuse else n['proxy']}, Secondary Proxy None and Fail Close on; then preview again "
                               "to add the forwarding rule.")
        P.p["notes"].extend(ag.GATEWAY_STEPS)
    ao._check_stop(cancel)
    # 4. the destination group of the apps' domains
    say("Reading the IP destination groups and network services…")
    groups, grerr = listing(client, "ip_destination_group")
    if grerr:
        P.p["blockers"].append(f"The IP destination groups could not be read ({grerr}).")
    g = _by_name(groups, "ip_destination_group", n["group"])
    group_id: Any = ag.get(g, "id") if g else None
    if g is None:
        P.unit("group", "ip_destination_group", n["group"], before="not in ZIA", after=f"created: {len(domains)} domains",
               step={"op": "create", "ref": "group",
                     "payload": {"name": n["group"], "type": "DSTN_DOMAIN", "addresses": domains,
                                 "description": _desc(f"GenAI apps sent to AI Guard: {picked}.")},
                     "check": {"addresses": domains}})
    else:
        have = ag.get(g, "addresses") or []
        if canon(have) == canon(domains):
            P.unit("group", "ip_destination_group", n["group"], status="noop", oid=group_id, reason="already lists the apps' domains",
                   before=f"{len(have)} domains", after="unchanged")
        else:
            P.unit("group", "ip_destination_group", n["group"], oid=group_id, field="addresses", before=f"{len(have)} domains",
                   after=f"{len(domains)} domains",
                   step={"op": "update", "id": group_id, "set": {"addresses": domains}, "expect": {"addresses": have},
                         "restore": {"addresses": have}, "check": {"addresses": domains}})
    gref = group_id if group_id is not None else _ref("group")
    # 5. QUIC block
    if _bool(spec, "block_quic"):
        svcs, serr = ag.rows(ag._call(lambda: z.cloud_firewall.list_network_services(query_params={"search": "QUIC"})))
        quic = next((s for s in svcs if str(ag.get(s, "name") or "").upper() == "QUIC" or str(ag.get(s, "tag") or "").upper() == "QUIC"), None)
        fw, ferr = listing(client, "firewall_rule")
        if serr or ferr or quic is None:
            P.unit("quic", "firewall_rule", n["quic"], status="excluded",
                   reason=f"could not be planned: {serr or ferr}" if (serr or ferr) else "the predefined QUIC network service was not found")
        else:
            want = {"state": "ENABLED", "action": "BLOCK_ICMP", "nw_services": [{"id": ag.get(quic, "id")}]}
            ex = _by_name(fw, "firewall_rule", n["quic"])
            if ex is None:
                P.unit("quic", "firewall_rule", n["quic"], before="not in ZIA", after="created: Block/ICMP on QUIC (UDP 443)",
                       step={"op": "create", "ref": "quic",
                             "payload": {"name": n["quic"], "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK_ICMP",
                                         "nwServices": [{"id": ag.get(quic, "id")}],
                                         "description": _desc("Drop QUIC so GenAI apps use TCP 443, which ZIA inspects and chains to AI Guard.")},
                             "check": want})
            elif _same(ex, want):
                P.unit("quic", "firewall_rule", n["quic"], status="noop", oid=ag.get(ex, "id"), reason="already blocks QUIC", before="blocks QUIC", after="unchanged")
            else:
                cur = {k: ag.get(ex, k) for k in want}
                P.unit("quic", "firewall_rule", n["quic"], oid=ag.get(ex, "id"), field="state, action, nw_services",
                       before=f"{cur['state']}, {cur['action']}", after="ENABLED, BLOCK_ICMP on QUIC",
                       step={"op": "update", "id": ag.get(ex, "id"), "set": want, "expect": cur, "restore": cur, "check": want})
    ao._check_stop(cancel)
    # 6. SSL Inspect for the apps above every bypass
    if _bool(spec, "ssl_inspect"):
        if not parts["ssl"]:
            P.unit("ssl", "ssl_rule", n["ssl"], status="excluded",
                   reason="not in scope: SSL/TLS Inspection is not marked as run on Zscaler on the Scope page, so it is not read or changed")
        else:
            say("Reading the SSL inspection rules…")
            rules, rerr = listing(client, "ssl_rule")
            if rerr:
                P.p["blockers"].append(f"The SSL inspection rules could not be read ({rerr}).")
            ex = _by_name(rules, "ssl_rule", n["ssl"])
            dni = sorted((r for r in rules if r is not ex and str(ag.get(r, "action.type") or "").upper() == "DO_NOT_DECRYPT"
                          and str(ag.get(r, "state") or "ENABLED").upper() != "DISABLED" and not ag.get(r, "default_rule")),
                         key=lambda r: ao._int(ag.get(r, "order"), 0))
            action = {"type": "DECRYPT", "showEUN": False, "showEUNATP": False, "overrideDefaultCertificate": False,
                      "decryptSubActions": {"serverCertificates": "ALLOW", "ocspCheck": True, "blockSslTrafficWithNoSniEnabled": True,
                                            "minClientTLSVersion": "CLIENT_TLS_1_2", "minServerTLSVersion": "SERVER_TLS_1_2",
                                            "blockUndecrypt": True, "http2Enabled": False}}
            bypass = ", ".join(name_of("ssl_rule", r) for r in dni[:3])
            if ex is None:
                P.unit("ssl", "ssl_rule", n["ssl"], before="not in ZIA", depends=("group",),
                       after="created at order 1: Inspect the apps" + (f", above {bypass}" if bypass else ""),
                       step={"op": "create", "ref": "ssl",
                             "payload": {"name": n["ssl"], "order": 1, "rank": 7, "state": "ENABLED", "roadWarriorForKerberos": False,
                                         "destIpGroups": [{"id": gref}], "action": action,
                                         "description": _desc("Decrypt GenAI apps so ZIA can chain them to AI Guard. Keep it above every Do Not Decrypt rule.")},
                             "check": {"state": "ENABLED", "action.type": "DECRYPT", "order": 1}})
            else:
                above = not dni or ao._int(ag.get(ex, "order"), 0) < ao._int(ag.get(dni[0], "order"), 0)
                ok = str(ag.get(ex, "action.type") or "").upper() == "DECRYPT" and str(ag.get(ex, "state") or "").upper() != "DISABLED" \
                    and str(group_id) in ag.ref_ids(ag.get(ex, "dest_ip_groups"))
                if above and ok:
                    P.unit("ssl", "ssl_rule", n["ssl"], status="noop", oid=ag.get(ex, "id"), reason="already inspects the apps above every bypass",
                           before=f"order {ag.get(ex, 'order')}", after="unchanged")
                else:
                    fields = ("state", "action", "dest_ip_groups", "order")
                    cur = {k: ag.get(ex, k) for k in fields}
                    want = {"state": "ENABLED", "action": action, "dest_ip_groups": [{"id": gref}], "order": 1}
                    P.unit("ssl", "ssl_rule", n["ssl"], oid=ag.get(ex, "id"), field=", ".join(fields), depends=("group",),
                           before=f"order {cur['order']}, {ag.get(ex, 'action.type')}, {cur['state']}", after="order 1, DECRYPT, ENABLED",
                           step={"op": "update", "id": ag.get(ex, "id"), "set": want, "expect": {"state": cur["state"], "action.type": ag.get(ex, "action.type"),
                                                                                                 "dest_ip_groups": cur["dest_ip_groups"], "order": cur["order"]},
                                 "restore": cur, "check": {"state": "ENABLED", "action.type": "DECRYPT", "order": 1}})
            if "m365copilot" in apps:
                P.p["warnings"].append("Microsoft 365 Copilot also needs WebSocket inspection: ask Zscaler Support to enable it for the tenant.")
    # 7. GenAI prompt capture
    if _bool(spec, "prompt_capture"):
        say("Reading the subscriptions and the URL and Cloud App Control settings…")
        lic, _ids, lerr = ag.read_subscriptions(z)
        settings, complete, aerr = ag.read_app_settings(z)
        fields = [ag.APPS_BY_ID[a]["prompt"] for a in apps if ag.APPS_BY_ID[a]["prompt"]]
        if not lic:
            P.unit("prompt", "url_app_settings", "GenAI prompt capture", status="excluded", field="prompt capture",
                   reason=f"the subscriptions could not be read ({lerr})" if lerr else "no Gen AI Security subscription on this tenant: left off")
        elif aerr or not complete:
            P.unit("prompt", "url_app_settings", "GenAI prompt capture", status="excluded", field="prompt capture",
                   reason=f"the settings could not be read ({aerr})" if aerr else "only part of the settings could be read, so they are not written back")
        else:
            have = [f for f in fields if f in settings]
            off = [f for f in have if settings.get(f) is not True]
            if not off:
                P.unit("prompt", "url_app_settings", "GenAI prompt capture", status="noop", field=", ".join(have) or "prompt capture",
                       reason="already on for the apps that have a switch" if have else "none of the picked apps has a prompt-capture switch here",
                       before="on", after="unchanged")
            else:
                cur = {f: settings.get(f) for f in off}
                P.unit("prompt", "url_app_settings", "GenAI prompt capture", field=", ".join(off), before="off", after="on",
                       step={"op": "update", "id": "settings", "set": {f: True for f in off}, "expect": cur, "restore": cur,
                             "check": {f: True for f in off}})
    ao._check_stop(cancel)
    # 8. the forwarding rule to the gateway
    say("Reading the forwarding rules…")
    fwd, fwerr = listing(client, "forwarding_rule")
    if fwerr:
        P.p["blockers"].append(f"The forwarding rules could not be read ({fwerr}).")
    exf = _by_name(fwd, "forwarding_rule", n["fwd"])
    if gw is None:
        P.unit("fwd", "forwarding_rule", n["fwd"], status="excluded", reason="waits for the proxy gateway (a portal step); preview again once it exists")
    else:
        gwref = {"id": gw_id, "name": name_of("proxy_gateway", gw)}
        want = {"state": "ENABLED", "forward_method": "PROXYCHAIN", "proxy_gateway": gwref, "dest_ip_groups": [{"id": gref}]}
        if exf is None:
            P.unit("fwd", "forwarding_rule", n["fwd"], before="not in ZIA", after=f"created at order 1: Proxy Chaining to {gwref['name']}",
                   depends=("group",),
                   step={"op": "create", "ref": "fwd",
                         "payload": {"name": n["fwd"], "type": "FORWARDING", "forwardMethod": "PROXYCHAIN", "state": "ENABLED", "rank": 7, "order": 1,
                                     "destIpGroups": [{"id": gref}], "proxyGateway": gwref, "description": _desc("Send GenAI apps to AI Guard.")},
                         "check": {"forward_method": "PROXYCHAIN", "proxy_gateway": gwref}})
        elif _same(exf, {k: v for k, v in want.items() if k != "dest_ip_groups"}) and str(group_id) in ag.ref_ids(ag.get(exf, "dest_ip_groups")):
            P.unit("fwd", "forwarding_rule", n["fwd"], status="noop", oid=ag.get(exf, "id"), reason="already chains the apps to the gateway",
                   before="Proxy Chaining", after="unchanged")
        else:
            cur = {k: ag.get(exf, k) for k in want}
            P.unit("fwd", "forwarding_rule", n["fwd"], oid=ag.get(exf, "id"), field=", ".join(want), depends=("group",),
                   before=f"{cur['forward_method']}, {cur['state']}", after=f"PROXYCHAIN to {gwref['name']}, ENABLED",
                   step={"op": "update", "id": ag.get(exf, "id"), "set": want, "expect": cur, "restore": cur,
                         "check": {"forward_method": "PROXYCHAIN", "proxy_gateway": gwref}})
    # 9. Allow in ZIA above Block, Caution or Isolate
    if _bool(spec, "allow_in_zia"):
        _plan_allow(client, P, n, apps, parts, say, cancel)
    P.p["warnings"].append("Then, in the AI Guard portal: " + " ".join(s.replace("In the AI Guard portal, ", "") for s in ag.PORTAL_STEPS[:2]))
    return P.p


_STOP_WEB_USE = re.compile(r"^(DENY|BLOCK|CAUTION|ISOLATE)_AI_ML_WEB_USE$")


def _plan_allow(client, P: _Plan, n: Dict[str, str], apps: List[str], parts: Dict[str, bool], say, cancel) -> None:
    z = client.zia
    cloud_apps = sorted({c for a in apps for c in ag.APPS_BY_ID[a]["cloud_apps"]})
    # Cloud App Control
    if not parts["cac"]:
        P.unit("allow", "cac_rule", n["allow"], status="excluded",
               reason="not in scope: Cloud App Control is not marked as run on Zscaler on the Scope page, so it is not read or changed")
    else:
        say("Reading the AI & ML Cloud App Control rules…")
        rules, err = listing(client, "cac_rule")
        if err:
            P.unit("allow", "cac_rule", n["allow"], status="excluded", reason=f"could not be read: {err}")
        else:
            ex = _by_name(rules, "cac_rule", n["allow"])
            stoppers = [r for r in rules if r is not ex and str(ag.get(r, "state") or "ENABLED").upper() != "DISABLED"
                        and any(_STOP_WEB_USE.match(str(a)) for a in ag.get(r, "actions") or [])
                        and (not ag.get(r, "applications") or set(map(str, ag.get(r, "applications"))) & set(cloud_apps))]
            want = {"state": "ENABLED", "actions": ["ALLOW_AI_ML_WEB_USE"], "applications": cloud_apps, "order": 1}
            if ex is None and not stoppers:
                P.unit("allow", "cac_rule", n["allow"], status="noop", reason="not needed: no Cloud App Control rule blocks, cautions or isolates these apps",
                       before="no stopper", after="nothing to add")
            elif ex is None:
                P.p["warnings"].append("Cloud App Control: " + ", ".join(name_of("cac_rule", r) for r in stoppers[:5])
                                       + " would stop the picked apps; the allow rule at order 1 lets them through first. Those rules still apply to every other AI app.")
                P.unit("allow", "cac_rule", n["allow"], before="not in ZIA", after=f"created at order 1: Allow web use for {len(cloud_apps)} app(s)",
                       step={"op": "create", "ref": "allow",
                             "payload": {"name": n["allow"], "type": "AI_ML", "order": 1, "rank": 7, "state": "ENABLED",
                                         "actions": ["ALLOW_AI_ML_WEB_USE"], "applications": cloud_apps,
                                         "description": _desc("Sanctioned GenAI apps reach AI Guard through ZIA inspection.")},
                             "check": {"state": "ENABLED", "actions": ["ALLOW_AI_ML_WEB_USE"], "applications": cloud_apps}})
            elif _same(ex, want):
                P.unit("allow", "cac_rule", n["allow"], status="noop", oid=ag.get(ex, "id"), reason="already allows the apps first", before="order 1", after="unchanged")
            else:
                cur = {k: ag.get(ex, k) for k in want}
                P.unit("allow", "cac_rule", n["allow"], oid=ag.get(ex, "id"), field=", ".join(want), before=f"order {cur['order']}, {cur['state']}",
                       after="order 1, ENABLED, Allow web use",
                       step={"op": "update", "id": ag.get(ex, "id"), "set": want, "expect": cur, "restore": cur, "check": want})
    ao._check_stop(cancel)
    # URL filtering: only when a Block, Caution or Isolate rule covers the apps' categories
    if not parts["url"]:
        return
    say("Looking up the apps' URL categories and reading the URL filtering rules…")
    hosts = sorted({d.lstrip(".") for a in apps for d in ag.APPS_BY_ID[a]["domains"]})
    looked, lerr = ag.rows(ag._call(lambda: z.url_categories.lookup(hosts)))
    rules, rerr = listing(client, "url_rule")
    if lerr or rerr:
        P.unit("allow_url", "url_rule", n["allow_url"], status="excluded", reason=f"could not be planned: {lerr or rerr}")
        return
    cats = {str(c) for r in looked for c in (ag.get(r, "url_classifications") or [])}
    ex = _by_name(rules, "url_rule", n["allow_url"])
    hits = [r for r in rules if r is not ex and str(ag.get(r, "state") or "ENABLED").upper() != "DISABLED"
            and str(ag.get(r, "action") or "").upper() in ("BLOCK", "CAUTION", "ISOLATE")
            and set(map(str, ag.get(r, "url_categories") or [])) & cats]
    if ex is None and not hits:
        P.unit("allow_url", "url_rule", n["allow_url"], status="noop", reason="not needed: no URL filtering rule blocks, cautions or isolates these apps",
               before="no stopper", after="nothing to add")
        return
    customs, cerr = listing(client, "url_category")
    if cerr:
        P.unit("allow_url", "url_rule", n["allow_url"], status="excluded", reason=f"the custom URL categories could not be read: {cerr}")
        return
    if hits:
        P.p["warnings"].append("URL filtering: " + ", ".join(f"{name_of('url_rule', r)} ({ag.get(r, 'action')})" for r in hits[:5])
                               + " cover the apps' categories; the allow rule at order 1 lets the picked apps through first.")
    urls = sorted(ag.domains_for(apps))
    cat = _by_name(customs, "url_category", n["allow_url"])
    cat_id = ag.get(cat, "id") if cat else None
    if cat is None:
        P.unit("allow_cat", "url_category", n["allow_url"], before="not in ZIA", after=f"created: {len(urls)} domains",
               step={"op": "create", "ref": "allow_cat",
                     "payload": {"configured_name": n["allow_url"], "super_category": "USER_DEFINED", "custom_category": True, "urls": urls,
                                 "description": _desc("Sanctioned GenAI apps (AI Guard).")},
                     "check": {"urls": urls}})
    elif canon(ag.get(cat, "urls") or []) != canon(urls):
        have = ag.get(cat, "urls") or []
        P.unit("allow_cat", "url_category", n["allow_url"], oid=cat_id, field="urls", before=f"{len(have)} URLs", after=f"{len(urls)} URLs",
               step={"op": "update", "id": cat_id, "set": {"urls": urls}, "expect": {"urls": have}, "restore": {"urls": have}, "check": {"urls": urls}})
    else:
        P.unit("allow_cat", "url_category", n["allow_url"], status="noop", oid=cat_id, reason="already lists the apps' domains", before="listed", after="unchanged")
    cref = cat_id if cat_id is not None else _ref("allow_cat")
    want = {"state": "ENABLED", "action": "ALLOW", "order": 1, "url_categories": [cref]}
    if ex is None:
        P.unit("allow_url", "url_rule", n["allow_url"], before="not in ZIA", after="created at order 1: Allow", depends=("allow_cat",),
               step={"op": "create", "ref": "allow_url",
                     "payload": {"name": n["allow_url"], "order": 1, "rank": 7, "state": "ENABLED", "action": "ALLOW", "urlCategories": [cref],
                                 "protocols": ["ANY_RULE"], "description": _desc("Allow the sanctioned GenAI apps; AI Guard inspects them.")},
                     "check": {"state": "ENABLED", "action": "ALLOW", "order": 1}})
    elif cat_id is not None and _same(ex, want):
        P.unit("allow_url", "url_rule", n["allow_url"], status="noop", oid=ag.get(ex, "id"), reason="already allows the apps first", before="order 1", after="unchanged")
    else:
        cur = {k: ag.get(ex, k) for k in want}
        P.unit("allow_url", "url_rule", n["allow_url"], oid=ag.get(ex, "id"), field=", ".join(want), depends=("allow_cat",),
               before=f"order {cur['order']}, {cur['action']}", after="order 1, ALLOW",
               step={"op": "update", "id": ag.get(ex, "id"), "set": want, "expect": cur, "restore": cur, "check": {"state": "ENABLED", "action": "ALLOW", "order": 1}})


# ── the detection policy ─────────────────────────────────────────────────
def build_policy(name: str, profile: str, mode: str) -> Dict[str, Any]:
    """The detection policy body for a compliance profile. Monitor detects
    everything and blocks nothing; Block blocks the profile's identifiers
    and the attacks (prompt injection, malicious URLs, invisible text)."""
    P = ag.PROFILES[profile]
    block = mode == "block"
    ents = [{"entityType": t, "action": ("BLOCK" if block else "DETECT") if t in P["block"] else ("DETECT" if t in P["detect"] else "DISABLE")}
            for t in ag.PII_ENTITIES]
    pii = {"detector": "pii", "enabled": True, "severity": "CRITICAL",
           "configuration": {"entities": ents, "threshold": 0.8, "anonymization": "NONE", "defaultAction": "ALLOW", "replaceWithMaskedContent": False}}

    def det(d: str, action: str, threshold: float, severity: str = "HIGH") -> Dict[str, Any]:
        return {"detector": d, "enabled": True, "severity": severity, "configuration": {"action": action, "threshold": threshold}}
    attack = "BLOCK" if block else "DETECT"
    inp = [det("prompt_injection", attack, 0.75, "CRITICAL"), det("malicious_url", attack, 0.8, "CRITICAL"), det("invisible_text", attack, 0.8),
           det("toxicity", "DETECT", 0.87, "LOW"), pii]
    out = [det("malicious_url", attack, 0.8, "CRITICAL"), det("toxicity", "DETECT", 0.87, "LOW"), dict(pii, severity="HIGH")]
    if P["deep"]:
        inp += [det("pii_deepscan", "BLOCK" if block else "DETECT", 0.87), det("personal_data", "DETECT", 0.8, "LOW")]
        out += [det("pii_deepscan", "DETECT", 0.87, "LOW")]
    return {"name": name, "description": f"{P['name']}, {'Block' if block else 'Monitor'} mode.",
            "inputDetectorPolicies": inp, "outputDetectorPolicies": out}


def _plan_policy(client, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    if spec.get("action") == "undo":
        return _plan_undo(client, spec, POLICY, "aiguard", say, cancel)
    profile = str(spec.get("profile") or "").strip().upper()
    if profile not in ag.PROFILES:
        raise ao.OperationError(f"Pick a compliance profile: {', '.join(ag.PROFILES)}.")
    mode = str(spec.get("mode") or "monitor").strip().lower()
    if mode not in ag.MODES:
        raise ao.OperationError("mode must be 'monitor' (detect only, the default) or 'block'.")
    prefix, apps = _prefix(spec), _apps(spec)
    n = names(prefix)
    svc, why = ag.aiguard_service(client)
    if svc is None:
        raise ao.OperationError(why)
    P = _Plan(POLICY, "aiguard", f"AI Guard detection policy: {ag.PROFILES[profile]['name']}, {mode.capitalize()}", spec)
    P.p["apply_note"] = "AI Guard applies each change as it is saved; there is no activation step."
    say("Reading AI Guard: detection policies, policy match rules and LLM providers…")
    got = ag.read_aiguard(svc)
    if got["policies"][1]:
        raise ao.OperationError(ag.classify_aiguard_error(got["policies"][1]))
    for k in ("rules", "providers"):
        if got[k][1]:
            P.p["blockers"].append(f"AI Guard's {k} could not be read ({got[k][1]}).")
    ao._check_stop(cancel)
    want = build_policy(n["policy"], profile, mode)
    ex = _by_name(got["policies"][0], "aiguard_policy", n["policy"])
    pid: Any = None
    if ex is None:
        P.unit("policy", "aiguard_policy", n["policy"], before="not in AI Guard", after=f"created: {ag.PROFILES[profile]['name']}, {mode}",
               step={"op": "create", "ref": "policy", "payload": want,
                     "check": {"input_detector_policies": want["inputDetectorPolicies"], "output_detector_policies": want["outputDetectorPolicies"]}})
    else:
        pid = ag.get(ex, "id")
        full, ferr = fetch(client, "aiguard_policy", pid)
        if full is None:
            P.p["blockers"].append(f"The existing policy {n['policy']} could not be read in full ({ferr}).")
            full = ex
        cur = {"input_detector_policies": ag.get(full, "input_detector_policies") or [], "output_detector_policies": ag.get(full, "output_detector_policies") or [],
               "description": ag.get(full, "description") or ""}
        setv = {"input_detector_policies": want["inputDetectorPolicies"], "output_detector_policies": want["outputDetectorPolicies"],
                "description": want["description"]}
        if _same(full, {k: v for k, v in setv.items() if k != "description"}):
            P.unit("policy", "aiguard_policy", n["policy"], status="noop", oid=pid, reason="already matches the profile and mode", before="as asked", after="unchanged")
        else:
            P.unit("policy", "aiguard_policy", n["policy"], oid=pid, field="detectors", before="other detectors", after=f"{ag.PROFILES[profile]['name']}, {mode}",
                   step={"op": "update", "id": pid, "set": setv, "expect": {k: cur[k] for k in ("input_detector_policies", "output_detector_policies")},
                         "restore": cur, "check": {k: setv[k] for k in ("input_detector_policies", "output_detector_policies")}})
    pref = pid if pid is not None else _ref("policy")
    # the match rule: the apps' LLM providers, after the tenant's own rules
    known = {str(ag.get(p, "name")) for p in got["providers"][0]}
    wanted = [p for a in apps for p in ag.APPS_BY_ID[a]["providers"]]
    prov = [p for p in dict.fromkeys(wanted) if p in known]
    rules = got["rules"][0]
    exr = _by_name(rules, "aiguard_rule", n["policy_rule"])
    if not prov:
        P.unit("rule", "aiguard_rule", n["policy_rule"], status="excluded",
               reason="none of the picked apps has an LLM provider in AI Guard, so no rule can match them")
    else:
        mc = {"type": "APPLICATION", "llmProviders": [{"llmProvider": p, "llmProviderModels": []} for p in prov], "llmApplications": [],
              "sourceIpAddresses": [], "applicationGroups": [], "customRequestHeaders": []}
        others = [r for r in rules if r is not exr and ag.get(r, "enabled") is not False
                  and {str(ag.get(x, "llm_provider")) for x in (ag.get(r, "match_criteria.llm_providers") or [])} & set(prov)]
        if others:
            P.p["warnings"].append("AI Guard: " + ", ".join(name_of("aiguard_rule", r) for r in others[:5])
                                   + " already match some of these providers and come first; the new rule is added after the existing rules.")
        order = max([ao._int(ag.get(r, "rule_order"), 0) for r in rules if r is not exr] or [0]) + 1
        setv = {"policy_id": pref, "enabled": True, "match_criteria": mc}
        if exr is None:
            P.unit("rule", "aiguard_rule", n["policy_rule"], before="not in AI Guard", after=f"created at order {order}: {len(prov)} provider(s)",
                   depends=("policy",),
                   step={"op": "create", "ref": "rule", "payload": {"policyId": pref, "name": n["policy_rule"], "enabled": True, "ruleOrder": order,
                                                                    "matchCriteria": mc},
                         "check": {"policy_id": pref, "enabled": True}})
        elif _same(exr, setv):
            P.unit("rule", "aiguard_rule", n["policy_rule"], status="noop", oid=ag.get(exr, "id"), reason="already matches the providers", before="as asked", after="unchanged")
        else:
            cur = {k: ag.get(exr, k) for k in setv}
            P.unit("rule", "aiguard_rule", n["policy_rule"], oid=ag.get(exr, "id"), field="policy, enabled, providers", depends=("policy",),
                   before="other providers or policy", after=f"{len(prov)} provider(s) to {n['policy']}",
                   step={"op": "update", "id": ag.get(exr, "id"), "set": setv, "expect": cur, "restore": cur, "check": {"policy_id": pref, "enabled": True}})
    if mode == "monitor":
        P.p["notes"].append("Monitor mode: AI Guard detects and logs; nothing is blocked. Preview again with Block once the detections look right.")
    P.p["warnings"].append("In the AI Guard portal, Tenant Settings > Security: turn on Store Prompts/Responses to see what was detected.")
    return P.p


# ── Undo ─────────────────────────────────────────────────────────────────
def _undo_steps(spec: Dict[str, Any], product: str) -> List[Dict[str, Any]]:
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_UNDO_STEPS:
        raise ao.OperationError(f"An Undo lists 1 to {MAX_UNDO_STEPS} steps.")
    out = []
    for s in steps:
        if not isinstance(s, dict):
            raise ao.OperationError("Each Undo step must be an object.")
        kind, op, name = str(s.get("kind") or ""), str(s.get("op") or ""), str(s.get("name") or "")
        if kind not in KINDS or not KINDS[kind]["ops"] or KINDS[kind]["product"] != product or op not in ("delete", "update"):
            raise ao.OperationError("An Undo step names an object this builder does not change.")
        if not _ID.match(str(s.get("id") or "")) or not name or len(name) > 128:
            raise ao.OperationError("An Undo step needs the object's id and name.")
        if op == "delete" and MARK not in name:
            raise ao.OperationError(f"An Undo deletes only objects this builder created (their names carry {MARK}).")
        if op == "update":
            setv, expect = s.get("set"), s.get("expect")
            if not isinstance(setv, dict) or not isinstance(expect, dict) or not setv:
                raise ao.OperationError("An Undo update needs the fields to put back and their current values.")
            allowed = KINDS[kind]["fields"]
            bad = [k for k in list(setv) + list(expect)
                   if not (str(k).split(".")[0] in allowed or ("*Prompt" in allowed and re.fullmatch(r"enable\w+Prompt", str(k))))]
            if bad:
                raise ao.OperationError(f"An Undo may put back only the fields this builder changes ({', '.join(bad[:3])[:120]} is not one).")
        out.append({"kind": kind, "op": op, "id": s.get("id"), "name": name, "set": s.get("set") or {}, "expect": s.get("expect") or {}})
    return out


def _plan_undo(client, spec: Dict[str, Any], type_name: str, product: str, say, cancel) -> Dict[str, Any]:
    steps = _undo_steps(spec, product)
    P = _Plan(type_name, product, f"Undo: {len(steps)} AI Guard change(s)", spec)
    if product == "aiguard":
        svc, why = ag.aiguard_service(client)
        if svc is None:
            raise ao.OperationError(why)
        P.p["apply_note"] = "AI Guard applies each change as it is saved; there is no activation step."
    say("Reading each object the Undo touches…")
    for i, s in enumerate(steps):
        ao._check_stop(cancel)
        key = f"u{i}"
        fresh, err = fetch(client, s["kind"], s["id"])
        if s["op"] == "delete":
            if fresh is None:
                P.unit(key, s["kind"], s["name"], status="noop", oid=s["id"], reason="already gone" if err == "not found" else f"could not be read: {err}",
                       before="gone", after="gone")
            elif name_of(s["kind"], fresh) != s["name"]:
                P.unit(key, s["kind"], s["name"], status="excluded", oid=s["id"], reason=f"renamed since ({name_of(s['kind'], fresh)}): kept")
            else:
                P.unit(key, s["kind"], s["name"], oid=s["id"], before="in the tenant", after="deleted",
                       step={"op": "delete", "id": s["id"], "expect": {}})
        else:
            if fresh is None:
                P.unit(key, s["kind"], s["name"], status="excluded", oid=s["id"], field=", ".join(s["set"]), reason=f"could not be read: {err}")
            elif _same(fresh, s["expect"]):
                P.unit(key, s["kind"], s["name"], oid=s["id"], field=", ".join(s["set"]), before="as the change left it", after="put back",
                       step={"op": "update", "id": s["id"], "set": s["set"], "expect": s["expect"], "restore": s["expect"], "check": s["set"]})
            elif _same(fresh, s["set"]):
                P.unit(key, s["kind"], s["name"], status="noop", oid=s["id"], field=", ".join(s["set"]), reason="already as before", before="as before", after="unchanged")
            else:
                P.unit(key, s["kind"], s["name"], status="excluded", oid=s["id"], field=", ".join(s["set"]),
                       reason="changed by someone else since: left as it is")
    return P.p


# ── the write ────────────────────────────────────────────────────────────
def _body(kind: str, fresh: Dict[str, Any], setv: Dict[str, Any]) -> Dict[str, Any]:
    """The object as the API takes it back, with only `setv` changed."""
    if kind == "url_app_settings":
        body = dict(fresh)
    else:
        import proposal_apply
        body = proposal_apply._body_from(fresh)
        for k in _BOOKKEEPING:
            body.pop(k, None)
    for k, v in setv.items():
        if kind != "url_app_settings":
            for alt in (ag._camel(k),):
                if alt != k:
                    body.pop(alt, None)
        body[k] = v
    if kind == "cac_rule":
        body["type"] = "AI_ML"
    if kind in ("firewall_rule", "ssl_rule", "forwarding_rule", "cac_rule", "url_rule"):
        body.pop("enabled", None)
    return body


def _root(run, kind: str) -> Any:
    return _aig(run.client) if KINDS[kind]["product"] == "aiguard" else run.client.zia


def _not_read(run, units, err: Optional[str], what: str) -> None:
    halt = ao._read_halt(err)
    if halt:
        run.halt = halt
        run.mark(units, "skipped", f"not attempted: {halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again before the change: {err}")
        run.counts["failed"] += 1


def _h_step(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    kind, op, name = t["kind"], t["op"], t["name"]
    info = KINDS[kind]
    ids: Dict[str, Any] = run.__dict__.setdefault("aig_ids", {})
    try:
        payload, setv, expect = (_resolve(t.get(k) or {}, ids) for k in ("payload", "set", "expect"))
    except KeyError as e:
        run.mark(units, "skipped", f"not attempted: it needs {e.args[0]}, which was not created")
        return
    u = units[0]
    root = _root(run, kind)
    common = {"channel": info.get("channel"), "name": name, "log": run.log}
    if op == "create":
        have, err = listing(run.client, kind)
        if err:
            _not_read(run, units, err, f"the {info['label'].lower()}s")
            return
        if _by_name(have, kind, name):
            run.mark(units, "conflict", f"a {info['label'].lower()} named {name} now exists (made since the preview); nothing was created")
            return
        if "description" in payload and run.assessor:
            payload["description"] = f"{payload['description']} By {run.assessor}."[:255]
        out = ops.create(root, info["ops"], payload, **common)
        if run.outcome(units, out, "create"):
            oid = out.id if out.id is not None else ag.get(out.data if isinstance(out.data, dict) else ag._plain(out.data), "id")
            if t.get("ref"):
                ids[t["ref"]] = oid
            u["object"] = dict(u["object"], id=oid)
            u["check"] = _resolve(t.get("check") or {}, ids)
            u["undo"] = {"kind": kind, "op": "delete", "id": oid, "name": name}
    else:
        oid = t.get("id")
        fresh, err = fetch(run.client, kind, oid)
        if fresh is None:
            if op == "delete" and err == "not found":
                run.mark(units, "noop", "already gone")
                return
            _not_read(run, units, err, f"the {info['label'].lower()}")
            return
        if op == "delete":
            if name_of(kind, fresh) != name:
                run.mark(units, "conflict", f"renamed since the preview ({name_of(kind, fresh)}): kept")
                return
            out = ops.delete(root, {"kind": info["ops"], "id": oid, "name": name, "channel": info.get("channel"), "type": "AI_ML" if kind == "cac_rule" else None},
                             log=run.log)
            run.outcome(units, out, "delete")
        else:
            if not _same(fresh, expect):
                run.mark(units, "conflict", f"changed in the tenant since the preview ({u['field']}); left as it is")
                return
            out = ops.update(root, info["ops"], oid if kind != "url_app_settings" else None, _body(kind, fresh, setv), **common)
            if run.outcome(units, out, "update"):
                if t.get("ref"):
                    ids[t["ref"]] = oid
                u["check"] = _resolve(t.get("check") or {}, ids)
                u["undo"] = {"kind": kind, "op": "update", "id": oid, "name": name, "set": t.get("restore") or {}, "expect": u["check"]}
    if u["status"] == "applied" and info["product"] == "zia":
        run.wrote_zia = True


def _verify(run) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    targets = {g["key"]: g["target"] for g in run.p["groups"]}
    for u in run.p["items"]:
        if u["status"] != "applied":
            continue
        t = targets.get(u["group"]) or {}
        out["checked"] += 1
        oid = u["object"].get("id") if t.get("op") == "create" else t.get("id")
        row, err = fetch(run.client, t.get("kind"), oid)
        if t.get("op") == "delete":
            ok = row is None and err == "not found"
            if row is None and not ok:
                out["unread"].append(f"{t.get('name')}: {err}")
                u["verified"] = None
                continue
        elif row is None:
            out["unread"].append(f"{t.get('name')}: {err}")
            u["verified"] = None
            continue
        else:
            ok = _same(row, u.get("check") or {}) and (t.get("op") != "create" or name_of(t["kind"], row) == t.get("name"))
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{t.get('name')}: not as written when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Delete what the run created and put back the fields it changed, newest first."""
    if (result.get("spec") or {}).get("action") == "undo":
        return None
    steps = [u["undo"] for u in reversed(result.get("items") or []) if u.get("status") == "applied" and u.get("undo")]
    return {"type": result.get("type"), "action": "undo", "steps": steps} if steps else None


# ── what the page picks from ─────────────────────────────────────────────
def _objects_routing(client, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    parts = _scope_parts(scope)
    rd = ag.readiness(client, zia=True, aiguard=parts["aiguard"], log=say, cancel=cancel)
    return {"catalog": ag.catalog(), "readiness": rd, "certificates": rd["zia"]["certificates"], "proxies": rd["zia"]["proxies"],
            "gateways": rd["zia"]["gateways"], "genai_licensed": rd["zia"]["genai_licensed"], "names": names(""),
            "in_scope": {"ssl_inspection": parts["ssl"], "cloud_app_control": parts["cac"]}}


def _objects_policy(client, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    rd = ag.readiness(client, zia=False, aiguard=True, log=say, cancel=cancel)
    return {"catalog": ag.catalog(), "readiness": rd, "policies": rd["aiguard"]["policies"], "rules": rd["aiguard"]["rules"],
            "providers": rd["aiguard"]["providers"], "names": names("")}


ao.register(ROUTING, family="aiguard_routing_setup", product="zia", label="AI Guard routing for GenAI apps",
            hint="Send ChatGPT, Microsoft 365 Copilot, Claude, Gemini and other GenAI apps through Zscaler AI Guard: root certificate, proxy, "
                 "forwarding rule, QUIC block, SSL Inspect on top, prompt capture and Allow in ZIA. Needs ZIA platform and AI Guard ticked.",
            in_scope=_in_scope_routing, plan=_plan_routing, read_objects=_objects_routing, handlers={HANDLER: _h_step},
            verify=_verify, inverse=_inverse, script="ops_aiguard.js")
ao.register(POLICY, family="aiguard_policy_setup", product="aiguard", label="AI Guard detection policy",
            hint="Turn a compliance profile (HIPAA, HITRUST, PCI, GDPR, CJIS, FERPA, SOX, general) into an AI Guard detection policy and a "
                 "match rule for the GenAI apps. Monitor (detect only) by default. Needs AI Guard ticked.",
            in_scope=_in_scope_policy, plan=_plan_policy, read_objects=_objects_policy, handlers={HANDLER: _h_step},
            verify=_verify, inverse=_inverse, script="ops_aiguard.js")
