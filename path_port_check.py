"""Port and service check: "is this protocol and port blocked for everyone?"

The Path analyzer answers for one destination. This asks the question the
other way round: for a protocol and port alone, what does the Cloud
Firewall do to traffic to ANY destination from ANY source? It runs the
Cloud Firewall step of zia_path_modules over a tenant read that was
already fetched (a kept Path analyzer read), with a destination and a
source nobody knows. A rule that restricts the destination or the source
is therefore "unknown" for it, so only rules that apply to everyone can
settle the answer. Nothing is sent to a tenant and nothing is written.

Answers:
  blocked_for_everyone   a rule with no destination or source condition
                         blocks it and no earlier rule could change that;
  allowed_for_everyone   the same for allow;
  depends                a rule that is limited to some destinations or
                         sources (or a condition this tool cannot judge)
                         could decide it: the rules are named;
  not_read               the Cloud Firewall was not read (out of scope or
                         the read failed): nothing is claimed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import zia_path_modules as zpm

ANSWERS = ("blocked_for_everyone", "allowed_for_everyone", "depends", "not_read")


def _rule_names(items: List[Dict[str, Any]]) -> List[str]:
    return [f"{i.get('name')} ({i.get('action')})" for i in items if isinstance(i, dict)]


def check(zia: Optional[Dict[str, Any]], protocol: Any, port: Any) -> Dict[str, Any]:
    """Pure. `zia` is a kept tenant read's ZIA block (with `modules`).
    Raises ValueError, in a plain sentence, for a missing or invalid
    protocol or port."""
    if port in (None, ""):
        raise ValueError("Give a port from 1 to 65535.")
    traffic = zpm.traffic_context({"input": "", "host": ""}, protocol or "tcp", port)
    assumptions = [
        "Any destination and any source: a rule limited to some destinations, sources, users or locations cannot settle the answer, so it is listed instead.",
        f"Traffic reaches the Cloud Firewall (Z-Tunnel 2.0 or a site tunnel): {traffic['label']}.",
        "The Cloud Firewall as read now; nothing was sent to the tenant and nothing is written.",
    ]
    base = {"traffic": {k: traffic[k] for k in ("protocol", "port", "service", "label", "web")}, "assumptions": assumptions, "read_only": True}
    sec = ((zia or {}).get("modules") or {}).get("firewall") or {}
    if sec.get("state") not in ("read", "partial"):
        return dict(base, answer="not_read", rule=None, depends_on=[],
                    detail=sec.get("why") or "The Cloud Firewall was not read, so nothing is claimed about this port.")
    ctx = {"host": "", "ip": None, "dest": {"input": "", "host": ""}, "traffic": traffic, "visible": None, "source_ip": None,
           "categories": [], "alerts": [], "applications": [], "app_classes": [], "file_types": [], "dst_groups": None, "src_groups": None,
           "oneclick": None, "fw": {}, "dns_gateways": None, "app_list": None,
           "ranking": zia.get("admin_ranking") if isinstance(zia.get("admin_ranking"), dict) else None}
    res = zpm._firewall(ctx, sec)
    depends = _rule_names(res.get("could_override") or []) + _rule_names(res.get("overlaps") or [])
    rule = res.get("rule")
    if res["verdict"] in ("block", "allow") and res["certainty"] == "definite" and rule:
        answer = "allowed_for_everyone" if res["verdict"] == "allow" else "blocked_for_everyone"
        detail = f"{traffic['label']} is {'blocked' if res['verdict'] == 'block' else 'allowed'} for every destination and source by '{rule.get('name')}'."
    else:
        answer = "depends"
        detail = (f"{traffic['label']} is not decided for everyone: " + (res.get("reason") or res.get("detail") or "a rule limited to some destinations or sources decides it") if res["verdict"] != "unknown"
                  else f"{traffic['label']} is not decided: {res.get('detail')}")
    return dict(base, answer=answer, verdict=res["verdict"], certainty=res["certainty"], rule=rule, depends_on=depends, detail=detail,
                notes=list(res.get("notes") or []))
