"""An example local plugin for Zscaler Made Easy (not loaded by default).

Copy this folder into the folder DLP_CHECK_PLUGINS_DIR names, switch local
plugins on in Advanced settings, review this code, and approve its SHA-256
there. It then adds:

* a read-only page listing the Bulk changes operation types; and
* an operation that disables the Cloud Firewall rules whose name starts
  with a given prefix. It is planned with the read-only client the app
  hands over, previewed with a plan hash, and applied only through the
  app's gates; its handler writes through run.update, never the SDK.
"""


def _page():
    import admin_ops
    return {"columns": ["Operation type", "Product"],
            "rows": [[t, admin_ops.product_of(t)] for t in admin_ops.types()],
            "notes": ["Read from the app itself; nothing is read from a tenant."]}


def _rows(ret):
    data = ret[0] if isinstance(ret, tuple) else ret
    out = []
    for r in data or []:
        out.append(r if isinstance(r, dict) else (r.as_dict() if hasattr(r, "as_dict") else {}))
    return out


def _plan(client, spec, scope, say, cancel):
    import admin_ops
    prefix = str((spec or {}).get("name_prefix") or "").strip()
    if len(prefix) < 3:
        raise admin_ops.OperationError("Give a rule name prefix of at least 3 characters.")
    say("Reading the Cloud Firewall rules…")
    rows = _rows(client.zia.cloud_firewall_rules.list_rules())
    items, groups = [], []
    for r in rows:
        name = str(r.get("name") or "")
        if not name.startswith(prefix) or r.get("default_rule") or r.get("predefined"):
            continue
        key = f"rule:{r.get('id')}"
        obj = {"type": "firewall_rule", "id": r.get("id"), "name": name}
        if str(r.get("state") or "ENABLED") == "DISABLED":
            items.append(admin_ops._unit(key, key, "rule", obj, "state", "DISABLED", "DISABLED", status="noop", reason="already disabled"))
            continue
        items.append(admin_ops._unit(key, key, "rule", obj, "state", "ENABLED", "DISABLED", reason="Disables it."))
        groups.append({"key": key, "handler": "disable", "target": {"id": r.get("id"), "name": name}})
    return {"type": "plugin_example_rule_counter_disable", "title": f"Disable Cloud Firewall rules named {prefix}…",
            "spec": {"type": "plugin_example_rule_counter_disable", "name_prefix": prefix}, "items": items, "groups": groups,
            "warnings": [], "blockers": []}


def _objects(client, scope, say, cancel):
    return {"status": "done", "note": "Type a rule name prefix; the preview lists the rules it matches."}


def _disable(run, g, units):
    t = g["target"]
    fresh = _rows([run.zia.cloud_firewall_rules.get_rule(t["id"])[0]])
    if not fresh or str(fresh[0].get("state") or "ENABLED") != "ENABLED":
        run.mark(units, "conflict", "changed since the preview; left as it is")
        return
    body = {k: v for k, v in fresh[0].items() if k not in ("id",)}
    body["state"] = "DISABLED"
    out = run.update("policy", t["id"], body, name=t["name"], channel="firewall")
    run.outcome(units, out, "update")


def register(api):
    api.add_page("operations", title="Operation types (example plugin)", render=_page)
    api.add_operation("disable", label="Disable firewall rules by name (example)", product="zia",
                      hint="Example plugin: disable the Cloud Firewall rules whose name starts with a prefix.",
                      plan=_plan, read_objects=_objects, handlers={"disable": _disable})
