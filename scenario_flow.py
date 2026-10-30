"""Pure scenario/evidence model. No network, tenant writes, caching or traffic.

The API handler explicitly composes independently requested reads; this module
only joins evidence from that one run. A local corpus never becomes a live event.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

CHANNELS = {"web": ("web_dlp", "/zia/webDlpRules", "Inline Web DLP"),
            "endpoint": ("endpoint_dlp", "/zia/endPointDlpRules", "Endpoint DLP"),
            "email": ("email_dlp", "/zia/emailDlpRules", "Email DLP"),
            "saas": ("saas_casb", "/zia/casbDlpRules/all", "SaaS API DLP")}
CONTROLS = (("url", "URL filtering"), ("ssl", "SSL inspection"), ("ftc", "File Type Control"), ("cac", "Cloud App Control"))


def normalize_input(raw):
    channel = str(raw.get("channel") or "web").lower()
    if channel not in CHANNELS:
        raise ValueError("Choose web, endpoint, email or saas as the tested channel")
    network = str(raw.get("network") or "off").lower()
    platform = str(raw.get("platform") or "windows").lower()
    if network not in ("off", "on", "vpn"):
        raise ValueError("Network must be off, on or vpn")
    if platform not in ("windows", "macos", "ios", "android", "linux"):
        raise ValueError("Unsupported device platform")
    out = {"channel": channel, "network": network, "platform": platform}
    for key, limit in (("destination", 2048), ("operation", 80), ("file_type", 120), ("scenario_id", 100)):
        value = raw.get(key) or ""
        if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value):  # C0, DEL, C1
            raise ValueError("Invalid " + key)
        out[key] = value.strip()
    corpus = raw.get("corpus") or ""
    if not isinstance(corpus, str) or len(corpus.encode("utf-8")) > 256 * 1024:
        raise ValueError("Test content must be text of at most 256 KB")
    out["corpus"] = corpus
    return out


def scope_key(scopes, channels):
    return hashlib.sha256(json.dumps({"scopes": sorted(set(scopes)), "channels": channels}, sort_keys=True).encode()).hexdigest()[:24]


def build_result(context, *, tenant_key, scope, corpus=None, path=None, rules_evidence=None, read_at=None):
    """One-run graph; configuration, simulation and observation never conflated."""
    at = read_at or datetime.now(timezone.utc).isoformat()
    channel = context["channel"]
    read = set(scope.get("read") or [])
    enabled = scope.get("channel_enabled", False)
    corpus = corpus or None
    simulated = bool(context.get("corpus", "").strip())
    scenario = {"id": context.get("scenario_id") or uuid.uuid4().hex,
                "tenant_key": tenant_key, "scope_key": scope.get("key", ""),
                "configuration_id": uuid.uuid4().hex, "mode": "simulated" if simulated else "configuration",
                **{k: context[k] for k in ("channel", "destination", "operation", "file_type", "network", "platform")}}
    scenario["scenario_id"] = scenario["id"]
    stages = []
    limitations = ["Configuration predicts candidate paths; it does not observe a transaction.",
                   "Test content is evaluated locally and is never sent as tenant traffic or counted as a Workflow Automation incident."]
    errors = list((corpus or {}).get("errors") or [])
    required_controls = list(scope.get("required_controls") or [])
    required = {row["key"]: row for row in required_controls}

    def stage(key, label, status, detail, source="scenario", obj=None, evidence_status=None):
        obj = obj or {}
        item = {"key": key, "label": label, "status": status, "detail": detail,
                "object_id": obj.get("id"), "object_name": obj.get("name"),
                "source": source, "read_at": at, "channel": channel,
                "evidence_status": evidence_status or ("configuration" if status in ("pass", "configured", "candidate", "conditional") else status)}
        stages.append(item)
        return item

    stage("channel", "Tested channel: " + CHANNELS[channel][2], "configured", "Operation: " + (context.get("operation") or "not specified"))
    trace = (path or {}).get("trace") or {}
    if channel == "web":
        for hop in trace.get("hops", []):
            if hop.get("key") in ("dlp", "incident"):
                continue
            item = stage(hop.get("key", "unknown"), hop.get("label", "Control"), hop.get("status", "unverified"),
                         hop.get("detail", ""), "tenant configuration", hop.get("decided_by"))
            if item["key"] in required and item["status"] == "out_of_scope":
                item.update(status="unverified", evidence_status="unverified", detail=required[item["key"]]["detail"])
            if hop.get("stopped_by"):
                item["stopped_by"] = hop["stopped_by"]
        keys = {s["key"] for s in stages}
        for key, label in CONTROLS:
            if key not in keys:
                status = "unverified" if key in required else "out_of_scope" if key not in read else "unverified"
                stage(key, label, status, required.get(key, {}).get("detail") or ("Not read in the current scope" if status == "out_of_scope" else "Destination/path context has not been established"))
    else:
        # An applicability panel, not fake inline enforcement on non-web data.
        for key, label in CONTROLS:
            stage(key, label, "not_applicable", "Inline web control is not an enforcement hop of the selected " + channel + " channel")
        details = {"endpoint": "Device policy delivery, assignment and intercepted activity require device evidence",
                   "email": "Connector, per-recipient routing, verdict headers and mail-platform enforcement require separate evidence",
                   "saas": "Application onboarding, authorized scan configuration and at-rest scan progress require separate evidence"}
        stage("capture", CHANNELS[channel][2] + " capture", "unverified" if enabled else "out_of_scope", details[channel])

    stopped = next((s for s in stages if s["status"] in ("blocked", "bypass")), None)
    local = (corpus or {}).get("read_evidence") or {}
    engines = (corpus or {}).get("engines") or []
    dictionaries = {}
    for engine in engines:
        for dictionary in engine.get("dictionary_refs", []):
            dictionaries[str(dictionary["id"])] = dictionary
    for key, label in (("dictionaries", "Dictionaries: detectors and match counts"), ("engines", "Engines: Boolean expressions and thresholds")):
        ev = local.get(key) or {}
        status = "simulated" if simulated and ev.get("status") == "verified" else "configured" if ev.get("status") == "verified" else "unverified" if "dlp" in scope.get("scopes", []) else "out_of_scope"
        detail = ("Local content simulation, separate from the traffic path" if simulated else "Configuration references; no content was tested")
        if ev.get("status") == "unverified":
            detail = ev.get("reason", "Read unavailable")
        node = stage(key, label, "not_reached" if stopped else status, detail, ev.get("source", "DLP configuration"), evidence_status=status)
        if stopped:
            node["detail"] = "Traffic cannot reach this stage after " + stopped["label"] + ". " + detail
            node["stopped_by"] = {"key": stopped["key"], "label": stopped["label"]}
        node["objects"] = list(dictionaries.values()) if key == "dictionaries" else engines

    rules = (corpus or {}).get("rules") or []
    rev = rules_evidence or local.get("rules") or {}
    rule_status = "out_of_scope" if not enabled else "unverified" if rev.get("status") != "verified" else "conditional" if rules else "none"
    node = stage("rules", CHANNELS[channel][2] + " rules", "not_reached" if stopped else rule_status,
                 "Configured rule references with actual IDs and actions. Eligibility and final action are not proven by an engine match alone" if rules else rev.get("reason", "No readable applicable channel rules"), CHANNELS[channel][1])
    node["objects"] = rules
    stage("action", "Channel action", "not_reached" if stopped else "unverified", "No observed or fully evaluated channel action is claimed by this local test")
    forwarding = [r for r in rules if r.get("applicability") != "disabled" and r.get("incident_receiver")]
    stage("evidence", "Incident evidence forwarding", "not_reached" if stopped else "configured" if forwarding else "unverified",
          "Receiver enabled on candidate rule(s); delivery is not verified" if forwarding else "A receiver flag or ICAP server alone does not prove Workflow Automation delivery", "channel rule configuration")
    for key, label in (("storage", "Evidence storage"), ("storage_event", "Storage event"), ("integration", "Workflow Automation integration")):
        stage(key, label, "unverified", "Not verified by the available configuration reads; no successful delivery inferred")
    wa = "dlp" in scope.get("scopes", []) and scope.get("workflow_enabled", False)
    stage("workflow", "Workflow Automation incident", "unverified" if wa or "workflow" in required else "out_of_scope",
          required.get("workflow", {}).get("detail") or ("Use the separate observed feed; this test creates no incident" if wa else "Observed feed requires DLP and Workflow Automation in scope; simulation remains available"))
    if channel != "web":
        limitations.append("This channel's device/mailbox/application assignment and enforcement context is not available from the rule list alone.")
    if not context.get("destination") and channel == "web":
        limitations.append("Enter a destination to evaluate its configured web path.")
    if stopped and simulated:
        limitations.append("Local detector results are counterfactual: the selected traffic path stops before DLP.")
    if (corpus or {}).get("dictionary_limit_reached"):
        limitations.append("The custom dictionary limit was reached; omitted dictionary results remain unknown.")
    if simulated and "dlp" not in scope.get("scopes", []):
        execution_status = "out_of_scope"
        summary = "Test content was not evaluated because DLP is out of scope. Required controls remain visible with their evidence gaps."
    elif errors:
        execution_status = "partial"
        summary = "Analysis is incomplete because one or more configuration reads failed. Unknown results are not negative matches."
    elif simulated:
        execution_status = "complete"
        confirmed = sum(e.get("fires") is True for e in engines)
        unknown = sum(e.get("fires") is None for e in engines)
        summary = f"Local simulation: {confirmed} confirmed engine match(es), {unknown} unresolved engine(s). Live enforcement and Workflow Automation delivery are not verified."
    else:
        execution_status = "complete"
        summary = "Configuration analysis only. No test content was evaluated and no traffic or Workflow Automation incident was generated."
    return {"schema_version": 1, "scenario": scenario, "read_at": at, "stages": stages,
            "required_controls": required_controls, "corpus": corpus, "path": path, "rules": rules, "limitations": limitations, "errors": errors,
            "execution_status": execution_status, "summary": summary}
