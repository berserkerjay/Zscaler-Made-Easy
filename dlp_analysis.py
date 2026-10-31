"""Required controls for an explicitly requested DLP analysis.

This footprint never changes saved declarations, deployments or scheduled work.
Configuration inventory is not proof of traffic enforcement or incident delivery.
"""
from __future__ import annotations

from datetime import datetime, timezone
import md_safe
import channel_scope

CONTROLS = (
    ("url", "URL filtering", None, "/zia/urlFilteringRules"),
    ("ssl", "SSL/TLS Inspection", "ssl_inspection", "/zia/sslInspectionRules"),
    ("ftc", "File Type Control", None, "/zia/fileTypeRules"),
    ("cac", "Cloud App Control", "cloud_app_control", "/zia/cloudApplicationRules"),
    ("workflow", "Workflow Automation", "workflow_automation", None),
)
REQUIRED_CHANNELS = {cid for _, _, cid, _ in CONTROLS if cid}
NOTE = ("DLP analysis always includes SSL/TLS Inspection, URL filtering, File Type Control, "
        "Cloud App Control and Workflow Automation evidence. An unavailable or alternative-vendor "
        "control remains an explicit evidence gap, never an excluded control. Configuration reads "
        "do not prove enforcement or delivery; saved and deployment selections are unchanged.")


def active(scopes):
    return isinstance(scopes, (list, tuple, set)) and "dlp" in scopes


def channels(channels, scopes):
    """Analysis-only required channels; explicit other-vendor choices survive."""
    if not active(scopes):
        return channel_scope.resolve(channels)
    # Once DLP is selected, an omitted channel is a gap, not the legacy
    # no-declaration convention that permits every product.
    result = channel_scope.effective(channels)
    for cid, name in channel_scope.CHANNELS.items():
        result.setdefault(cid, {"choice": "gap", "note": "", "name": name})
    for cid in REQUIRED_CHANNELS:
        if result[cid]["choice"] != "alternative":
            result[cid] = dict(result[cid], choice="zscaler", required_for_dlp=True)
    return result


def requirements(scopes, declared, *, tested_channel=None):
    if not active(scopes):
        return []
    normalized = channel_scope.normalize(declared)
    rows = []
    for key, label, cid, endpoint in CONTROLS:
        alternative = cid and normalized.get(cid, {}).get("choice") == "alternative"
        detail = (f"Required DLP control. {label} is declared Alternative; its Zscaler configuration is not read. "
                  "Supply the other vendor's evidence or correct the declaration; the dependency is unmet."
                  if alternative else "Required DLP control; configuration and applicability have not yet been verified.")
        if key == "workflow" and not alternative:
            detail = "Required DLP evidence stage. Workflow integration and incident delivery are unverified; this local analysis does not poll or generate incidents."
        rows.append({"key": key, "label": label, "required": True, "status": "unverified", "detail": detail,
                     "source": endpoint or "Workflow Automation observed feed", "read_at": None,
                     "read_permitted": not bool(alternative), "declared": normalized.get(cid, {}).get("choice", "gap") if cid else "required",
                     "applicability": "not_applicable" if tested_channel not in (None, "web") and key != "workflow" else "required"})
    return rows


def read_control(client, row):
    import dlp_efficacy
    row = dict(row)
    if not row["read_permitted"] or row["key"] == "workflow":
        return row
    ev = dlp_efficacy.read_collection(client, row["source"])
    row["read_at"] = ev.get("read_at") or datetime.now(timezone.utc).isoformat()
    row["evidence_status"] = ev["status"]
    if ev["status"] != "verified":
        row["detail"] = "Required DLP control could not be verified: " + ev.get("reason", "configuration read failed")
        if ev.get("http_status"):
            row["detail"] += f" (HTTP {ev['http_status']})"
        return row
    row["status"] = "configured" if ev["items"] else "unverified"
    row["objects"] = [{k: value for k in ("id", "name", "action", "state") if (value := item.get(k)) is not None
                       and isinstance(value, (str, int, float, bool))} for item in ev["items"]]
    row["count"] = len(ev["items"])
    row["detail"] = (f"Read {len(ev['items'])} configured {row['label']} object(s). "
                     "This inventory does not establish traffic applicability or enforcement." if ev["items"] else
                     f"The {row['label']} configuration read succeeded but returned no objects. Coverage remains unverified.")
    return row


def inspect(client, scopes, declared, *, tested_channel=None):
    return [read_control(client, row) for row in requirements(scopes, declared, tested_channel=tested_channel)]


def assessment_checks(checks, declared, scopes):
    """Keep mandatory evidence gaps visible and guarantee its read footprint."""
    from dlp_assessment_full_auto import R
    resolved = channels(declared, scopes)
    if not active(scopes):
        run, hidden, _ = channel_scope.partition(checks, declared)
        return run, hidden, declared
    if not declared:
        resolved = {cid: {"choice": "zscaler", "note": "", "name": name} for cid, name in channel_scope.CHANNELS.items()}
    run, skipped, order = channel_scope.partition(checks, resolved)
    selected, hidden = [], []
    for kind, index in order:
        if kind == "run":
            selected.append(run[index])
            continue
        row = skipped[index]
        if row.get("channel") in REQUIRED_CHANNELS:
            detail = (f"Required DLP control: {row.get('channel')}. Alternative-vendor evidence is unavailable; "
                      "this dependency remains unverified and no excluded configuration was read.")
            selected.append((row["id"], row["section"], row["label"], lambda client, detail=detail: R(R.INFO, detail)))
        else:
            hidden.append(row)
    for row in requirements(scopes, declared):
        def check(client, row=row):
            evidence = read_control(client, row)
            return R(R.INFO, evidence["detail"], {"required_control": evidence})
        selected.append(("DLP.CTRL." + row["key"].upper(), "Required DLP controls", row["label"], check))
    return selected, hidden, resolved


# The first path segment of a read -> the scope that must be selected for it.
_SERVICE_SCOPE = {"zcc": "zcc", "zpa": "zpa", "zdx": "zdx", "zidentity": "zidentity", "zid": "zidentity", "ziam": "zidentity", "ztw": "ztw",
                  # The other products (other_products.py), each behind its own Scope page key.
                  "ztb": "ztb", "easm": "easm", "bi": "zbi", "zcell": "zcell", "zms": "zms"}
# Services whose reads may be sent as a POST (a Microsegmentation GraphQL
# query): the guard refuses that POST too when the service is not selected.
_POST_READ_SCOPES = frozenset({"zms"})


class ScopedClient(channel_scope.ScopedClient):
    """The analysis footprint never implicitly enables another service."""
    def __init__(self, client, declared, scopes):
        super().__init__(client, channels(declared, scopes))
        self._analysis_scopes = set(scopes or [])

    def get(self, ep, *args, **kwargs):
        path = str(ep or "").removeprefix("raw:")
        # The short ZIdentity paths are /zid/... and the resolved ones /ziam/...:
        # both belong to the ZIdentity scope.
        service = _SERVICE_SCOPE.get(path.lstrip("/").split("/", 1)[0])
        if service and service not in self._analysis_scopes:
            self.refused.append(path)
            rec = getattr(self._tl, "unanswered", None)
            if rec is not None:
                rec.append((path, 0))
            return {"error": "required evidence unavailable", "message": "This service was not selected; no request was sent."}, 0
        return super().get(ep, *args, **kwargs)

    def post(self, ep, *args, **kwargs):
        path = str(ep or "").removeprefix("raw:")
        service = path.lstrip("/").split("/", 1)[0]
        if service in _POST_READ_SCOPES and _SERVICE_SCOPE[service] not in self._analysis_scopes:
            self.refused.append(path)
            return {"error": "required evidence unavailable", "message": "This service was not selected; no request was sent."}, 0
        return self._client.post(ep, *args, **kwargs)


def markdown(report):
    rows = md_safe.escape_data(report.get("required_controls") or [])   # tenant-derived detail: inert text
    if not rows:
        return []
    return ["", "## Required DLP controls", NOTE, ""] + [
        f"- {r['label']} — {r['status']}: {r['detail']}" for r in rows]


class ReadOnce:
    """One request's four required collection reads, including refusals.

    No cross-request/tenant persistence; cancellation is checked even on hits.
    """
    def __init__(self, client):
        import threading
        self._client = client
        self._responses = {}
        self._lock = threading.RLock()

    def __getattr__(self, name):
        return getattr(self._client, name)

    def get(self, endpoint, *args, **kwargs):
        import copy
        import dlp_efficacy
        def check_stop():
            stop = getattr(self, "stop_check", None)
            if callable(stop) and stop():
                raise dlp_efficacy.CorpusReadStopped("Configuration read cancelled")
        check_stop()
        if endpoint not in {source for _, _, _, source in CONTROLS if source} or args or kwargs:
            return self._client.get(endpoint, *args, **kwargs)
        with self._lock:
            check_stop()
            if endpoint not in self._responses:
                try:
                    self._responses[endpoint] = copy.deepcopy(self._client.get(endpoint))
                except Exception as exc:
                    from data_flow import ReadStopped
                    if isinstance(exc, (dlp_efficacy.CorpusReadStopped, ReadStopped)):
                        raise
                    self._responses[endpoint] = ({"error": "Configuration read failed", "error_type": type(exc).__name__}, 0)
            return copy.deepcopy(self._responses[endpoint])


def read_once(client):
    return client if isinstance(client, ReadOnce) else ReadOnce(client)


def scope_key(scopes, declared):
    import hashlib
    import json
    return hashlib.sha256(json.dumps({"scopes": sorted(set(scopes or [])),
                                      "channels": channel_scope.normalize(declared)}, sort_keys=True).encode()).hexdigest()[:24]
