"""Continuous evaluation, phase 5: run when asked, and it tells you.

One run of the loop, for every tenant profile that remembers its secret,
reading only what that profile's Scope page puts in scope (see
profile_scope): nothing in scope, nothing read.

  1. guidance     new library articles are mapped to checks and packs and
                  become proposals (guidance.py); stale sources are flagged;
                  the SaaS capability matrix is refreshed from Zscaler's pages;
  2. detection    (scope "dlp") FP/TP Detection Ratio is generated, its
                  findings become proposals in the tenant's queue, a compact
                  entry goes to the profile history;
  3. tenants      (channel SaaS Security on Zscaler) onboarded SaaS / email
                  tenants are read: which are not ACTIVE (re-authorise),
                  which DLP-capable applications are not onboarded, which
                  sit at the 16-tenant limit;
  4. drift        (scope "dlp") the journey is measured against the
                  profile's ticked packs, on the DLP channels the Scope page
                  puts on Zscaler only, and compared with the last stage;
  5. digest       everything new since the last run is written as one
                  digest (JSON + Markdown) and, when it is noteworthy, sent
                  by e-mail and/or to a Teams / Slack webhook.

Every tenant read counts against the ZIA API rate limit, so nothing runs
on its own by default. The same function runs when the operator clicks
Run the loop now (POST /api/digests/run), from the command line
(`python continuous_eval.py --once`, which a Windows scheduled task, cron
or a container can call), and from the server's timer only when the
operator opts in with DLP_CHECK_CONTINUOUS_EVAL_HOURS (unset or 0: off).
Nothing here writes to any tenant.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import smtplib
import ssl
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
DIGEST_DIRNAME = "digests"
KEEP_DIGESTS = 60
LogFn = Optional[Callable[[str], None]]


# The Scope page's channels that govern a pack's DLP channel
# (pack_channels.DLP_CHANNELS: web / endpoint / saas / email).
SCOPE_PACK_CHANNELS = {"web_dlp": "web", "endpoint_dlp": "endpoint", "saas_casb": "saas", "email_dlp": "email"}
SAAS_SCOPE_CHANNEL = "saas_casb"


# The opt-in timer's bounds. Every pass reads every in-scope tenant, so a
# typo such as 0.0001 must not turn it into a busy loop against the ZIA API
# rate limit; a value beyond a year (or one whose seconds overflow) is not a
# schedule either.
MIN_INTERVAL_HOURS = 1.0
MAX_INTERVAL_HOURS = 24.0 * 366


def interval_hours(*, warn: bool = True) -> float:
    """DLP_CHECK_CONTINUOUS_EVAL_HOURS as a number of hours; unset, blank,
    zero, negative, invalid or outside MIN_INTERVAL_HOURS..MAX_INTERVAL_HOURS
    is 0 (the server's timer is off), with a line in the log for a value
    that is not usable (warn=False reads it without logging)."""
    raw = (os.environ.get("DLP_CHECK_CONTINUOUS_EVAL_HOURS") or "").strip()
    if not raw:
        return 0.0
    shown = ascii(raw)   # ASCII only: the log may be a cp1252 file (server.log)

    def _off(why: str) -> float:
        if warn:
            print(f"[continuous-eval] DLP_CHECK_CONTINUOUS_EVAL_HOURS={shown} {why}; the timer stays off.")
        return 0.0
    try:
        hours = float(raw)
    except ValueError:
        return _off("is not a number")
    if hours == 0:
        return 0.0
    if not math.isfinite(hours) or hours < 0 or not math.isfinite(hours * 3600):   # NaN, infinite, negative, overflowing
        return _off("is not a usable number of hours (0 is off)")
    if hours < MIN_INTERVAL_HOURS:
        return _off(f"is below the minimum of {MIN_INTERVAL_HOURS:g} hour(s): every run reads every in-scope tenant against the ZIA API rate limit")
    if hours > MAX_INTERVAL_HOURS:
        return _off(f"is above the maximum of {MAX_INTERVAL_HOURS:g} hours")
    return hours


def profile_scope(profile: Dict[str, Any]) -> Dict[str, Any]:
    """What a profile's saved Scope page lets the loop read: `dlp` (FP/TP
    Detection Ratio and pack drift), `saas` (the SaaS / email tenants) and
    `pack_channels` (the DLP channels a pack is measured on). Only a channel
    marked "zscaler" is in scope; "alternative", "gap" or no choice is not."""
    import channel_scope
    raw = profile.get("scopes")
    if isinstance(raw, str):          # a hand-edited "dlp" or "dlp, zia_extras"
        raw = raw.split(",")
    if not isinstance(raw, (list, tuple)):   # 5, true, a dict: nothing in scope
        raw = []
    scopes = [str(x).strip().lower() for x in raw if isinstance(x, (str, int, float)) and not isinstance(x, bool) and str(x).strip()]
    chans = channel_scope.normalize(profile.get("channels"))
    on_zscaler = {cid for cid, v in chans.items() if v["choice"] == "zscaler"}
    return {"scopes": scopes, "dlp": "dlp" in scopes, "saas": SAAS_SCOPE_CHANNEL in on_zscaler,
            "pack_channels": [pc for cid, pc in SCOPE_PACK_CHANNELS.items() if cid in on_zscaler]}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest_dir() -> str:
    d = os.environ.get("DLP_CHECK_DIGESTS") or os.path.join(ROOT, DIGEST_DIRNAME)
    os.makedirs(d, exist_ok=True)
    return d


# ── The run ──────────────────────────────────────────────────────────
def run_once(*, build_client: Optional[Callable[[Dict[str, str]], Any]] = None, safe_get=None, log: LogFn = None,
             days: int = 30, notify: bool = True) -> Dict[str, Any]:
    """Run the loop once. Returns the digest (also written to disk)."""
    _log = log or (lambda s: None)
    started = time.time()
    digest: Dict[str, Any] = {"id": datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"), "at": _now(), "guidance": {}, "sources": {},
                              "saas_matrix": {}, "tenants": [], "errors": [], "notified": []}

    # 1. guidance
    try:
        import guidance
        from zscaler_best_practices import list_all
        try:
            from bp_crawler import last_summary
            guidance.update_source_health((last_summary() or {}).get("per_source") or [])
        except Exception as e:  # noqa: BLE001
            digest["errors"].append(f"source health: {e}")
        g = guidance.evaluate(list_all())
        digest["guidance"] = g
        health = guidance.source_health()
        digest["sources"] = {"watched": sum(1 for s in health if s["watched"]), "stale": [s for s in health if s["stale"]],
                             "not_crawlable": [s["name"] for s in health if not s["watched"]]}
        digest["checks_config"] = guidance.config_summary()
        _log(f"guidance: {len(g.get('raised') or [])} proposal(s), {g.get('no_action')} no action, {len(digest['sources']['stale'])} stale source(s)")
    except Exception as e:  # noqa: BLE001
        digest["errors"].append(f"guidance: {type(e).__name__}: {e}")

    # 1b. SaaS capability matrix
    try:
        import saas_matrix
        if safe_get is None:
            try:
                from zscaler_update_check import _safe_get as safe_get  # type: ignore
            except Exception:  # noqa: BLE001
                safe_get = None
        if safe_get is not None and os.environ.get("DLP_CHECK_SAAS_MATRIX_REFRESH", "1") not in ("0", "false", "no"):
            digest["saas_matrix"] = saas_matrix.refresh(safe_get)
        else:
            digest["saas_matrix"] = {"ok": False, "skipped": True, "errors": ["refresh disabled or no fetcher"]}
    except Exception as e:  # noqa: BLE001
        digest["errors"].append(f"saas matrix: {type(e).__name__}: {e}")

    # 2–4. per tenant
    try:
        import tenant_profiles
        profiles = [p for p in tenant_profiles.list_profiles() if p.get("has_secret")]
    except Exception as e:  # noqa: BLE001
        profiles = []
        digest["errors"].append(f"profiles: {e}")
    if profiles and build_client is None:
        digest["errors"].append("no API client builder: tenant sections skipped")
        profiles = []
    for p in profiles:
        try:
            digest["tenants"].append(_evaluate_tenant(p, build_client, days=days, log=_log))
        except Exception as e:  # noqa: BLE001  # one malformed profile must not stop the others or the digest
            pid = str(p.get("id") or "?")
            digest["tenants"].append({"profile_id": pid, "name": p.get("name") or pid, "tenant": p.get("vanity_domain") or pid,
                                      "detection_health": None, "proposals": None, "tenants": None, "drift": None, "skipped": [],
                                      "errors": [f"profile: {type(e).__name__}: {str(e)[:200]}"]})

    digest["duration_s"] = round(time.time() - started, 1)
    digest["noteworthy"] = noteworthy(digest)
    digest["summary"] = summarise(digest)
    if notify:
        digest["notified"] = send_notifications(digest)
    path = write_digest(digest)     # written after the send, so the file records what was notified
    digest["path"] = path
    try:
        import audit
        audit.record("continuous_evaluation", digest=digest["id"], tenants=len(digest["tenants"]), noteworthy=digest["noteworthy"],
                     proposals_new=digest["summary"].get("proposals_new"), errors=len(digest["errors"]))
    except Exception:  # noqa: BLE001
        pass
    return digest


def _evaluate_tenant(profile: Dict[str, Any], build_client, *, days: int, log) -> Dict[str, Any]:
    import tenant_profiles
    pid = profile["id"]
    out: Dict[str, Any] = {"profile_id": pid, "name": profile.get("name") or pid, "tenant": profile.get("vanity_domain") or pid,
                           "detection_health": None, "proposals": None, "tenants": None, "drift": None, "errors": [], "skipped": []}
    # Only what the profile's Scope page puts in scope is read: every read
    # counts against the tenant's API rate limit. Nothing in scope: no
    # client is built and nothing is read.
    sc = profile_scope(profile)
    out["scope"] = sc
    if not sc["scopes"]:
        out["note"] = "nothing in scope: no scopes are saved on this profile, so the tenant was not read; choose them on the Scope page and save the profile"
        log(f"{pid}: nothing in scope, not read")
        return out
    if not sc["dlp"]:
        out["skipped"].append("FP/TP Detection Ratio and pack drift: DLP is not in the profile's scopes")
    if not sc["saas"]:
        out["skipped"].append("SaaS tenants: SaaS Security (CASB) is not marked as run on Zscaler on the Scope page")
    if not sc["dlp"] and not sc["saas"]:
        out["note"] = "nothing in scope for the loop: neither DLP nor SaaS Security (CASB) on Zscaler is in this profile's scope, so the tenant was not read"
        log(f"{pid}: nothing in scope for the loop, not read")
        return out
    try:
        full = tenant_profiles.get(pid, with_secret=True) or {}
        creds = tenant_profiles.creds_from(full)
        client = build_client(creds)
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"connect: {str(e)[:200]}")
        return out
    tenant_key = creds.get("vanity_domain") or pid

    # 2. detection health + proposals
    try:
        if not sc["dlp"]:
            raise _Skip()
        import detection_health
        import proposals
        rep = detection_health.generate(client, days=days)
        s = rep.get("summary") or {}
        before = proposals.summary(tenant_key)
        merged = proposals.refresh_from_report(rep, tenant_key)
        after = proposals.summary(tenant_key)
        out["detection_health"] = {"incidents": rep.get("incident_count"), "closed": s.get("closed"), "not_real": s.get("not_real"), "fp_rate_pct": s.get("fp_rate_pct"),
                                   "noisy_rules": s.get("noisy_rules"), "dead_rules": s.get("dead_rules"), "promotable_rules": s.get("promotable_rules"),
                                   "noisy_dictionaries": s.get("noisy_dictionaries"), "delivery": (rep.get("delivery") or {}).get("path"), "errors": len(rep.get("errors") or [])}
        out["proposals"] = {"new": int((merged or {}).get("new") or 0), "updated": int((merged or {}).get("updated") or 0), "open": after.get("open", 0),
                            "approved": after.get("approved", 0), "applied": after.get("applied", 0), "open_before": before.get("open", 0),
                            "titles": [q["title"] for q in proposals.list_queue(tenant_key) if q.get("status") == "open"][:8]}
        tenant_profiles.add_history(pid, {"detection_health": out["detection_health"], "continuous_evaluation": True})
        log(f"{pid}: detection health {rep.get('incident_count')} incidents, {out['proposals']['new']} new proposal(s)")
    except _Skip:
        pass
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"detection health: {type(e).__name__}: {str(e)[:200]}")

    # 3. SaaS / email tenants
    try:
        if not sc["saas"]:
            raise _Skip()
        import saas_matrix
        tenants, err = saas_matrix.list_tenants(client)
        if err:
            out["errors"].append(f"tenants: {err}")
        else:
            packs_channels = tuple(c for c in ("saas", "email") if c in sc["pack_channels"])
            f = saas_matrix.tenant_findings(tenants, pack_channels=packs_channels)
            out["tenants"] = {k: f[k] for k in ("tenants", "active", "at_limit", "gaps", "types_present")}
            out["tenants"]["not_active"] = [{"name": t["name"], "app": t.get("app"), "status": t.get("status")} for t in f["not_active"]]
            out["tenants"]["onboard_candidates"] = [c["name"] for c in f["onboard_candidates"]][:12]
            _sync_reauthorise(tenant_key, f["not_active"])   # raises for tenants not ACTIVE, resolves the ones that recovered
    except _Skip:
        pass
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"tenants: {type(e).__name__}: {str(e)[:200]}")
    # The queue after every source of proposals has run.
    try:
        import proposals
        after = proposals.summary(tenant_key)
        pr = out.get("proposals") or {}
        pr.update({"open": after.get("open", 0), "approved": after.get("approved", 0), "applied": after.get("applied", 0),
                   "titles": [q["title"] for q in proposals.list_queue(tenant_key) if q.get("status") == "open"][:10]})
        pr.setdefault("new", 0)
        pr["new"] = max(pr["new"], pr["open"] - int(pr.get("open_before") or 0))
        out["proposals"] = pr
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"queue: {type(e).__name__}: {str(e)[:200]}")

    # 4. drift: the journey against the profile's packs, compared with the last record
    try:
        if not sc["dlp"]:
            raise _Skip()
        import pack_deploy
        from dlp_importer import discover_packs
        wanted = [str(x) for x in (profile.get("baseline_packs") or full.get("baseline_packs") or []) if x]
        packs = [pk for pk in discover_packs(ROOT) if pk["id"] in wanted] if wanted else []   # only the ticked packs, never every pack
        if packs and not sc["pack_channels"]:
            out["drift"] = {"packs": [], "changed": [], "note": "no DLP channel (Inline Web, Endpoint, SaaS Security, Email) is marked as run on Zscaler on the Scope page; drift not measured"}
        elif packs:
            # Each pack is measured on the in-scope DLP channels only.
            targets = {pk["id"]: list(sc["pack_channels"]) for pk in packs}
            rep = pack_deploy.preflight(client, packs, writes_enabled=False, apply_tweaks=False, channel_targets=targets)
            j = pack_deploy.journey(rep)
            last = _last_journey(full)
            rows = []
            for b in j.get("baselines") or []:
                prev = (last or {}).get(b.get("id")) or {}
                rows.append({"id": b.get("id"), "name": b.get("name"), "stage": b.get("stage"), "stage_name": b.get("stage_name"), "score": b.get("score"),
                             "previous_stage": prev.get("stage"), "previous_score": prev.get("score"),
                             "moved": ("up" if prev.get("stage") is not None and (b.get("stage") or 0) > prev["stage"] else
                                       "down" if prev.get("stage") is not None and (b.get("stage") or 0) < prev["stage"] else "same"),
                             "customized": sum(1 for o in (b.get("objects") or []) if o.get("position") == "customized"),
                             "relaxed": sum(1 for o in (b.get("objects") or []) if o.get("position") == "relaxed"),
                             "missing": sum(1 for o in (b.get("objects") or []) if o.get("position") == "missing"),
                             "next_steps": (b.get("next_steps") or [])[:3]})
            out["drift"] = {"packs": rows, "changed": [r["name"] for r in rows if r["moved"] != "same" or r["relaxed"]]}
            tenant_profiles.add_history(pid, {"journey": {"stage": j.get("stage"), "score": j.get("score"),
                                                          "baselines": [{"id": r["id"], "name": r["name"], "stage": r["stage"], "stage_name": r["stage_name"], "score": r["score"]} for r in rows]},
                                              "continuous_evaluation": True})
        else:
            out["drift"] = {"packs": [], "changed": [], "note": "no packs ticked on the profile; tick the packs to measure drift"}
    except _Skip:
        pass
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"drift: {type(e).__name__}: {str(e)[:200]}")
    return out


class _Skip(Exception):
    """A section the profile's scope leaves out: not read, not an error."""


def _last_journey(profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    for entry in reversed(profile.get("history") or []):
        j = entry.get("journey")
        if j and j.get("baselines"):
            return {b.get("id"): b for b in j["baselines"]}
    return {}


def _sync_reauthorise(tenant_key: str, not_active: List[Dict[str, Any]]) -> None:
    import proposals
    fresh = []
    for t in not_active:
        target = f"tenant:{t.get('app') or '?'}:{t['name']}"
        fresh.append({"id": proposals.proposal_id(tenant_key, "reauthorise_tenant", target), "tenant": proposals.tenant_key(tenant_key),
                      "kind": "reauthorise_tenant", "label": proposals.KIND_LABELS["reauthorise_tenant"], "target": target,
                      "title": f"Re-authorise SaaS tenant {t['name']} ({t.get('app') or 'unknown application'}): status {t.get('status') or 'unknown'}",
                      "change": {"apply": "manual", "kind": "reauthorise_tenant", "tenant_name": t["name"], "app": t.get("app")},
                      "evidence": {"status": t.get("status"), "why": "An onboarded SaaS application tenant that is not ACTIVE produces no incidents: every SaaS or email rule that depends on it is silent."},
                      "expected_effect": "The tenant scans again and its rules produce incidents.",
                      "rollback": {"note": "The consent is given in the vendor's admin console; nothing to roll back in ZIA."},
                      "gate": proposals.GATES.get("reauthorise_tenant", "approve"), "applies_via": "manual"})
    proposals.merge(tenant_key, fresh, source="continuous_evaluation")


# ── Digest ───────────────────────────────────────────────────────────
def noteworthy(d: Dict[str, Any]) -> bool:
    g = d.get("guidance") or {}
    if g.get("raised"):
        return True
    if (d.get("sources") or {}).get("stale"):
        return True
    if (d.get("saas_matrix") or {}).get("new_since_seed"):
        return True
    for t in d.get("tenants") or []:
        pr = t.get("proposals") or {}
        if pr.get("new") or pr.get("open"):
            return True
        tn = t.get("tenants") or {}
        if tn.get("not_active") or tn.get("gaps") or tn.get("at_limit"):
            return True
        dr = t.get("drift") or {}
        if dr.get("changed"):
            return True
        if t.get("errors"):
            return True
    return bool(d.get("errors"))


def summarise(d: Dict[str, Any]) -> Dict[str, Any]:
    tenants = d.get("tenants") or []
    # A profile with nothing in scope (a note, no client built) was not read:
    # it is counted apart, never as evaluated.
    not_read = [t for t in tenants if t.get("note")]
    return {"tenants": len(tenants) - len(not_read), "tenants_not_in_scope": len(not_read),
            "proposals_new": sum(int((t.get("proposals") or {}).get("new") or 0) for t in tenants) + len((d.get("guidance") or {}).get("raised") or []),
            "proposals_open": sum(int((t.get("proposals") or {}).get("open") or 0) for t in tenants),
            "guidance_new": len((d.get("guidance") or {}).get("raised") or []),
            "stale_sources": len((d.get("sources") or {}).get("stale") or []),
            "tenants_not_active": sum(len((t.get("tenants") or {}).get("not_active") or []) for t in tenants),
            "drift_changed": sum(len((t.get("drift") or {}).get("changed") or []) for t in tenants),
            "errors": len(d.get("errors") or []) + sum(len(t.get("errors") or []) for t in tenants)}


def to_markdown(d: Dict[str, Any]) -> str:
    s = d.get("summary") or summarise(d)
    L = [f"# DLP-Check digest — {d.get('at')}", "",
         f"**{'Something needs a look.' if d.get('noteworthy') else 'Nothing new: the loop ran and found nothing to raise.'}** "
         f"{s['proposals_new']} new proposal(s), {s['proposals_open']} open, {s['guidance_new']} new guidance item(s), "
         f"{s['stale_sources']} stale source(s), {s['tenants_not_active']} SaaS tenant(s) not active, {s['drift_changed']} pack(s) moved, {s['errors']} error(s).", ""]
    g = d.get("guidance") or {}
    L.append("## New guidance")
    if g.get("first_run"):
        L.append(f"First run: {g.get('baselined', 0)} existing articles were baselined (no proposals); from now on every new article is mapped.")
    for r in g.get("raised") or []:
        L.append(f"- **{r.get('title') or r.get('url')}** ({r.get('kind')}): {', '.join(r.get('topics') or [])}; checks {', '.join((r.get('checks') or [])[:6])}. {r.get('url')}")
        if r.get("outcome"):
            L.append(f"  - Once acted on: {r['outcome']}")
    if not g.get("raised"):
        L.append(f"- No new article on a mapped topic ({g.get('no_action', 0)} new article(s) recorded as no action).")
    src = d.get("sources") or {}
    if src.get("stale"):
        L.append("")
        L.append("## Stale sources (no answer for 7 days)")
        for x in src["stale"]:
            L.append(f"- {x.get('name')} ({x.get('host')}): last answered {x.get('last_reached_at') or 'never'}{'; ' + x['last_error'] if x.get('last_error') else ''}")
    sm = d.get("saas_matrix") or {}
    if sm.get("new_since_seed"):
        L.append("")
        L.append("## SaaS applications newly supported by Zscaler")
        L.extend(f"- {n}" for n in sm["new_since_seed"])
    for t in d.get("tenants") or []:
        L.append("")
        L.append(f"## Tenant {t.get('name')} ({t.get('tenant')})")
        dh = t.get("detection_health")
        if dh:
            L.append(f"- FP/TP Detection Ratio: {dh.get('incidents')} incidents, {dh.get('fp_rate_pct')}% not real, {dh.get('noisy_rules')} noisy rule(s), {dh.get('dead_rules')} dead, {dh.get('promotable_rules')} ready to promote, {dh.get('noisy_dictionaries')} noisy dictionar(ies); incidents reach Workflow Automation via {dh.get('delivery') or 'unknown'}.")
        pr = t.get("proposals")
        if pr:
            L.append(f"- Proposals: {pr.get('new')} new, {pr.get('open')} open, {pr.get('approved')} approved waiting to apply, {pr.get('applied')} applied.")
            for title in pr.get("titles") or []:
                L.append(f"  - {title}")
        tn = t.get("tenants")
        if tn:
            L.append(f"- SaaS tenants: {tn.get('active')} of {tn.get('tenants')} active" + (f"; not active: {', '.join(x['name'] for x in tn['not_active'])}" if tn.get("not_active") else "")
                     + (f"; at the {16}-tenant limit: {', '.join(tn['at_limit'])}" if tn.get("at_limit") else "") + ".")
            for gap in tn.get("gaps") or []:
                L.append(f"  - {gap}")
            if tn.get("onboard_candidates"):
                L.append(f"  - DLP-capable applications not onboarded: {', '.join(tn['onboard_candidates'])}.")
        dr = t.get("drift")
        if dr:
            for r in dr.get("packs") or []:
                arrow = {"up": "↑", "down": "↓"}.get(r.get("moved"), "→")
                L.append(f"- {r['name']}: stage {r.get('stage')} ({r.get('stage_name')}) {arrow} previously {r.get('previous_stage') if r.get('previous_stage') is not None else 'not recorded'}; "
                         f"{r.get('missing')} missing, {r.get('customized')} customized, {r.get('relaxed')} relaxed.")
                for step in r.get("next_steps") or []:
                    L.append(f"  - next: {step}")
            if dr.get("note"):
                L.append(f"- {dr['note']}")
        if t.get("note"):
            L.append(f"- {t['note'][0].upper()}{t['note'][1:]}.")
        elif t.get("skipped"):
            L.extend(f"- Not read (not in scope): {x}." for x in t["skipped"])
        for e in t.get("errors") or []:
            L.append(f"- Error: {e}")
    if d.get("errors"):
        L.append("")
        L.append("## Errors")
        L.extend(f"- {e}" for e in d["errors"])
    L.append("")
    L.append(f"Run took {d.get('duration_s', '?')} s. Nothing was written to any tenant. Open the app's Digest tab for the queue and the actions.")
    return "\n".join(L)


def write_digest(d: Dict[str, Any]) -> str:
    dd = digest_dir()
    base = os.path.join(dd, f"digest-{d['id']}")
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in d.items() if k != "path"}, f, indent=2, default=str)
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(to_markdown(d))
    # keep the newest KEEP_DIGESTS
    files = sorted(x for x in os.listdir(dd) if x.startswith("digest-") and x.endswith(".json"))
    for old in files[:-KEEP_DIGESTS] if len(files) > KEEP_DIGESTS else []:
        for ext in (".json", ".md"):
            try:
                os.remove(os.path.join(dd, old[:-5] + ext))
            except OSError:
                pass
    return base + ".json"


def list_digests(limit: int = 30) -> List[Dict[str, Any]]:
    dd = digest_dir()
    out = []
    for name in sorted((x for x in os.listdir(dd) if x.startswith("digest-") and x.endswith(".json")), reverse=True)[:limit]:
        try:
            with open(os.path.join(dd, name), "r", encoding="utf-8") as f:
                d = json.load(f)
            out.append({"id": d.get("id"), "at": d.get("at"), "noteworthy": d.get("noteworthy"), "summary": d.get("summary"), "notified": d.get("notified")})
        except Exception:  # noqa: BLE001
            continue
    return out


def get_digest(digest_id: str) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"\d{8}-\d{6}", digest_id or ""):
        return None
    path = os.path.join(digest_dir(), f"digest-{digest_id}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


# ── Notifications ────────────────────────────────────────────────────
def notification_settings() -> Dict[str, Any]:
    """What is configured, without the secrets."""
    env = os.environ
    webhook = env.get("DLP_CHECK_DIGEST_WEBHOOK", "").strip()
    host = urlparse(webhook).hostname if webhook else None
    return {"mode": (env.get("DLP_CHECK_NOTIFY") or "noteworthy").strip().lower(),
            "email": {"configured": bool(env.get("DLP_CHECK_SMTP_HOST") and env.get("DLP_CHECK_DIGEST_TO")), "host": env.get("DLP_CHECK_SMTP_HOST") or None,
                      "port": int(env.get("DLP_CHECK_SMTP_PORT") or 587), "to": env.get("DLP_CHECK_DIGEST_TO") or None, "from": env.get("DLP_CHECK_DIGEST_FROM") or env.get("DLP_CHECK_SMTP_USER") or None,
                      "tls": env.get("DLP_CHECK_SMTP_TLS", "1") not in ("0", "false", "no")},
            "webhook": {"configured": bool(webhook and webhook.startswith("https://")), "host": host,
                        "kind": "teams" if host and ("webhook.office.com" in host or "logic.azure.com" in host or "powerautomate" in host) else ("slack" if host and "hooks.slack.com" in host else ("generic" if host else None))},
            "interval_hours": interval_hours(warn=False)}   # logged once, when the server decides the timer


def send_notifications(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    cfg = notification_settings()
    mode = cfg["mode"]
    if mode == "never" or (mode != "always" and not d.get("noteworthy")):
        return [{"channel": "none", "sent": False, "why": f"mode {mode}, digest {'noteworthy' if d.get('noteworthy') else 'quiet'}"}]
    out = []
    md = to_markdown(d)
    s = d.get("summary") or {}
    subject = f"DLP-Check digest: {s.get('proposals_new', 0)} new proposal(s), {s.get('guidance_new', 0)} new guidance, {s.get('drift_changed', 0)} pack(s) moved"
    if cfg["email"]["configured"]:
        out.append(_send_email(subject, md, cfg["email"]))
    if cfg["webhook"]["configured"]:
        out.append(_send_webhook(subject, md, os.environ.get("DLP_CHECK_DIGEST_WEBHOOK", "").strip()))
    if not out:
        out.append({"channel": "none", "sent": False, "why": "no e-mail or webhook configured (DLP_CHECK_SMTP_HOST + DLP_CHECK_DIGEST_TO, or DLP_CHECK_DIGEST_WEBHOOK)"})
    return out


def _send_email(subject: str, body: str, e: Dict[str, Any]) -> Dict[str, Any]:
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = e["from"] or "dlp-check@localhost"
        msg["To"] = e["to"]
        msg.set_content(body)
        user = os.environ.get("DLP_CHECK_SMTP_USER", "")
        password = os.environ.get("DLP_CHECK_SMTP_PASSWORD", "")
        if user and not e["tls"]:
            # Never send the mail password in clear text. Without TLS only an
            # unauthenticated relay (no DLP_CHECK_SMTP_USER) is used.
            return {"channel": "email", "sent": False,
                    "why": "not sent: DLP_CHECK_SMTP_TLS=0 would send the SMTP password unencrypted; turn TLS back on, or use a relay that needs no sign-in"}
        with smtplib.SMTP(e["host"], int(e["port"]), timeout=20) as smtp:
            if e["tls"]:
                # Verify the mail server's certificate and name. A private CA
                # is trusted through SSL_CERT_FILE, not by switching checks off.
                smtp.starttls(context=ssl.create_default_context())
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return {"channel": "email", "sent": True, "to": e["to"]}
    except Exception as ex:  # noqa: BLE001
        return {"channel": "email", "sent": False, "why": f"{type(ex).__name__}: {str(ex)[:200]}"}


def _send_webhook(subject: str, body: str, url: str) -> Dict[str, Any]:
    if not url.startswith("https://"):
        return {"channel": "webhook", "sent": False, "why": "the webhook must be an https:// URL"}
    try:
        import requests
        text = f"**{subject}**\n\n{body}"
        payload = {"text": text[:38000]}
        r = requests.post(url, json=payload, timeout=20)
        ok = 200 <= r.status_code < 300
        return {"channel": "webhook", "sent": ok, "host": urlparse(url).hostname, "status": r.status_code, **({} if ok else {"why": (r.text or "")[:200]})}
    except Exception as ex:  # noqa: BLE001
        return {"channel": "webhook", "sent": False, "why": f"{type(ex).__name__}: {str(ex)[:200]}"}


# ── Command line ─────────────────────────────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run the continuous evaluation once (for a scheduled task, cron or a container).")
    ap.add_argument("--once", action="store_true", help="run one evaluation and exit (the default)")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--no-notify", action="store_true", help="write the digest but send nothing")
    ap.add_argument("--print", action="store_true", help="print the Markdown digest")
    args = ap.parse_args(argv)
    try:
        from dlp_api_server import _build_sdk_client as build_client  # the same client the app uses
    except Exception as e:  # noqa: BLE001
        print(f"warning: API client unavailable ({e}); tenant sections are skipped", file=sys.stderr)
        build_client = None
    d = run_once(build_client=build_client, log=lambda s: print(s, file=sys.stderr), days=args.days, notify=not args.no_notify)
    if args.print:
        print(to_markdown(d))
    else:
        print(f"digest {d['id']}: {'noteworthy' if d['noteworthy'] else 'quiet'}; written to {d['path']}; notified: {d.get('notified')}")
    return 0 if not run_errors(d) else 1


def run_errors(d: Dict[str, Any]) -> int:
    """How many errors a run recorded, the run's own and each tenant's (a
    tenant read refused by the rate limit is one): a run with any is not a
    clean success."""
    return len(d.get("errors") or []) + sum(len(t.get("errors") or []) for t in d.get("tenants") or [])


if __name__ == "__main__":
    sys.exit(main())
