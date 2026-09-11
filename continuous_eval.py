"""Continuous evaluation, phase 5: always on, and it tells you.

One run of the loop, for every tenant profile that remembers its secret:

  1. guidance     new library articles are mapped to checks and packs and
                  become proposals (guidance.py); stale sources are flagged;
                  the SaaS capability matrix is refreshed from Zscaler's pages;
  2. detection    Detection Health is generated, its findings become
                  proposals in the tenant's queue, a compact entry goes to
                  the profile history;
  3. tenants      onboarded SaaS / email tenants are read: which are not
                  ACTIVE (re-authorise), which DLP-capable applications are
                  not onboarded, which sit at the 16-tenant limit;
  4. drift        the journey is measured against the profile's packs and
                  compared with the last recorded stage;
  5. digest       everything new since the last run is written as one
                  digest (JSON + Markdown) and, when it is noteworthy, sent
                  by e-mail and/or to a Teams / Slack webhook.

The same function runs from the server every six hours and from the
command line (`python continuous_eval.py --once`), so a Windows scheduled
task, cron, or a container can keep the loop alive without the browser.
Nothing here writes to any tenant.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
DIGEST_DIRNAME = "digests"
KEEP_DIGESTS = 60
INTERVAL_SECONDS = 6 * 3600
LogFn = Optional[Callable[[str], None]]


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
        digest["tenants"].append(_evaluate_tenant(p, build_client, days=days, log=_log))

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
                           "detection_health": None, "proposals": None, "tenants": None, "drift": None, "errors": []}
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
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"detection health: {type(e).__name__}: {str(e)[:200]}")

    # 3. SaaS / email tenants
    try:
        import saas_matrix
        tenants, err = saas_matrix.list_tenants(client)
        if err:
            out["errors"].append(f"tenants: {err}")
        else:
            packs_channels = ("saas", "email")
            f = saas_matrix.tenant_findings(tenants, pack_channels=packs_channels)
            out["tenants"] = {k: f[k] for k in ("tenants", "active", "at_limit", "gaps", "types_present")}
            out["tenants"]["not_active"] = [{"name": t["name"], "app": t.get("app"), "status": t.get("status")} for t in f["not_active"]]
            out["tenants"]["onboard_candidates"] = [c["name"] for c in f["onboard_candidates"]][:12]
            _sync_reauthorise(tenant_key, f["not_active"])   # raises for tenants not ACTIVE, resolves the ones that recovered
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
        import pack_deploy
        from dlp_importer import discover_packs
        wanted = [str(x) for x in (profile.get("baseline_packs") or full.get("baseline_packs") or []) if x]
        packs = [pk for pk in discover_packs(ROOT) if pk["id"] in wanted] if wanted else []
        if packs:
            rep = pack_deploy.preflight(client, packs, writes_enabled=False, apply_tweaks=False)
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
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"drift: {type(e).__name__}: {str(e)[:200]}")
    return out


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
    return {"tenants": len(tenants),
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
            L.append(f"- Detection Health: {dh.get('incidents')} incidents, {dh.get('fp_rate_pct')}% not real, {dh.get('noisy_rules')} noisy rule(s), {dh.get('dead_rules')} dead, {dh.get('promotable_rules')} ready to promote, {dh.get('noisy_dictionaries')} noisy dictionar(ies); incidents reach Workflow Automation via {dh.get('delivery') or 'unknown'}.")
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
            "interval_hours": INTERVAL_SECONDS // 3600}


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
        with smtplib.SMTP(e["host"], int(e["port"]), timeout=20) as smtp:
            if e["tls"]:
                smtp.starttls()
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
    return 0 if not d.get("errors") else 1


if __name__ == "__main__":
    sys.exit(main())
