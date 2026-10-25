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
                  by e-mail and/or to a Teams / Slack webhook. A score that
                  fell by at least the threshold (posture_plus, default 5
                  points) is listed as a score-drop alert; it makes the
                  digest sendable only when notify_score_drop is turned on.

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
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
WA_SCOPE_CHANNEL = "workflow_automation"


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
    `pack_channels` (the DLP channels whose rules are read and on which a
    pack is measured). Only a channel marked "zscaler" is in scope;
    "alternative", "gap" or no choice is not. `incidents` is False when
    Workflow Automation is covered by another product: its incidents (the
    FP/TP Detection Ratio's input) are then not read, and with it the
    whole FP/TP Detection Ratio. `read_incidents` is True only when
    Workflow Automation is marked "zscaler": otherwise the ratio reads
    the in-scope channels' rules but no incidents."""
    import channel_scope
    raw = profile.get("scopes")
    if isinstance(raw, str):          # a hand-edited "dlp" or "dlp, zia_extras"
        raw = raw.split(",")
    if not isinstance(raw, (list, tuple)):   # 5, true, a dict: nothing in scope
        raw = []
    scopes = [str(x).strip().lower() for x in raw if isinstance(x, (str, int, float)) and not isinstance(x, bool) and str(x).strip()]
    chans = channel_scope.normalize(profile.get("channels"))   # ongoing pack/drift targets stay explicitly selected
    on_zscaler = {cid for cid, v in chans.items() if v["choice"] == "zscaler"}
    return {"scopes": scopes, "dlp": "dlp" in scopes, "saas": SAAS_SCOPE_CHANNEL in on_zscaler,
            "pack_channels": [pc for cid, pc in SCOPE_PACK_CHANNELS.items() if cid in on_zscaler],
            "incidents": (chans.get(WA_SCOPE_CHANNEL) or {}).get("choice") != "alternative",
            "read_incidents": (chans.get(WA_SCOPE_CHANNEL) or {}).get("choice") == "zscaler"}


def tenant_label(profile: Dict[str, Any], pid: str) -> str:
    """How the digest names a profile's tenant: the vanity domain for
    OneAPI; for the classic API, which signs in with an admin login and no
    vanity domain, tenant_auth.record_label ('classic API (cloud)'), so a
    vanity domain left in the form never reaches a digest."""
    import tenant_auth
    if tenant_auth.method_of(profile or {}) == tenant_auth.LEGACY:
        return tenant_auth.record_label(profile)
    return str((profile or {}).get("vanity_domain") or pid)


def proposal_key(creds: Dict[str, Any], pid: str) -> str:
    """The profile's key in the proposal queue (tenant_fingerprint.proposal_key)."""
    import tenant_fingerprint
    return tenant_fingerprint.proposal_key(creds, pid)


def _proposal_key_migrated(creds: Dict[str, Any], pid: str) -> str:
    """proposal_key, after moving, once, the proposals a saved classic-API
    profile was queued under before this release (its stale vanity domain,
    else its profile id) to it.

    Only a saved classic profile with the same fingerprint as `creds` is
    migrated, and only from what that profile stored, never from a vanity
    domain in the request's form. A key another saved profile claims (a
    OneAPI profile's vanity domain or id, or any other profile's id or
    vanity domain) is never moved: that queue may be another tenant's. The
    profile is marked once it has been looked at, so no later run moves
    anything again."""
    import tenant_fingerprint
    key = proposal_key(creds, pid)
    try:
        import tenant_auth
        import tenant_profiles
        fp = tenant_fingerprint.fingerprint(creds)
        if not pid or not fp:
            return key
        rows = tenant_profiles.list_profiles()
        mine = next((r for r in rows if r.get("id") == pid), None)
        if (not mine or tenant_auth.method_of(mine) != tenant_auth.LEGACY or mine.get("proposal_queue_migrated")
                or tenant_fingerprint.fingerprint(tenant_profiles.creds_from(mine)) != fp):
            return key
        claimed = set()
        for r in rows:
            if r.get("id") == pid:
                continue
            claimed.update(str(x) for x in (r.get("id"), r.get("vanity_domain")) if x)
            if tenant_auth.method_of(r) != tenant_auth.LEGACY:
                claimed.add(tenant_fingerprint.proposal_key(tenant_profiles.creds_from(r), str(r.get("id") or "")))
        import proposals
        claimed = {proposals.tenant_key(k) for k in claimed}
        for old in tenant_fingerprint.proposal_key_aliases(tenant_profiles.creds_from(mine), pid):
            if proposals.tenant_key(old) not in claimed:
                proposals.rekey(old, key)
        tenant_profiles.mark_proposal_queue_migrated(pid)
    except Exception:  # noqa: BLE001
        pass
    return key


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest_dir() -> str:
    d = os.environ.get("DLP_CHECK_DIGESTS") or os.path.join(ROOT, DIGEST_DIRNAME)
    os.makedirs(d, exist_ok=True)
    return d


class LoopRunInProgress(RuntimeError):
    """A run of the loop is already reading the tenants (in this process or
    another one: the server, RUN_Continuous_Evaluation.bat, a scheduled
    continuous_eval.py --once)."""


LOCK_NAME = ".loop.lock"


@contextmanager
def run_lock():
    """One run of the loop at a time, across processes: every tenant read
    counts against the ZIA API rate limit, and two runs would also write
    the same digest and history. An OS file lock on digests/.loop.lock,
    released by the OS if the process dies, so a crash never leaves it
    stuck. A second run raises LoopRunInProgress before reading anything."""
    f = open(os.path.join(digest_dir(), LOCK_NAME), "a+")
    try:
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        raise LoopRunInProgress("a run of the loop is already in progress (the server's Run the loop now or timer, "
                                "or RUN_Continuous_Evaluation.bat / continuous_eval.py --once); wait for it to finish") from None
    try:
        # Who holds it: self_heal releases a lock whose owner process is gone.
        f.seek(0)
        f.truncate()
        f.write(f"{os.getpid()} {int(time.time())}\n")
        f.flush()
    except OSError:
        pass
    try:
        yield
    finally:
        try:
            f.seek(0)
            f.truncate()
        except OSError:
            pass
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        f.close()


# ── The run ──────────────────────────────────────────────────────────
def run_once(*, build_client: Optional[Callable[[Dict[str, str]], Any]] = None, safe_get=None, log: LogFn = None,
             days: int = 30, notify: bool = True) -> Dict[str, Any]:
    """Run the loop once. Returns the digest (also written to disk).
    Raises LoopRunInProgress, before reading anything, while another run
    (in any process) is in progress."""
    with run_lock():
        return _run_once_locked(build_client=build_client, safe_get=safe_get, log=log, days=days, notify=notify)


def _run_once_locked(*, build_client, safe_get, log: LogFn, days: int, notify: bool) -> Dict[str, Any]:
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
            digest["tenants"].append({"profile_id": pid, "name": p.get("name") or pid, "tenant": tenant_label(p, pid),
                                      "detection_health": None, "proposals": None, "tenants": None, "drift": None, "skipped": [],
                                      "errors": [f"profile: {type(e).__name__}: {str(e)[:200]}"]})

    # Score-drop alerts (posture_plus): a journey score this run measured, or
    # the latest assessment score, lower than the one before by at least the
    # threshold (default 5 points). Each assessment drop is reported once.
    # Listed in the digest; it makes the digest noteworthy (and so sendable
    # through the notifications already configured) only when the operator
    # turned notify_score_drop on.
    try:
        import posture_plus
        import tenant_profiles
        cfg = posture_plus.settings()
        seen = _alerts_seen()
        for t in digest["tenants"]:
            full = tenant_profiles.get(str(t.get("profile_id") or "")) or {}
            t["score_alerts"] = posture_plus.tenant_alerts(t, full.get("history") or [], cfg=cfg,
                                                           seen={(k, a) for p, k, a in seen if p == t.get("profile_id")})
        digest["score_drop_points"] = cfg["score_drop_points"]
    except Exception as e:  # noqa: BLE001
        digest["errors"].append(f"score alerts: {type(e).__name__}: {str(e)[:200]}")

    digest["duration_s"] = round(time.time() - started, 1)
    digest["noteworthy"] = noteworthy(digest)
    digest["summary"] = summarise(digest)
    if notify:
        digest["notified"] = send_notifications(digest)
    path = write_digest(digest)     # written after the send, so the file records what was notified
    digest["path"] = path
    try:
        import audit
        # Profiles read, not profiles listed: one with nothing in scope was
        # not read and is counted apart; every error of the run counts.
        audit.record("continuous_evaluation", digest=digest["id"], tenants=digest["summary"].get("tenants"),
                     tenants_not_in_scope=digest["summary"].get("tenants_not_in_scope"), noteworthy=digest["noteworthy"],
                     proposals_new=digest["summary"].get("proposals_new"), errors=run_errors(digest))
    except Exception:  # noqa: BLE001
        pass
    return digest


def _evaluate_tenant(profile: Dict[str, Any], build_client, *, days: int, log) -> Dict[str, Any]:
    import tenant_profiles
    pid = profile["id"]
    out: Dict[str, Any] = {"profile_id": pid, "name": profile.get("name") or pid, "tenant": tenant_label(profile, pid),
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
    full = tenant_profiles.get(pid, with_secret=True) or {}
    # What each section may read. FP/TP Detection Ratio reads the rules of
    # the DLP channels on Zscaler only, and Workflow Automation's incidents
    # unless another product covers that channel; drift measures the ticked
    # packs on those channels only.
    read_dh = sc["dlp"] and bool(sc["pack_channels"]) and sc["incidents"]
    wanted = [str(x) for x in (profile.get("baseline_packs") or full.get("baseline_packs") or []) if x]
    read_drift = sc["dlp"] and bool(sc["pack_channels"]) and bool(wanted)
    if not sc["dlp"]:
        out["skipped"].append("FP/TP Detection Ratio and pack drift: DLP is not in the profile's scopes")
    elif not sc["pack_channels"]:
        out["skipped"].append("FP/TP Detection Ratio and pack drift: no DLP channel (Inline Web, Endpoint, SaaS Security, Email) is marked as run on Zscaler on the Scope page")
        if wanted:
            out["drift"] = {"packs": [], "changed": [], "note": "no DLP channel (Inline Web, Endpoint, SaaS Security, Email) is marked as run on Zscaler on the Scope page; drift not measured"}
    else:
        if not sc["incidents"]:
            out["skipped"].append("FP/TP Detection Ratio: Workflow Automation is covered by another product on the Scope page, so its incidents are not read")
        elif not sc["read_incidents"]:
            out["skipped"].append("Workflow Automation incidents: Workflow Automation is not marked as run on Zscaler on the Scope page")
        off = [CHANNEL_LABELS[c] for c in SCOPE_PACK_CHANNELS.values() if c not in sc["pack_channels"]]
        if off:
            out["skipped"].append(f"DLP rules on {', '.join(off)}: not marked as run on Zscaler on the Scope page")
        if not wanted:
            out["drift"] = {"packs": [], "changed": [], "note": "no packs ticked on the profile; tick the packs to measure drift"}
    if not sc["saas"]:
        out["skipped"].append("SaaS tenants: SaaS Security (CASB) is not marked as run on Zscaler on the Scope page")
    if not (read_dh or read_drift or sc["saas"]):
        out["note"] = ("nothing in scope for the loop: neither DLP on a channel run on Zscaler nor SaaS Security (CASB) on Zscaler is in this "
                       "profile's scope, so the tenant was not read")
        log(f"{pid}: nothing in scope for the loop, not read")
        return out
    try:
        creds = tenant_profiles.creds_from(full)
        client = build_client(creds)
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"connect: {str(e)[:200]}")
        return out
    try:
        return _evaluate_in_scope(out, profile, full, client, creds, sc, wanted, read_dh, read_drift, days=days, log=log)
    finally:
        close = getattr(client, "close", None)   # end the session (a classic ZIA API one stays open otherwise)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001
                pass


def _evaluate_in_scope(out: Dict[str, Any], profile: Dict[str, Any], full: Dict[str, Any], client: Any, creds: Dict[str, Any],
                       sc: Dict[str, Any], wanted: List[str], read_dh: bool, read_drift: bool, *, days: int, log) -> Dict[str, Any]:
    """The reads _evaluate_tenant decided are in scope, on a signed-in client."""
    import tenant_profiles
    pid = profile["id"]
    tenant_key = _proposal_key_migrated(creds, pid)
    # The queue as it was before this run, so "new" counts only what this
    # run raised, whichever sections ran.
    open_before = None
    try:
        import proposals
        open_before = int(proposals.summary(tenant_key).get("open", 0) or 0)
    except Exception:  # noqa: BLE001
        pass

    # 2. detection health + proposals
    try:
        if not read_dh:
            raise _Skip()
        import detection_health
        import proposals
        rep = detection_health.generate(client, days=days, channels=list(sc["pack_channels"]), read_incidents=sc["read_incidents"])
        read_errors = [str(e)[:200] for e in (rep.get("errors") or [])]
        if read_errors:
            # A report built on reads that failed (a 429, say) is not a
            # measurement: it raises no proposal and is not recorded.
            out["errors"].extend(f"detection health: {e}" for e in read_errors[:10])
            log(f"{pid}: detection health not measured, {len(read_errors)} read(s) failed")
            raise _Skip()
        s = rep.get("summary") or {}
        if (rep.get("read") or {}).get("incidents", True) is False:
            # Incidents that were not read are not "no incident": nothing
            # measured from them (dead, noisy or promotable rules, the
            # ratio) is reported, recorded or proposed, and the proposals
            # raised when they were read stay as they are. Only what the
            # rules alone show (incident forwarding) is proposed.
            merged = proposals.merge(tenant_key, proposals.build_proposals(rep, tenant_key), resolve_missing=False)
            out["detection_health"] = {"incidents": None, "incidents_read": False, "closed": None, "not_real": None, "fp_rate_pct": None,
                                       "noisy_rules": None, "dead_rules": None, "promotable_rules": None, "noisy_dictionaries": None,
                                       "delivery": (rep.get("delivery") or {}).get("path"), "errors": 0}
            out["proposals"] = {"new": int((merged or {}).get("new") or 0), "updated": int((merged or {}).get("updated") or 0)}
            log(f"{pid}: detection health not measured, Workflow Automation incidents were not read")
            raise _Skip()
        merged = proposals.refresh_from_report(rep, tenant_key)
        out["detection_health"] = {"incidents": rep.get("incident_count"), "closed": s.get("closed"), "not_real": s.get("not_real"), "fp_rate_pct": s.get("fp_rate_pct"),
                                   "noisy_rules": s.get("noisy_rules"), "dead_rules": s.get("dead_rules"), "promotable_rules": s.get("promotable_rules"),
                                   "noisy_dictionaries": s.get("noisy_dictionaries"), "delivery": (rep.get("delivery") or {}).get("path"), "errors": 0}
        out["proposals"] = {"new": int((merged or {}).get("new") or 0), "updated": int((merged or {}).get("updated") or 0)}
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
        if open_before is not None:
            pr["open_before"] = open_before
            pr["new"] = max(pr["new"], pr["open"] - open_before)
        out["proposals"] = pr
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"queue: {type(e).__name__}: {str(e)[:200]}")

    # 4. drift: the journey against the profile's packs, compared with the last record
    try:
        if not read_drift:
            raise _Skip()
        import pack_deploy
        from dlp_importer import discover_packs
        packs = [pk for pk in discover_packs(ROOT) if pk["id"] in wanted]   # only the ticked packs, never every pack
        # Each pack is measured as packed, on the channels it ships rules
        # for that are also in scope: a channel the pack has no rule on is
        # never added (that would invent a "missing" monitor rule), and a
        # channel out of scope is never read.
        targets: Dict[str, List[str]] = {}
        not_measured: List[str] = []
        for pk in packs:
            own = _pack_channels(pk)
            on = [c for c in sc["pack_channels"] if c in own]
            if on:
                targets[pk["id"]] = on
            else:
                not_measured.append(pk.get("name") or pk["id"])
        measured = [pk for pk in packs if pk["id"] in targets]
        if not measured:
            out["drift"] = {"packs": [], "changed": [], "not_measured": not_measured,
                            "note": ("the ticked packs ship no rule on a DLP channel the Scope page marks as run on Zscaler; drift not measured" if packs
                                     else "none of the ticked packs was found; drift not measured")}
            raise _Skip()
        # The tenant read is capped to the scope too: no Web DLP rules unless
        # Inline Web DLP is run on Zscaler, and no SaaS application tenants
        # (which Email rules would otherwise pull in) unless SaaS Security is.
        rep = pack_deploy.preflight(client, measured, writes_enabled=False, apply_tweaks=False, channel_targets=targets,
                                    read_scope={"channels": sorted(sc["pack_channels"]), "casb": bool(sc["saas"])})
        ten = rep.get("tenant") or {}
        failed = ([str(e)[:200] for e in (ten.get("errors") or [])]
                  + [f"{ch} rules: {str(e)[:200]}" for ch, e in (ten.get("channel_errors") or {}).items() if e])
        if failed or ten.get("reachable") is False:
            # A journey measured on reads that failed is not a stage: it is
            # neither reported as a move nor kept as the next baseline.
            out["errors"].extend(f"drift: {e}" for e in (failed or ["the tenant could not be read"])[:10])
            out["drift"] = {"packs": [], "changed": [], "note": "drift not measured: the tenant reads failed (see the errors)"}
            log(f"{pid}: drift not measured, the tenant reads failed")
            raise _Skip()
        j = pack_deploy.journey(rep)
        heal = _heal_proposals(rep, tenant_key, creds, sc, log)
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
        out["drift"] = {"packs": rows, "changed": [r["name"] for r in rows if r["moved"] != "same" or r["relaxed"]],
                        # the overall journey score, against the last one recorded (the score-drop alert, posture_plus)
                        "score": j.get("score"), "previous_score": _last_journey_score(full), "measured_at": _now()}
        if heal is not None:
            out["drift"]["heal"] = heal
        if not_measured:
            out["drift"]["not_measured"] = not_measured
            out["drift"]["note"] = f"not measured (no rule on a DLP channel run on Zscaler): {', '.join(not_measured)}"
        tenant_profiles.add_history(pid, {"journey": {"stage": j.get("stage"), "score": j.get("score"),
                                                      "baselines": [{"id": r["id"], "name": r["name"], "stage": r["stage"], "stage_name": r["stage_name"], "score": r["score"]} for r in rows]},
                                          "continuous_evaluation": True})
    except _Skip:
        pass
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"drift: {type(e).__name__}: {str(e)[:200]}")
    return out


CHANNEL_LABELS = {"web": "Inline Web", "endpoint": "Endpoint", "saas": "SaaS Security", "email": "Email"}


def _pack_channels(pack: Dict[str, Any]) -> set:
    """The DLP channels a pack ships rules on, read from the pack's own
    files (no tenant read)."""
    import pack_channels as pc
    import pack_deploy
    src = pack_deploy.load_sources([pack])[0]
    return {pc.channel_of(p) for p in src.get("policies") or []} & set(pc.DLP_CHANNELS)


def _heal_proposals(rep: Dict[str, Any], tenant_key: str, creds: Dict[str, Any], sc: Dict[str, Any], log) -> Optional[Dict[str, Any]]:
    """Self-healing, layer 2: the same drift read compared with what was
    approved; a setting that drifted back becomes a heal proposal in the
    queue (self_heal.raise_from_report). Nothing is written to the tenant."""
    try:
        import self_heal
        import tenant_auth
        res = self_heal.raise_from_report(rep, tenant_key=tenant_key, labels=list(tenant_auth.record_labels(creds)),
                                          channels=list(sc["pack_channels"]), source="continuous_evaluation")
        if res.get("drifts"):
            log(f"self-healing: {len(res['drifts'])} setting(s) drifted from what was approved; heal proposals are in the queue")
        return {"drifted": len(res.get("drifts") or []), "proposals": res.get("proposals")}
    except Exception as e:  # noqa: BLE001 - the drift step stands without it
        log(f"self-healing: not measured ({type(e).__name__})")
        return None


class _Skip(Exception):
    """A section the profile's scope leaves out: not read, not an error."""


def _last_journey(profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    for entry in reversed(profile.get("history") or []):
        j = entry.get("journey")
        if j and j.get("baselines"):
            return {b.get("id"): b for b in j["baselines"]}
    return {}


def _last_journey_score(profile: Dict[str, Any]) -> Any:
    """The overall journey score of the last record that has one (None: never measured)."""
    for entry in reversed(profile.get("history") or []):
        j = entry.get("journey")
        if isinstance(j, dict) and isinstance(j.get("score"), (int, float)):
            return j["score"]
    return None


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


def _alerts_seen() -> set:
    """(profile id, kind, at) of the assessment score drops the previous
    digest already reported, so one drop is reported once."""
    try:
        last = list_digests(1)
        prev = get_digest(str(last[0]["id"])) if last else None
    except Exception:  # noqa: BLE001
        prev = None
    out = set()
    for t in (prev or {}).get("tenants") or []:
        for a in t.get("score_alerts") or []:
            if a.get("kind") == "assessment":
                out.add((t.get("profile_id"), "assessment", str(a.get("at"))))
    return out


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
        if any(a.get("notify") for a in t.get("score_alerts") or []):   # off by default (posture_plus.settings)
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
            "score_drops": sum(len(t.get("score_alerts") or []) for t in tenants),
            "errors": len(d.get("errors") or []) + sum(len(t.get("errors") or []) for t in tenants)}


def to_markdown(d: Dict[str, Any]) -> str:
    s = d.get("summary") or summarise(d)
    L = [f"# Zscaler Made Easy digest — {d.get('at')}", "",
         f"**{'Something needs a look.' if d.get('noteworthy') else 'Nothing new: the loop ran and found nothing to raise.'}** "
         f"{s['proposals_new']} new proposal(s), {s['proposals_open']} open, {s['guidance_new']} new guidance item(s), "
         f"{s['stale_sources']} stale source(s), {s['tenants_not_active']} SaaS tenant(s) not active, {s['drift_changed']} pack(s) moved, {s.get('score_drops', 0)} score drop(s), {s['errors']} error(s).", ""]
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
        for a in t.get("score_alerts") or []:
            L.append(f"- **Score drop:** {a.get('what')} {a.get('from')}% → {a.get('to')}% (−{a.get('points')}, threshold {a.get('threshold')}). {a.get('sentence') or ''}".rstrip())
            for c in (a.get("newly_failing") or [])[:10]:
                L.append(f"  - started failing: {c.get('id')} {c.get('label')} ({c.get('from')} → {c.get('to')})")
        dh = t.get("detection_health")
        if dh and dh.get("incidents_read") is False:
            L.append(f"- FP/TP Detection Ratio: Workflow Automation incidents not read (not marked as run on Zscaler on the Scope page), so no rule is judged dead, noisy or ready to promote; incidents reach Workflow Automation via {dh.get('delivery') or 'unknown'}.")
        elif dh:
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
    # The id is the run's second; a run in the same second as the previous
    # one takes the next free second, so a digest is never overwritten.
    while os.path.exists(os.path.join(dd, f"digest-{d['id']}.json")):
        d["id"] = (datetime.strptime(d["id"], "%Y%m%d-%H%M%S") + timedelta(seconds=1)).strftime("%Y%m%d-%H%M%S")
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
    subject = f"Zscaler Made Easy digest: {s.get('proposals_new', 0)} new proposal(s), {s.get('guidance_new', 0)} new guidance, {s.get('drift_changed', 0)} pack(s) moved"
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
    try:
        d = run_once(build_client=build_client, log=lambda s: print(s, file=sys.stderr), days=args.days, notify=not args.no_notify)
    except LoopRunInProgress as e:
        # Another run (the server's, or another scheduled one) is reading the
        # tenants: this one reads nothing and says so.
        print(f"not run: {e}", file=sys.stderr)
        return 2
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
