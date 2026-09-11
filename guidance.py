"""Continuous evaluation, phase 4: guidance that keeps itself current.

The best-practice library refreshes itself every six hours, but a new
article was only ever a library entry. This module closes the gap:

* every article the crawler finds is MAPPED, not just listed: its title
  and URL are matched to topics, and each topic names the checks, the
  packs and the DLP channels it can affect;
* a mapped article becomes a proposal in the app-wide queue (kind
  `update_check`, or `extend_coverage` when the article announces a new
  capability); an unmapped one is recorded as "no action" with the
  reason, so the same article is never raised twice;
* approving an update_check records the article as a reference for the
  checks it touches in checks_config.json, the versioned file that ships
  with the app, so the next release carries it;
* a source that has not answered for STALE_DAYS is flagged as stale,
  never silently kept.

State lives in guidance_state.json next to the app (git-ignored;
DLP_CHECK_GUIDANCE_STATE overrides the path). Nothing here touches a
tenant.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

STATE_FILE = "guidance_state.json"
CONFIG_FILE = "checks_config.json"
STALE_DAYS = 7
BASELINE_DAYS = 7          # on the first run, only articles this recent become proposals
APP_TENANT = "app"         # the queue the guidance proposals live in (not tenant-specific)
_LOCK = threading.RLock()

# ── Topics: what an article can touch ────────────────────────────────
# `checks` are check ids, "PREFIX.*" wildcards, or "section:<text>" (a
# case-insensitive match on the registry's section name). `channels` are
# the DLP channels whose pack mirrors the guidance can change; `packs`
# are the packs whose subject the topic is.
TOPICS: List[Dict[str, Any]] = [
    {"id": "email_dlp", "label": "Outbound Email DLP",
     "keywords": r"email dlp|outbound email|exchange online|office 365 mail|microsoft 365 mail|gmail|google workspace mail|proofpoint|mail flow|journaling|smtp relay",
     "checks": ["MC.4", "MC.9", "8.9"], "channels": ["email"]},
    {"id": "saas_api", "label": "SaaS Security API tenants",
     "keywords": r"saas security api|saas security|casb|out-of-band|application tenant|saas application tenant|onedrive|sharepoint|google drive|\bbox\b|dropbox|egnyte|sharefile|salesforce|hubspot|dynamics 365|servicenow tenant|jira cloud|zendesk|freshservice|github|gitlab|bitbucket|azure devops|amazon s3|azure blob|cloud storage|sspm|app governance",
     "checks": ["MC.3", "MC.10", "8.10", "5.18", "A.7"], "channels": ["saas"]},
    {"id": "workflow_automation", "label": "Workflow Automation and incident management",
     "keywords": r"workflow automation|incident receiver|\bicap\b|incident management|incident response|itsm|servicenow|jira ticket|user justification|notification template|dlp incident",
     "checks": ["12.1", "12.2", "12.3", "12.4", "12.5", "12.6", "12.7", "12.11", "12.12", "12.13", "12.14", "12.15", "B.15", "A.12", "A.14", "A.15", "A.16"], "channels": []},
    {"id": "logging", "label": "NSS, Cloud NSS and SIEM",
     "keywords": r"\bnss\b|cloud nss|\bsiem\b|splunk|microsoft sentinel|log streaming|log feed|nanolog|syslog",
     "checks": ["12.8", "12.9", "12.10", "AI.16", "E.15"], "channels": []},
    {"id": "client_connector", "label": "Client Connector, posture and device trust",
     "keywords": r"client connector|\bzcc\b|z-?tunnel|forwarding profile|app profile|device posture|posture profile|device trust|crowdstrike|sentinelone|tamper protection|strict enforcement|captive portal|trusted network",
     "checks": ["1.*", "3.*", "6.*", "10.*", "ZCC.*", "ZPA.12", "B.1", "B.2", "B.12"], "channels": ["endpoint"]},
    {"id": "endpoint_dlp", "label": "Endpoint DLP",
     "keywords": r"endpoint dlp|removable (media|drive)|usb|printer|network share|zdp|data protection agent",
     "checks": ["5.1", "5.2", "5.4", "B.*", "8.1", "8.2", "8.3", "8.4"], "channels": ["endpoint"]},
    {"id": "ssl", "label": "SSL inspection and certificates",
     "keywords": r"ssl inspection|tls inspection|decrypt|do not decrypt|certificate pinning|pinned app|root certificate|tls 1\.3|\bech\b|quic",
     "checks": ["4.*", "7.*", "A.2", "AI.5", "AI.6", "E.2"], "channels": []},
    {"id": "genai", "label": "Generative AI",
     "keywords": r"gen(erative)? ?ai|chatgpt|openai|copilot|gemini|\bllm\b|ai/ml|ai applications|prompt|claude|perplexity",
     "checks": ["AI.*", "E.*", "5.21", "5.22"], "channels": ["web"], "packs": ["zbp_source_code_baseline"]},
    {"id": "identity", "label": "Identity and access",
     "keywords": r"zidentity|\bokta\b|entra id|azure ad|\bsaml\b|\bscim\b|single sign-on|\bsso\b|identity provider|\bmfa\b|admin role|rbac",
     "checks": ["ZID.*", "RBAC.*", "section:Users & Admin"], "channels": []},
    {"id": "dlp_engine", "label": "DLP dictionaries, engines and rules",
     "keywords": r"dlp dictionar|dlp engine|exact data match|\bedm\b|indexed document|\bidm\b|\bocr\b|evaluate all rules|first match|dlp rule|dlp polic|match count|proximity|confidence",
     "checks": ["5.10", "5.11", "5.12", "5.13", "5.14", "5.15", "5.16", "5.17", "5.19", "5.20", "A.*"], "channels": ["web"]},
    {"id": "containment", "label": "Cloud App Control, URL and file type control, isolation",
     "keywords": r"cloud app control|url filtering|file type control|browser isolation|isolation profile|cloud application",
     "checks": ["4.7", "A.6", "E.3", "AI.3", "AI.4", "3.7", "3.8", "E.13", "AI.19", "section:URL Filtering", "section:Cloud Apps"], "channels": []},
    {"id": "automation", "label": "Terraform, SDK and OneAPI",
     "keywords": r"terraform|zscaler-terraformer|ansible|oneapi|api client|sdk|provider release|changelog",
     "checks": ["AUTO-*"], "channels": []},
    {"id": "healthcare", "label": "Healthcare PHI", "keywords": r"\bphi\b|hipaa|medical|patient|healthcare", "checks": ["E.6"], "channels": [], "packs": ["healthcare_phi_baseline"]},
    {"id": "banking", "label": "Financial services", "keywords": r"\bpci\b|payment card|cardholder|banking|financial services|\bglba\b|\bmnpi\b", "checks": ["E.6"], "channels": [], "packs": ["global_banking_baseline"]},
    {"id": "federal", "label": "Federal and CUI", "keywords": r"\bcui\b|\bitar\b|\bfouo\b|cmmc|nist 800-171|fedramp", "checks": [], "channels": [], "packs": ["fed_policy_pack"]},
    {"id": "cjis", "label": "CJIS", "keywords": r"\bcjis\b|criminal justice", "checks": [], "channels": [], "packs": ["cjis_policy_pack"]},
]
_NEW_CAPABILITY = re.compile(r"now supports?|new (feature|capability|integration|application)|adds? support|introduc|generally available|is now available|support for", re.I)
_COMPILED = [(t, re.compile(t["keywords"], re.I)) for t in TOPICS]


# ── Registry lookups ─────────────────────────────────────────────────
def _registries() -> List[Sequence[Any]]:
    out: List[Sequence[Any]] = []
    for mod, attr in (("dlp_assessment_full_auto", "REG"), ("zscaler_full_checks", "PLATFORM_REG"), ("zscaler_genai_checks", "GENAI_REG"),
                      ("zscaler_automation_checks", "AUTOMATION_REG"), ("zscaler_rbac_checks", "RBAC_REG"), ("zscaler_zdx_checks", "ZDX_REG"),
                      ("zscaler_zidentity_checks", "ZID_REG")):
        try:
            out.extend(getattr(__import__(mod), attr))
        except Exception:  # noqa: BLE001
            continue
    return out


_CHECK_CACHE: Dict[str, List[Dict[str, str]]] = {}


def all_checks() -> List[Dict[str, str]]:
    if "all" not in _CHECK_CACHE:
        _CHECK_CACHE["all"] = [{"id": str(r[0]), "section": str(r[1]), "name": str(r[2])} for r in _registries()]
    return _CHECK_CACHE["all"]


def resolve_checks(patterns: Sequence[str]) -> List[str]:
    """Expand ids, 'PREFIX.*' wildcards and 'section:<text>' into check ids."""
    checks = all_checks()
    out: List[str] = []
    for p in patterns:
        if p.startswith("section:"):
            needle = p[len("section:"):].lower()
            out.extend(c["id"] for c in checks if needle in c["section"].lower())
        elif p.endswith("*"):
            pre = p[:-1]
            out.extend(c["id"] for c in checks if c["id"].startswith(pre))
        else:
            out.append(p)
    seen: List[str] = []
    for c in out:
        if c not in seen:
            seen.append(c)
    return seen


# ── Mapping ──────────────────────────────────────────────────────────
def map_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Topics, checks, packs and channels an article touches, or None."""
    text = f"{entry.get('title') or ''} {entry.get('url') or ''} {entry.get('service') or ''}"
    hits = [t for t, rx in _COMPILED if rx.search(text)]
    if not hits:
        return None
    checks: List[str] = []
    channels: List[str] = []
    packs: List[str] = []
    for t in hits:
        for c in resolve_checks(t.get("checks") or []):
            if c not in checks:
                checks.append(c)
        for ch in t.get("channels") or []:
            if ch not in channels:
                channels.append(ch)
        for p in t.get("packs") or []:
            if p not in packs:
                packs.append(p)
    kind = "extend_coverage" if (channels and _NEW_CAPABILITY.search(entry.get("title") or "")) else "update_check"
    return {"topics": [t["id"] for t in hits], "labels": [t["label"] for t in hits], "checks": checks, "channels": channels, "packs": packs, "kind": kind}


# ── State ────────────────────────────────────────────────────────────
def state_path() -> str:
    return os.environ.get("DLP_CHECK_GUIDANCE_STATE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), STATE_FILE)


def config_path() -> str:
    return os.environ.get("DLP_CHECK_CHECKS_CONFIG") or os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_FILE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else dict(default)
    except Exception:  # noqa: BLE001
        return dict(default)


def _write_json(path: str, data: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def load_state() -> Dict[str, Any]:
    return _read_json(state_path(), {"seen": {}, "sources": {}, "baselined_at": None})


def save_state(state: Dict[str, Any]) -> None:
    _write_json(state_path(), state)


# ── Evaluate: new articles become proposals ──────────────────────────
def evaluate(entries: Sequence[Dict[str, Any]], *, now: Optional[float] = None) -> Dict[str, Any]:
    """Look at every library entry not seen before. Mapped ones become
    proposals in the app-wide queue; unmapped ones are recorded as no
    action. The first run baselines the library: only articles first
    seen in the last BASELINE_DAYS become proposals, the rest are marked
    seen so the queue is not flooded with years of history."""
    import proposals
    now = now or time.time()
    with _LOCK:
        state = load_state()
        first_run = not state.get("baselined_at")
        seen: Dict[str, Any] = state.setdefault("seen", {})
        fresh: List[Dict[str, Any]] = []
        raised: List[Dict[str, Any]] = []
        no_action = 0
        baselined = 0
        for e in entries:
            url = e.get("url")
            if not url or url in seen:
                continue
            first_seen = float(e.get("first_seen") or 0) or None
            if first_run and (first_seen is None or now - first_seen > BASELINE_DAYS * 86400):
                seen[url] = {"at": _now(), "action": "baseline"}
                baselined += 1
                continue
            m = map_entry(e)
            if not m:
                seen[url] = {"at": _now(), "action": "none", "why": "no mapped topic in the title or URL"}
                no_action += 1
                continue
            target = f"guidance:{_slug(url)}"
            title = f"{'New capability' if m['kind'] == 'extend_coverage' else 'New guidance'}: {e.get('title') or url}"
            checks_txt = ", ".join(m["checks"][:8]) + ("…" if len(m["checks"]) > 8 else "")
            expected = (f"Checks {checks_txt} cite current guidance" if m["checks"] else "The affected packs cite current guidance")
            if m["channels"]:
                expected += f"; the {', '.join(m['channels'])} mirrors of every pack are reviewed against it"
            p = {
                "id": proposals.proposal_id(APP_TENANT, m["kind"], target), "tenant": APP_TENANT, "kind": m["kind"],
                "label": proposals.KIND_LABELS.get(m["kind"], m["kind"]), "target": target, "title": title,
                "change": {"apply": "guidance", "article": url, "checks": m["checks"], "channels": m["channels"], "packs": m["packs"], "topics": m["topics"]},
                "evidence": {"article": url, "article_title": e.get("title"), "source": e.get("source_name") or e.get("source_id") or e.get("source"),
                             "tier": e.get("tier"), "credibility": e.get("credibility"), "topics": m["labels"], "checks": m["checks"][:12],
                             "why": f"{e.get('source_name') or 'A watched source'} published an article on {', '.join(m['labels'])}."},
                "expected_effect": expected,
                "rollback": {"note": "Approving only records the article as a reference for those checks (checks_config.json); remove the line to undo. No tenant write."},
                "gate": proposals.GATES.get(m["kind"], "approve"), "applies_via": "guidance",
            }
            fresh.append(p)
            raised.append({"url": url, "title": e.get("title"), "kind": m["kind"], "topics": m["labels"], "checks": m["checks"]})
            seen[url] = {"at": _now(), "action": m["kind"], "topics": m["topics"]}
        if first_run:
            state["baselined_at"] = _now()
        state["last_run_at"] = _now()
        save_state(state)
    merged = proposals.merge(APP_TENANT, fresh, source="guidance", resolve_missing=False) if fresh else {"new": 0, "updated": 0}
    return {"raised": raised, "no_action": no_action, "baselined": baselined, "first_run": first_run, "merged": merged}


def _slug(url: str) -> str:
    import hashlib
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]


# ── Approval: record the reference in the shipped config ─────────────
def record_approval(proposal: Dict[str, Any], *, by: str = "") -> Dict[str, Any]:
    """An approved guidance proposal records its article as a reference
    for every check it maps to. checks_config.json ships with the app,
    so the change lands in the next release; nothing touches a tenant."""
    c = proposal.get("change") or {}
    url = c.get("article")
    if not url:
        raise ValueError("this proposal has no article to record")
    with _LOCK:
        cfg = _read_json(config_path(), {"version": 1, "checks": {}})
        checks = cfg.setdefault("checks", {})
        touched = []
        for cid in c.get("checks") or []:
            entry = checks.setdefault(cid, {"references": []})
            refs = entry.setdefault("references", [])
            if not any(r.get("url") == url for r in refs):
                refs.append({"url": url, "title": (proposal.get("evidence") or {}).get("article_title"), "added_at": _now(), "by": by,
                             "kind": proposal.get("kind"), "topics": c.get("topics")})
                touched.append(cid)
        if c.get("packs") or c.get("channels"):
            packs = cfg.setdefault("packs", {})
            for pid in (c.get("packs") or []) + [f"channel:{ch}" for ch in (c.get("channels") or [])]:
                refs = packs.setdefault(pid, {"references": []})["references"]
                if not any(r.get("url") == url for r in refs):
                    refs.append({"url": url, "title": (proposal.get("evidence") or {}).get("article_title"), "added_at": _now(), "by": by})
        cfg["updated_at"] = _now()
        _write_json(config_path(), cfg)
    return {"checks": touched, "config": config_path()}


def references_for(check_id: str) -> List[Dict[str, Any]]:
    cfg = _read_json(config_path(), {"checks": {}})
    return list(((cfg.get("checks") or {}).get(check_id) or {}).get("references") or [])


def config_summary() -> Dict[str, Any]:
    cfg = _read_json(config_path(), {"checks": {}, "packs": {}})
    return {"path": config_path(), "updated_at": cfg.get("updated_at"),
            "checks_with_references": sum(1 for v in (cfg.get("checks") or {}).values() if v.get("references")),
            "references": sum(len(v.get("references") or []) for v in (cfg.get("checks") or {}).values())}


# ── Source health: stale sources are flagged, never silently kept ───
def update_source_health(per_source: Sequence[Dict[str, Any]], *, now: Optional[float] = None) -> None:
    """Record, per source, the last time it answered (a crawl that
    reached it)."""
    now = now or time.time()
    with _LOCK:
        state = load_state()
        src = state.setdefault("sources", {})
        for r in per_source:
            sid = r.get("source_id")
            if not sid:
                continue
            rec = src.setdefault(sid, {})
            rec.setdefault("first_attempt_at", now)
            rec["last_attempt_at"] = now
            if r.get("reached"):
                rec["last_reached_at"] = now
                rec["last_matched"] = r.get("matched_count")
            else:
                rec["last_error"] = r.get("error") or "not reached"
        save_state(state)


def source_health(*, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Every registered source with whether it is watched, when it last
    answered, and a stale flag after STALE_DAYS without an answer."""
    import bp_sources
    now = now or time.time()
    state = load_state()
    src = state.get("sources") or {}
    out = []
    for s in bp_sources.SOURCES:
        rec = src.get(s["id"]) or {}
        reached = rec.get("last_reached_at")
        attempted = rec.get("last_attempt_at")
        # Stale: watched, tried at least once, and no answer for STALE_DAYS. A
        # source never tried yet is "not yet checked", not stale.
        first = rec.get("first_attempt_at") or attempted
        stale = bool(s.get("crawlable")) and attempted is not None and (
            (reached is None and now - float(first) > STALE_DAYS * 86400) or (reached is not None and now - float(reached) > STALE_DAYS * 86400))
        out.append({"id": s["id"], "name": s.get("name"), "host": s.get("host"), "tier": s.get("tier"), "credibility": s.get("credibility"),
                    "watched": bool(s.get("crawlable")), "affects": s.get("affects") or [], "why": s.get("why", ""),
                    "last_reached_at": datetime.fromtimestamp(float(reached), tz=timezone.utc).isoformat(timespec="seconds") if reached else None,
                    "last_error": rec.get("last_error") if not reached or (now - float(reached) > STALE_DAYS * 86400) else None,
                    "stale": stale, "stale_days": STALE_DAYS, "checked": attempted is not None,
                    "note": None if s.get("crawlable") else "Not crawlable (login-walled or a single-page app): Zscaler's own integration guide is the signal for this partner."})
    return out
