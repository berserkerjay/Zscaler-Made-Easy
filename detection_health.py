"""
Detection Health: what the tenant's DLP rules actually do, measured from
Workflow Automation incidents and the analysts' verdicts on them.

Phase 1 of the continuous evaluation loop (read-only). For a window of
incidents (default 30 days) the report says, per rule, engine,
dictionary, channel and application:

  * how many incidents fired, how many were closed, and how many of the
    closed ones analysts marked as not a real leak (the false-positive
    rate);
  * which enabled rules produced nothing at all in the window (dead);
  * which monitor-only rules have been right long enough to promote;
  * which dictionaries carry the noise.

Incidents come from the Workflow Automation API through the same OneAPI
client the rest of the app uses (`client.zwa.dlp_incidents`). Rules come
from the same inventory the removal wizard lists. No user identities are
kept in the report: departments and counts only.

Thresholds (the defaults the operator accepted) live in DEFAULTS and can
be overridden per request; nothing here writes to the tenant.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULTS: Dict[str, Any] = {
    "days": 30,
    "fp_window_days": 14,        # false-positive rate is judged over this window
    "fp_rate_pct": 40,           # ...and called noisy at or above this rate
    "fp_min_incidents": 10,      # ...with at least this many closed incidents
    "dead_days": 30,             # an enabled rule with no incident in this many days is dead
    "promote_window_days": 30,   # a monitor rule is promotable when, over this window,
    "promote_fp_pct": 5,         # ...its FP rate is at or below this
    "promote_min_incidents": 20, # ...with at least this many closed incidents
    # Resolutions / closed codes that mean "not a real leak". Matched after
    # lower-casing and stripping punctuation, so "False-Positive" matches.
    "not_real": ["false positive", "business justified", "not an incident", "not a violation", "benign"],
}
MONITOR_ACTIONS = {"ALLOW", "OFLCASB_DLP_REPORT_INCIDENT", "OFLCASB_DLP_ALLOW", "REPORT"}
MAX_PAGES = 50           # 50 x 100 incidents per run
PAGE_SIZE = 100


# ── helpers ────────────────────────────────────────────────────────────
def _norm(s: Any) -> str:
    return re.sub(r"[^a-z0-9 ]+", " ", str(s or "").lower()).strip()


def _g(obj: Any, *names: str, default: Any = None) -> Any:
    """Read a field from a dict or an SDK object under any of its names
    (camelCase or snake_case)."""
    for n in names:
        if isinstance(obj, dict):
            if n in obj and obj[n] is not None:
                return obj[n]
        else:
            v = getattr(obj, n, None)
            if v is not None:
                return v
    return default


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _both(name: str) -> Tuple[str, str]:
    return name, _snake(name)


def _parse_time(v: Any) -> Optional[datetime]:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):
        ts = float(v)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    s = str(v).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def channel_of_incident(source_type: Any, sub_type: Any = None, integration: Any = None) -> str:
    s = " ".join(str(x or "") for x in (source_type, sub_type, integration)).upper()
    if "ENDPOINT" in s or "ZDP" in s or "DEVICE" in s:
        return "endpoint"
    if "EMAIL" in s or "MAIL" in s or "SMTP" in s:
        return "email"
    if "SAAS" in s or "CASB" in s or "API" in s or "OFLCASB" in s:
        return "saas"
    if "WEB" in s or "INLINE" in s or "ZIA" in s or "PROXY" in s:
        return "web"
    return "other"


def verdict(status: Any, resolution: Any, closed_code: Any, not_real: Iterable[str]) -> Optional[bool]:
    """True = analysts treated it as a real leak, False = not real, None =
    still open (no verdict yet)."""
    st = _norm(status)
    closed = any(w in st for w in ("closed", "resolved", "complete", "done"))
    words = [_norm(x) for x in not_real if _norm(x)]
    for v in (resolution, closed_code):
        nv = _norm(v)
        if nv and any(w in nv for w in words):
            return False
    if not closed:
        return None
    return True


# ── incidents ──────────────────────────────────────────────────────────
def normalize_incident(inc: Any, not_real: Iterable[str]) -> Dict[str, Any]:
    d = inc.as_dict() if hasattr(inc, "as_dict") else inc
    mp = _g(d, *_both("matchingPolicies"), default={}) or {}
    rules = [str(_g(r, "name", default="")) for r in (_g(mp, "rules", default=[]) or []) if _g(r, "name")]
    engines = [str(_g(e, "name", default="")) for e in (_g(mp, "engines", default=[]) or []) if _g(e, "name")]
    dicts = [{"name": str(_g(x, "name", default="")), "count": int(_g(x, *_both("matchCount"), default=0) or 0)}
             for x in (_g(mp, "dictionaries", default=[]) or []) if _g(x, "name")]
    app = _g(d, *_both("applicationInfo"), default={}) or {}
    user = _g(d, *_both("userInfo"), default={}) or {}
    source_type = _g(d, *_both("sourceType"))
    sub_type = _g(d, *_both("sourceSubType"))
    integration = _g(d, *_both("integrationType"))
    status = _g(d, "status")
    resolution = _g(d, "resolution")
    closed_code = _g(d, *_both("closedCode"))
    created = _parse_time(_g(d, *_both("createdAt"), *_both("sourceFirstObservedAt")))
    return {
        "id": str(_g(d, *_both("internalId"), "id", default="") or ""),
        "created_at": created.isoformat() if created else None,
        "_created": created,
        "status": str(status or ""),
        "resolution": str(resolution or closed_code or ""),
        "severity": str(_g(d, "severity", default="") or ""),
        "channel": channel_of_incident(source_type, sub_type, integration),
        "source_type": str(source_type or ""),
        "application": str(_g(app, "name", *_both("hostnameOrApplication"), "url", default="") or ""),
        "department": str(_g(user, "department", default="") or ""),
        "rules": rules, "engines": engines, "dictionaries": dicts,
        "match_count": int(_g(d, *_both("matchCount"), default=0) or 0),
        "real": verdict(status, resolution, closed_code, not_real),
    }


def fetch_incidents(client, days: int = 30, log=None, *, max_pages: int = MAX_PAGES) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Every Workflow Automation incident created in the last `days`,
    normalised. Errors are returned, never raised."""
    _log = log or (lambda m: None)
    errors: List[str] = []
    zwa = getattr(client, "zwa", None)
    api = getattr(zwa, "dlp_incidents", None) if zwa is not None else None
    if api is None:
        return [], ["The Workflow Automation API is not available on this client (the SDK exposes no zwa.dlp_incidents). "
                    "Grant the API client the Workflow Automation read scope and try again."]
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=max(1, int(days)))
    time_range = {"startTime": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "endTime": end.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
    out: List[Dict[str, Any]] = []
    seen: set = set()
    page = 1
    while page <= max_pages:
        try:
            result, _resp, err = api.dlp_incident_search(query_params={"page": page, "page_size": PAGE_SIZE}, fields=[], time_range=time_range)
        except Exception as e:  # noqa: BLE001
            errors.append(f"incident search failed on page {page}: {str(e)[:200]}")
            break
        if err:
            errors.append(f"incident search failed on page {page}: {str(err)[:200]}")
            break
        items = _flatten(result)
        if not items:
            break
        new = 0
        for inc in items:
            n = normalize_incident(inc, DEFAULTS["not_real"])
            key = n["id"] or f"{n['created_at']}|{n['rules']}|{n['application']}"
            if key in seen:
                continue
            seen.add(key)
            out.append(n)
            new += 1
        _log(f"Incidents page {page}: {len(items)} read, {new} new")
        if new == 0 or len(items) < PAGE_SIZE:
            break
        page += 1
    return out, errors


def _flatten(result: Any) -> List[Any]:
    """The search result nests incidents (search -> incidents[] -> incidents[]
    in some SDK versions); return the leaf incident records."""
    if result is None:
        return []
    items = _g(result, "incidents", default=None)
    if items is None and isinstance(result, list):
        items = result
    leaves: List[Any] = []
    for it in items or []:
        inner = _g(it, "incidents", default=None)
        if isinstance(inner, list) and inner and not _g(it, *_both("matchingPolicies")):
            leaves.extend(inner)
        else:
            leaves.append(it)
    return leaves


# ── evaluation ─────────────────────────────────────────────────────────
def _rate(closed: int, not_real: int) -> Optional[int]:
    return round(100 * not_real / closed) if closed else None


def _window(incidents: List[Dict[str, Any]], now: datetime, days: int) -> List[Dict[str, Any]]:
    cutoff = now - timedelta(days=days)
    return [i for i in incidents if i.get("_created") is None or i["_created"] >= cutoff]


def _tally(incs: List[Dict[str, Any]]) -> Dict[str, int]:
    closed = [i for i in incs if i["real"] is not None]
    return {"incidents": len(incs), "open": len(incs) - len(closed), "closed": len(closed),
            "not_real": sum(1 for i in closed if i["real"] is False), "real": sum(1 for i in closed if i["real"] is True)}


def evaluate(incidents: List[Dict[str, Any]], rules: List[Dict[str, Any]], settings: Optional[Dict[str, Any]] = None,
             now: Optional[datetime] = None, definitions: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Per rule / engine / dictionary / channel / application metrics and
    the findings they imply. `rules` is the tenant's DLP rule inventory
    (name, channel, state, action, engines) so dead and monitor-only rules
    can be judged; rules seen only in incidents are reported too."""
    s = dict(DEFAULTS, **(settings or {}))
    now = now or datetime.now(timezone.utc)
    fp_win = _window(incidents, now, int(s["fp_window_days"]))
    pr_win = _window(incidents, now, int(s["promote_window_days"]))
    dead_cut = now - timedelta(days=int(s["dead_days"]))

    def by_rule(incs):
        m: Dict[str, List[Dict[str, Any]]] = {}
        for i in incs:
            for r in i["rules"] or ["(no rule name)"]:
                m.setdefault(r, []).append(i)
        return m
    all_by_rule, fp_by_rule, pr_by_rule = by_rule(incidents), by_rule(fp_win), by_rule(pr_win)

    rule_rows: List[Dict[str, Any]] = []
    known = {}
    for r in rules or []:
        known.setdefault(str(r.get("name")), r)
    names = list(known) + [n for n in all_by_rule if n not in known]
    for name in names:
        r = known.get(name) or {}
        incs = all_by_rule.get(name, [])
        t_all, t_fp, t_pr = _tally(incs), _tally(fp_by_rule.get(name, [])), _tally(pr_by_rule.get(name, []))
        last = max((i["_created"] for i in incs if i.get("_created")), default=None)
        enabled = str(r.get("state") or "").upper() == "ENABLED" if r else None
        monitor = str(r.get("action") or "").upper() in MONITOR_ACTIONS if r else None
        fp_rate = _rate(t_fp["closed"], t_fp["not_real"])
        pr_rate = _rate(t_pr["closed"], t_pr["not_real"])
        status, why = "healthy", ""
        if r and not enabled:
            status, why = "disabled", "rule is disabled in the tenant"
        elif r and enabled and not incs and (last is None):
            status, why = "dead", f"enabled but no incident in {s['dead_days']} days"
        elif enabled and last is not None and last < dead_cut and not [i for i in incs if i["_created"] and i["_created"] >= dead_cut]:
            status, why = "dead", f"enabled but no incident in {s['dead_days']} days"
        elif fp_rate is not None and t_fp["closed"] >= int(s["fp_min_incidents"]) and fp_rate >= int(s["fp_rate_pct"]):
            status, why = "noisy", f"{fp_rate}% of {t_fp['closed']} closed incidents in {s['fp_window_days']} days were not real"
        elif monitor and pr_rate is not None and t_pr["closed"] >= int(s["promote_min_incidents"]) and pr_rate <= int(s["promote_fp_pct"]):
            status, why = "promotable", f"monitor-only; {pr_rate}% not real over {t_pr['closed']} closed incidents in {s['promote_window_days']} days"
        elif not r:
            status, why = "unknown_rule", "incidents name a rule the inventory does not list (renamed or deleted?)"
        elif t_all["closed"] == 0 and incs:
            status, why = "no_verdicts", "incidents exist but none has been closed yet"
        rule_rows.append({"name": name, "channel": r.get("channel") or (incs[0]["channel"] if incs else None),
                          "state": r.get("state"), "action": r.get("action"), "monitor_only": monitor, "tagged": r.get("tagged"),
                          "engines": r.get("engines") or sorted({e for i in incs for e in i["engines"]}),
                          "incidents": t_all["incidents"], "open": t_all["open"], "closed": t_all["closed"], "not_real": t_all["not_real"],
                          "fp_rate_pct": fp_rate, "fp_closed": t_fp["closed"], "promote_rate_pct": pr_rate, "promote_closed": t_pr["closed"],
                          "last_incident_at": last.isoformat() if last else None, "status": status, "why": why})

    def group(key_fn, incs, win):
        m: Dict[str, List[Dict[str, Any]]] = {}
        for i in incs:
            for k in key_fn(i):
                m.setdefault(k, []).append(i)
        w: Dict[str, List[Dict[str, Any]]] = {}
        for i in win:
            for k in key_fn(i):
                w.setdefault(k, []).append(i)
        rows = []
        for k, lst in m.items():
            t, tw = _tally(lst), _tally(w.get(k, []))
            rate = _rate(tw["closed"], tw["not_real"])
            noisy = rate is not None and tw["closed"] >= int(s["fp_min_incidents"]) and rate >= int(s["fp_rate_pct"])
            rows.append({"name": k, **t, "fp_rate_pct": rate, "fp_closed": tw["closed"], "noisy": noisy,
                         "rules": sorted({r for i in lst for r in i["rules"]})[:12]})
        rows.sort(key=lambda x: (-x["incidents"], x["name"]))
        return rows

    engines = group(lambda i: i["engines"] or [], incidents, fp_win)
    dictionaries = group(lambda i: [d["name"] for d in i["dictionaries"]], incidents, fp_win)
    for d in dictionaries:
        if d["noisy"]:
            d.update(dictionary_why(d["name"], [i for i in fp_win if any(x["name"] == d["name"] for x in i["dictionaries"])],
                                    (definitions or {}).get(d["name"])))
        else:
            d["why"], d["fix"], d["evidence"] = [], "", {}
    channels = group(lambda i: [i["channel"]], incidents, fp_win)
    applications = group(lambda i: [i["application"] or "(unknown application)"], incidents, fp_win)
    departments = group(lambda i: [i["department"] or "(unknown department)"], incidents, fp_win)

    findings: List[Dict[str, Any]] = []
    for row in rule_rows:
        if row["status"] == "noisy":
            findings.append({"kind": "noisy_rule", "severity": "medium", "name": row["name"], "channel": row["channel"],
                             "text": f"{row['name']}: {row['why']}. Tune the dictionaries behind it before enabling anything stricter.",
                             "proposal": "tune_dictionary"})
        elif row["status"] == "dead":
            findings.append({"kind": "dead_rule", "severity": "low", "name": row["name"], "channel": row["channel"],
                             "text": f"{row['name']}: {row['why']}. Either the traffic never reaches it or the engine cannot match; consider retiring or re-scoping it.",
                             "proposal": "retire_rule"})
        elif row["status"] == "promotable":
            findings.append({"kind": "promotable_rule", "severity": "info", "name": row["name"], "channel": row["channel"],
                             "text": f"{row['name']}: {row['why']}. Ready to move from monitor to confirm or block.",
                             "proposal": "promote_rule"})
        elif row["status"] == "unknown_rule":
            findings.append({"kind": "unknown_rule", "severity": "low", "name": row["name"], "channel": row["channel"],
                             "text": f"{row['name']}: {row['why']}.", "proposal": None})
    for d in dictionaries:
        if d["noisy"]:
            findings.append({"kind": "noisy_dictionary", "severity": "medium", "name": d["name"], "channel": None,
                             "text": f"Dictionary {d['name']}: {d['fp_rate_pct']}% of {d['fp_closed']} closed incidents in {s['fp_window_days']} days were not real (rules: {', '.join(d['rules'][:4])}). "
                                     f"Why: {' '.join(d['why']) if d['why'] else 'the analysts closed most of its matches as not real.'} Fix: {d['fix']}",
                             "why": d["why"], "fix": d["fix"], "evidence": d["evidence"], "proposal": "tune_dictionary"})
    sev = {"medium": 0, "low": 1, "info": 2}
    findings.sort(key=lambda f: (sev.get(f["severity"], 9), f["name"]))

    total = _tally(incidents)
    summary = {**total, "fp_rate_pct": _rate(_tally(fp_win)["closed"], _tally(fp_win)["not_real"]),
               "rules": len(rule_rows), "noisy_rules": sum(1 for r in rule_rows if r["status"] == "noisy"),
               "dead_rules": sum(1 for r in rule_rows if r["status"] == "dead"),
               "promotable_rules": sum(1 for r in rule_rows if r["status"] == "promotable"),
               "noisy_dictionaries": sum(1 for d in dictionaries if d["noisy"]),
               "channels": {c["name"]: c["incidents"] for c in channels}}
    order = {"noisy": 0, "promotable": 1, "dead": 2, "unknown_rule": 3, "no_verdicts": 4, "healthy": 5, "disabled": 6}
    rule_rows.sort(key=lambda r: (order.get(r["status"], 9), -r["incidents"], r["name"]))
    return {"settings": {k: v for k, v in s.items() if k != "not_real"} | {"not_real": list(s["not_real"])},
            "summary": summary, "rules": rule_rows, "engines": engines, "dictionaries": dictionaries,
            "channels": channels, "applications": applications[:40], "departments": departments[:40], "findings": findings}


# ── why a dictionary is false-positive prone ───────────────────────────
# What is known about the predefined patterns, keyed by a regex on the
# dictionary name: (why it over-matches, what to do about it).
KNOWN_PATTERNS = [
    (r"social.?security|\bssn\b", "nine-digit numbers with no context also match: order numbers, phone numbers, account and employee ids pass the format check",
     "use the high-confidence SSN dictionary (needs 'SSN' or 'social security' nearby), raise the match count so one stray number is not an incident, or exclude the sanctioned applications that legitimately carry ids"),
    (r"date.?of.?birth|\bdob\b|\bbirth", "any date matches: invoices, schedules and logs are full of dates, and a birth date is only sensitive next to a name or identifier",
     "keep it only inside an engine that also requires a name or id dictionary (AND), never on its own"),
    (r"\bname|first.?name|last.?name|full.?name", "name lists match ordinary words and common surnames in business documents and e-mail signatures",
     "use it only as a second condition in an engine (AND with an identifier), and raise the match count"),
    (r"credit.?card|payment.?card|\bpan\b|card.?number", "any 13–19 digit number that passes the Luhn check matches: order numbers, IMEIs, tracking and serial numbers often do",
     "use the high-confidence card dictionary (issuer prefix plus expiry or CVV context), raise the match count for bulk detection, or exclude internal applications that carry serial numbers"),
    (r"phone|telephone", "any ten-digit number in phone shape matches: reference numbers, fax lines in signatures and vendor contact details",
     "only pair it with a real identifier in an engine; on its own it is not sensitive data"),
    (r"e-?mail", "every e-mail address matches, including the sender's own signature and internal addresses",
     "restrict to bulk (high match count) or to external domains; a single address is not a leak"),
    (r"address|street|postal|zip", "postal addresses appear in every letterhead, invoice and signature",
     "pair with an identifier in an engine and raise the match count"),
    (r"\bip\b|ipv4|ipv6", "IP addresses appear in logs, tickets, monitoring exports and configuration files that are routine for IT staff",
     "exclude the IT groups and ticketing applications, or retire it unless network diagrams are the asset to protect"),
    (r"medical|\bphi\b|health|hipaa|clinical|diagnos|icd", "clinical vocabulary occurs in ordinary e-mail (sick leave, insurance questions, wellness newsletters) and short codes like ICD look like product codes",
     "require a patient identifier (MRN, member id) in the engine and lower the weight of vocabulary-only terms"),
    (r"financ|balance.?sheet|income.?statement|earnings|corporate", "financial vocabulary is everyday language for finance, sales and procurement; the classifier fires on budgets, quotes and forecasts",
     "scope the rule to the groups and applications where the statements are confidential (pre-release), and set the confidence to high"),
    (r"salary|payroll|compensation", "salary words appear in HR templates, job postings and internal FAQs",
     "scope the rule to HR systems and exclude HR staff, or require an employee id alongside"),
    (r"password|credential|secret|token|api.?key", "the words 'password' and 'token' appear in guidance documents, help-desk tickets and reset e-mails without a real secret",
     "prefer the shaped secret dictionaries (AWS, Google, private key headers) over the keyword one; exclude the help-desk application"),
    (r"source.?code|\bcode\b", "configuration files, log snippets, SQL and scripts in tickets look like source code",
     "restrict to the repositories' file types and the engineering groups; exclude ticketing"),
    (r"resume|\bcv\b|curriculum", "resumes match every candidate e-mail and HR workflow, which is legitimate traffic",
     "scope to the recruiting application or retire it"),
    (r"legal|contract|agreement|\bnda\b", "contract vocabulary is routine for sales, procurement and legal",
     "scope to the groups who must not send drafts outside and set the confidence to high"),
    (r"passport|driver|licen[cs]e|national.?id", "identifier shapes without context match booking references, invoice and serial numbers",
     "use the context-aware variant of the dictionary and raise the match count"),
    (r"\biban\b|routing|\baba\b|bank.?account|swift", "account numbers appear in the company's own invoices, remittance advice and supplier onboarding, all legitimate",
     "exclude the finance groups and the banking applications, or require a customer identifier in the engine"),
]


def _top(counter: Dict[str, int], n: int = 3) -> List[Tuple[str, int]]:
    return sorted(((k, v) for k, v in counter.items() if k), key=lambda kv: (-kv[1], kv[0]))[:n]


def dictionary_why(name: str, incs: List[Dict[str, Any]], definition: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Why this dictionary's matches are closed as not real, from the
    incidents themselves (alone or co-fired, thin match counts, where the
    noise comes from), what is known about the pattern, and the
    dictionary's own settings. Returns {why: [..], fix: str, evidence}."""
    nr = [i for i in incs if i["real"] is False]
    real = [i for i in incs if i["real"] is True]
    why: List[str] = []
    fixes: List[str] = []
    ev: Dict[str, Any] = {"not_real": len(nr), "real": len(real)}
    if nr:
        alone = sum(1 for i in nr if len(i["dictionaries"]) == 1)
        led = sum(1 for i in nr if max((d["count"] for d in i["dictionaries"]), default=0) == next((d["count"] for d in i["dictionaries"] if d["name"] == name), 0) > 0)
        ev.update({"alone": alone, "led": led})
        co: Dict[str, int] = {}
        for i in nr:
            for d in i["dictionaries"]:
                if d["name"] != name:
                    co[d["name"]] = co.get(d["name"], 0) + 1
        ev["co_fired"] = _top(co)
        counts = sorted(next((d["count"] for d in i["dictionaries"] if d["name"] == name), 0) for i in nr)
        median = counts[len(counts) // 2] if counts else 0
        ev["median_matches_not_real"] = median
        real_counts = sorted(next((d["count"] for d in i["dictionaries"] if d["name"] == name), 0) for i in real)
        ev["median_matches_real"] = real_counts[len(real_counts) // 2] if real_counts else None
        if alone == 0 and co:
            top = ev["co_fired"][0]
            why.append(f"It never fired alone: every not-real incident also matched {top[0]} ({top[1]} of {len(nr)}), so the noise may belong to that dictionary rather than this one.")
        elif alone >= max(1, len(nr) // 2):
            why.append(f"It carries the noise itself: it was the only dictionary in {alone} of {len(nr)} not-real incidents.")
        if led and led >= max(1, len(nr) // 2) and alone < len(nr):
            why.append(f"It led the match (highest count) in {led} of {len(nr)} not-real incidents.")
        if median and median <= 2:
            why.append(f"Matches are thin: typically {median} hit(s) per not-real incident, the signature of a pattern that catches stray look-alike values rather than a data set.")
            fixes.append("raise the match count on the rule (or the dictionary's threshold) so one or two look-alike values are not an incident")
        if ev["median_matches_real"] and median and ev["median_matches_real"] >= 3 * max(1, median):
            why.append(f"Real incidents carry far more matches (typically {ev['median_matches_real']}) than the not-real ones ({median}): a count threshold separates them.")
        apps: Dict[str, int] = {}
        depts: Dict[str, int] = {}
        for i in nr:
            apps[i.get("application") or ""] = apps.get(i.get("application") or "", 0) + 1
            depts[i.get("department") or ""] = depts.get(i.get("department") or "", 0) + 1
        ev["applications"] = _top(apps)
        ev["departments"] = _top(depts)
        if ev["applications"] and ev["applications"][0][1] >= max(2, len(nr) // 2):
            a, n = ev["applications"][0]
            why.append(f"Most of the noise ({n} of {len(nr)}) comes from {a}: the analysts treat that traffic as legitimate.")
            fixes.append(f"exclude {a} from the rule (or move it to a sanctioned-application rule with a higher threshold)")
        if ev["departments"] and ev["departments"][0][1] >= max(2, len(nr) // 2):
            dpt, n = ev["departments"][0]
            why.append(f"{n} of {len(nr)} not-real incidents come from {dpt}, whose work legitimately involves this data.")
            fixes.append(f"scope the rule away from {dpt}, or give that department a monitor-only rule")
    for rx, reason, fix in KNOWN_PATTERNS:
        if re.search(rx, name or "", re.I):
            why.append(f"Known for this pattern: {reason}.")
            fixes.append(fix)
            break
    d = definition or {}
    if d:
        ev["definition"] = d
        if d.get("custom"):
            if d.get("patterns") and not d.get("phrases"):
                why.append("It is a custom dictionary built only on regular expressions, with no phrases to anchor them.")
                fixes.append("add anchoring phrases or word boundaries to the patterns, and validate check digits where the identifier has them")
            if d.get("phrase_match", "").upper().startswith("MATCH_ANY") and (d.get("phrases") or 0) > 20:
                why.append(f"It matches on any one of {d['phrases']} phrases (match-any), so a single common word is enough.")
                fixes.append("switch to match-all for the phrases that must co-occur, or split the list")
            if not d.get("proximity_enabled") and d.get("patterns") and d.get("phrases"):
                why.append("Proximity is off: its phrases and patterns do not have to appear near each other.")
                fixes.append("turn on proximity so the identifier must sit close to its keyword")
        else:
            conf = str(d.get("predefined_confidence") or "").upper()
            if conf and ("LOW" in conf or "MEDIUM" in conf):
                why.append(f"It runs at {conf.replace('CONFIDENCE_LEVEL_', '').lower()} confidence, which accepts the identifier without context.")
                fixes.append("raise the predefined dictionary's confidence to high (the variant that needs supporting context)")
        if d.get("confidence_threshold") is not None:
            ev["confidence_threshold"] = d["confidence_threshold"]
    if not why:
        why.append("The analysts closed most of its matches as not real; the incidents do not show a single cause.")
    if not fixes:
        fixes.append("raise the match count, add an exclusion for the sanctioned application, or pair the dictionary with an identifier in the engine")
    fix = "; ".join(dict.fromkeys(fixes))
    return {"why": why, "fix": fix[0].upper() + fix[1:] + ".", "evidence": ev}


# ── report ─────────────────────────────────────────────────────────────
def generate(client, *, days: int = 30, settings: Optional[Dict[str, Any]] = None, log=None) -> Dict[str, Any]:
    """The Detection Health report for one tenant: incidents from
    Workflow Automation, rules from the tenant inventory, metrics and
    findings. Never raises; read problems are listed in `errors`."""
    _log = log or (lambda m: None)
    s = dict(DEFAULTS, **(settings or {}))
    days = int(days or s["days"])
    errors: List[str] = []
    _log(f"Reading Workflow Automation incidents for the last {days} days…")
    incidents, errs = fetch_incidents(client, days, _log)
    errors.extend(errs)
    rules: List[Dict[str, Any]] = []
    definitions: Dict[str, Dict[str, Any]] = {}
    try:
        from pack_removal import inventory
        inv = inventory(client)
        rules = inv.get("rules") or []
        definitions = inv.get("dictionaries") or {}
        for ch, err in (inv.get("errors") or {}).items():
            if err:
                errors.append(f"{ch} rules could not be listed: {err}")
    except Exception as e:  # noqa: BLE001
        errors.append(f"rule inventory failed: {str(e)[:200]}")
    _log(f"{len(incidents)} incident(s), {len(rules)} rule(s); evaluating…")
    ev = evaluate(incidents, rules, s, definitions=definitions)
    delivery = incident_delivery(client)
    errors.extend(delivery.pop("errors", []))
    ev["delivery"] = delivery
    if delivery["path"] == "none" and not incidents:
        ev["findings"].insert(0, {"kind": "no_incident_delivery", "severity": "medium", "name": "Incident delivery", "channel": "web",
                                  "text": delivery["explain"] + " Enable 'Zscaler Incident Receiver' (cloud-to-cloud) or an ICAP server on the rules.",
                                  "proposal": "enable_incident_forwarding"})
    for i in incidents:
        i.pop("_created", None)
    ev.update({"days": days, "incident_count": len(incidents), "errors": errors,
               "read": {"incidents": not any("incident search" in e or "Workflow Automation" in e for e in errors), "rules": bool(rules)},
               "sources": {"incidents": "Workflow Automation: POST /zwa/dlp/v1/incidents/search",
                           "rules": "ZIA: /webDlpRules, /endpointDlpRules, /casbDlpRules, /emailDlpRules"}})
    return ev


def to_markdown(rep: Dict[str, Any], label: str = "") -> str:
    s = rep.get("summary") or {}
    lines = [f"# Detection Health{' — ' + label if label else ''}", "",
             f"{rep.get('incident_count', 0)} incident(s) in the last {rep.get('days')} days: {s.get('closed', 0)} closed, {s.get('not_real', 0)} not real "
             f"({s.get('fp_rate_pct') if s.get('fp_rate_pct') is not None else '–'}% over the {rep.get('settings', {}).get('fp_window_days')}-day window). "
             f"{s.get('rules', 0)} rules: {s.get('noisy_rules', 0)} noisy, {s.get('dead_rules', 0)} dead, {s.get('promotable_rules', 0)} promotable; "
             f"{s.get('noisy_dictionaries', 0)} noisy dictionaries.", ""]
    if rep.get("findings"):
        lines.append("## Findings")
        for f in rep["findings"]:
            lines.append(f"- [{f['severity']}] {f['text']}")
        lines.append("")
    lines.append("## Rules")
    lines.append("| Rule | Channel | State | Incidents | Closed | Not real | FP % | Status |")
    lines.append("|---|---|---|---:|---:|---:|---:|---|")
    for r in rep.get("rules", []):
        lines.append(f"| {r['name']} | {r.get('channel') or ''} | {r.get('state') or ''} | {r['incidents']} | {r['closed']} | {r['not_real']} | "
                     f"{r['fp_rate_pct'] if r['fp_rate_pct'] is not None else '–'} | {r['status']} |")
    lines.append("")
    lines.append("## Dictionaries")
    lines.append("| Dictionary | Incidents | Closed | Not real | FP % | Why it is noisy | Fix |")
    lines.append("|---|---:|---:|---:|---:|---|---|")
    for d in rep.get("dictionaries", []):
        lines.append(f"| {d['name']} | {d['incidents']} | {d['closed']} | {d['not_real']} | {d['fp_rate_pct'] if d['fp_rate_pct'] is not None else '–'} | "
                     f"{' '.join(d.get('why') or [])} | {d.get('fix') or ''} |")
    if rep.get("errors"):
        lines += ["", "## Read problems"] + [f"- {e}" for e in rep["errors"]]
    return "\n".join(lines)


# ── incident delivery: how incidents reach Workflow Automation ──────────
def incident_delivery(client) -> Dict[str, Any]:
    """The two ways a DLP match becomes an incident an analyst can act on:
    cloud-to-cloud forwarding (the rule sends to the Zscaler Incident
    Receiver in the cloud, no appliance) or an on-premises Incident
    Receiver reached over ICAP. Reads the enabled Web DLP rules and the
    receivers the tenant has configured, and says which path is in use —
    or that neither is, which is why a tenant can have matches but no
    incidents."""
    out: Dict[str, Any] = {"path": "none", "rules_enabled": 0, "rules_cloud": 0, "rules_icap": 0, "rules_silent": [],
                           "receivers": [], "icap_servers": [], "errors": []}
    zia = getattr(client, "zia", None)
    if zia is None:
        out["errors"].append("no ZIA client")
        return out
    rules: List[Dict[str, Any]] = []
    try:
        from ssl_flow import normalize_dlp_rule
        import pack_channels as pc
        data, err = pc._nx(zia.dlp_web_rules.list_rules())
        if err:
            out["errors"].append(f"Web DLP rules could not be read: {str(err)[:200]}")
        for r in data or []:
            raw = r.as_dict() if hasattr(r, "as_dict") else (r if isinstance(r, dict) else {k: v for k, v in vars(r).items() if not k.startswith("_")})
            rules.append(normalize_dlp_rule(raw))
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"Web DLP rules could not be read: {str(e)[:200]}")
    enabled = [r for r in rules if r.get("enabled")]
    out["rules_enabled"] = len(enabled)
    out["rules_cloud"] = sum(1 for r in enabled if r.get("incident_receiver") and not r.get("icap_server"))
    out["rules_icap"] = sum(1 for r in enabled if r.get("icap_server"))
    out["rules_silent"] = [r["name"] for r in enabled if not r.get("incident_receiver") and not r.get("icap_server")][:40]
    res = getattr(zia, "dlp_resources", None)
    for attr, key, label in (("list_dlp_incident_receiver", "receivers", "incident receivers"), ("list_dlp_icap_servers", "icap_servers", "ICAP servers")):
        fn = getattr(res, attr, None) if res is not None else None
        if fn is None:
            continue
        try:
            data, _resp, err = fn()
            if err:
                out["errors"].append(f"{label} could not be listed: {str(err)[:160]}")
                continue
            for item in data or []:
                out[key].append({"name": str(_g(item, "name", default="") or ""), "url": str(_g(item, "url", default="") or ""),
                                 "status": str(_g(item, "status", default="") or "")})
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"{label} could not be listed: {str(e)[:160]}")
    if out["rules_icap"] and out["rules_cloud"]:
        out["path"] = "both"
    elif out["rules_icap"]:
        out["path"] = "icap"
    elif out["rules_cloud"]:
        out["path"] = "cloud"
    out["explain"] = {
        "cloud": "Cloud-to-cloud forwarding: the rules send the match and the file to the Zscaler Incident Receiver in the cloud; Workflow Automation reads incidents from there. No appliance to run.",
        "icap": "On-premises Incident Receiver: the rules send the match and the file over ICAP to an Incident Receiver you host; Workflow Automation reads incidents from it.",
        "both": "Some rules forward cloud-to-cloud and some over ICAP to an on-premises Incident Receiver; both feed Workflow Automation.",
        "none": "No enabled Web DLP rule forwards to an Incident Receiver, cloud or on-premises: matches are logged but never become incidents, so Workflow Automation has nothing to show and this report has no verdicts to learn from.",
    }[out["path"]]
    return out
