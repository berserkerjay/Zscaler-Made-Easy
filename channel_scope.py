"""Channel ownership, declared on the Scope page, applied to the assessment.

The Scope page lists the Zscaler data-security channels (Inline Web DLP,
Endpoint DLP, Email DLP, ...) and the operator marks each one:

- **zscaler**: the customer runs it on Zscaler. Its checks run as usual,
  and so do those of its prerequisites (PREREQUISITES).
- **alternative**: another product covers it. Its checks are not run: the
  tenant is not read for them and they are hidden (not shown, outside
  the score and the coverage; one line counts them). Scoring a
  customer's Zscaler tenant for a channel they knowingly bought elsewhere
  would only produce noise.
- **gap** (not ticked): nothing covers it, and the operator did not put it
  in scope. Its checks are not run either: every read counts against the
  tenant's ZIA API rate limit, so the assessment reads only what was put
  in scope. They are hidden the same way.

A check that belongs to several channels runs when any of them is on
Zscaler. A check that *reads* a channel's own configuration (its rules,
`CHANNEL_READS`) runs only when that channel is on Zscaler, whatever
section it sits in: an unticked channel is never read. Once any channel
is declared, a channel left out of the declaration (or sent with a value
that cannot be read) counts as a gap. With no declaration at all (an MCP
or CLI caller that sends no `channels`) nothing is narrowed: every check
in the selected scopes runs.

**Prerequisites** (PREREQUISITES): some channels cannot work without
another one, so when a channel is on Zscaler its prerequisites are put in
scope too, even when they were not ticked (or were marked alternative):
Inline Web DLP only sees what SSL inspection decrypts, so ticking it
assesses SSL inspection as well. A prerequisite counts as in scope
everywhere (its checks run, its endpoints may be read, the Path analyzer
and the watch read it), and the page and the report say why it was
added ("SSL/TLS Inspection: included because Inline Web DLP needs it").
The saved declaration is never rewritten: the prerequisites are derived
each time (resolve / effective).

**Hidden, not listed**: a check that does not qualify (its channel is
neither on Zscaler nor a prerequisite of one) is not run and not shown
anywhere: not in the findings, the sections, the score, the coverage,
the Word report, the compliance mapping or the exports. The report keeps
only its count, said in one line (hidden_note): "N checks are outside the
selected scope and are not shown."

The declaration travels with the assessment request (`channels`), is
saved on the tenant profile, and comes back in the report as
`channel_coverage` so the dashboard, the JSON export and the Word report
say the same thing."""
from __future__ import annotations

import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

CHOICES = ("zscaler", "alternative", "gap")

# The Scope page's channels (dashboard.js carries their descriptions).
CHANNELS: Dict[str, str] = {
    "web_dlp": "Inline Web DLP",
    "endpoint_dlp": "Endpoint DLP",
    "email_dlp": "Email DLP",
    "saas_casb": "SaaS Security (CASB)",
    "genai_security": "GenAI Security",
    "shadow_it": "Shadow IT Discovery",
    "endpoint_scan": "Endpoint Data Scan",
    "ssl_inspection": "SSL/TLS Inspection",
    "cloud_app_control": "Cloud App Control",
    "device_control": "Device Control",
    "workflow_automation": "Workflow Automation",
}

# The Scope page's DLP channels as policy packs name them (pack_channels):
# the journey's preflight measures a pack only on these, when on Zscaler.
PACK_CHANNELS: Dict[str, str] = {"web_dlp": "web", "endpoint_dlp": "endpoint", "saas_casb": "saas", "email_dlp": "email"}

# Which checks read each channel: whole sections (matched on the section
# name's start) and single check ids. Deliberately narrow: "5 — Endpoint
# DLP" is really the general DLP section (dictionaries, engines, EDM, IDM,
# web DLP rules) despite its name, so only its ZDP-install check belongs
# to the Endpoint DLP channel. A channel with no entry (Shadow IT
# Discovery) is recorded in the report but changes nothing that runs.
CHANNEL_CHECKS: Dict[str, Dict[str, Sequence[str]]] = {
    "web_dlp": {"sections": ("Ch.A — Inline Web",), "ids": ("MC.1", "8.5")},
    "endpoint_dlp": {"sections": ("Ch.B — Endpoint",), "ids": ("3.2", "5.1", "5.4", "9.1", "10.1", "MC.2", "MC.8", "8.1", "8.2", "8.3")},
    "email_dlp": {"sections": ("Ch.D — Email DLP",), "ids": ("MC.4", "MC.9", "8.9")},
    "saas_casb": {"sections": ("Ch.C — SaaS Security",), "ids": ("MC.3", "MC.10", "8.10")},
    "genai_security": {"sections": ("Ch.E — GenAI", "GenAI —"), "ids": ("MC.7", "8.8")},
    "shadow_it": {"sections": (), "ids": ()},
    "endpoint_scan": {"sections": (), "ids": ("MC.6", "MC.11")},
    "ssl_inspection": {"sections": ("4 — SSL Policy", "7 — SSL Alignment", "GenAI — SSL Inspection"), "ids": ("5.5", "CA.3", "E.2")},
    "cloud_app_control": {"sections": ("ZIA — Cloud Apps",), "ids": ("E.3",)},
    "device_control": {"sections": (), "ids": ("8.1",)},
    "workflow_automation": {"sections": (), "ids": ("12.4", "12.5", "12.7")},
}


# Hard technical prerequisites: when the key channel is on Zscaler, each
# listed channel is assessed too (its checks run and its endpoints may be
# read), with the reason the page and the report give. Only true
# dependencies belong here, never "nice to have" links: the dependent
# channel cannot do its job on Zscaler without the prerequisite.
PREREQUISITES: Dict[str, Tuple[Tuple[str, str], ...]] = {
    # ZIA's inline DLP engines only see content Zscaler itself decrypts:
    # without SSL inspection every HTTPS upload passes uninspected (the
    # Ch.A check A.2 "SSL+DNI" is the SSL inspection scope check).
    "web_dlp": (("ssl_inspection", "Inline Web DLP can only inspect traffic that SSL inspection decrypts; "
                                   "without it, HTTPS uploads pass uninspected."),),
    # GenAI prompt, upload and download controls act on the decrypted
    # request: without SSL inspection the prompts are invisible (E.2
    # "No SSL — GenAI invisible", AI.5 / AI.6 in "GenAI — SSL Inspection").
    "genai_security": (("ssl_inspection", "GenAI prompt and upload controls act on decrypted traffic; "
                                          "without SSL inspection the prompts are invisible."),),
    # Zscaler Device Control is enforced by the Endpoint DLP module: its
    # rules are Endpoint DLP rules (/zia/endPointDlpRules, removable
    # storage), which fire only where Endpoint DLP is installed (5.1, B.1).
    "device_control": (("endpoint_dlp", "Device Control rules are Endpoint DLP rules and are enforced by the Endpoint DLP "
                                        "module; without Endpoint DLP installed, no device control rule fires."),),
}


def with_prerequisites(ch: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """`ch` (a normalized declaration) with the prerequisites of every
    channel on Zscaler put on Zscaler too, transitively. An added one
    carries `required_by` (the channel ids that need it), `reasons` and
    `declared` (what the Scope page said: gap or alternative). A channel
    the operator ticked as Zscaler is left as it is. Returns a new dict."""
    out: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in (ch or {}).items()}
    queue = [cid for cid, v in out.items() if v.get("choice") == "zscaler"]
    while queue:
        cid = queue.pop(0)
        for pre, reason in PREREQUISITES.get(cid, ()):
            cur = out.get(pre)
            if cur is not None and cur.get("choice") == "zscaler" and "required_by" not in cur:
                continue   # ticked by the operator: no prerequisite note
            if cur is None or "required_by" not in cur:
                cur = cur or {"choice": "gap", "note": "", "name": CHANNELS.get(pre, pre)}
                out[pre] = {"choice": "zscaler", "note": cur.get("note", ""), "name": cur.get("name") or CHANNELS.get(pre, pre),
                            "declared": cur.get("choice", "gap"), "required_by": [], "reasons": []}
                queue.append(pre)
            if cid not in out[pre]["required_by"]:
                out[pre]["required_by"].append(cid)
                out[pre]["reasons"].append(reason)
    return out


def resolve(channels: Any) -> Dict[str, Dict[str, Any]]:
    """normalize() plus the prerequisites (with_prerequisites): what is in
    scope for a tenant read. An empty declaration stays empty."""
    return with_prerequisites(normalize(channels))


def prerequisites(channels: Any) -> List[Dict[str, Any]]:
    """The channels put in scope only as a prerequisite, each with who
    needs it, why, and the one line the page and the report show."""
    ch = effective(channels)
    out: List[Dict[str, Any]] = []
    for cid, v in ch.items():
        if not v.get("required_by"):
            continue
        by = [ch.get(r, {}).get("name") or CHANNELS.get(r, r) for r in v["required_by"]]
        need = " and ".join(by) + (" need it" if len(by) > 1 else " needs it")
        out.append({"id": cid, "name": v["name"], "required_by": list(v["required_by"]), "required_by_names": by,
                    "reasons": list(v["reasons"]), "declared": v.get("declared", "gap"),
                    "note": f"{v['name']}: included because {need}."})
    return out


def is_hidden(result: Any) -> bool:
    """A result that does not qualify for the selected scope (an
    out-of-scope placeholder): never shown, never counted."""
    return isinstance(result, dict) and bool(result.get("out_of_scope"))


def visible(results: Any) -> Tuple[List[Dict[str, Any]], int]:
    """(the results to show, how many were hidden as outside the scope)."""
    shown: List[Dict[str, Any]] = []
    hidden = 0
    for r in results or []:
        if is_hidden(r):
            hidden += 1
        elif isinstance(r, dict):
            shown.append(r)
    return shown, hidden


def hidden_note(n: Any) -> str:
    """The single line that stands for every hidden check ('' for none)."""
    try:
        n = int(n or 0)
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        return ""
    verb = "is" if n == 1 else "are"
    return f"{n} check{'' if n == 1 else 's'} {verb} outside the selected scope and {verb} not shown."


# The tenant endpoints that hold a channel's own configuration, and the
# channels each belongs to (any of them on Zscaler lets it be read: the
# SaaS tenant list serves both SaaS Security and Email DLP; the Endpoint
# DLP rules hold Device Control too; the DLP global
# options serve the three DLP channels). Shared objects (dictionaries,
# engines, URL categories, ...) are not a channel's and stay readable.
ENDPOINT_CHANNELS: Dict[str, Tuple[str, ...]] = {
    "/zia/webDlpRules": ("web_dlp",),
    "/zia/webDlpGlobalOptions": ("web_dlp", "endpoint_dlp", "email_dlp"),
    "/zia/endPointDlpRules": ("endpoint_dlp", "device_control"),
    "/zia/emailDlpRules": ("email_dlp",),
    "/zia/casbDlpRules": ("saas_casb",),
    "/zia/casbTenant": ("saas_casb", "email_dlp"),
    "/zia/sslInspectionRules": ("ssl_inspection",),
    "/zia/cloudApplicationRules": ("cloud_app_control",),
    "/zia/tenancyRestrictionProfile": ("cloud_app_control",),
}

# Which checks read each of those endpoints. tests/test_no_implicit_reads.py
# runs every check against a recording client (list-, dict- and
# error-shaped answers) and fails when a check reads one of them without
# being listed here, so this cannot drift.
CHANNEL_READS: Dict[str, Sequence[str]] = {
    "/zia/webDlpRules": ("4.8", "5.3", "5.7", "5.9", "5.13", "5.16", "5.17", "5.19", "5.20", "MC.1", "MC.12", "8.5", "8.6",
                         "8.8", "8.12", "12.1", "12.3", "12.6", "12.12", "12.15", "A.1", "A.3", "A.4", "A.5", "A.8", "A.9",
                         "A.10", "A.14", "B.10", "E.4", "E.5", "E.6", "E.7", "AI.1", "AI.7", "AI.8", "AI.9", "AI.10", "AI.17",
                         "AI.18", "AUTO-TF-01", "AUTO-TF-02", "AUTO-TF-03", "AUTO-TF-04", "AUTO-TF-05"),
    "/zia/webDlpGlobalOptions": ("5.17", "5.19", "5.20", "8.12", "A.9", "B.10", "D.9"),
    "/zia/endPointDlpRules": ("MC.2", "8.1", "8.2", "8.3", "8.4", "8.6", "12.1", "12.3", "12.12", "A.14", "B.5", "B.6", "B.7",
                              "B.8", "B.9", "B.11", "B.16"),
    "/zia/emailDlpRules": ("MC.4", "8.9", "D.2", "D.3", "D.4", "D.5", "D.6", "D.7", "D.8", "D.9"),
    "/zia/casbDlpRules": ("MC.3", "8.10", "C.2", "C.3", "C.4", "C.5", "C.6", "C.7", "C.8"),
    "/zia/casbTenant": ("C.1", "C.3", "D.1", "D.6"),
    "/zia/sslInspectionRules": ("4.1", "4.3", "4.4", "4.5", "4.6", "4.10", "4.11", "4.13", "4.14", "5.5", "MC.12", "6.4", "6.5",
                                "7.2", "7.3", "9.2", "9.3", "A.2", "E.2", "CA.3", "AI.1", "AI.5", "AI.6", "AUTO-TF-01"),
    "/zia/cloudApplicationRules": ("3.7", "4.7", "5.18", "MC.5", "A.6", "A.7", "A.17", "E.1", "E.3", "E.8", "E.9", "E.13", "CA.1",
                                   "CA.2", "CA.3", "CA.4", "CA.5", "AI.3", "AI.8", "AI.14", "AI.15", "AI.20"),
    "/zia/tenancyRestrictionProfile": ("5.18", "A.7", "CA.2", "AI.14"),
}


def endpoint_channels(ep: Any) -> Tuple[str, ...]:
    """The channels whose configuration `ep` (a GET path) holds, else ()."""
    path = str(ep or "").split("?", 1)[0]
    if path.startswith("raw:"):
        path = path[4:]
    for prefix, chans in ENDPOINT_CHANNELS.items():
        if path == prefix or path.startswith(prefix + "/"):
            return chans
    return ()


def channels_read_by(check_id: str) -> List[Tuple[str, ...]]:
    """The channel groups a check reads (one per CHANNEL_READS endpoint)."""
    return [ENDPOINT_CHANNELS[ep] for ep, ids in CHANNEL_READS.items() if str(check_id) in ids]


def normalize(channels: Any) -> Dict[str, Dict[str, str]]:
    """{id: {choice, note, name}} from whatever the browser or a profile
    sent. Unknown choices read as a gap; custom channels are kept by id."""
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(channels, dict):
        return out
    for cid, v in channels.items():
        cid = str(cid).strip()[:64]
        if not cid:
            continue
        if isinstance(v, str):
            v = {"choice": v}
        if not isinstance(v, dict):
            if cid not in CHANNELS:
                continue
            v = {}   # a Scope-page channel sent as null or junk: a gap, never dropped (it would be read)
        choice = str(v.get("choice") or "gap").strip().lower()
        if choice not in CHOICES:
            choice = "gap"
        out[cid] = {"choice": choice, "note": str(v.get("note") or "").strip()[:200],
                    "name": str(v.get("name") or CHANNELS.get(cid) or cid).strip()[:80]}
    return out


def effective(channels: Any) -> Dict[str, Dict[str, str]]:
    """normalize(), and once anything is declared, every Scope-page channel
    the declaration leaves out counts as a gap: only channels marked
    Zscaler are read. An empty declaration stays empty (nothing narrowed);
    a non-empty one is a declaration even when none of its entries can be
    read (a blank key, an unknown id sent as null): every channel is then a
    gap, never "nothing narrowed". The prerequisites of the channels on
    Zscaler are on Zscaler too (with_prerequisites)."""
    ch = normalize(channels)
    if ch or (isinstance(channels, dict) and channels):
        for cid, name in CHANNELS.items():
            ch.setdefault(cid, {"choice": "gap", "note": "", "name": name})
    return with_prerequisites(ch)


def _matches(spec: Dict[str, Sequence[str]], check_id: str, section: str) -> bool:
    if check_id in spec.get("ids", ()):
        return True
    return any(section == s or section.startswith(s) for s in spec.get("sections", ()))


def in_scope(channels: Any) -> List[str]:
    """The channel ids on Zscaler, ticked or added as a prerequisite: the
    only ones the tenant is read for."""
    return [cid for cid, v in resolve(channels).items() if v["choice"] == "zscaler"]


def pack_targets(channels: Any) -> List[str]:
    """The pack channels (web / endpoint / saas / email) on Zscaler."""
    return [PACK_CHANNELS[cid] for cid in in_scope(channels) if cid in PACK_CHANNELS]


def channel_of_check(check_id: str, section: str, channels: Dict[str, Dict[str, str]]) -> Optional[str]:
    """The first of `channels` whose checks include this one, else None."""
    for cid in channels:
        spec = CHANNEL_CHECKS.get(cid)
        if spec and _matches(spec, str(check_id), str(section or "")):
            return cid
    return None


def skipped_result(check_id: str, section: str, label: str, cid: str, ch: Dict[str, str]) -> Dict[str, Any]:
    """The result a not-run check is reported with: INFO, flagged out of
    scope, saying which channel and why. It carries its own plain-English
    block so the findings row explains itself."""
    note = f" ({ch['note']})" if ch.get("note") else ""
    name = ch.get("name") or CHANNELS.get(cid) or cid
    if ch.get("choice") == "gap":
        return {
            "id": check_id, "section": section, "label": label, "status": "INFO",
            "detail": (f"Not in scope: {name} was not ticked on the Scope page (a gap: nothing covers it). "
                       "The tenant was not read for this check and it is outside the score."),
            "out_of_scope": True, "channel": cid, "gap": True,
            "plain": {"found": f"Not read: {name} was left out of scope on the Scope page.",
                      "means": "", "do": "",
                      "outcome": "Tick the channel as Zscaler on the Scope page and run again to assess it."},
        }
    return {
        "id": check_id, "section": section, "label": label, "status": "INFO",
        "detail": (f"Not in scope: {name} is covered by an alternative solution{note}, as declared on the Scope page. "
                   "The tenant was not read for this check and it is outside the score."),
        "out_of_scope": True, "channel": cid,
        "plain": {"found": f"Not read: {name} is covered outside Zscaler{note}.",
                  "means": "", "do": "",
                  "outcome": "Declared on the Scope page. Mark the channel as Zscaler there and run again to assess it."},
    }


def partition(checks: Sequence[Tuple], channels: Any) -> Tuple[List[Tuple], List[Dict[str, Any]], List[Tuple[str, int]]]:
    """Split the check tuples (id, section, label, fn) into the ones to run
    and the results of the ones out of scope (alternative or gap), plus
    the order to merge them back in (`merge`) so the findings keep their
    section order. A check of a Zscaler channel always runs."""
    ch = effective(channels)
    out = {k: v for k, v in ch.items() if v["choice"] != "zscaler"}
    on = {k: v for k, v in ch.items() if v["choice"] == "zscaler"}
    to_run: List[Tuple] = []
    skipped: List[Dict[str, Any]] = []
    order: List[Tuple[str, int]] = []
    for chk in checks:
        check_id, section, label = str(chk[0]), str(chk[1]), str(chk[2])
        cid = channel_of_check(check_id, section, out) if out else None
        if cid and channel_of_check(check_id, section, on):
            cid = None
        if not cid and out:
            # It reads a channel's own configuration: that channel must be on Zscaler.
            for group in channels_read_by(check_id):
                if not any(c in on for c in group):
                    cid = next(c for c in group if c in out)
                    break
        if cid:
            order.append(("skip", len(skipped)))
            skipped.append(skipped_result(check_id, section, label, cid, out[cid]))
        else:
            order.append(("run", len(to_run)))
            to_run.append(chk)
    return to_run, skipped, order


class ScopedClient:
    """The assessment client as the checks see it: a GET of a channel's
    own configuration whose channel is not on Zscaler is refused without
    touching the tenant (the backstop to partition(): an unticked channel
    is never read, even by a code path the check map missed). Everything
    else goes to the real client. With no declaration nothing is refused."""

    # Answers that mean the tenant did not answer the read (rate limited,
    # unavailable, timed out or unreachable): a check built on one cannot
    # judge anything (unanswered()).
    UNANSWERED = frozenset({0, 429, 502, 503, 504})

    def __init__(self, client: Any, channels: Any):
        ch = effective(channels)
        self._client = client
        self._declared = bool(ch)
        self._on = {k for k, v in ch.items() if v["choice"] == "zscaler"}
        self.refused: List[str] = []
        self._tl = threading.local()

    def begin(self) -> None:
        """Start recording the reads of the check running on this thread."""
        self._tl.unanswered = []

    def unanswered(self) -> List[Tuple[str, int]]:
        """(endpoint, code) of this thread's reads since begin() that the
        tenant did not answer."""
        return list(getattr(self._tl, "unanswered", None) or [])

    def get(self, ep, *a, **k):
        chans = endpoint_channels(ep)
        if self._declared and chans and not any(c in self._on for c in chans):
            self.refused.append(str(ep))
            return ({"error": "not in scope",
                     "message": "This channel was not ticked on the Scope page; the tenant was not read."}, 0)
        res = self._client.get(ep, *a, **k)
        try:
            code = res[1]
        except Exception:  # noqa: BLE001
            code = None
        rec = getattr(self._tl, "unanswered", None)
        if rec is not None and code in self.UNANSWERED:
            rec.append((str(ep), int(code)))
        return res

    def __getattr__(self, name):
        return getattr(self._client, name)


def merge(order: Iterable[Tuple[str, int]], run_results: Sequence[Dict[str, Any]], skipped: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [run_results[i] if kind == "run" else skipped[i] for kind, i in order]


def coverage(channels: Any, skipped: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """What was declared and what it did, for the report: the channels on
    Zscaler (ticked, or added as a prerequisite with the reason), and how
    many checks were left out as outside the scope. The note names only
    what was assessed; what was left out is one count (hidden_note), never
    a list. The alternative and gap channels stay in the data (the JSON
    export) for the profile, not on the page."""
    ch = effective(channels)
    skipped = list(skipped)
    per: Dict[str, int] = {}
    for r in skipped:
        per[str(r.get("channel"))] = per.get(str(r.get("channel")), 0) + 1
    by: Dict[str, List[Dict[str, Any]]] = {"zscaler": [], "alternative": [], "gap": []}
    for cid, v in ch.items():
        row: Dict[str, Any] = {"id": cid, "name": v["name"], "note": v["note"], "checks_not_in_scope": per.get(cid, 0)}
        if v.get("required_by"):
            row["prerequisite_of"] = list(v["required_by"])
            row["declared"] = v.get("declared", "gap")
        by[v["choice"]].append(row)
    declared = bool(ch)
    pre = prerequisites(channels) if declared else []
    hidden = len(skipped)
    if not declared:
        note = "No channel ownership was declared on the Scope page: every check in the selected scopes ran."
    else:
        ticked = [r["name"] for r in by["zscaler"] if not r.get("prerequisite_of")]
        note = ("Channels assessed on Zscaler, as declared on the Scope page: " + (", ".join(ticked) if ticked else "none ticked") + "."
                + "".join(" " + p["note"] for p in pre))
    return {"declared": declared, "zscaler": by["zscaler"], "alternative": by["alternative"], "gaps": by["gap"],
            "prerequisites": pre, "not_in_scope": hidden, "hidden": hidden, "hidden_note": hidden_note(hidden), "note": note}
