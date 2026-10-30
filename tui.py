"""Terminal UI: `zscaler-made-easy tui` (and the old `dlp-check tui`).

A keyboard-only front end for a terminal, over SSH too, built on the
standard library's curses. It is a client of the app's own server (the one
`zscaler-made-easy` starts, by default http://127.0.0.1:8000): every view
calls the same API the web pages call, so the Scope rule, the UI token,
write mode, the writer check, the named assessor, the typed confirmation,
the plan hash, the re-read before each write, the read-back, Undo and the
audit log are exactly the web app's. The TUI holds no tenant secret and
writes nothing by itself.

Views (read-only unless said):
  1 Tenant           pick a saved tenant profile, or the sample tenant
  2 Assessment       run the assessment (the profile's Scope selection) and show the score
  3 Findings         the last run's failed and review checks, with the fix
  4 Path analyzer    one destination: the verdict and each step
  5 Test a list      a list of destinations from a text or CSV file
  6 Snapshots        the profile's snapshots; compare one with the live tenant
  7 Preview a plan   a Bulk changes operation (JSON file) or a migration
                     plan: the server's preview, item by item, with its hash
  8 Apply            the previewed plan, after you type the confirmation
                     phrase and your name; the server checks every gate

No secret is shown: the UI token is read from ui_token.txt (or
ZSCALER_UI_TOKEN) and never printed, keys that name a secret are masked,
and every string from the tenant or the server is stripped of control and
escape characters before it reaches the terminal.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

APP_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_FILE_BYTES = 1024 * 1024
MAX_LINE = 400
SAMPLE_SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"]
SAMPLE_CHANNELS = {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "genai_security", "shadow_it",
                                          "ssl_inspection", "cloud_app_control")}
_SECRET_KEY = re.compile(r"(secret|password|passwd|token|api_?key|private|otp|credential|cookie|authorization)", re.I)
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁠-⁩﻿]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*(\x07|\x1b\\)?")


class ApiError(RuntimeError):
    """The server refused or could not be reached (its plain reason)."""


# ---------------------------------------------------------------------------
# Text safety
# ---------------------------------------------------------------------------

def clean(text: Any, limit: int = MAX_LINE) -> str:
    """One line for the terminal: escape sequences and control characters
    removed (a tenant string cannot move the cursor or recolour the screen)."""
    s = _ANSI.sub("", str(text if text is not None else ""))
    s = _CONTROL.sub(" ", s.replace("\t", " ").replace("\r", " ").replace("\n", " "))
    return s[:limit]


def redact(obj: Any) -> Any:
    """A copy with every value under a secret-looking key masked."""
    if isinstance(obj, dict):
        return {k: ("•••" if isinstance(k, str) and _SECRET_KEY.search(k) and v not in (None, "", False) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


# ---------------------------------------------------------------------------
# Talking to the server
# ---------------------------------------------------------------------------

def default_url() -> str:
    port = (os.environ.get("ZSCALER_PORT") or "8000").strip()
    return f"http://127.0.0.1:{port if port.isdigit() else '8000'}"


def check_url(url: str) -> str:
    """The server address: http only to this computer (the token must not
    cross a network in clear), https anywhere."""
    u = urlparse(str(url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ApiError("The server address must be http://127.0.0.1:<port> (or an https:// address).")
    if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ApiError("Over plain http the TUI talks only to this computer (127.0.0.1); use https:// for a server elsewhere.")
    return f"{u.scheme}://{u.netloc}"


def read_token(token_file: str = "") -> str:
    """The UI token: ZSCALER_UI_TOKEN, else ui_token.txt (next to the app or
    in DLP_CHECK_UI_TOKEN_DIR). Never printed."""
    t = (os.environ.get("ZSCALER_UI_TOKEN") or "").strip()
    if t:
        return t
    paths = [token_file] if token_file else [os.path.join(os.environ.get("DLP_CHECK_UI_TOKEN_DIR") or APP_DIR, "ui_token.txt")]
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read(4096).strip()
        except OSError:
            continue
    return ""


class HttpTransport:
    """requests against the running server, the UI token in its header."""

    def __init__(self, base_url: str, token: str, timeout: float = 120.0):
        import requests
        import security
        self.base = check_url(base_url)
        self.s = requests.Session()
        self.s.trust_env = False   # straight to the app, never through a proxy
        if token:
            self.s.headers[security.UI_TOKEN_HEADER] = token
        self.timeout = timeout

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        try:
            r = self.s.request(method, self.base + path, json=body, timeout=self.timeout)
        except Exception as e:  # noqa: BLE001
            raise ApiError(f"The app's server did not answer at {self.base} ({type(e).__name__}). Start it with zscaler-made-easy.") from None
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {"detail": clean(r.text, 200)}

    def stream(self, path: str, body: Dict[str, Any]):
        try:
            with self.s.post(self.base + path, json=body, stream=True, timeout=self.timeout) as r:
                if r.status_code != 200:
                    try:
                        detail = r.json().get("detail")
                    except ValueError:
                        detail = r.text[:200]
                    raise ApiError(clean(detail or f"HTTP {r.status_code}", 300))
                for line in r.iter_lines(decode_unicode=True):
                    yield line or ""
        except ApiError:
            raise
        except Exception as e:  # noqa: BLE001
            raise ApiError(f"The app's server did not answer ({type(e).__name__}).") from None


class Api:
    """The calls the views make. Each sends the chosen tenant (a profile, or
    the sample tenant's cookie) and lets the profile's Scope selection decide
    what is read; the server refuses what is not in scope."""

    def __init__(self, transport: Any):
        self.t = transport
        self.profile: Optional[Dict[str, Any]] = None
        self.sample = False
        self.report: Optional[Dict[str, Any]] = None
        self.prepared: Optional[Dict[str, Any]] = None
        self.spec: Optional[Dict[str, Any]] = None

    def _ok(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        code, data = self.t.request(method, path, body)
        if code >= 400:
            d = data.get("detail") if isinstance(data, dict) else data
            if isinstance(d, dict):
                d = d.get("cause") or d.get("message") or json.dumps(d)[:200]
            raise ApiError(clean(d or f"HTTP {code}", 300))
        return data

    # who and what
    def tenant_body(self) -> Dict[str, Any]:
        if self.sample:
            return {"scopes": SAMPLE_SCOPES, "channels": SAMPLE_CHANNELS, "from_page": True}
        if self.profile:
            return {"profile_id": self.profile["id"], "customer_id": str(self.profile.get("customer_id") or ""), "from_page": False}
        raise ApiError("Pick a tenant first (1 Tenant).")

    def label(self) -> str:
        if self.sample:
            return "Sample tenant (Larkspur Freight, nothing here is real)"
        if self.profile:
            return clean(f"{self.profile.get('name') or self.profile.get('org_name') or 'profile'}", 80)
        return "no tenant picked"

    def profiles(self) -> List[Dict[str, Any]]:
        return list(self._ok("GET", "/api/tenant-profiles").get("profiles") or [])

    def use_profile(self, p: Dict[str, Any]) -> None:
        if self.sample:
            self._ok("POST", "/api/offline/leave", {})
        self.sample, self.profile, self.report = False, p, None

    def use_sample(self) -> None:
        self._ok("POST", "/api/offline/sample", {})
        self.sample, self.profile, self.report = True, None, None

    def write_mode(self) -> Dict[str, Any]:
        return self._ok("GET", "/api/write-mode")

    # read-only views
    def assess(self, on_progress: Callable[[str], None] = lambda m: None) -> Dict[str, Any]:
        body = dict(self.tenant_body())
        if self.profile:
            body.update(scopes=list(self.profile.get("scopes") or []), channels=dict(self.profile.get("channels") or {}),
                        org_name=str(self.profile.get("org_name") or "Unknown"), assessor=str(self.profile.get("assessor") or "Unknown"))
        if not body.get("scopes"):
            raise ApiError("This profile has nothing in scope: tick the scopes on the web app's Scope page and save the profile.")
        body["scope"] = ""
        event, report = "", None
        for line in self.t.stream("/api/assess", body):
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                try:
                    data = json.loads(line[5:])
                except ValueError:
                    continue
                if event == "progress" and isinstance(data, dict):
                    on_progress(f"Checks: {data.get('completed', 0)} of {data.get('total', 0)} ({data.get('pct', 0)}%)")
                elif event == "error":
                    raise ApiError(clean((data or {}).get("message") or "The assessment failed.", 300))
                elif event == "complete":
                    report = data
        if not isinstance(report, dict):
            raise ApiError("The assessment ended without a result.")
        self.report = report
        return report

    def path(self, destination: str) -> Dict[str, Any]:
        return self._ok("POST", "/api/path-analyzer", dict(self.tenant_body(), destination=str(destination)[:2048]))

    def job(self, start: Dict[str, Any], on_progress: Callable[[str], None] = lambda m: None, timeout: float = 900.0,
            sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
        jid = str(start.get("job_id") or "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{4,80}", jid):
            raise ApiError("The server did not start the job.")
        since, t0 = 0, time.monotonic()
        while time.monotonic() - t0 < timeout:
            snap = self._ok("GET", f"/api/dlp-packs/jobs/{jid}?since={since}")
            for ln in snap.get("logs") or []:
                on_progress(clean(ln, 200))
            since = int(snap.get("next") or since)
            if snap.get("status") in ("done", "failed", "stopped"):
                if snap.get("status") != "done":
                    raise ApiError(clean(snap.get("error") or f"The job {snap.get('status')}.", 300))
                return snap.get("result") or {}
            sleep(0.5)
        raise ApiError("The job is still running; look at it in the web app.")

    def bulk_test(self, text: str, on_progress: Callable[[str], None] = lambda m: None) -> Dict[str, Any]:
        start = self._ok("POST", "/api/bulk-test/start", dict(self.tenant_body(), text=text, lookup=False))
        return self.job(start, on_progress)

    def snapshots(self) -> List[Dict[str, Any]]:
        data = self._ok("GET", "/api/tenant-profiles")
        if self.profile:
            p = next((x for x in data.get("profiles") or [] if x.get("id") == self.profile.get("id")), {})
            return list(p.get("snapshots") or [])
        return list(data.get("unfiled_snapshots") or [])

    def compare(self, snapshot_id: str, on_progress: Callable[[str], None] = lambda m: None) -> Dict[str, Any]:
        start = self._ok("POST", "/api/tenant-profiles/snapshots/compare/start", dict(self.tenant_body(), snapshot_id=snapshot_id))
        return self.job(start, on_progress)

    # plans: preview (read-only) and apply (the server's gates)
    def preview(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        out = self._ok("POST", "/api/operations/preview", dict(self.tenant_body(), operation=spec))
        self.spec, self.prepared = spec, out
        return out

    def apply(self, confirm_text: str, assessor: str) -> Dict[str, Any]:
        if not self.prepared or not self.spec:
            raise ApiError("Preview a plan first (7).")
        body = dict(self.tenant_body(), operation=self.spec, plan_hash=self.prepared.get("plan_hash") or "", confirm=True,
                    confirm_text=confirm_text, assessor=assessor)
        code, data = self.t.request("POST", "/api/operations/apply", body)
        if code == 409 and isinstance(data, dict):
            return data
        if code >= 400:
            d = data.get("detail") if isinstance(data, dict) else data
            raise ApiError(clean(d or f"HTTP {code}", 300))
        self.prepared = None
        return data


# ---------------------------------------------------------------------------
# Plans from files
# ---------------------------------------------------------------------------

def read_text_file(path: str, what: str = "file") -> str:
    p = os.path.expanduser(str(path or "").strip())
    if not p:
        raise ApiError(f"Give the {what}'s path.")
    try:
        st = os.stat(p)
    except OSError:
        raise ApiError(f"No such {what}: {clean(p, 120)}") from None
    if not os.path.isfile(p):
        raise ApiError(f"{clean(p, 120)} is not a file.")
    if st.st_size > MAX_FILE_BYTES:
        raise ApiError(f"The {what} is larger than {MAX_FILE_BYTES // 1024} KB.")
    with open(p, "rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ApiError(f"The {what} is not UTF-8 text.") from None


def specs_from_file(text: str) -> List[Tuple[str, Dict[str, Any]]]:
    """The operations a JSON file holds: one Bulk changes operation ({type,
    ...}), or a migration plan (its ZIA import and ZPA builder specs)."""
    try:
        doc = json.loads(text)
    except ValueError:
        raise ApiError("The file is not JSON.") from None
    if not isinstance(doc, dict):
        raise ApiError("The file must hold one JSON object.")
    if doc.get("format") == "panos-migration-plan":
        out = []
        if isinstance(doc.get("zia"), dict):
            out.append(("ZIA firewall import", doc["zia"]))
        zpa = doc.get("zpa") if isinstance(doc.get("zpa"), dict) else {}
        for k, label in (("segments_spec", "ZPA application segments"), ("policies_spec", "ZPA access rule")):
            if isinstance(zpa.get(k), dict):
                out.append((label, zpa[k]))
        if not out:
            raise ApiError("The migration plan has nothing to import.")
        return out
    if isinstance(doc.get("type"), str):
        return [(clean(doc["type"], 60), doc)]
    raise ApiError("Not a Bulk changes operation (no 'type') or a migration plan.")


# ---------------------------------------------------------------------------
# What each view shows (pure: lists of lines)
# ---------------------------------------------------------------------------

def fmt_profiles(rows: List[Dict[str, Any]]) -> List[str]:
    out = []
    for i, p in enumerate(rows, 1):
        last = p.get("last_assessment") or {}
        score = last.get("score") if isinstance(last, dict) else None
        out.append(clean(f"{i:>3}. {p.get('name') or p.get('org_name') or p.get('id')}  ·  {p.get('cloud') or ''}"
                         f"{'  ·  last score ' + str(score) if score is not None else ''}"))
    return out or ["No saved tenant profiles. Save one in the web app (Connect to the tenant), or use the sample tenant."]


def fmt_report(r: Dict[str, Any]) -> List[str]:
    checks = r.get("checks") or []
    by = {}
    for c in checks:
        by[c.get("status")] = by.get(c.get("status"), 0) + 1
    out = [clean(f"Score: {r.get('score') if r.get('score') is not None else 'not assessed'}   Maturity: {(r.get('maturity') or {}).get('level') if isinstance(r.get('maturity'), dict) else r.get('maturity') or ''}"),
           clean(f"Checks: {len(checks)}  ·  " + "  ·  ".join(f"{k}: {v}" for k, v in sorted(by.items(), key=lambda kv: str(kv[0])))), ""]
    secs = r.get("sections") or {}
    if isinstance(secs, dict):
        out.append("Scores by section:")
        for name, s in sorted(secs.items()):
            v = s.get("score") if isinstance(s, dict) else s
            out.append(clean(f"  {v if v is not None else '-':>5}  {name}"))
    return out


def fmt_findings(r: Optional[Dict[str, Any]]) -> List[str]:
    if not r:
        return ["Run the assessment first (2)."]
    out = []
    for status in ("FAIL", "REVIEW"):
        rows = [c for c in r.get("checks") or [] if c.get("status") == status]
        out.append(f"{'Critical findings' if status == 'FAIL' else 'To review'} ({len(rows)})")
        for c in rows:
            out.append(clean(f"  [{c.get('id') or ''}] {c.get('label') or c.get('name') or ''}"))
            for k in ("finding", "detail", "fix", "remediation"):
                if c.get(k):
                    out.append(clean(f"      {k}: {c[k]}"))
        out.append("")
    return out


def fmt_any(obj: Any, indent: int = 0, limit: int = 600) -> List[str]:
    """A JSON answer as indented lines, secrets masked."""
    out: List[str] = []

    def walk(v: Any, pad: int, key: str = "") -> None:
        if len(out) >= limit:
            return
        lead = " " * pad + (f"{clean(key, 60)}: " if key else "")
        if isinstance(v, dict):
            if key:
                out.append(lead.rstrip())
            for k, x in v.items():
                walk(x, pad + (2 if key else 0), str(k))
        elif isinstance(v, list):
            out.append(lead + f"({len(v)})")
            for x in v[:50]:
                walk(x, pad + 2, "-")
        else:
            out.append(clean(lead + str(v)))
    walk(redact(obj), indent)
    return out


def fmt_path(res: Dict[str, Any]) -> List[str]:
    """The Path analyzer's answer: the verdict, then each hop of the trace."""
    d = res.get("destination") if isinstance(res.get("destination"), dict) else {}
    v = res.get("verdict") if isinstance(res.get("verdict"), dict) else {}
    out = [clean(f"Destination: {d.get('host') or d.get('input') or res.get('destination') or ''}"),
           clean(f"Outcome: {v.get('outcome') or ''}  ·  {v.get('headline') or ''}")]
    if v.get("summary"):
        out.append(clean(f"{v['summary']}"))
    if v.get("stops_at"):
        out.append(clean(f"Stops at: {v['stops_at']}"))
    hops = ((res.get("trace") or {}).get("hops") or []) if isinstance(res.get("trace"), dict) else []
    if hops:
        out += ["", "Steps:"]
        for h in hops:
            if isinstance(h, dict):
                out.append(clean(f"  [{h.get('status') or ''}] {h.get('label') or h.get('key') or ''}: {h.get('detail') or ''}"))
    for a in res.get("assumptions") or []:
        out.append(clean(f"Assumed: {a}"))
    return out


def fmt_plan(p: Dict[str, Any]) -> List[str]:
    c = p.get("counts") or {}
    out = [clean(p.get("title") or p.get("type") or "Plan"), clean(f"Status: {p.get('status')}  ·  changes {c.get('change', 0)}, "
                                                                     f"no-ops {c.get('noop', 0)}, excluded {c.get('excluded', 0)}"),
           clean(f"Plan hash: {p.get('plan_hash') or ''}"),
           clean(f"Confirmation phrase: {p.get('confirm_phrase') or '(none: type APPLY)'}"), ""]
    for b in p.get("blockers") or []:
        out.append(clean(f"BLOCKED: {b}"))
    for w in p.get("warnings") or []:
        out.append(clean(f"Note: {w}"))
    out.append("")
    for u in p.get("items") or []:
        o = u.get("object") or {}
        out.append(clean(f"[{u.get('status')}] {o.get('label') or u.get('kind') or ''} {o.get('name') or ''}: {u.get('field')} "
                         f"{json.dumps(redact(u.get('before')), default=str)[:60]} -> {json.dumps(redact(u.get('after')), default=str)[:60]}"))
        if u.get("value"):
            out.append(clean(f"      {u['value']}"))
        if u.get("reason"):
            out.append(clean(f"      {u['reason']}"))
    return out


def fmt_result(r: Dict[str, Any]) -> List[str]:
    c = r.get("counts") or {}
    out = [clean(f"Status: {r.get('status')}"), clean("Counts: " + ", ".join(f"{k} {v}" for k, v in c.items()))]
    for u in r.get("items") or []:
        o = u.get("object") or {}
        out.append(clean(f"[{u.get('status')}] {o.get('name') or ''}: {u.get('reason') or u.get('error') or ''}"))
    if r.get("message"):
        out.append(clean(r["message"]))
    if r.get("inverse"):
        out.append("An Undo is recorded: preview it in the web app's Bulk changes history.")
    return out


def fmt_bulk(r: Dict[str, Any]) -> List[str]:
    rows = r.get("rows") or r.get("results") or []
    out = [clean(f"{len(rows)} destination(s) tested")]
    for x in rows[:500]:
        if isinstance(x, dict):
            out.append(clean(f"  {x.get('destination') or x.get('input') or ''}: {x.get('verdict') or x.get('outcome') or x.get('summary') or ''}"))
    return out if rows else out + fmt_any(r, limit=200)


def fmt_diff(r: Dict[str, Any]) -> List[str]:
    t = r.get("totals") or {}
    out = [clean(f"Compared {r.get('compared', 0)} lists: {t.get('added', 0)} added, {t.get('removed', 0)} removed, {t.get('changed', 0)} changed")]
    for lst in r.get("lists") or r.get("changes") or []:
        if isinstance(lst, dict):
            out.append(clean(f"  {lst.get('label') or lst.get('path') or ''}: +{lst.get('added', 0) if not isinstance(lst.get('added'), list) else len(lst['added'])}"
                             f" -{lst.get('removed', 0) if not isinstance(lst.get('removed'), list) else len(lst['removed'])}"
                             f" ~{lst.get('changed', 0) if not isinstance(lst.get('changed'), list) else len(lst['changed'])}"))
    return out


# ---------------------------------------------------------------------------
# The curses front end
# ---------------------------------------------------------------------------

MENU = [("1", "Tenant: pick a profile or the sample tenant"), ("2", "Run the assessment and show the score"), ("3", "Findings"),
        ("4", "Path analyzer: one destination"), ("5", "Test a list from a file"), ("6", "Snapshots and differences"),
        ("7", "Preview a change plan (JSON file)"), ("8", "Apply the previewed plan"), ("q", "Quit")]
KEY_UP, KEY_DOWN, KEY_PPAGE, KEY_NPAGE = 259, 258, 339, 338
KEY_BACKSPACE, KEY_ENTER = 263, 343


class Tui:
    def __init__(self, scr: Any, api: Api):
        self.scr, self.api = scr, api
        self.status = "Keys: a number to open a view, q to quit. Nothing is changed without a preview and your typed confirmation."

    # drawing
    def _size(self) -> Tuple[int, int]:
        h, w = self.scr.getmaxyx()
        return max(h, 5), max(w, 20)

    def _put(self, y: int, text: str, attr: int = 0) -> None:
        h, w = self._size()
        if 0 <= y < h:
            try:
                self.scr.addnstr(y, 0, clean(text, w - 1).ljust(w - 1), w - 1, attr)
            except Exception:  # noqa: BLE001 - writing the last cell of a terminal raises; harmless
                pass

    def _frame(self, title: str) -> None:
        self.scr.erase()
        self._put(0, f"Zscaler Made Easy · {title} · {self.api.label()}", 0)
        self._put(self._size()[0] - 1, self.status)

    def say(self, msg: str) -> None:
        self.status = clean(msg, 300)
        self._put(self._size()[0] - 1, self.status)
        self.scr.refresh()

    def pager(self, title: str, lines: Sequence[str]) -> None:
        top = 0
        while True:
            h, _w = self._size()
            body = h - 3
            self._frame(f"{title} (arrows / PgUp / PgDn, q back)")
            for i, ln in enumerate(lines[top:top + body]):
                self._put(i + 1, ln)
            self.scr.refresh()
            k = self.scr.getch()
            if k in (ord("q"), 27, ord("b")):
                return
            if k in (KEY_DOWN, ord("j")):
                top = min(top + 1, max(0, len(lines) - body))
            elif k in (KEY_UP, ord("k")):
                top = max(0, top - 1)
            elif k in (KEY_NPAGE, ord(" ")):
                top = min(top + body, max(0, len(lines) - body))
            elif k == KEY_PPAGE:
                top = max(0, top - body)

    def ask(self, prompt: str, *, secret: bool = False, limit: int = 200) -> Optional[str]:
        """A line typed on the bottom row (Esc cancels)."""
        buf = ""
        while True:
            h, _w = self._size()
            self._put(h - 2, f"{prompt} {('•' * len(buf)) if secret else buf}")
            self.scr.refresh()
            k = self.scr.getch()
            if k == 27:
                self._put(h - 2, "")
                return None
            if k in (10, 13, KEY_ENTER):
                self._put(h - 2, "")
                return buf.strip()
            if k in (KEY_BACKSPACE, 127, 8):
                buf = buf[:-1]
            elif 32 <= k < 0x110000 and k not in (127,) and len(buf) < limit:
                ch = chr(k)
                if not _CONTROL.match(ch):
                    buf += ch

    def pick(self, title: str, labels: Sequence[str]) -> Optional[int]:
        if not labels:
            return None
        while True:
            self._frame(title)
            for i, ln in enumerate(labels[: self._size()[0] - 4]):
                self._put(i + 1, ln)
            got = self.ask("Number (Esc to go back):", limit=5)
            if got is None or got == "":
                return None
            if got.isdigit() and 1 <= int(got) <= len(labels):
                return int(got) - 1
            self.say("Type one of the numbers shown.")

    # views
    def v_tenant(self) -> None:
        rows = self.api.profiles()
        labels = ["  0. The sample tenant (Larkspur Freight, made up: nothing here is real)"] + fmt_profiles(rows)
        self._frame("Tenant")
        for i, ln in enumerate(labels[: self._size()[0] - 4]):
            self._put(i + 1, ln)
        got = self.ask("Number (0 for the sample, Esc to go back):", limit=5)
        if got is None or not got.isdigit():
            return
        n = int(got)
        if n == 0:
            self.api.use_sample()
            self.say("Using the sample tenant. Nothing here is real; its changes stay in the server's memory.")
        elif 1 <= n <= len(rows):
            self.api.use_profile(rows[n - 1])
            self.say(f"Using {self.api.label()}: its Scope selection decides what is read.")

    def v_assess(self) -> None:
        self.say("Running the assessment (read-only)…")
        rep = self.api.assess(on_progress=self.say)
        self.pager("Assessment", fmt_report(rep))

    def v_path(self) -> None:
        dest = self.ask("Destination (URL, host name or IP):", limit=2048)
        if dest:
            self.say("Asking the Path analyzer (read-only)…")
            self.pager("Path analyzer", fmt_path(self.api.path(dest)))

    def v_list(self) -> None:
        path = self.ask("Path of the list (one destination per line, or a CSV):", limit=1024)
        if path:
            text = read_text_file(path, "list")
            self.say("Testing the list (read-only)…")
            self.pager("Test a list", fmt_bulk(self.api.bulk_test(text, on_progress=self.say)))

    def v_snapshots(self) -> None:
        snaps = self.api.snapshots()
        labels = [clean(f"{i:>3}. {s.get('id')}  ·  {s.get('saved_at') or ''}  ·  {s.get('tenant_label') or ''}") for i, s in enumerate(snaps, 1)]
        if not labels:
            self.pager("Snapshots", ["No snapshots for this tenant. Save one in the web app (Connect to the tenant → Save a snapshot)."])
            return
        i = self.pick("Snapshots: pick one to compare with the live tenant", labels)
        if i is not None:
            self.say("Comparing with the live tenant (read-only)…")
            self.pager("Differences", fmt_diff(self.api.compare(str(snaps[i].get("id")), on_progress=self.say)))

    def v_preview(self) -> None:
        path = self.ask("Path of the plan (a Bulk changes operation or a migration plan, JSON):", limit=1024)
        if not path:
            return
        specs = specs_from_file(read_text_file(path, "plan"))
        idx = 0
        if len(specs) > 1:
            got = self.pick("The file holds several operations: preview which?", [f"{i:>3}. {lab}" for i, (lab, _s) in enumerate(specs, 1)])
            if got is None:
                return
            idx = got
        self.say("Previewing (the server reads the tenant; nothing is written)…")
        self.pager("Preview", fmt_plan(self.api.preview(specs[idx][1])))

    def v_apply(self) -> None:
        p = self.api.prepared
        if not p:
            self.say("Preview a plan first (7).")
            return
        if p.get("status") != "ready":
            self.say(f"This plan cannot be applied: {p.get('status')}.")
            return
        wm = self.api.write_mode()
        if not wm.get("enabled"):
            self.pager("Apply", ["Write mode is off on the server, so nothing can be applied.",
                                 "Turn it on in the web app (or start the app with writes enabled), then preview again."])
            return
        phrase = str(p.get("confirm_phrase") or "")
        want = phrase or "APPLY"
        typed = self.ask(f"Type {want} to apply {p.get('counts', {}).get('change', 0)} change(s) (Esc cancels):", limit=80)
        if typed is None or typed.strip().upper() != want.upper():
            self.say("Not applied: the confirmation did not match.")
            return
        who = self.ask("Your name (the assessor named in the change record):", limit=80)
        if not who:
            self.say("Not applied: the assessor's name is required.")
            return
        self.say("Applying through the server's gates…")
        self.pager("Result", fmt_result(self.api.apply(typed if phrase else "", who)))

    def run(self) -> None:
        views = {"1": self.v_tenant, "2": self.v_assess, "3": lambda: self.pager("Findings", fmt_findings(self.api.report)),
                 "4": self.v_path, "5": self.v_list, "6": self.v_snapshots, "7": self.v_preview, "8": self.v_apply}
        while True:
            self._frame("Menu")
            for i, (k, lab) in enumerate(MENU):
                self._put(i + 2, f"  {k}  {lab}")
            self.scr.refresh()
            k = self.scr.getch()
            ch = chr(k) if 0 <= k < 0x110000 else ""
            if ch in ("q", "Q") or k == 27:
                return
            fn = views.get(ch)
            if fn is None:
                continue
            try:
                fn()
            except ApiError as e:
                self.say(f"{e}")
            except Exception as e:  # noqa: BLE001 - one view failing never ends the TUI
                self.say(f"That did not work ({type(e).__name__}).")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="zscaler-made-easy tui", description="Keyboard-only terminal UI for a running Zscaler Made Easy server.")
    ap.add_argument("--url", default=default_url(), help="the app's server (default http://127.0.0.1:$ZSCALER_PORT or 8000)")
    ap.add_argument("--token-file", default="", help="the UI token file (default ui_token.txt next to the app)")
    ap.add_argument("--sample", action="store_true", help="start on the sample tenant")
    a = ap.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("The TUI needs a terminal (over SSH, use ssh -t).", file=sys.stderr)
        return 2
    try:
        api = Api(HttpTransport(a.url, read_token(a.token_file)))
        code, _ = api.t.request("GET", "/api/write-mode")
        if code == 401:
            print("The server wants the UI token: run the TUI on the computer the app runs on (it reads ui_token.txt), "
                  "or set ZSCALER_UI_TOKEN.", file=sys.stderr)
            return 2
        if a.sample:
            api.use_sample()
    except ApiError as e:
        print(str(e), file=sys.stderr)
        return 2
    import curses

    def _run(scr: Any) -> None:
        try:
            curses.curs_set(0)
        except Exception:  # noqa: BLE001 - some terminals cannot hide the cursor
            pass
        scr.keypad(True)
        Tui(scr, api).run()
    curses.wrapper(_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
