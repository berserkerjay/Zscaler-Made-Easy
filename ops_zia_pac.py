"""ZIA hosted PAC files on the Bulk changes engine: list, view, validate,
create a new version, create, clone, switch the active version, delete.

One operation type (`zia_pac`), one action per operation, through the
shared engine (admin_ops.register): the scope check before anything is
read (ZIA platform ticked on the Scope page), a plan that only reads, the
plan hash (the PAC content is part of the spec, so a different text is a
different plan), the re-plan before writing, write mode, the writer, the
named assessor and the confirmation, a re-read right before the write, one
ZIA activation, the read-back, the record, the audit log with the actor, and
Undo where one exists.

The PAC is never run. Its text is checked twice before anything is
written: by this app's own parser (pac_eval.inspect: parsed, never
executed; a construct outside the PAC subset it reads is reported, not a
refusal), and by ZIA's validator (POST /pacFiles/validate, which changes
nothing; its errors block the plan). The preview shows a line diff against
the version it replaces or comes from (difflib; capped).

  validate     both checks and the diff; writes nothing (no change items).
  new_version  a new version of a PAC file, from a version of it, created
               STAGED: nothing uses it until it is deployed. No Undo: the
               SDK has no call that deletes one version (the preview says so).
  create       a new PAC file. ZIA requires its first version DEPLOYED (the
               SDK says so); its URL is new, so nothing uses it yet.
               Undo deletes it.
  clone        a new PAC file with the text of a version of another one
               (the same as create, from that text). Undo deletes it.
  deploy       switch the active (deployed) version of a PAC file. Undo
               deploys the version that was active before.
  delete       a whole PAC file with every version; asks its name typed and
               cannot be undone.

SDK calls, verified against the installed zscaler-sdk-python 1.11.3
(zscaler/zia/pac_files.py, client.zia.pac_files): list_pac_files,
get_pac_file (every version), get_pac_file_version, validate_pac_file,
add_pac_file (validates first), clone_pac_file (POST
/pacFiles/{id}/version/{from}: a new version; validates first; at ten
versions it evicts the oldest unless told), update_pac_file (PUT
/pacFiles/{id}/version/{v}/action/DEPLOY), delete_pac_file. ASSUMED: that
the DEPLOY action takes the version's own fields as its body (the SDK
example sends them; this sends them as read), that a PAC file change waits
for activation like other ZIA policy (the SDK says a clone needs the parent
committed), and the version status words DEPLOYED, STAGE and LKG.
"""
from __future__ import annotations

import difflib
import hashlib
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao
import pack_ops as ops
import pac_eval

TYPE = "zia_pac"
FAMILY = "zia_pac_files"
SCRIPT = "ops_zia_admin.js"
ACTIONS = ("validate", "new_version", "create", "clone", "deploy", "delete")
MAX_CONTENT = pac_eval.MAX_SOURCE         # characters of PAC text
MAX_FILES = 200                           # PAC files listed
MAX_DIFF_LINES = 2000
MAX_VIEW = 64 * 1024                      # characters of the deployed text the picker shows
MAX_VERSIONS = 10                         # ZIA keeps ten versions per PAC file (SDK)
_ID = re.compile(r"^[0-9]{1,19}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_PAC_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
NOT_IN_SCOPE = "Not in scope: hosted PAC files are ZIA platform objects; tick ZIA platform on the Scope page. Nothing was read."
NO_UNDO_VERSION = ("Cannot be undone here: the Zscaler SDK has no call that deletes one PAC version. The new version is STAGED, so nothing "
                   "uses it until it is deployed; delete it in the ZIA Admin Portal if it is not wanted.")
NO_UNDO_DELETE = "Cannot be undone: the PAC file and every version of it are deleted, and anything that still points at its URL stops getting it."
NEVER_RUN = "The PAC is never run: this app parses it without executing it, and ZIA's validator checks it."

LogFn = Callable[[str], None]


def _svc(client: Any) -> Any:
    zia = getattr(client, "zia", None)
    svc = getattr(zia, "pac_files", None) if zia is not None else None
    if svc is None:
        raise ao.OperationError("This sign-in has no ZIA PAC file service (zscaler-sdk-python pac_files), so nothing was read.")
    return svc


def _call(fn: Callable[..., Any], *a: Any, **k: Any) -> Tuple[Any, Optional[str]]:
    import ops_zia_directory as od
    return od._call(fn, *a, **k)


def plain(obj: Any) -> Any:
    import ops_zia_directory as od
    return od.plain(obj)


def _rid(v: Any) -> str:
    return "" if v in (None, "") else str(v)


def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def list_files(client: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    data, err = _call(_svc(client).list_pac_files)
    rows = [r for r in (plain(data) or []) if isinstance(r, dict)] if not err else []
    return rows[:MAX_FILES], err


def versions(client: Any, pac_id: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every version of one PAC file, with its text (get_pac_file)."""
    data, err = _call(_svc(client).get_pac_file, pac_id)
    if err:
        return [], err
    rows = plain(data)
    rows = rows if isinstance(rows, list) else [rows] if isinstance(rows, dict) else []
    return sorted([r for r in rows if isinstance(r, dict)], key=lambda r: _int(r.get("pac_version")) or 0), None


def deployed(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return next((r for r in rows if str(r.get("pac_version_status") or "").upper() == "DEPLOYED"), None)


def file_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    text = str(row.get("pac_content") or "")
    return {"id": _rid(row.get("id")), "name": str(row.get("name") or ""), "domain": str(row.get("domain") or ""),
            "description": str(row.get("description") or ""), "url": str(row.get("pac_url") or row.get("pac_url_obfuscated") or ""),
            "version": _int(row.get("pac_version")), "status": str(row.get("pac_version_status") or ""),
            "verification": str(row.get("pac_verification_status") or ""), "editable": row.get("editable") is not False,
            "commit_message": str(row.get("pac_commit_message") or ""), "content": text[:MAX_VIEW], "content_cut": len(text) > MAX_VIEW,
            "lines": text.count("\n") + 1 if text else 0}


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Every PAC file (its deployed version's text, cut for display) and the
    version list of each. Read-only; the text is shown, never run."""
    say("Reading the hosted PAC files…")
    rows, err = list_files(client)
    files, errors = [], {}
    if err:
        errors["zia_pac_files"] = err
    for r in sorted(rows, key=lambda r: str(r.get("name") or "").lower()):
        ao._check_stop(cancel)
        f = file_summary(r)
        vers, verr = versions(client, f["id"]) if f["id"] else ([], "no id")
        if verr:
            errors[f"PAC file {f['name'] or f['id']}"] = verr
        f["versions"] = [{"version": _int(v.get("pac_version")), "status": str(v.get("pac_version_status") or ""),
                          "commit_message": str(v.get("pac_commit_message") or ""), "verification": str(v.get("pac_verification_status") or ""),
                          "lines": str(v.get("pac_content") or "").count("\n") + 1 if v.get("pac_content") else 0} for v in vers]
        files.append(f)
    say(f"{len(files)} PAC file(s).")
    return {"pac_files": files, "errors": errors, "limits": {"content_chars": MAX_CONTENT, "versions": MAX_VERSIONS},
            "never_run": NEVER_RUN}


# ---------------------------------------------------------------------------
# Checks: this app's parse (never run) and ZIA's validator
# ---------------------------------------------------------------------------

def content(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ao.OperationError("Paste the PAC file's text.")
    text = raw.replace("\r\n", "\n")
    if len(text) > MAX_CONTENT:
        raise ao.OperationError(f"The PAC text is longer than {MAX_CONTENT // 1024} KB, the most this app reads.")
    if _PAC_CONTROL.search(text):
        raise ao.OperationError("The PAC text contains a control character (only tabs and line breaks are allowed).")
    return text


def local_check(text: str) -> Dict[str, Any]:
    """pac_eval's parse: never executed. {ok, error, has_function, direct, returns}."""
    info = pac_eval.inspect(text)
    has_fn = False
    if info["ok"]:
        try:
            has_fn = "FindProxyForURL" in (pac_eval.compile_pac(text).get("functions") or {})
        except pac_eval.Unsafe:
            has_fn = False
    return {"ok": bool(info["ok"]), "error": info.get("error"), "has_function": has_fn,
            "direct": sorted({r["value"] for r in info.get("direct_rules") or [] if r.get("value")})[:50],
            "returns": sorted({x for x in info.get("returns") or [] if isinstance(x, str)})[:20]}


def zia_check(client: Any, text: str) -> Dict[str, Any]:
    """ZIA's validator (POST /pacFiles/validate; changes nothing): {ran, success, messages, error}."""
    data, err = _call(_svc(client).validate_pac_file, text)
    if err:
        return {"ran": False, "success": None, "messages": [], "error": err}
    d = plain(data)
    msgs = []
    for m in (d or {}).get("messages") or []:
        if isinstance(m, dict):
            msgs.append({"line": m.get("line"), "column": m.get("column"), "severity": str(m.get("severity") or ""),
                         "message": str(m.get("message") or "")[:300]})
    return {"ran": True, "success": bool((d or {}).get("success")), "messages": msgs[:50], "error": None,
            "warnings": (d or {}).get("warning_count"), "errors": (d or {}).get("error_count")}


def diff(old: str, new: str, old_label: str, new_label: str) -> Dict[str, Any]:
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), fromfile=old_label, tofile=new_label, lineterm="", n=3))
    added = sum(1 for x in lines if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in lines if x.startswith("-") and not x.startswith("---"))
    return {"from": old_label, "to": new_label, "added": added, "removed": removed, "same": not lines,
            "lines": [x[:500] for x in lines[:MAX_DIFF_LINES]], "cut": len(lines) > MAX_DIFF_LINES}


def _checks(client: Any, text: str, P: Dict[str, Any]) -> None:
    loc = local_check(text)
    zia = zia_check(client, text)
    P["pac_check"] = {"local": loc, "zia": zia}
    if not loc["ok"]:
        P["warnings"].append(f"This app could not parse the PAC safely ({loc['error']}): the Path analyzer will say \"could not evaluate\" "
                             "for it. ZIA's validator decides whether it is valid.")
    elif not loc["has_function"]:
        P["blockers"].append("The PAC has no FindProxyForURL(url, host) function: browsers would not use it.")
    if zia["ran"] and not zia["success"]:
        first = "; ".join(f"line {m['line']}: {m['message']}" for m in zia["messages"][:3]) or "no detail"
        P["blockers"].append(f"ZIA's validator refused the PAC ({first}).")
    elif not zia["ran"]:
        P["warnings"].append(f"ZIA's validator could not be asked ({zia['error']}); ZIA validates again when the PAC is saved.")


# ---------------------------------------------------------------------------
# The spec and the plan
# ---------------------------------------------------------------------------

def _id(v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if not _ID.match(s):
        raise ao.OperationError(f"{what} must be a ZIA id (digits only).")
    return s


def _version(v: Any) -> int:
    n = _int(v)
    if n is None or not 1 <= n <= 1_000_000:
        raise ao.OperationError("Pick the PAC version (a number).")
    return n


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    action = str(spec.get("action") or "").strip().lower()
    if action == "undo":
        d = spec.get("delete") if isinstance(spec.get("delete"), dict) else {}
        return {"type": TYPE, "action": "undo", "delete": {"id": _id(d.get("id"), "The PAC file"), "name": ao._object_name(d.get("name"), "PAC file")}}
    if action not in ACTIONS:
        raise ao.OperationError(f"Pick what to do with the PAC file: {', '.join(ACTIONS)}.")
    n: Dict[str, Any] = {"type": TYPE, "action": action}
    if action in ("new_version", "deploy", "delete", "clone") or (action == "validate" and spec.get("pac_id") not in (None, "")):
        n["pac_id"] = _id(spec.get("pac_id"), "The PAC file")
    if action in ("new_version", "deploy", "clone") or (action == "validate" and spec.get("version") not in (None, "")):
        n["version"] = _version(spec.get("version"))
    if action in ("validate", "new_version", "create"):
        n["content"] = content(spec.get("content"))
    if action in ("create", "clone"):
        n["name"] = ao._object_name(spec.get("name"), "PAC file")
        if not n["name"] or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,62}", n["name"]):
            raise ao.OperationError("Name the PAC file: up to 63 letters, digits, spaces and . _ ( ) -, starting with a letter or digit.")
        dom = str(spec.get("domain") or "").strip().lower()
        if not _DOMAIN.match(dom):
            raise ao.OperationError("The PAC file's domain must be one of the organisation's domains, like example.com.")
        n["domain"] = dom
        n["description"] = str(spec.get("description") or "").strip()[:1024]
        if ao._has_control(n["description"]):
            raise ao.OperationError("The description contains a control character.")
    if action in ("new_version", "create", "clone"):
        msg = str(spec.get("commit_message") or "").strip()[:255]
        if ao._has_control(msg):
            raise ao.OperationError("The commit message contains a control character.")
        n["commit_message"] = msg
    return n


def _file(client: Any, pac_id: str, P: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    rows, err = list_files(client)
    if err:
        halt = ao._read_halt(err)
        P["blockers"].append(halt or f"The PAC files could not be read: {err}")
        return None, []
    row = next((r for r in rows if _rid(r.get("id")) == pac_id), None)
    if row is None:
        P["blockers"].append(f"PAC file {pac_id} is not in ZIA (read the tenant again).")
        return None, []
    vers, err = versions(client, pac_id)
    if err:
        P["blockers"].append(f"The versions of '{row.get('name')}' could not be read: {err}")
    return row, vers


def _obj(row: Dict[str, Any], **kw: Any) -> Dict[str, Any]:
    return dict({"type": "zia_pac_file", "policy_label": "PAC file", "id": _rid(row.get("id")), "name": str(row.get("name") or "")}, **kw)


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    act = n["action"]
    P: Dict[str, Any] = {"type": TYPE, "product": "zia", "spec": n, "items": [], "groups": [], "warnings": [], "blockers": [],
                         "notes": [NEVER_RUN]}
    titles = {"validate": "Validate a PAC file", "new_version": "New PAC version (staged)", "create": "New PAC file", "clone": "Clone a PAC file",
              "deploy": "Switch the active PAC version", "delete": "Delete a PAC file", "undo": "Undo: delete the PAC file this app made"}
    P["title"] = titles[act]
    say("Reading the PAC files…")
    if act == "undo":
        d = n["delete"]
        row, _vers = _file(client, d["id"], P)
        if row is None:
            P["blockers"] = [b for b in P["blockers"] if "is not in ZIA" not in b]
            P["items"].append(ao._unit("pac", "pac", "zia_pac_file", {"type": "zia_pac_file", "name": d["name"], "id": d["id"]}, "exists", None, False,
                                       status="noop", reason="already gone"))
            return P
        if str(row.get("name") or "") != d["name"]:
            P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row), "exists", True, False, status="excluded",
                                       reason=f"its name is now '{row.get('name')}', not '{d['name']}': it is left as it is"))
            return P
        _delete(P, row, undo=True)
        return P
    row: Optional[Dict[str, Any]] = None
    vers: List[Dict[str, Any]] = []
    if n.get("pac_id"):
        row, vers = _file(client, n["pac_id"], P)
        if row is None:
            return P
    src = None
    if n.get("version") is not None:
        src = next((v for v in vers if _int(v.get("pac_version")) == n["version"]), None)
        if src is None:
            P["blockers"].append(f"Version {n['version']} of '{row.get('name') if row else n.get('pac_id')}' is not in ZIA.")
            return P
    live = deployed(vers) if vers else None
    if act == "validate":
        base = src or live
        _checks(client, n["content"], P)
        if base is not None:
            P["diff"] = diff(str(base.get("pac_content") or ""), n["content"], f"version {base.get('pac_version')}", "your text")
        P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row or {"name": "PAC text"}), "validation", None, None, status="noop",
                                   reason="checked only: nothing is written"))
        return P
    if act == "delete":
        _delete(P, row, undo=False)
        return P
    if act == "deploy":
        cur = _int((live or {}).get("pac_version"))
        if cur == n["version"]:
            P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row), "deployed version", cur, cur, status="noop", reason="already the active version"))
            return P
        P["diff"] = diff(str((live or {}).get("pac_content") or ""), str(src.get("pac_content") or ""),
                         f"version {cur} (active)" if cur else "no active version", f"version {n['version']}")
        _checks(client, str(src.get("pac_content") or ""), P)
        P["groups"].append({"key": "pac", "handler": "zia_pac_write",
                            "target": {"action": "deploy", "pac_id": n["pac_id"], "name": str(row.get("name") or ""), "version": n["version"],
                                       "before": cur, "content_digest": digest(str(src.get("pac_content") or ""))}})
        P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row), "deployed version", cur, n["version"],
                                   reason="Undo deploys the version that was active before"))
        P["warnings"].append(f"Every browser and Client Connector that uses '{row.get('name')}' gets version {n['version']} after the activation.")
        return P
    if act == "new_version":
        text = n["content"]
        if len(vers) >= MAX_VERSIONS:
            oldest = min((_int(v.get("pac_version")) or 0) for v in vers if str(v.get("pac_version_status") or "").upper() not in ("DEPLOYED", "LKG"))
            P["warnings"].append(f"'{row.get('name')}' has {len(vers)} versions, the most ZIA keeps: ZIA removes version {oldest} to make room.")
        if str(src.get("pac_content") or "") == text:
            P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row), "new version", None, None, status="noop",
                                       reason=f"the text is the same as version {n['version']}"))
            return P
        P["diff"] = diff(str(src.get("pac_content") or ""), text, f"version {n['version']}", "new version")
        _checks(client, text, P)
        P["groups"].append({"key": "pac", "handler": "zia_pac_write",
                            "target": {"action": "new_version", "pac_id": n["pac_id"], "name": str(row.get("name") or ""), "version": n["version"],
                                       "content_digest": digest(text), "commit_message": n["commit_message"],
                                       "source_digest": digest(str(src.get("pac_content") or "")),
                                       "known_versions": sorted(_int(v.get("pac_version")) or 0 for v in vers)}})
        P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row), "new version", None, "STAGE", value=f"from version {n['version']}",
                                   reason=NO_UNDO_VERSION))
        P["warnings"].append(NO_UNDO_VERSION)
        return P
    # create / clone: a new PAC file
    text = n["content"] if act == "create" else str(src.get("pac_content") or "")
    rows, err = list_files(client)
    if any(str(r.get("name") or "").lower() == n["name"].lower() for r in rows):
        P["items"].append(ao._unit("pac", "pac", "zia_pac_file", {"type": "zia_pac_file", "name": n["name"]}, "exists", True, True, status="excluded",
                                   reason="a PAC file with this name exists: pick another name"))
        return P
    _checks(client, text, P)
    P["diff"] = diff("", text, "(new file)", n["name"]) if act == "create" else \
        diff(str(src.get("pac_content") or ""), text, f"{row.get('name')} version {n['version']}", n["name"])
    P["groups"].append({"key": "pac", "handler": "zia_pac_write",
                        "target": {"action": "create", "name": n["name"], "domain": n["domain"], "description": n["description"],
                                   "commit_message": n["commit_message"] or (f"Cloned from {row.get('name')} version {n['version']}" if act == "clone" else ""),
                                   "content_digest": digest(text), "from": {"pac_id": n.get("pac_id"), "version": n.get("version")} if act == "clone" else None}})
    P["items"].append(ao._unit("pac", "pac", "zia_pac_file", {"type": "zia_pac_file", "policy_label": "PAC file", "name": n["name"]}, "exists", False, True,
                               value=f"{n['domain']}; {text.count(chr(10)) + 1} lines", reason="Undo deletes it"))
    P["notes"].append("ZIA makes the first version of a new PAC file the deployed one; its URL is new, so nothing uses it until you point "
                      "a forwarding profile or a browser at it.")
    return P


def _delete(P: Dict[str, Any], row: Dict[str, Any], *, undo: bool) -> None:
    name = str(row.get("name") or "")
    if row.get("editable") is False:
        P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row), "exists", True, False, status="excluded",
                                   reason="ZIA marks this PAC file as not editable (a Zscaler default)"))
        return
    P["groups"].append({"key": "pac", "handler": "zia_pac_write", "target": {"action": "delete", "pac_id": _rid(row.get("id")), "name": name,
                                                                             "url": str(row.get("pac_url") or "")}})
    P["items"].append(ao._unit("pac", "pac", "zia_pac_file", _obj(row), "exists", True, False,
                               reason="Undo deletes the PAC file the operation made" if undo else NO_UNDO_DELETE))
    P["confirm_always"] = f"DELETE {name}" if len(name) <= 60 else "DELETE PAC FILE"
    if not undo:
        P["warnings"].append(NO_UNDO_DELETE)


# ---------------------------------------------------------------------------
# The write (pack_ops.call: pacing, retries, Stop, audit)
# ---------------------------------------------------------------------------

def _write(run: Any, fn: Callable[..., Any], *args: Any, op: str, name: str, kw: Optional[Dict[str, Any]] = None,
           oid: Any = None) -> ops.Outcome:
    out = ops.call(fn, *args, op=op, kind="zia_pac_file", name=name, log=run.log, kw=kw, zia=run.zia)
    ops._audit_write(op, "zia_pac_file", out.id if op == "create" else oid, name, None, out)
    return out


def _fail(run: Any, units: List[Dict[str, Any]], err: Optional[str], what: str) -> None:
    import ops_zia_directory as od
    od._halt_or_fail(run, units, err, what)


def version_payload(v: Dict[str, Any]) -> Dict[str, Any]:
    """The version's own fields, as read, for the DEPLOY action's body."""
    keys = ("name", "description", "domain", "pac_commit_message", "pac_verification_status", "pac_content")
    return {k: v.get(k) for k in keys if v.get(k) is not None}


def h_write(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    svc = _svc(run.client)
    spec = run.p["spec"]
    if t["action"] == "create":
        text = spec["content"] if spec["action"] == "create" else None
        if text is None:
            vers, err = versions(run.client, t["from"]["pac_id"])
            src = next((v for v in vers if _int(v.get("pac_version")) == t["from"]["version"]), None)
            if src is None:
                _fail(run, units, err or "the source version is gone", "the PAC version to clone")
                return
            text = str(src.get("pac_content") or "")
        if digest(text) != t["content_digest"]:
            run.mark(units, "conflict", "the source PAC text changed since the preview; nothing was created")
            run.counts["skipped"] += len(units)
            return
        rows, err = list_files(run.client)
        if err:
            _fail(run, units, err, "the PAC files")
            return
        if any(str(r.get("name") or "").lower() == t["name"].lower() for r in rows):
            run.mark(units, "conflict", "a PAC file with this name was made since the preview; nothing was created")
            run.counts["skipped"] += len(units)
            return
        payload = {"name": t["name"], "description": t["description"], "domain": t["domain"], "pac_commit_message": t["commit_message"],
                   "pac_verification_status": "VERIFY_NOERR", "pac_version_status": "DEPLOYED", "pac_content": text}
        out = _write(run, svc.add_pac_file, op="create", name=t["name"], kw=payload)
        if run.outcome(units, out, "create"):
            run.wrote_zia = True
            oid = _rid(out.id)
            for u in units:
                u["object"] = dict(u["object"], id=oid)
            run.created.append({"type": "zia_pac_file", "id": oid, "name": t["name"]})
            run.log(f"[PAC file] {t['name']}: created")
        return
    vers, err = versions(run.client, t["pac_id"])
    if err:
        import ops_zia_directory as od
        if t["action"] == "delete" and od.is_missing(err):
            run.mark(units, "noop", "already gone")
            return
        _fail(run, units, err, f"the PAC file '{t['name']}'")
        return
    live = _int((deployed(vers) or {}).get("pac_version"))
    if t["action"] == "delete":
        out = _write(run, svc.delete_pac_file, t["pac_id"], op="delete", name=t["name"], oid=t["pac_id"])
        if run.outcome(units, out, "delete"):
            run.wrote_zia = True
            run.log(f"[PAC file] {t['name']}: deleted")
        return
    src = next((v for v in vers if _int(v.get("pac_version")) == t["version"]), None)
    if t["action"] == "deploy":
        if live != t["before"] or src is None or digest(str(src.get("pac_content") or "")) != t["content_digest"]:
            run.mark(units, "conflict", "the PAC file's versions changed since the preview; the active version was not switched")
            run.counts["skipped"] += len(units)
            return
        out = _write(run, svc.update_pac_file, t["pac_id"], t["version"], "DEPLOY", op="update", name=t["name"], kw=version_payload(src),
                     oid=t["pac_id"])
        if run.outcome(units, out, "update"):
            run.wrote_zia = True
            run.log(f"[PAC file] {t['name']}: version {t['version']} deployed")
        return
    # new_version
    if src is None or sorted(_int(v.get("pac_version")) or 0 for v in vers) != t["known_versions"] \
            or digest(str(src.get("pac_content") or "")) != t["source_digest"]:
        run.mark(units, "conflict", "the PAC file's versions changed since the preview; no version was added")
        run.counts["skipped"] += len(units)
        return
    text = spec["content"]
    kw = {"pac_content": text, "pac_version_status": "STAGE", "pac_verification_status": "VERIFY_NOERR", "pac_commit_message": t["commit_message"]}
    out = _write(run, svc.clone_pac_file, t["pac_id"], str(t["version"]), op="create", name=t["name"], kw=kw)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        made = plain(out.data)
        run.created.append({"type": "zia_pac_version", "id": t["pac_id"], "name": t["name"],
                            "version": _int(made.get("pac_version")) if isinstance(made, dict) else None})
        run.log(f"[PAC file] {t['name']}: new staged version added")


HANDLERS = {"zia_pac_write": h_write}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    if not applied:
        return out
    t = run.p["groups"][0]["target"]
    out["checked"] = len(applied)
    if t["action"] == "create":
        rows, err = list_files(run.client)
        ok = not err and any(str(r.get("name") or "") == t["name"] for r in rows)
    else:
        vers, err = versions(run.client, t["pac_id"])
        if t["action"] == "delete":
            import ops_zia_directory as od
            ok = bool(err) and od.is_missing(err) or (not err and not vers)
            err = None if ok else err
        elif t["action"] == "deploy":
            ok = not err and _int((deployed(vers) or {}).get("pac_version")) == t["version"]
        else:
            ok = not err and len(vers) >= len(t["known_versions"]) and any(
                digest(str(v.get("pac_content") or "")) == t["content_digest"] and str(v.get("pac_version_status") or "").upper() == "STAGE"
                for v in vers)
    if err and not ok:
        out["checked"] = 0
        out["unread"].append(f"{t['name']}: {err}")
        for u in applied:
            u["verified"] = None
        return out
    for u in applied:
        u["verified"] = bool(ok)
    if ok:
        out["confirmed"] = len(applied)
    else:
        out["mismatched"].append(f"{t['name']}: not as planned when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """create / clone: delete the new file (an Undo-only form); deploy: deploy
    the version that was active before. new_version and delete: none."""
    if not any(u.get("status") == "applied" for u in result.get("items") or []):
        return None
    t = ((result.get("groups") or [{}])[0] or {}).get("target") or {}
    if t.get("action") == "create":
        made = next((c for c in result.get("created") or [] if c.get("type") == "zia_pac_file" and c.get("id")), None)
        return {"type": TYPE, "action": "undo", "delete": {"id": str(made["id"]), "name": made["name"]}} if made else None
    if t.get("action") == "deploy" and t.get("before"):
        return {"type": TYPE, "action": "deploy", "pac_id": t["pac_id"], "version": t["before"]}
    return None


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if "zia_extras" in (scope.get("scopes") or []) else NOT_IN_SCOPE


ao.register(TYPE, family=FAMILY, product="zia", label="ZIA PAC files", group="Day-to-day admin",
            hint=("List and view the hosted PAC files and their versions; validate a PAC (never run: parsed here and checked by ZIA), add a "
                  "staged version, create or clone a PAC file, switch the active version, with a line diff. Needs ZIA platform ticked."),
            in_scope=in_scope, plan=plan, read_objects=read_objects, handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT)
