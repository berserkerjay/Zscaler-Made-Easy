"""Bulk changes plugin: block known-bad files by their MD5 hash in Cloud Sandbox.

One operation type on the admin_ops engine (/report/operations, "Build
new"): add MD5 file hashes to the ZIA Cloud Sandbox custom block list
(Policy > Sandbox > Behavioral Analysis). Planned from the list as it is
now, previewed hash by hash, approved by its plan hash and applied through
the engine's gates (write mode, a writer, a named assessor and, always, a
typed confirmation): the list is read again right before the write, only
this operation's hashes are added to it, it is read back after the
activation, and Undo removes exactly the hashes that were added.

SDK (zscaler-sdk-python 1.11.3, zscaler/zia/sandbox.py):
  sandbox.get_behavioral_analysis    GET /behavioralAnalysisAdvancedSettings
  sandbox.get_file_hash_count        GET /behavioralAnalysisAdvancedSettings/fileHashCount
  sandbox.add_hash_to_custom_list    PUT /behavioralAnalysisAdvancedSettings
The PUT replaces the whole list ({"md5HashValueList": [{url, urlComment,
type}]}; "Pass an empty list to clear"), so the list is re-read before the
write and sent back with every other entry untouched. An entry's `url` is
the MD5 and `type` is CUSTOM_FILEHASH_DENY (block) or CUSTOM_FILEHASH_ALLOW;
this builder only ever adds DENY entries and never touches an ALLOW one.
Assumed (not modelled by the SDK): the fileHashCount fields
blockedFileHashesCount and remainingFileHashes; the 100-hash cap per
operation is the app's own limit, not a ZIA one.

Only an MD5 (32 hexadecimal characters) is accepted: the SDK documents MD5
only. Input is untrusted: at most MAX_HASHES hashes, each comment cleaned of
control characters and capped at COMMENT_MAX characters.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import admin_ops as ao
import pack_ops as ops

TYPE = "zia_sandbox_hashes"
FAMILY = "zia_sandbox_hash_list"
HANDLER = "zsb_put"
DENY = "CUSTOM_FILEHASH_DENY"
ALLOW = "CUSTOM_FILEHASH_ALLOW"
MAX_HASHES = 100          # per operation (the app's limit)
COMMENT_MAX = 100         # characters kept of a comment
MAX_LIST = 20000          # entries read from the tenant's list (bounded parse)
_MD5 = re.compile(r"\A[0-9a-f]{32}\Z")
NOT_IN_SCOPE = "Not in scope: tick ZIA platform on the Scope page to read and change the Cloud Sandbox hash list."


def normalize_md5(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """(the MD5 in lower case, None) or (None, why it is refused)."""
    if not isinstance(raw, str):
        return None, "not text"
    s = raw.strip().lower()
    if len(s) > 64:
        return None, "longer than an MD5 hash"
    if not _MD5.match(s):
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", s):
            return None, "a SHA-1 or SHA-256 hash; Cloud Sandbox takes MD5 hashes only"
        return None, "not an MD5 hash (32 characters, 0-9 and a-f)"
    if s == "0" * 32:
        return None, "the empty-file hash placeholder"
    return s, None


def _comment(raw: Any) -> str:
    s = "".join(ch for ch in str(raw or "") if ch.isprintable()).strip()
    return s[:COMMENT_MAX]


def _show(md5: str) -> str:
    return md5   # a file hash is not a secret; shown whole so it can be checked against the incident


def parse_spec(spec: Dict[str, Any]) -> Tuple[List[Dict[str, str]], bool]:
    """([{md5, comment}], is_undo). Raises OperationError naming every bad hash."""
    undo = ao.is_undo_only(spec)
    raw = spec.get("hashes")
    if not isinstance(raw, list) or not raw:
        raise ao.OperationError("List at least one MD5 file hash to block.")
    if len(raw) > MAX_HASHES:
        raise ao.OperationError(f"At most {MAX_HASHES} hashes per operation; split the list.")
    out: List[Dict[str, str]] = []
    bad: List[str] = []
    seen = set()
    for i, e in enumerate(raw, 1):
        val, note = (e.get("md5"), e.get("comment")) if isinstance(e, dict) else (e, "")
        md5, why = normalize_md5(val)
        if why:
            bad.append(f"line {i}: {why}")
            continue
        if md5 in seen:
            continue
        seen.add(md5)
        out.append({"md5": md5, "comment": "" if undo else _comment(note)})
    if bad:
        raise ao.OperationError("Some entries are not MD5 hashes, so nothing was planned: " + "; ".join(bad[:10])
                                + (f" and {len(bad) - 10} more" if len(bad) > 10 else "") + ".")
    return out, undo


def _in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if "zia_extras" in (scope.get("scopes") or []) else NOT_IN_SCOPE


def _entries(body: Any) -> Optional[List[Dict[str, Any]]]:
    """The list's entries as {url, urlComment, type}, or None when the body is not the list."""
    if isinstance(body, dict):
        rows = body.get("md5HashValueList", body.get("md5_hash_value_list"))
        if isinstance(rows, list):
            out = []
            for r in rows[:MAX_LIST]:
                if isinstance(r, dict):
                    out.append({"url": str(r.get("url") or "").strip().lower(), "urlComment": r.get("urlComment", r.get("url_comment")),
                                "type": str(r.get("type") or "")})
            return out
    return None


def read_list(zia: Any) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """(the custom hash list as the tenant sent it, error). Read-only."""
    import ai_guard as ag
    try:
        ret = zia.sandbox.get_behavioral_analysis()
    except Exception as e:  # noqa: BLE001 - a failed read is reported, never raised
        return None, str(e)[:200]
    err = ret[2] if isinstance(ret, tuple) and len(ret) >= 3 else None
    if err:
        return None, str(err)[:200]
    rows = _entries(ag.raw_body(ret))
    if rows is None:
        data = ret[0] if isinstance(ret, tuple) else ret
        rows = _entries(ag._plain(data) if data is not None else None)
    if rows is None:
        return None, "the Cloud Sandbox hash list came back in a shape this app does not know, so it is not changed"
    return rows, None


def read_quota(zia: Any) -> Tuple[Optional[int], Optional[int]]:
    """(used, remaining) of the custom hash quota, or (None, None) when unknown."""
    import ai_guard as ag
    try:
        ret = zia.sandbox.get_file_hash_count()
        body = ag.raw_body(ret)
        if body is None and isinstance(ret, tuple) and isinstance(ret[0], dict):
            body = ret[0]
        if isinstance(body, dict):
            return int(body.get("blockedFileHashesCount")), int(body.get("remainingFileHashes"))
    except Exception:  # noqa: BLE001 - the quota is advice only
        pass
    return None, None


def _plan(client, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    wanted, undo = parse_spec(spec)
    zia = client.zia
    say("Reading the Cloud Sandbox custom hash list…")
    rows, err = read_list(zia)
    ao._check_stop(cancel)
    title = ("Undo: remove " if undo else "Block ") + f"{len(wanted)} file hash{'es' if len(wanted) != 1 else ''} in Cloud Sandbox"
    prepared: Dict[str, Any] = {"type": TYPE, "product": "zia", "title": title, "spec": spec, "items": [], "groups": [], "warnings": [], "blockers": []}
    if err is not None or rows is None:
        prepared["blockers"].append(f"The Cloud Sandbox hash list could not be read ({err}), so nothing can be planned. It needs the Cloud Sandbox "
                                    "subscription and an API role that can read and change the Sandbox settings.")
        return prepared
    have = {r["url"]: r for r in rows}
    changes = 0
    for w in wanted:
        md5 = w["md5"]
        cur = have.get(md5)
        state = "absent" if cur is None else ("allowed" if cur["type"].upper() == ALLOW else "blocked")
        key = f"h:{md5}"
        obj = {"id": md5, "name": _show(md5), "comment": w["comment"]}
        if undo:
            if state == "blocked":
                prepared["items"].append(ao._unit(key, "list", "sandbox_hash", obj, "block list", "blocked", "absent", value=md5))
                changes += 1
            else:
                prepared["items"].append(ao._unit(key, "list", "sandbox_hash", obj, "block list", state, "absent", value=md5, status="noop",
                                                  reason="not on the block list any more"))
        elif state == "blocked":
            prepared["items"].append(ao._unit(key, "list", "sandbox_hash", obj, "block list", "blocked", "blocked", value=md5, status="noop",
                                              reason="already blocked"))
        elif state == "allowed":
            prepared["items"].append(ao._unit(key, "list", "sandbox_hash", obj, "block list", "allowed", "allowed", value=md5, status="excluded",
                                              reason="it is on the allow list; an allow-listed hash is a deliberate choice, change it in the ZIA portal"))
        else:
            prepared["items"].append(ao._unit(key, "list", "sandbox_hash", obj, "block list", "absent", "blocked", value=md5))
            changes += 1
    if changes and not undo:
        used, left = read_quota(zia)
        if left is not None and changes > left:
            prepared["blockers"].append(f"The Cloud Sandbox custom hash quota has room for {left} more hash(es) and this adds {changes}. "
                                        "Remove hashes that are no longer needed first.")
        prepared["warnings"].append("A blocked hash takes effect for every user once the change is activated: a file with that hash is blocked "
                                    "without sandbox analysis. Check each hash against the incident before you apply.")
    prepared["groups"].append({"key": "list", "handler": HANDLER, "target": {"op": "remove" if undo else "add", "count": changes}})
    n = changes
    # Always a typed phrase (deny by default): even one hash blocks files for every user.
    prepared["confirm_always"] = (f"REMOVE {n} FILE HASHES" if undo else f"BLOCK {n} FILE HASHES") if n else ""
    prepared["impact"] = [f"{len(rows)} hash(es) are on the list now; " + (f"{n} would be removed." if undo else f"{n} would be added as blocked.")]
    prepared["apply_note"] = "ZIA keeps the change pending until it is activated."
    return prepared


def _h_put(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Re-read the list, check every planned hash is still as previewed, and
    send the list back with only this operation's hashes added or removed."""
    remove = g["target"]["op"] == "remove"
    rows, err = read_list(run.zia)
    if rows is None:
        halt = ao._read_halt(err)
        if halt:
            run.halt = halt
            run.mark(units, "skipped", f"not attempted: {halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the Cloud Sandbox hash list again before the change: {err}")
            run.counts["failed"] += 1
        return
    have = {r["url"]: r for r in rows}
    ready = []
    for u in units:
        md5 = u["value"]
        cur = have.get(md5)
        now = "absent" if cur is None else ("allowed" if cur["type"].upper() == ALLOW else "blocked")
        if now != u["before"]:
            run.mark([u], "conflict", f"changed in the tenant since the preview ({now} now); left as it is")
        else:
            ready.append(u)
    if not ready:
        return
    gone = {u["value"] for u in ready}
    if remove:
        new = [r for r in rows if not (r["url"] in gone and r["type"].upper() != ALLOW)]
    else:
        new = list(rows)
        for u in ready:
            # The comment is the operator's own; who applied it is in the app's audit log, not written to the tenant.
            new.append({"url": u["value"], "urlComment": u["object"].get("comment") or "", "type": DENY})
    body = [{k: v for k, v in r.items() if v not in (None, "") or k == "url"} for r in new]
    out = ops.update(run.zia, "sandbox_hashes", None, {"md5_hash_value_list": body}, name="Cloud Sandbox hash list", log=run.log)
    if run.outcome(ready, out, "update"):
        run.wrote_zia = True
        for u in ready:
            u["check"] = "absent" if remove else "blocked"


def _verify(run) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    done = [u for u in run.p["items"] if u["status"] == "applied"]
    if not done:
        return out
    rows, err = read_list(run.zia)
    for u in done:
        out["checked"] += 1
        if rows is None:
            u["verified"] = None
            out["unread"].append(f"{u['value']}: {err}")
            continue
        cur = {r["url"]: r for r in rows}.get(u["value"])
        now = "absent" if cur is None else ("allowed" if cur["type"].upper() == ALLOW else "blocked")
        u["verified"] = now == u.get("check")
        if u["verified"]:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['value']}: {now} when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Remove exactly the hashes this run added (an Undo is not itself undone here)."""
    if ao.is_undo_only(result.get("spec") or {}):
        return None
    added = [u["value"] for u in result.get("items") or [] if u.get("status") == "applied"]
    return {"type": TYPE, "action": "undo", "hashes": added} if added else None


def _objects(client, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """What the page shows beside the form: counts only (the hashes are not listed)."""
    say("Reading the Cloud Sandbox custom hash list…")
    rows, err = read_list(client.zia)
    used, left = read_quota(client.zia)
    out: Dict[str, Any] = {"max_hashes": MAX_HASHES, "comment_max": COMMENT_MAX, "errors": {}}
    if rows is None:
        out["errors"]["sandbox"] = err
        return out
    out.update(blocked=sum(1 for r in rows if r["type"].upper() != ALLOW), allowed=sum(1 for r in rows if r["type"].upper() == ALLOW),
               quota_left=left)
    return out


ao.register(TYPE, family=FAMILY, product="zia", label="Sandbox file hashes",
            hint="Block files your incident response confirmed as malicious, by MD5 hash, in the Cloud Sandbox custom block list. "
                 "Only adds blocked hashes; never changes an allow-listed one. Always asks for a typed confirmation. Needs ZIA platform ticked.",
            in_scope=_in_scope, plan=_plan, read_objects=_objects, handlers={HANDLER: _h_put},
            verify=_verify, inverse=_inverse, script="ops_zia_sandbox.js")
