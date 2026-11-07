"""SCIM visibility: a read-only view of the identity providers (IdPs) ZPA
knows, which of them provision by SCIM, the SCIM groups each holds and a
sync status per IdP (group count, newest change ZPA reports).

Read-only: list_idps and list_scim_groups of the SDK, paced and stoppable
through zpa_reader. The SDK has no read that lists SCIM users, so users
are not listed (a user's groups are looked up by name on the Path analyzer
page instead); group names are shown, member lists never are.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import zpa_identity as zi
import zpa_reader as zr

MAX_SCIM_IDPS = 20       # SCIM-enabled IdPs whose groups are read
GROUP_PAGES = 2          # pages of 500 groups read per IdP
SHOWN_GROUPS = 100       # group names shown per IdP


def _newest(rows: List[Dict[str, Any]]) -> str:
    """The newest modifiedTime ZPA reports for the groups (epoch seconds as text), or ''."""
    best: Optional[int] = None
    for r in rows:
        try:
            v = int(str(zr.get(r, "modifiedTime") or "").strip())
        except ValueError:
            continue
        best = v if best is None or v > best else best
    return str(best) if best is not None else ""


def overview(client: Any, cancel: Any = None) -> Dict[str, Any]:
    """{idps: [{id, name, enabled, scim_enabled, scim_policy, groups,
    group_count, complete, last_change, status, error}], scim_idps, error}.
    status: scim_off, no_groups, synced or unreadable. Never writes."""
    base = zi.list_idps(client, cancel)
    out: Dict[str, Any] = {"idps": [], "scim_idps": 0, "error": base.get("error")}
    if base.get("error"):
        return out
    gate = zr._Gate(cancel, zr.PACE_SECONDS)
    zpa = zi._zpa(client)
    read = 0
    for idp in base["idps"]:
        row = dict(idp, groups=[], group_count=0, complete=True, last_change="", error=None,
                   status="scim_off" if not idp.get("scim_enabled") else "no_groups")
        if idp.get("scim_enabled") and read < MAX_SCIM_IDPS:
            read += 1
            try:
                rows, complete = zr.list_all(lambda q, i=str(idp["id"]): zpa.scim_groups.list_scim_groups(i, query_params=q), gate, GROUP_PAGES)
                names = sorted({zr.as_str(zr.get(g, "name")) for g in rows if isinstance(g, dict) and zr.as_str(zr.get(g, "name"))}, key=str.casefold)
                row.update(groups=names[:SHOWN_GROUPS], group_count=len(rows), complete=complete, last_change=_newest(rows),
                           status="synced" if rows else "no_groups")
            except zr.Stopped:
                raise
            except Exception as e:  # noqa: BLE001 — said in words
                row.update(error=zr._err_text(e), status="unreadable")
        out["idps"].append(row)
    out["scim_idps"] = sum(1 for i in out["idps"] if i.get("scim_enabled"))
    return out
