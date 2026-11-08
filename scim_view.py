"""SCIM visibility: a read-only view of the identity providers (IdPs) ZPA
knows, which of them provision by SCIM, the SCIM groups each holds and a
sync status per IdP (group count, newest change ZPA reports).

Read-only: list_idps and list_scim_groups of the SDK, paced and stoppable
through zpa_reader. The SDK has no read that lists SCIM users, so the opt-in
user list (list_users) reads the IdP's own SCIM 2.0 service,
GET {scimServiceProviderEndpoint}/Users, the way an identity provider's
client would:

* OFF unless the admin has entered that IdP's SCIM shared secret (the bearer),
  once, into the operating-system credential store (set_token; the same
  ``keyring`` use as report_delivery); it is never written to a file, a log,
  the audit trail or a response, and is sent to no other host;
* the endpoint comes from the tenant's IdP object (never typed), must be
  https with no credentials in it and a Zscaler-owned SCIM host name
  (check_endpoint, on zscaler_update_check.url_shape), else nothing is sent;
* GET only, no redirect followed, a timeout, TLS verified, the answer capped,
  paged with startIndex/count up to MAX_PAGES pages;
* only user name, active, display name and the number of groups are kept;
  group member lists are never fetched or shown.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import re
from urllib.parse import urlparse

import zpa_identity as zi
import zpa_reader as zr
import zscaler_update_check as _uc

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


# ── opt-in: the SCIM users of one IdP (the IdP's own SCIM 2.0 service) ─────
KEYRING_SERVICE = "dlp-check-scim"
PAGE_SIZE = 100          # count= sent per page
MAX_PAGES = 5            # pages read per request: at most 500 users
MAX_USERS = PAGE_SIZE * MAX_PAGES
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = (5, 20)
SHOWN_TEXT = 200
# Zscaler-owned domains a SCIM service can live under (the clouds in zscaler_clouds, the ZPA clouds and zscaler.com).
SCIM_DOMAINS = ("zscaler.com", "zscaler.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net", "zscloud.net", "zscalerten.net",
                "zscalerbeta.net", "zscalergov.net", "zscalergov.us", "private.zscaler.com", "zpatwo.net", "zpabeta.net", "zpagov.net", "zpagov.us")
_SCIM_LABEL = re.compile(r"^scim[a-z0-9-]*$")
_TOKEN_OK = re.compile(r"^[\x21-\x7e]{8,2048}$")      # printable ASCII, no space: a bearer token


class ScimUsersError(Exception):
    """A refusal said in words. Never carries the token."""


def _keyring() -> Any:
    try:
        import keyring  # type: ignore
        if keyring is None:
            return None
        keyring.get_keyring()
        return keyring
    except Exception:  # noqa: BLE001
        return None


def _idp_key(idp_id: Any) -> str:
    v = str(idp_id or "")
    if not zi._IDP_ID.match(v):
        raise ScimUsersError("That is not one of the tenant's IdP ids.")
    return v


def set_token(idp_id: Any, token: Any) -> None:
    """Keep the IdP's SCIM shared secret in the OS credential store only (no file fallback)."""
    key = _idp_key(idp_id)
    kr = _keyring()
    if kr is None:
        raise ScimUsersError("No operating-system credential store is available; the SCIM secret is not kept anywhere else.")
    if not isinstance(token, str) or not _TOKEN_OK.match(token.strip()):
        raise ScimUsersError("That is not a usable SCIM shared secret (8 to 2048 printable characters, no spaces).")
    kr.set_password(KEYRING_SERVICE, key, token.strip())


def clear_token(idp_id: Any) -> bool:
    key = _idp_key(idp_id)
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.delete_password(KEYRING_SERVICE, key)
        return True
    except Exception:  # noqa: BLE001 — nothing stored is the same as cleared
        return False


def _token(idp_id: str) -> str:
    kr = _keyring()
    if kr is None:
        return ""
    try:
        return kr.get_password(KEYRING_SERVICE, idp_id) or ""
    except Exception:  # noqa: BLE001
        return ""


def has_token(idp_id: Any) -> bool:
    try:
        return bool(_token(_idp_key(idp_id)))
    except ScimUsersError:
        return False


def check_endpoint(url: Any) -> str:
    """The SCIM service address, canonical without a trailing slash, or ScimUsersError: https only, no credentials, no query or
    fragment, no port other than 443, and a host that is a Zscaler-owned SCIM host (a name starting with 'scim' under one of
    SCIM_DOMAINS). Nothing is sent before this passes."""
    u = str(url or "").strip()
    if not u:
        raise ScimUsersError("This IdP has no SCIM service address.")
    host, why = _uc.url_shape(u)
    if why:
        raise ScimUsersError(why[0].upper() + why[1:] + ". Nothing was sent.")
    p = urlparse(u)
    try:
        port = p.port
    except ValueError:
        port = -1
    if port not in (None, 443) or p.query or p.fragment or p.params:
        raise ScimUsersError("The SCIM service address must be a plain https address (no port, query or fragment). Nothing was sent.")
    labels = host.split(".")
    owned = any(host == d or host.endswith("." + d) for d in SCIM_DOMAINS)
    if not owned or not _SCIM_LABEL.match(labels[0]) or len(labels) < 3:
        raise ScimUsersError("The SCIM service address is not a Zscaler SCIM host, so it is not contacted. Nothing was sent.")
    return f"https://{host}{p.path.rstrip('/')}"


def _http_get(url: str, headers: Dict[str, str]) -> Any:
    """(status, body bytes) of one GET: timeout, TLS verified, no redirect, answer capped at MAX_BYTES."""
    import requests
    r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False, stream=True)
    try:
        body = r.raw.read(MAX_BYTES + 1, decode_content=True)
    finally:
        r.close()
    return r.status_code, body


def _row(u: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(u, dict):
        return None
    name = u.get("userName")
    if not isinstance(name, str) or not name:
        return None
    disp = u.get("displayName")
    if not isinstance(disp, str):
        n = u.get("name")
        disp = n.get("formatted") if isinstance(n, dict) and isinstance(n.get("formatted"), str) else ""
    groups = u.get("groups")
    return {"userName": name[:SHOWN_TEXT], "active": u.get("active") if isinstance(u.get("active"), bool) else None,
            "displayName": disp[:SHOWN_TEXT], "group_count": len(groups) if isinstance(groups, list) else 0}


def list_users(endpoint: Any, idp_id: Any, get: Optional[Any] = None) -> Dict[str, Any]:
    """{users: [{userName, active, displayName, group_count}], total, shown, complete, error, token_stored}. Off (error, nothing sent)
    without a stored secret; refused (nothing sent) for an endpoint that is not an https Zscaler SCIM host. `get(url, headers)`
    -> (status, bytes) is injectable for tests. Read-only: GET /Users only; the secret is in the Authorization header of
    requests to the checked host and nowhere else, and is in no result, log or error text."""
    out: Dict[str, Any] = {"users": [], "total": None, "shown": 0, "complete": True, "error": None, "token_stored": False}
    try:
        key = _idp_key(idp_id)
        tok = _token(key)
        out["token_stored"] = bool(tok)
        if not tok:
            out["error"] = "The user list is off: enter this IdP's SCIM shared secret first (it is kept in the operating-system credential store only)."
            return out
        base = check_endpoint(endpoint)
    except ScimUsersError as e:
        out["error"] = str(e)
        return out
    headers = {"Authorization": f"Bearer {tok}", "Accept": "application/scim+json, application/json"}
    fetch = get or _http_get
    start = 1
    for _page in range(MAX_PAGES):
        url = f"{base}/Users?startIndex={start}&count={PAGE_SIZE}&attributes=userName,active,displayName,name,groups"
        try:
            status, body = fetch(url, headers)
        except Exception as e:  # noqa: BLE001 — the class only: an exception's text could carry the request
            out.update(error=f"The SCIM service could not be reached ({type(e).__name__}).", complete=False)
            return out
        if status in (401, 403):
            out.update(error="The SCIM service refused the shared secret (HTTP %d). Check it was copied from this IdP's SCIM settings." % status, complete=False)
            return out
        if status != 200 or body is None or len(body) > MAX_BYTES:
            out.update(error=f"The SCIM service answered HTTP {int(status) if isinstance(status, int) else 0} or too much data.", complete=False)
            return out
        try:
            doc = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            out.update(error="The SCIM service did not answer SCIM JSON.", complete=False)
            return out
        res = doc.get("Resources") if isinstance(doc, dict) else None
        if not isinstance(res, list):
            out.update(error="The SCIM service did not answer a Resources list.", complete=False)
            return out
        total = doc.get("totalResults")
        if isinstance(total, int) and not isinstance(total, bool):
            out["total"] = total
        for u in res:
            r = _row(u)
            if r and len(out["users"]) < MAX_USERS:
                out["users"].append(r)
        start += len(res)
        if not res or (out["total"] is not None and start > out["total"]):
            break
    else:
        out["complete"] = out["total"] is not None and start > out["total"]
    if out["total"] is not None and len(out["users"]) < out["total"]:
        out["complete"] = False
    out["shown"] = len(out["users"])
    return out


def users_for_idp(client: Any, idp_id: Any, get: Optional[Any] = None, cancel: Any = None) -> Dict[str, Any]:
    """Read the IdP's SCIM address from the tenant (SDK list_idps), then list_users. {idp, users, ...}."""
    empty = {"idp": None, "users": [], "total": None, "shown": 0, "complete": True, "token_stored": False, "endpoint_host": ""}
    try:
        key = _idp_key(idp_id)
        gate = zr._Gate(cancel, zr.PACE_SECONDS)
        zpa = zi._zpa(client)
        rows = zi._one_page(lambda q: zpa.idp.list_idps(query_params=q), gate, zi.MAX_IDPS)
    except (ScimUsersError, zr.ReadError) as e:
        return dict(empty, error=str(e))
    idp = next((r for r in rows if isinstance(r, dict) and zr.as_str(zr.get(r, "id")) == key), None)
    if idp is None:
        return dict(empty, error="That IdP is not one of the tenant's. Nothing was read.")
    out = {"idp": {"id": key, "name": zr.as_str(zr.get(idp, "name")) or key}, "scim_enabled": zr.as_bool(zr.get(idp, "scimEnabled")),
           "secret_set_in_zpa": zr.as_bool(zr.get(idp, "scimSharedSecretExists")),
           "endpoint_host": ""}
    if not out["scim_enabled"]:
        return dict(out, users=[], total=None, shown=0, complete=True, token_stored=has_token(key),
                    error="SCIM is not enabled on this IdP in ZPA, so there is no user list to read.")
    ep = zr.as_str(zr.get(idp, "scimServiceProviderEndpoint"))
    try:
        out["endpoint_host"] = urlparse(check_endpoint(ep)).hostname or ""
    except ScimUsersError:
        pass
    return dict(out, **list_users(ep, key, get))
