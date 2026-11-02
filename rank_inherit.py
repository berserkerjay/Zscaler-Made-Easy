"""The admin rank a rule the app creates or moves needs.

Today every builder wrote rank 7 (the lowest). With the tenant's Admin
Ranking on, ZIA evaluates a ranked policy by admin rank first (admin_rank),
so a rank-7 rule asked for at order 1 lands below every rule of rank 0-6:
it is not first. This module decides, for each rule the app creates or
moves, the rank it takes and why, and checks what ZIA stored.

  read_setting(client, scopes)  the Admin Ranking setting through the SDK
                                (zia.advanced_settings.get_advanced_settings,
                                GET /zia/advancedSettings, field
                                enableAdminRankAccess), only when ZIA platform
                                is ticked on the Scope page (admin_rank.SCOPES);
                                parsed by admin_rank.parse (absent: unknown).
  place(rules, order, setting)  a new rule at order N (None: last):
                                  on       it takes the rank of the rule now at
                                           order N (the rule it sits above), or,
                                           going last, of the rule just above it;
                                           never a rank the API client's own
                                           admin rank cannot assign (below);
                                  off      rank 7, as before;
                                  unknown  rank 7, as before, and the preview
                                           says the setting was not read.
  place_moves(...)              the same for the rules a reorder moves: a moved
                                rule keeps its rank when it fits between its new
                                neighbours, else takes the rank of the rule it
                                now sits above (or just below, when it goes last).
  stored(planned, row)          the read-back: the rank and order ZIA stored,
                                compared with what was sent.

The API client's own admin rank (assumed: inferred, never read)
---------------------------------------------------------------
zscaler-sdk-python 1.11.3 has no call that returns the calling API client's
own admin role or rank: zia.admin_roles.list_roles lists every role (with
its `rank`, models/admin_roles.py) and zia.admin_users.list_admin_users every
admin (with its `role`), but neither says which one is this API client; a
OneAPI client's role is set in ZIdentity, whose SDK (zid) has no rank. So it
is inferred from the rules read, and marked assumed:

  * a rule's `accessControl` (READ_WRITE / READ_ONLY, on every ranked rule
    model of the SDK, e.g. models/ssl_inspection_rules.py) is assumed to be
    READ_ONLY when the rule's rank is above the API client's admin rank
    (admin_ops.lock_reason reads it the same way): a READ_WRITE rule of rank
    r means the client's rank is r or higher (it may assign rank r); a
    READ_ONLY rule of rank r means it is lower than r (it may not).
  * ZIA refuses a rule whose rank is above the client's admin rank with
    403 RBA_LIMITED "Rule rank is higher than the admin rank." (seen on a
    real tenant, pack_deploy._rank_refusal); rank 7 is always assignable.
  * When the rules say nothing either way, the rank is planned as needed and
    the preview warns that the client's rank could not be read.

Other assumptions, said where they matter:

  * Rule orders within a ranked policy follow the ranks when Admin Ranking
    is on (ZIA keeps a higher-rank rule above a lower-rank one), so the rule
    "at order N" is the N-th rule in (rank, order) order.
  * Forwarding control rules carry a rank in the SDK (models/
    forwarding_control_policy.py) and are placed the same way; whether ZIA
    evaluates them by rank is assumed, not documented in a source here.
  * Inline Web DLP sub-rules (exceptions) and Outbound Email DLP rules (no
    rank in the SDK model) are left as they are.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

import admin_rank

ON, OFF, UNKNOWN, OUT_OF_SCOPE = admin_rank.ON, admin_rank.OFF, admin_rank.UNKNOWN, admin_rank.OUT_OF_SCOPE
HIGHEST, LOWEST = admin_rank.HIGHEST, admin_rank.LOWEST
LEGACY_RANK = LOWEST          # what every builder wrote before: kept while Admin Ranking is off or unknown

CALLER_NOT_READABLE = ("the Zscaler SDK (1.11.3) has no call that returns this API client's own admin rank, so it is inferred from "
                       "which rules ZIA lets it edit (assumed)")
REFUSAL = "Rule rank is higher than the admin rank"


# ---------------------------------------------------------------------------
# The setting
# ---------------------------------------------------------------------------

def _setting(state: str, why: str = "") -> Dict[str, Any]:
    return {"state": state, "why": why, "source": admin_rank.SOURCE}


def _raw(resp: Any) -> Optional[Dict[str, Any]]:
    """The JSON object the tenant sent behind an SDK response, or None."""
    getter = getattr(resp, "get_body", None)
    try:
        body = getter() if callable(getter) else None
        if isinstance(body, (bytes, str)) and body:
            import json
            body = json.loads(body)
    except Exception:  # noqa: BLE001 — the SDK model is used instead
        return None
    return body if isinstance(body, dict) else None


def read_setting(client: Any, scopes: Any) -> Dict[str, Any]:
    """{state, why, source}: the Admin Ranking setting, read once through the
    SDK when ZIA platform is in scope. A failed or absent read is unknown,
    never off. The raw answer is preferred: through the SDK model a missing
    enableAdminRankAccess reads as false (the model's default; assumed)."""
    if not admin_rank.in_scope(scopes):
        return _setting(OUT_OF_SCOPE, admin_rank.NOT_IN_SCOPE_WHY)
    svc = getattr(getattr(client, "zia", None), "advanced_settings", None)
    fn = getattr(svc, "get_advanced_settings", None)
    if not callable(fn):
        return _setting(UNKNOWN, "this sign-in offers no ZIA advanced settings")
    try:
        ret = fn()
    except Exception as e:  # noqa: BLE001 — a Stop is re-raised; anything else is "could not read"
        _reraise_stop(e)
        return _setting(UNKNOWN, f"the advanced settings could not be read ({type(e).__name__})")
    data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        st = err.get("status") if isinstance(err, dict) else getattr(err, "status", None)
        return _setting(UNKNOWN, f"the advanced settings could not be read{f' (HTTP {st})' if st else ''}")
    raw = _raw(resp)
    if raw is not None:
        return admin_rank.parse(raw)
    if data is not None and not isinstance(data, dict):
        for m in ("as_dict", "to_dict"):
            if callable(getattr(data, m, None)):
                try:
                    data = getattr(data, m)()
                    break
                except Exception:  # noqa: BLE001
                    data = None
    return admin_rank.parse(data)


def _reraise_stop(e: BaseException) -> None:
    import zia_rate
    from data_flow import ReadStopped
    if isinstance(e, (ReadStopped, zia_rate.Cancelled)):   # pack_deploy.ReadsStopped is a BaseException: never caught here
        raise e


def state_of(setting: Any) -> str:
    return admin_rank.state_of(setting)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _get(rule: Any, *keys: str) -> Any:
    if not isinstance(rule, dict):
        return None
    for k in keys:
        if rule.get(k) is not None:
            return rule[k]
    return None


def _int(v: Any, default: int = 0) -> int:
    if isinstance(v, bool):
        return default
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def is_default(rule: Any) -> bool:
    d = _get(rule, "default_rule", "defaultRule")
    return d is True or str(d).lower() == "true" or _int(_get(rule, "order"), 1) <= 0


def access(rule: Any) -> Optional[str]:
    """READ_WRITE, READ_ONLY or None (not said)."""
    a = str(_get(rule, "access_control", "accessControl") or "").strip().upper()
    return a if a in ("READ_WRITE", "READ_ONLY") else None


def name_of(rule: Any) -> str:
    return str(_get(rule, "name") or f"rule {_get(rule, 'id')}")


def live(rules: Iterable[Any], *, exclude: Any = None) -> List[Dict[str, Any]]:
    """The policy's rules other than the Default rule (and `exclude`, a rule
    id), in evaluation order with Admin Ranking on: rank, then order."""
    ex = None if exclude is None else str(exclude)
    rows = [r for r in rules if isinstance(r, dict) and not is_default(r) and (ex is None or str(_get(r, "id")) != ex)]
    return sorted(rows, key=lambda r: (admin_rank.rank_of(r), _int(_get(r, "order"), 0), str(_get(r, "id"))))


def caller(rules: Iterable[Any]) -> Dict[str, Any]:
    """What the rules say about the API client's own admin rank (assumed,
    module docstring): {at_most, at_least, basis}. at_most: it may assign
    this rank and every lower one (it can edit a rule of that rank);
    at_least: it may not assign a rank above this (it cannot edit a rule
    of the rank just above). None when the rules say nothing."""
    rules = list(rules)
    rw = [admin_rank.rank_of(r) for r in rules if isinstance(r, dict) and access(r) == "READ_WRITE" and admin_rank.shown_rank(r) is not None]
    ro = [admin_rank.rank_of(r) for r in rules if isinstance(r, dict) and access(r) == "READ_ONLY" and admin_rank.shown_rank(r) is not None]
    at_most = min(rw) if rw else None
    at_least = (max(ro) + 1) if ro else None
    if at_least is not None and at_least > LOWEST:
        at_least = LOWEST
    if at_most is not None and at_least is not None and at_most < at_least:
        at_most = None   # the rules disagree (a role without write access to the policy): trust only the refusal side
    return {"at_most": at_most, "at_least": at_least, "basis": CALLER_NOT_READABLE}


def can_assign(rank: int, who: Dict[str, Any]) -> Optional[bool]:
    """True: the API client may give a rule this rank; False: it may not;
    None: not known. Rank 7 is always assignable."""
    if rank >= LOWEST:
        return True
    if who.get("at_most") is not None and rank >= who["at_most"]:
        return True
    if who.get("at_least") is not None and rank < who["at_least"]:
        return False
    return None


def _surely_assignable(who: Dict[str, Any]) -> int:
    return who["at_most"] if who.get("at_most") is not None else LOWEST


def unknown_why(setting: Any) -> str:
    st = state_of(setting)
    why = (setting or {}).get("why") if isinstance(setting, dict) else ""
    return ("Admin ranking was not read" if st == OUT_OF_SCOPE else "Admin ranking could not be read") + (f" ({why})" if why else "")


# ---------------------------------------------------------------------------
# Placing a new rule
# ---------------------------------------------------------------------------

def place(rules: Sequence[Any], order: Optional[int], setting: Any, *, name: str = "", exclude: Any = None,
          who: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The rank (and the order to send) for a rule placed at `order` (1 is
    the top; None or past the end: last) among `rules` (the policy as read).
    {rank, order, asked_order, state, why, warning, assumed, neighbour}:
    `warning` is set when the rule will not be where asked or the client's
    rank is not known; `assumed` when the rank rests on an assumption."""
    st = state_of(setting)
    asked = None if order is None else max(1, _int(order, 1))
    base = {"state": st, "asked_order": asked, "order": asked, "name": name, "warning": "", "assumed": False, "neighbour": None}
    if st == OFF:
        return dict(base, rank=LEGACY_RANK, why=f"Admin ranking is off, so rank {LEGACY_RANK} as before: rule order alone decides.")
    if st != ON:
        return dict(base, rank=LEGACY_RANK, assumed=True,
                    why=f"{unknown_why(setting)}: rank {LEGACY_RANK}, as before. If admin ranking is on, the rule is evaluated after every rule "
                        f"of rank 0 to 6, so it may not sit where asked.")
    rows = live(rules, exclude=exclude)
    who = who if who is not None else caller(rules)
    last = asked is None or asked > len(rows)
    if not rows:
        return dict(base, rank=LEGACY_RANK, order=1 if asked is not None else None,
                    why=f"Admin ranking is on and the policy has no other rule to take a rank from: rank {LEGACY_RANK} (the lowest).")
    nb = rows[-1] if last else rows[asked - 1]
    want = admin_rank.rank_of(nb)
    where = (f"it goes last, so it takes rank {want} of '{name_of(nb)}', the rule just above it" if last
             else f"it takes rank {want} of '{name_of(nb)}', the rule now at order {asked} that it is placed above")
    out = dict(base, neighbour={"name": name_of(nb), "rank": admin_rank.shown_rank(nb), "order": _get(nb, "order")})
    ok = can_assign(want, who)
    if ok is not False:
        out.update(rank=want, why=f"Admin ranking is on: {where}" + ("" if ok is None else "."))
        if ok is None:
            out.update(assumed=True, why=out["why"] + f" ({CALLER_NOT_READABLE}).",
                       warning=f"'{name}': this API client's own admin rank could not be read, so rank {want} is assumed to be one it may "
                               f"assign. If its rank is lower, ZIA refuses the rule ('{REFUSAL}').")
        return out
    got = _surely_assignable(who)
    eff = 1 + sum(1 for r in rows if admin_rank.rank_of(r) < got)
    send = None if last else max(asked, eff)
    above = [r for r in rows if admin_rank.rank_of(r) < got]
    cannot = f"it cannot edit '{name_of(nb)}'" if access(nb) == "READ_ONLY" else f"it cannot edit rules of rank {who['at_least'] - 1}"
    out.update(rank=got, order=send, assumed=True,
               why=f"Admin ranking is on: it should take rank {want} ({where}), but this API client may not assign rank {want} ({cannot}; "
                   f"assumed from what ZIA lets it edit), so it gets rank {got}.")
    if not last and send != asked:
        lo, hi = min(admin_rank.rank_of(r) for r in above), max(admin_rank.rank_of(r) for r in above)
        span = f"{lo}" if lo == hi else f"{lo}–{hi}"
        out["warning"] = (f"'{name}' was asked for order {asked}, but the API role's admin rank is too low for rank {want}: it is created at "
                          f"rank {got} and lands at order {send}, below {len(above)} rule(s) of rank {span} (for example '{name_of(above[0])}'), "
                          f"so it is {'not first' if asked == 1 else f'not at order {asked}'}. Raise the API role's admin rank (Role "
                          f"Management) to place it there.")
    return out


# ---------------------------------------------------------------------------
# A reorder: the ranks the moved rules need
# ---------------------------------------------------------------------------

def place_moves(rows_in_desired_order: Sequence[Dict[str, Any]], moved: Iterable[str], setting: Any,
                id_of: Callable[[Any], str]) -> Dict[str, Dict[str, Any]]:
    """{rule id: {rank, before, why, warning, assumed}} for each moved rule
    whose rank must change so it is evaluated where the reorder puts it
    (Admin Ranking on only). A moved rule keeps its rank when it fits
    between the rule above it and the next rule that stays; otherwise it
    takes the rank of the next rule that stays (the rule it now sits above),
    or, going last, of the rule just above it. A rank the API client cannot
    assign is not planned: the rule keeps its rank and a warning says the
    order may not hold."""
    if state_of(setting) != ON:
        return {}
    mv = {str(x) for x in moved}
    rows = [r for r in rows_in_desired_order if not is_default(r)]
    who = caller(rows)
    out: Dict[str, Dict[str, Any]] = {}
    floor: Optional[int] = None
    for i, r in enumerate(rows):
        rid = id_of(r)
        cur = admin_rank.rank_of(r)
        if rid not in mv:
            floor = cur if floor is None else max(floor, cur)
            continue
        nxt = next((x for x in rows[i + 1:] if id_of(x) not in mv), None)
        lo = floor if floor is not None else HIGHEST
        hi = admin_rank.rank_of(nxt) if nxt is not None else LOWEST
        if lo <= cur <= hi:
            floor = cur if floor is None else max(floor, cur)
            continue
        if nxt is not None:
            want, by = hi, f"the rank of '{name_of(nxt)}', the rule it now sits above"
        else:
            want, by = lo, "the rank of the rule just above it (it goes last)"
        ok = can_assign(want, who)
        if ok is False:
            out[rid] = {"rank": cur, "before": cur, "change": False, "assumed": True,
                        "why": f"Admin ranking is on: at its new place it needs rank {want} ({by}), but this API client's admin rank is too "
                               f"low to assign it, so it keeps rank {cur}.",
                        "warning": f"'{name_of(r)}' keeps rank {cur}: the API role's admin rank is too low for rank {want}, so ZIA keeps it "
                                   f"with the other rank-{cur} rules and it may not sit where the new order puts it; the read-back shows it."}
            floor = cur if floor is None else max(floor, cur)
            continue
        out[rid] = {"rank": want, "before": cur, "change": True, "assumed": ok is None,
                    "why": f"Admin ranking is on: rank {cur} → {want}, {by}, so it is evaluated where the new order puts it"
                           + (f" ({CALLER_NOT_READABLE})." if ok is None else "."),
                    "warning": (f"'{name_of(r)}': this API client's own admin rank could not be read, so rank {want} is assumed to be one it "
                                f"may assign. If its rank is lower, ZIA refuses the move ('{REFUSAL}').") if ok is None else ""}
        floor = want if floor is None else max(floor, want)
    return out


# ---------------------------------------------------------------------------
# Preview text and read-back
# ---------------------------------------------------------------------------

def notes(setting: Any) -> List[str]:
    """The plan's note on how ranks were chosen."""
    st = state_of(setting)
    if st == ON:
        return ["Admin ranking is on (ZIA advanced settings): each new rule takes the admin rank of the rule it is placed above "
                "(or of the rule just above it when it goes last), so it is evaluated where it is placed. The API client's own admin "
                "rank: " + CALLER_NOT_READABLE + "."]
    if st == OFF:
        return [f"Admin ranking is off (ZIA advanced settings): new rules get rank {LEGACY_RANK} as before; rule order alone decides."]
    return [f"{unknown_why(setting)}: new rules get rank {LEGACY_RANK} as before. If admin ranking is on in this tenant, a rule "
            f"placed at the top is evaluated after every rule of rank 0 to 6. Tick ZIA platform on the Scope page so the setting is read."]


def summary(setting: Any, placements: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """What a preview shows: the setting and each new or moved rule's rank."""
    return {"state": state_of(setting), "why": (setting or {}).get("why") if isinstance(setting, dict) else "",
            "describe": admin_rank.describe(setting), "caller": CALLER_NOT_READABLE,
            "rules": [{k: p.get(k) for k in ("name", "policy", "rank", "order", "asked_order", "why", "warning", "assumed", "before")}
                      for p in placements]}


def stored(sent: Dict[str, Any], row: Any) -> Optional[str]:
    """Why what ZIA stored differs from what was sent ({rank, order}; a key
    left out or None is not compared), or None when it matches. A field the
    read does not return is not called a difference."""
    if not isinstance(row, dict):
        return "the rule could not be read back"
    bad = []
    if sent.get("rank") is not None and _get(row, "rank") is not None and admin_rank.rank_of(row) != _int(sent["rank"], -1):
        bad.append(f"rank {admin_rank.rank_of(row)} stored, {sent['rank']} sent")
    if sent.get("order") is not None and _get(row, "order") is not None and _int(_get(row, "order"), -1) != _int(sent["order"], -2):
        bad.append(f"order {_get(row, 'order')} stored, {sent['order']} sent")
    return "; ".join(bad) or None
