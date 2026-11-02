"""ZPA identity for the Path analyzer: who the user is, as ZPA's access
policy sees them, and which identity condition decided.

Without an identity the ZPA stage (zpa_path) treats every user as "any
user": a rule condition on a SCIM group, a SCIM attribute, a SAML attribute
or an IdP stays "unknown". With one, those conditions are evaluated:

* the IdP the user signs in with (picked from the tenant's IdPs);
* the user's SCIM groups in that IdP, looked up read-only for a SCIM user
  name (`lookup`: scim_groups.list_scim_groups(idp_id, scim_user_name=...),
  the filter verified in zscaler-sdk-python 1.11.3's docstring and the
  SDK's camelCase conversion to scimUserName). A filter ZPA did not apply
  would answer every group as the user's, so a probe with a name no user
  has comes first: any answer to it means the membership stays unknown;
* attribute values typed by hand ("Department=Finance"), matched by
  attribute name (or id) against SAML conditions and SCIM attribute
  conditions. The SDK has no read of one user's SCIM attribute values
  (scim_attributes only lists an IdP's attribute names and every value of
  one attribute), so SCIM attribute values are typed too; the IdP's SCIM
  attribute names are read (list_scim_attributes) to match them by name.

The rules are evaluated by zpa_analysis.evaluate_rule with ZPA's
semantics: a condition's operands joined by its operator (OR unless it
says AND), a negated condition inverted, the conditions joined by the
rule's operator (AND unless it says OR), the first matching enabled rule
in rule order decides, default deny. Three-valued: anything not given or
not read stays "unknown", with the reason, never "match".

Data handling: a lookup is kept only for the run that made it (`Lookups`,
one per analysis or list, at most MAX_LOOKUPS users), never stored or
logged. Logs name counts, never a user name, group name or attribute
value; the result shows the user, the IdP, the groups (at most
SHOWN_GROUPS) and the attributes the admin typed, because that is what
the answer turns on. Every list is capped.

Read-only: list_idps, list_scim_groups, list_scim_attributes and
list_saml_attributes, nothing else. The caller checks the Scope page (ZPA
ticked) before signing in.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Dict, List, Optional, Tuple

import zpa_analysis
import zpa_reader as zr

IDENTITY_TYPES = ("SCIM_GROUP", "SCIM", "SAML", "IDP")
MAX_USER = 128            # a SCIM user name (an email or login)
MAX_IDP_REF = 128
MAX_ATTRS = 20            # attribute values typed by hand
MAX_ATTR_NAME = 100
MAX_ATTR_VALUE = 200
MAX_ATTR_TEXT = 4000
GROUP_PAGES = 4           # pages of 500 SCIM groups read for one user: 2,000 at most
SHOWN_GROUPS = 50         # SCIM group names the result shows
MAX_IDPS = 50
MAX_ATTR_NAMES = 200
MAX_LOOKUPS = 200         # distinct users looked up in one run (a list)
# A SCIM user name no user has: ZPA answering any group for it means the
# user filter was not applied (assumed: a real user name never has this
# reserved-domain shape).
PROBE_USER = "zme-no-such-user@invalid.invalid"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# An IdP id as it goes into the request path: ZPA's ids are digits; letters,
# '-' and '_' are allowed too, never '/', '.' or '%'.
_IDP_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


# ── what the page or a list row sends ──────────────────────────────────
def _text(v: Any, limit: int, what: str) -> str:
    if v is None:
        return ""
    if not isinstance(v, (str, int)) or isinstance(v, bool):
        raise ValueError(f"The {what} must be text.")
    s = str(v).strip()
    if len(s) > limit:
        raise ValueError(f"The {what} is longer than {limit} characters.")
    if _CONTROL.search(s):
        raise ValueError(f"The {what} has a control character.")
    return s


def parse_attributes(raw: Any) -> List[Tuple[str, str]]:
    """Attribute values typed by hand: "Name=value" per line or separated
    by ';' (or a {name: value | [values]} object). At most MAX_ATTRS pairs.
    ValueError in plain words."""
    pairs: List[Tuple[str, str]] = []
    if raw in (None, "", {}, []):
        return pairs
    if isinstance(raw, dict):
        items = [(k, x) for k, v in list(raw.items())[:MAX_ATTRS + 1] for x in (v if isinstance(v, list) else [v])]
    elif isinstance(raw, str):
        if len(raw) > MAX_ATTR_TEXT:
            raise ValueError(f"The attribute values are longer than {MAX_ATTR_TEXT} characters.")
        items = []
        for part in re.split(r"[\n;]", raw):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise ValueError("Type each attribute as Name=value, for example Department=Finance.")
            k, v = part.split("=", 1)
            items.append((k, v))
    else:
        raise ValueError("Type the attribute values as text: Name=value, one per line.")
    for k, v in items:
        name = _text(k, MAX_ATTR_NAME, "attribute name")
        value = _text(v, MAX_ATTR_VALUE, "attribute value")
        if not name:
            raise ValueError("An attribute has no name: type it as Name=value.")
        if (name, value) not in pairs:
            pairs.append((name, value))
        if len(pairs) > MAX_ATTRS:
            raise ValueError(f"Give at most {MAX_ATTRS} attribute values.")
    return pairs


def parse(raw: Any) -> Optional[Dict[str, Any]]:
    """{idp, user, attributes: [(name, value)]} from what the page sent
    (identity.zpa) or a list row, or None when nothing was given. `idp` is
    an IdP id or name, resolved against the tenant's IdPs later; `user` a
    SCIM user name, looked up only with an IdP. ValueError in plain words."""
    if raw in (None, "", {}):
        return None
    if not isinstance(raw, dict):
        raise ValueError("The ZPA identity must be an object: idp, user and attributes.")
    idp = _text(raw.get("idp"), MAX_IDP_REF, "IdP")
    user = _text(raw.get("user"), MAX_USER, "SCIM user name")
    attrs = parse_attributes(raw.get("attributes"))
    if user and not idp:
        raise ValueError("Pick the IdP the user signs in with, so their SCIM groups can be looked up.")
    if not (idp or user or attrs):
        return None
    return {"idp": idp, "user": user, "attributes": attrs}


def needs_lookup(p: Optional[Dict[str, Any]]) -> bool:
    return bool(p and p.get("idp") and p.get("user"))


def describe(p: Optional[Dict[str, Any]], idp_name: str = "") -> str:
    if not p:
        return ""
    parts = []
    if p.get("idp"):
        parts.append(f"IdP {idp_name or p['idp']}")
    if p.get("user"):
        parts.append(f"SCIM user {p['user']}")
    if p.get("attributes"):
        parts.append("attributes " + ", ".join(f"{k}={v}" for k, v in p["attributes"][:5]) + (" …" if len(p["attributes"]) > 5 else ""))
    return "; ".join(parts)


# ── read-only lookups ──────────────────────────────────────────────────
def _zpa(client: Any) -> Any:
    z = getattr(client, "zpa", None)
    if z is None:
        raise zr.ReadError("this sign-in has no ZPA API")
    problem = zr.customer_id_problem(client)
    if problem:
        raise zr.ReadError(problem)
    return z


def _one_page(call, gate: zr._Gate, size: int) -> List[Dict[str, Any]]:
    gate.before()
    result, resp, err = zr._triple(call({"page": "1", "page_size": str(size)}))
    if err:
        raise zr.ReadError(zr._err_text(err))
    return zr.raw_items(result, resp)


def list_idps(client: Any, cancel: Any = None) -> Dict[str, Any]:
    """The tenant's IdPs (id, name, SCIM and SAML switches) and their SAML
    attribute names, for the what-if's picker. At most MAX_IDPS and
    MAX_ATTR_NAMES. {idps, saml_attributes, error}."""
    out: Dict[str, Any] = {"idps": [], "saml_attributes": [], "error": None}
    gate = zr._Gate(cancel, zr.PACE_SECONDS)
    try:
        zpa = _zpa(client)
        rows = _one_page(lambda q: zpa.idp.list_idps(query_params=q), gate, MAX_IDPS)
        out["idps"] = [{k: v for k, v in zr.normalize_idp(r).items() if k in ("id", "name", "enabled", "scim_enabled", "scim_policy",
                                                                                 "saml_policy_disabled")}
                       for r in rows[:MAX_IDPS] if isinstance(r, dict)]
        attrs = _one_page(lambda q: zpa.saml_attributes.list_saml_attributes(query_params=q), gate, zr.PAGE_SIZE)
        out["saml_attributes"] = [{"id": zr.as_str(zr.get(a, "id")), "name": zr.as_str(zr.get(a, "name"))[:MAX_ATTR_NAME],
                                   "saml_name": zr.as_str(zr.get(a, "samlName"))[:MAX_ATTR_NAME], "idp_id": zr.as_str(zr.get(a, "idpId"))}
                                  for a in attrs[:MAX_ATTR_NAMES] if isinstance(a, dict)]
    except zr.Stopped:
        raise
    except Exception as e:  # noqa: BLE001 — said in words, never a guess
        out["error"] = zr._err_text(e)
    return out


def lookup(client: Any, idp_id: str, user: str, cancel: Any = None) -> Dict[str, Any]:
    """One user's SCIM groups in one IdP, and that IdP's SCIM attribute
    names. {groups: [{id, name}] or None, complete, count, error,
    scim_attr_names: {id: name}}. Read-only; raises zr.Stopped on Stop."""
    out: Dict[str, Any] = {"groups": None, "complete": False, "count": 0, "error": None, "scim_attr_names": {}}
    if not _IDP_ID.match(str(idp_id or "")):
        out["error"] = "the IdP is not one of the tenant's"
        return out
    gate = zr._Gate(cancel, zr.PACE_SECONDS)
    try:
        zpa = _zpa(client)
        fn = zpa.scim_groups.list_scim_groups

        def call(name: str):
            return lambda q: fn(str(idp_id), query_params=dict(q, scim_user_name=name))
        if _one_page(call(PROBE_USER), gate, 1):
            out["error"] = "ZPA did not apply the user filter (a name no user has got groups back), so the user's groups are not known"
            return out
        rows, complete = zr.list_all(call(user), gate, GROUP_PAGES)
        groups = [{"id": zr.as_str(zr.get(r, "id")), "name": zr.as_str(zr.get(r, "name"))[:200] or zr.as_str(zr.get(r, "id"))}
                  for r in rows if isinstance(r, dict) and zr.as_str(zr.get(r, "id"))]
        out.update(groups=groups, complete=complete, count=len(groups))
    except zr.Stopped:
        raise
    except Exception as e:  # noqa: BLE001
        out["error"] = f"the SCIM lookup failed ({zr._err_text(e)})"
        return out
    try:
        sa = getattr(zpa, "scim_attributes", None)
        if sa is not None:
            attrs = _one_page(lambda q: sa.list_scim_attributes(str(idp_id), query_params=q), gate, zr.PAGE_SIZE)
            out["scim_attr_names"] = {zr.as_str(zr.get(a, "id")): zr.as_str(zr.get(a, "name"))[:MAX_ATTR_NAME]
                                      for a in attrs[:MAX_ATTR_NAMES] if isinstance(a, dict) and zr.as_str(zr.get(a, "id"))}
    except zr.Stopped:
        raise
    except Exception:  # noqa: BLE001 — names only help match typed SCIM attributes by name; ids still match
        out["scim_attr_names"] = {}
    return out


class Lookups:
    """The SCIM lookups of one run (an analysis or a list), keyed by IdP and
    user: never kept after the run, at most MAX_LOOKUPS users."""

    def __init__(self, client: Any, cancel: Any = None):
        self.client, self.cancel = client, cancel
        self._done: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.capped = 0

    def get(self, idp_id: str, user: str) -> Dict[str, Any]:
        key = (str(idp_id), user.casefold())
        with self._lock:
            hit = self._done.get(key)
            if hit is not None:
                return hit
            if len(self._done) >= MAX_LOOKUPS:
                self.capped += 1
                return {"groups": None, "complete": False, "count": 0, "scim_attr_names": {},
                        "error": f"not looked up: a run looks up at most {MAX_LOOKUPS} users"}
        if self.client is None:
            res = {"groups": None, "complete": False, "count": 0, "scim_attr_names": {}, "error": "ZPA could not be asked in this run"}
        else:
            res = lookup(self.client, idp_id, user, self.cancel)
        with self._lock:
            self._done[key] = res
        return res

    def __len__(self) -> int:
        return len(self._done)


# ── the identity, resolved against one ZPA read ────────────────────────
def find_idp(snap: Dict[str, Any], ref: str) -> Optional[Dict[str, Any]]:
    """The tenant's IdP named by id or by name (case-insensitive)."""
    ref = (ref or "").strip()
    if not ref:
        return None
    idps = [i for i in snap.get("idps") or [] if isinstance(i, dict)]
    return next((i for i in idps if i.get("id") == ref), None) or next((i for i in idps if (i.get("name") or "").casefold() == ref.casefold()), None)


def resolve(p: Optional[Dict[str, Any]], snap: Dict[str, Any], lookups: Optional[Lookups] = None,
            log: Any = None) -> Optional[Dict[str, Any]]:
    """The identity as the ZPA stage evaluates it: {label, idp, user,
    attributes, groups (shown), group_count, complete, facts (for
    zpa_analysis._norm_user), unknown: [reasons]} or None."""
    if not p:
        return None
    say = log or (lambda m: None)
    unknown: List[str] = []
    facts: Dict[str, Any] = {}
    idp = find_idp(snap, p.get("idp") or "") if p.get("idp") else None
    if p.get("idp") and idp is None:
        unknown.append(("the IdP you picked is not among the tenant's IdPs" if snap.get("idps") is not None
                        else "the tenant's IdPs could not be read") + ", so conditions on the IdP stay unknown")
    if idp is not None:
        facts["idp"] = idp["id"]
    groups: Optional[List[Dict[str, Any]]] = None
    complete = False
    if p.get("user") and idp is not None:
        if lookups is None:
            unknown.append("SCIM groups: ZPA could not be asked in this run")
        else:
            say("Looking up the SCIM groups of the user you gave (read-only)…")
            res = lookups.get(idp["id"], p["user"])
            if res.get("error"):
                unknown.append(f"SCIM groups: {res['error']}")
                say("The SCIM lookup did not answer; SCIM group conditions stay unknown.")
            else:
                groups, complete = res["groups"], bool(res["complete"])
                say(f"Found {len(groups)} SCIM group{'s' if len(groups) != 1 else ''}" + ("" if complete else " (the first pages only)") + ".")
                if not complete:
                    unknown.append(f"SCIM groups: only the first {len(groups):,} were read, so a group not among them stays unknown")
            facts["scim_attr_names"] = res.get("scim_attr_names") or {}
    elif p.get("user"):
        unknown.append("SCIM groups: the user could not be looked up without the IdP")
    else:
        unknown.append("SCIM groups: no SCIM user was given to look up")
    if groups is not None:
        facts["scim_groups"] = [g["id"] for g in groups]
        facts["scim_complete"] = complete
    attrs: Dict[str, List[str]] = {}
    for k, v in p.get("attributes") or []:
        attrs.setdefault(k.strip().lower(), []).append(v)
    if attrs:
        facts["saml"] = attrs
    shown = sorted(groups or [], key=lambda g: g["name"].casefold())[:SHOWN_GROUPS]
    return {"label": describe(p, (idp or {}).get("name", "")), "idp": {"id": idp["id"], "name": idp.get("name")} if idp else None,
            "user": p.get("user") or "", "attributes": [{"name": k, "value": v} for k, v in p.get("attributes") or []],
            "groups": [{"id": g["id"], "name": g["name"]} for g in shown], "group_count": len(groups) if groups is not None else None,
            "groups_shown": len(shown), "complete": complete if groups is not None else None, "facts": facts, "unknown": unknown}


# ── which identity condition decided ───────────────────────────────────
def _q(s: Any) -> str:
    return f"“{s}”"


def operand_words(o: Dict[str, Any], ix: Any, u: Dict[str, Any]) -> str:
    """An identity operand in a person's words."""
    t, lhs, rhs = o["type"], o["lhs"], o["rhs"]
    if t == "SCIM_GROUP":
        g = ix.scim.get(rhs)
        return f"SCIM group {_q((g or {}).get('name') or o.get('name') or rhs)}"
    if t == "SAML":
        a = ix.saml.get(lhs)
        return f"SAML attribute {_q((a or {}).get('name') or o.get('name') or lhs)} = {_q(rhs)}"
    if t == "SCIM":
        name = (u.get("scim_attr_names") or {}).get(lhs) or o.get("name") or lhs
        return f"SCIM attribute {_q(name)} = {_q(rhs)}"
    if t == "IDP":
        i = ix.idps.get(rhs)
        return f"IdP {_q((i or {}).get('name') or o.get('name') or rhs)}"
    return ix.operand_label(o)


def _cond(c: Dict[str, Any], u: Dict[str, Any], seg: Any, ix: Any) -> Tuple[Optional[bool], List[Tuple[Dict[str, Any], Optional[bool]]]]:
    vals = [(o, zpa_analysis._eval_operand(o, u, seg, ix)[0]) for o in c.get("operands") or []]
    v = zpa_analysis._and([x for _, x in vals]) if c.get("operator") == "AND" else zpa_analysis._or([x for _, x in vals])
    if c.get("negated") and v is not None:
        v = not v
    return v, vals


def _is_identity(c: Dict[str, Any]) -> bool:
    return any(o["type"] in IDENTITY_TYPES for o in c.get("operands") or [])


def because(rule: Dict[str, Any], u: Dict[str, Any], seg: Any, ix: Any) -> List[str]:
    """The identity conditions that held for the deciding rule, in words:
    ["SCIM group “Finance” matched", "the user is not in SCIM group
    “Contractors”"]. Empty when no identity condition took part."""
    out: List[str] = []
    for c in rule.get("conditions") or []:
        if not _is_identity(c):
            continue
        v, vals = _cond(c, u, seg, ix)
        if v is not True:
            continue
        ids = [(o, x) for o, x in vals if o["type"] in IDENTITY_TYPES]
        if c.get("negated"):
            out.append("the user does not have " + " or ".join(operand_words(o, ix, u) for o, _ in ids[:3]) + " (a negated condition)")
        else:
            hit = [o for o, x in ids if x is True] or [o for o, _ in ids]
            out.append(" and ".join(operand_words(o, ix, u) for o in hit[:3]) + " matched")
    return out[:4]


def missed(rule: Dict[str, Any], u: Dict[str, Any], seg: Any, ix: Any) -> Optional[str]:
    """Why an earlier rule did not apply to this identity, when an identity
    condition is what failed: "needs SCIM group “Admins”, which the user is
    not in". None when it failed on something else (its application,
    posture, ...)."""
    failing = [(c, vals) for c in rule.get("conditions") or [] if c.get("operands")
               for v, vals in [_cond(c, u, seg, ix)] if v is False]
    if rule.get("operator") != "OR" and any(not _is_identity(c) for c, _ in failing):
        return None   # it fails on something that is not identity (its application, posture, ...)
    for c, vals in failing:
        if not _is_identity(c):
            continue
        ids = [o for o, _ in vals if o["type"] in IDENTITY_TYPES]
        words = " or ".join(operand_words(o, ix, u) for o in ids[:3]) + (f" (+{len(ids) - 3} more)" if len(ids) > 3 else "")
        if c.get("negated"):
            return f"it excludes {words}, and the user has that"
        why = next((zpa_analysis._other_idp(o, u, ix) for o in ids if zpa_analysis._other_idp(o, u, ix)), None) if u.get("idp") else None
        return f"it needs {words}" + (f", but {why}" if why else ", which the user does not have")
    return None


def explain(scen: Dict[str, Any], seg: Any, ix: Any, rules: List[Dict[str, Any]], ident: Dict[str, Any]) -> Dict[str, Any]:
    """What the identity decided in one scenario of the ZPA stage
    (zpa_path): {decided, because, missed: [{rule, why}], unknown, sentence}."""
    u, acc = scen["u"], scen["acc"]
    r = acc.get("rule")
    why = because(r, u, seg, ix) if r else []
    skipped = []
    for row in acc.get("walked") or []:
        if row.get("status") != "not_matched":
            continue
        rule = next((x for x in rules if x["id"] == row["id"]), None)
        m = missed(rule, u, seg, ix) if rule else None
        if m:
            skipped.append({"rule": row["name"], "order": row.get("order"), "why": m})
    conditional = [c["name"] for c in acc.get("conditional") or []]
    if r is not None:
        word = "allowed" if acc["effect"] == "allow" else "denied"
        sentence = f"{word.capitalize()} by {_q(r['name'])}" + (f" because {' and '.join(why)}" if why else "") + "."
    elif acc.get("effect") is None:
        sentence = ""
    else:
        sentence = "Denied by default: no access rule allows this user" + \
            (f" ({_q(skipped[0]['rule'])}: {skipped[0]['why']})" if skipped else "") + "."
    if conditional:
        sentence += (" An earlier rule may decide first, depending on facts not given: " + ", ".join(_q(n) for n in conditional[:3])
                     + (f" (+{len(conditional) - 3} more)" if len(conditional) > 3 else "") + ".")
    return {"decided": r["name"] if r else None, "because": why, "missed": skipped[:5], "conditional": conditional[:5],
            "unknown": list(ident.get("unknown") or []), "sentence": sentence.strip()}


def summary(ident: Optional[Dict[str, Any]], explained: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """The block the page shows: the identity (without the facts used
    internally) and what it decided."""
    if not ident:
        return None
    out = {k: v for k, v in ident.items() if k != "facts"}
    if explained:
        out.update(sentence=explained["sentence"], decided=explained["decided"], because=explained["because"], missed=explained["missed"],
                   conditional=explained["conditional"])
    return out


def assumption(ident: Dict[str, Any]) -> str:
    left = "; ".join(ident.get("unknown") or [])
    return ("ZPA identity: access rules are evaluated for " + (ident.get("label") or "the identity you gave")
            + ". SCIM groups are the ones ZPA lists for the user in that IdP; attribute values you typed are matched by attribute name, "
              "ignoring case; a condition of another IdP is not met; anything not given stays unknown"
            + (f" ({left})" if left else "") + ". Device posture is evaluated both ways; country and machine group are left as any.")
