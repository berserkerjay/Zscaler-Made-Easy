"""ZPA identity: the Path analyzer's ZPA step evaluated for a user
(zpa_identity, zpa_analysis, zpa_path), Test a list's identity columns
(bulk_test) and the ZPA builder's access rules over SCIM groups and SAML
attributes (ops_zpa).

Fakes only: the ZPA side answers through tests/test_zpa_analysis.FakeTenant
(the SDK's models) with a SCIM layer that applies, or ignores, the
scim_user_name filter; the builder runs against tests/zpa_fake (which
builds conditions with the SDK's own _create_conditions_v1). No network,
no clock, every state file in tmp_path."""
from __future__ import annotations

import copy
import inspect
import json
import os
import re
import sys
import threading

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import bulk_test  # noqa: E402
import ops_zpa  # noqa: E402
import zpa_analysis as za  # noqa: E402
import zpa_identity as zi  # noqa: E402
import zpa_path as zp  # noqa: E402
import zpa_reader  # noqa: E402
from test_path_zpa_workloads import CHANNELS, CREDS, SECRET, api, zpa_data  # noqa: E402,F401
from test_zpa_analysis import GRP, FakeTenant, _cond, _op, _rule  # noqa: E402
from zpa_fake import Client as BuilderClient  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER = "jane.doe@acme.example"
OTHER = "sam.lee@acme.example"


# ── the tenant ──────────────────────────────────────────────────────────
def scim(gid, idp="idp1"):
    return _op("SCIM_GROUP", idp, gid)


def saml(value, attr="sa1"):
    return _op("SAML", attr, value)


RULES = [
    _rule("r1", 1, "Contractors blocked", "DENY", _cond(GRP("g1")), _cond(scim("sg-con"))),
    _rule("r2", 2, "Admins", "ALLOW", _cond(GRP("g1")), _cond(scim("sg-admin"))),
    _rule("r3", 3, "Finance apps", "ALLOW", _cond(GRP("g1")), _cond(scim("sg-fin"), scim("sg-hr"))),
    _rule("r4", 4, "Finance department", "ALLOW", _cond(GRP("g1")), _cond(saml("Finance")), _cond(scim("sg-con"), negated=True)),
]
GROUPS = {"idp1": [{"id": "sg-fin", "name": "Finance", "idpId": "idp1"}, {"id": "sg-admin", "name": "Admins", "idpId": "idp1"},
                   {"id": "sg-con", "name": "Contractors", "idpId": "idp1"}, {"id": "sg-hr", "name": "HR", "idpId": "idp1"}],
          "idp2": [{"id": "sg-x", "name": "Finance", "idpId": "idp2"}]}
MEMBERS = {USER: {"sg-fin"}, OTHER: {"sg-con", "sg-fin"}}


def data(rules=None, scim_policy=True, saml_disabled=False):
    d = zpa_data(access=copy.deepcopy(rules if rules is not None else RULES))
    d["idps"] = [{"id": "idp1", "name": "Okta", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": scim_policy,
                  "disableSamlBasedPolicy": saml_disabled},
                 {"id": "idp2", "name": "Entra", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": True}]
    d["saml_attributes"] = [{"id": "sa1", "name": "Department_Okta", "samlName": "department", "idpId": "idp1"}]
    d["scim_groups"] = copy.deepcopy(GROUPS)
    return d


def snap(**kw):
    return zp.read(FakeTenant(data(**kw)), pace=0)


class Scim:
    """client.zpa.scim_groups / scim_attributes: the user filter applied
    (or ignored), every call recorded."""

    def __init__(self, ignore=False, fail=None):
        self.calls, self.ignore, self.fail = [], ignore, fail

    def list_scim_groups(self, idp_id, query_params=None):
        q = dict(query_params or {})
        self.calls.append(("list_scim_groups", idp_id, q))
        if self.fail:
            return None, None, self.fail
        rows = GROUPS.get(idp_id, [])
        if "scim_user_name" in q and not self.ignore:
            rows = [g for g in rows if g["id"] in MEMBERS.get(q["scim_user_name"], set())]
        page, size = int(q.get("page", 1)), int(q.get("page_size", 20))
        return [dict(g) for g in rows[(page - 1) * size: page * size]], None, None

    def list_scim_attributes(self, idp_id, query_params=None):
        self.calls.append(("list_scim_attributes", idp_id, dict(query_params or {})))
        return [{"id": "sca1", "name": "costCenter", "idpId": idp_id}], None, None


class IdClient:
    """An SDK client: client.zpa over the FakeTenant, with the SCIM layer."""

    def __init__(self, d=None, **kw):
        self.tenant = FakeTenant(d or data())
        self.scim = Scim(**kw)
        outer = self

        class Zpa:
            def __getattr__(self, name):
                if name in ("scim_groups", "scim_attributes"):
                    return outer.scim
                return getattr(outer.tenant.zpa, name)
        self.zpa = Zpa()


def run(s, ident_raw, dest="git.corp.example", client=None, log=None):
    sn, prof = s
    p = zi.parse(ident_raw)
    lk = zi.Lookups(client or IdClient()) if zi.needs_lookup(p) else None
    ident = zi.resolve(p, sn, lk, log=log)
    return zp.stage(sn, zp.destination(dest, None), profiles=prof, identity=ident)


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)


# ── ZPA's semantics: an oracle table over evaluate_rule ─────────────────
T, F, U = True, False, None


def _attr_user(vals):
    """A user context and index where SAML operand i is True (the user has
    the value), False (another value) or None (the attribute not given)."""
    ix = za._Index({"saml_attributes": [{"id": f"sa{i}", "name": f"attr{i}", "saml_name": "", "idp_id": "idp1"} for i in range(len(vals))]})
    given = {f"attr{i}": ["want" if v else "other"] for i, v in enumerate(vals) if v is not None}
    return za._norm_user({"saml": given}), ix


def _saml_ops(n):
    return [{"type": "SAML", "lhs": f"sa{i}", "rhs": "want", "name": "", "idp_id": ""} for i in range(n)]


@pytest.mark.parametrize("cond_op,negated,vals,expected", [
    ("OR", False, (T, F), "matched"), ("OR", False, (F, F), "not_matched"), ("OR", False, (F, U), "conditional"), ("OR", False, (T, U), "matched"),
    ("AND", False, (T, T), "matched"), ("AND", False, (T, F), "not_matched"), ("AND", False, (T, U), "conditional"), ("AND", False, (F, U), "not_matched"),
    ("OR", True, (T, F), "not_matched"), ("OR", True, (F, F), "matched"), ("OR", True, (F, U), "conditional"),
    ("AND", True, (T, T), "not_matched"), ("AND", True, (T, F), "matched"), ("AND", True, (F, U), "matched"),
])
def test_operands_join_by_the_condition_operator_and_negation_inverts(cond_op, negated, vals, expected):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a condition's operands join by its operator (OR unless AND), a negated condition is inverted, and an unknown operand stays unknown unless the others settle it (oracle table)."""
    u, ix = _attr_user(vals)
    r = {"conditions": [{"operator": cond_op, "negated": negated, "operands": _saml_ops(len(vals))}], "operator": "AND"}
    assert za.evaluate_rule(r, u, None, ix)["status"] == expected


@pytest.mark.parametrize("rule_op,a,b,expected", [
    ("AND", T, T, "matched"), ("AND", T, F, "not_matched"), ("AND", T, U, "conditional"), ("AND", F, U, "not_matched"),
    ("OR", F, F, "not_matched"), ("OR", T, F, "matched"), ("OR", F, U, "conditional"), ("OR", T, U, "matched"),
])
def test_conditions_join_by_the_rule_operator(rule_op, a, b, expected):
    """ASVS V4.1.3 · CWE-863: a rule's conditions join by its operator (AND unless OR); an unknown condition decides nothing on its own (oracle table)."""
    u, ix = _attr_user((a, b))
    ops = _saml_ops(2)
    r = {"conditions": [{"operator": "OR", "negated": False, "operands": [o]} for o in ops], "operator": rule_op}
    assert za.evaluate_rule(r, u, None, ix)["status"] == expected


def test_the_first_matching_rule_in_order_decides_and_no_match_is_denied():
    """ASVS V4.1.3 · CWE-863: rules are walked in rule order, a disabled rule is skipped, the first match decides, and no match is ZPA's default deny (oracle)."""
    u, ix = _attr_user((T, T))
    ops = _saml_ops(2)
    rules = [dict(id="a", name="A", order=1, action="DENY", disabled=True, operator="AND", conditions=[{"operator": "OR", "negated": False, "operands": [ops[0]]}]),
             dict(id="b", name="B", order=2, action="ALLOW", disabled=False, operator="AND", conditions=[{"operator": "OR", "negated": False, "operands": [ops[1]]}]),
             dict(id="c", name="C", order=3, action="DENY", disabled=False, operator="AND", conditions=[])]
    fm = zp.first_match(rules, u, None, ix, zp.ACCESS_EFFECT, "deny")
    assert fm["rule"]["name"] == "B" and fm["effect"] == "allow" and [w["status"] for w in fm["walked"]] == ["disabled", "matched"]
    u2, _ = _attr_user((F, F))
    none = zp.first_match(rules[:2], u2, None, ix, zp.ACCESS_EFFECT, "deny")
    assert none["rule"] is None and none["effect"] == "deny" and none["possible"] == {"deny"}


# ── the ZPA step for an identity ────────────────────────────────────────
@pytest.fixture(scope="module")
def tenant():
    zpa_reader.PACE_SECONDS = 0.0
    return snap()


@pytest.mark.parametrize("ident,outcome,decider,because", [
    ({"idp": "idp1", "user": USER}, "zpa_allowed", "Finance apps", "SCIM group “Finance” matched"),
    ({"idp": "idp1", "user": OTHER}, "zpa_denied", "Contractors blocked", "SCIM group “Contractors” matched"),
    ({"idp": "Okta", "user": "nobody@acme.example", "attributes": "department=Finance"}, "zpa_allowed", "Finance department",
     "SAML attribute “Department_Okta” = “Finance” matched and the user does not have SCIM group “Contractors”"),
    ({"idp": "idp1", "user": "nobody@acme.example", "attributes": "Department=Sales"}, "zpa_denied", None, None),
])
def test_the_access_policy_is_evaluated_for_the_identity_in_rule_order(tenant, ident, outcome, decider, because):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: SCIM groups looked up and attribute values typed decide ZPA's access rules in rule order with default deny, and the verdict names the identity condition that decided."""
    st = run(tenant, ident)
    assert st["outcome"] == outcome, st["headline"]
    z = st["identity"]
    assert z["decided"] == decider
    if decider:
        assert f"“{decider}”" in st["headline"] and because in st["headline"], st["headline"]
        assert z["sentence"].startswith(("Allowed by", "Denied by")) and because in z["sentence"]
    else:
        assert "default deny" in st["headline"] and z["sentence"].startswith("Denied by default")
        assert any(m["rule"] == "Finance apps" and "needs SCIM group “Finance”" in m["why"] for m in z["missed"]), z["missed"]
    access = next(m for m in st["modules"] if m["key"] == "zpa_access")
    assert z["sentence"] in access["notes"]


def test_without_an_identity_every_identity_condition_stays_unknown(tenant):
    """ASVS V4.1.3 · CWE-863: with no identity the step is unchanged: SCIM and SAML conditions are 'any user' and the answer is conditional, never a match."""
    st = zp.stage(tenant[0], zp.destination("git.corp.example", None), profiles=tenant[1])
    assert st["outcome"] == "zpa_conditional" and "identity" not in st
    assert any("give a ZPA identity in What-if" in a for a in st["assumptions"])


def test_an_attribute_not_given_stays_unknown_never_a_match(tenant):
    """ASVS V4.1.3 · CWE-863 · CWE-285: a SAML condition with no value given stays unknown: the rule is conditional, not a match, and the reason is said."""
    st = run(tenant, {"idp": "idp1", "user": "nobody@acme.example"})
    assert st["outcome"] == "zpa_conditional", st["headline"]
    acc = st["scenarios"]["pass"]
    assert acc["rule"] is None and "Finance department" in acc["conditional"]
    walked = next(m for m in st["modules"] if m["key"] == "zpa_access")
    assert any("Finance department" in c["name"] for c in walked["could_override"]), walked["could_override"]


def test_a_failed_or_ignored_lookup_leaves_scim_groups_unknown_with_the_reason(tenant):
    """ASVS V4.1.3 · CWE-863 · CWE-754: a SCIM lookup that fails, or that ZPA answered without applying the user filter, leaves SCIM group conditions unknown with the reason: never every group as the user's."""
    ignored = run(tenant, {"idp": "idp1", "user": USER}, client=IdClient(ignore=True))
    assert ignored["outcome"] == "zpa_conditional"
    assert any("did not apply the user filter" in u for u in ignored["identity"]["unknown"])
    assert ignored["identity"]["group_count"] is None
    failed = run(tenant, {"idp": "idp1", "user": USER}, client=IdClient(fail="HTTP 403 Forbidden"))
    assert failed["outcome"] == "zpa_conditional" and any("SCIM lookup failed" in u and "403" in u for u in failed["identity"]["unknown"])


def test_a_partial_membership_list_never_decides_that_a_user_is_not_in_a_group(tenant):
    """ASVS V4.1.3 · CWE-863: when only the first pages of a user's groups were read, a group not among them stays unknown, so an earlier deny rule keeps the answer conditional."""
    sn, prof = tenant
    ident = zi.resolve({"idp": "idp1", "user": "", "attributes": []}, sn)
    ident["facts"].update(scim_groups=["sg-fin"], scim_complete=False)
    st = zp.stage(sn, zp.destination("git.corp.example", None), profiles=prof, identity=ident)
    assert st["outcome"] == "zpa_conditional" and "Contractors blocked" in st["scenarios"]["pass"]["conditional"]
    ident["facts"]["scim_complete"] = True
    assert zp.stage(sn, zp.destination("git.corp.example", None), profiles=prof, identity=ident)["outcome"] == "zpa_allowed"


def test_a_condition_of_another_idp_or_a_switched_off_idp_is_not_met():
    """ASVS V4.1.3 · CWE-863: a user signs in through one IdP: SCIM groups and SAML attributes of another IdP are not met, nor SCIM conditions when the IdP's SCIM-based policy is off or SAML ones when its SAML-based policy is disabled."""
    other = run(snap(), {"idp": "Entra", "attributes": "department=Finance"})
    assert other["outcome"] == "zpa_denied" and other["identity"]["missed"], other["headline"]
    assert any("belongs to IdP Okta" in m["why"] for m in other["identity"]["missed"]), other["identity"]["missed"]
    off = run(snap(scim_policy=False), {"idp": "idp1", "user": USER})
    assert off["outcome"] != "zpa_allowed" or "Finance apps" not in off["headline"]
    assert any("SCIM-based policy off" in m["why"] for m in off["identity"]["missed"]), off["identity"]["missed"]
    saml_off = run(snap(saml_disabled=True), {"idp": "idp1", "user": "nobody@acme.example", "attributes": "department=Finance"})
    assert saml_off["outcome"] == "zpa_denied"
    assert any("SAML-based policy disabled" in m["why"] for m in saml_off["identity"]["missed"])


def test_a_workload_never_carries_a_user_identity():
    """ASVS V4.1.3 · CWE-863: workload traffic has no user, so an identity given for it is not used and identity conditions stay unmet or unknown as before."""
    sn, prof = snap()
    ident = zi.resolve(zi.parse({"idp": "idp1", "attributes": "department=Finance"}), sn)
    st = zp.stage(sn, zp.destination("git.corp.example", None), source="workload", profiles=prof, identity=ident)
    assert "identity" not in st


# ── input and the lookup ────────────────────────────────────────────────
@pytest.mark.parametrize("raw,msg", [
    ({"user": USER}, "Pick the IdP"),
    ({"idp": "idp1", "user": "a" * 129}, "longer than 128"),
    ({"idp": "idp1", "user": "jane\x00doe"}, "control character"),
    ({"idp": "idp1", "attributes": "no equals sign"}, "Name=value"),
    ({"idp": "idp1", "attributes": "\n".join(f"a{i}=v" for i in range(21))}, "at most 20"),
    ({"idp": "idp1", "attributes": "=value"}, "no name"),
    ({"idp": "idp1", "attributes": "x=" + "v" * 201}, "longer than 200"),
    ({"idp": ["idp1"]}, "must be text"),
    ("text", "must be an object"),
])
def test_bad_identity_input_is_refused_in_words(raw, msg):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the ZPA identity is validated (lengths, control characters, at most 20 attributes, a user only with an IdP) before anything is read."""
    with pytest.raises(ValueError, match=msg):
        zi.parse(raw)


def test_nothing_given_is_no_identity_and_attributes_are_kept_as_typed():
    """ASVS V5.1.3 · CWE-20: empty input is no identity; attribute values keep their case and order, duplicates once."""
    assert zi.parse({}) is None and zi.parse({"idp": "", "user": "", "attributes": ""}) is None
    p = zi.parse({"idp": "Okta", "attributes": "Department=Finance; memberOf=VPN Users\nDepartment=Finance"})
    assert p["attributes"] == [("Department", "Finance"), ("memberOf", "VPN Users")]


def test_the_lookup_is_one_users_groups_read_only_with_the_sdk_filter():
    """ASVS V1.4.1 · CWE-200 · WSTG-ATHZ-02: the lookup asks list_scim_groups for one user (scim_user_name, the SDK's documented filter, sent as scimUserName), after a probe proving ZPA applies it; it never writes."""
    c = IdClient()
    res = zi.lookup(c, "idp1", USER)
    assert [g["name"] for g in res["groups"]] == ["Finance"] and res["complete"] and res["error"] is None
    assert res["scim_attr_names"] == {"sca1": "costCenter"}
    calls = [x for x in c.scim.calls if x[0] == "list_scim_groups"]
    assert calls[0][2]["scim_user_name"] == zi.PROBE_USER and calls[1][2]["scim_user_name"] == USER and calls[1][2]["page_size"] == "500"
    assert not c.tenant.writes
    # The SDK: the method, its filter and the camelCase the API gets.
    from zscaler.helpers import convert_keys_to_camel_case
    from zscaler.zpa.scim_attributes import ScimAttributeHeaderAPI
    from zscaler.zpa.scim_groups import SCIMGroupsAPI
    assert list(inspect.signature(SCIMGroupsAPI.list_scim_groups).parameters)[:3] == ["self", "idp_id", "query_params"]
    assert "scim_user_name" in SCIMGroupsAPI.list_scim_groups.__doc__
    assert convert_keys_to_camel_case({"scim_user_name": USER}) == {"scimUserName": USER}
    assert list(inspect.signature(ScimAttributeHeaderAPI.list_scim_attributes).parameters)[:3] == ["self", "idp_id", "query_params"]


def test_lookups_are_kept_for_the_run_only_capped_and_stop_ends_them(monkeypatch):
    """ASVS V8.3.4 · CWE-524 · CWE-770: each user is looked up once per run (a new run asks again), at most MAX_LOOKUPS users, and Stop ends a lookup with nothing more read."""
    c = IdClient()
    run1 = zi.Lookups(c)
    run1.get("idp1", USER)
    run1.get("idp1", USER.upper())
    assert sum(1 for x in c.scim.calls if x[0] == "list_scim_groups" and x[2].get("scim_user_name") == USER) == 1
    zi.Lookups(c).get("idp1", USER)
    assert sum(1 for x in c.scim.calls if x[0] == "list_scim_groups" and x[2].get("scim_user_name") == USER) == 2, "no cache across runs"
    monkeypatch.setattr(zi, "MAX_LOOKUPS", 2)
    capped = zi.Lookups(c)
    capped.get("idp1", "a@x"), capped.get("idp1", "b@x")
    assert "at most 2 users" in capped.get("idp1", "c@x")["error"] and capped.capped == 1
    stop = threading.Event()
    stop.set()
    with pytest.raises(zpa_reader.Stopped):
        zi.lookup(c, "idp1", USER, cancel=stop)


def test_logs_never_carry_the_user_name_a_group_or_a_value(tenant):
    """ASVS V7.1.1 · CWE-532: the run's log says counts only: never the SCIM user name, a group name or an attribute value."""
    lines = []
    run(tenant, {"idp": "idp1", "user": USER, "attributes": "department=Finance"}, log=lines.append)
    text = "\n".join(lines)
    assert lines and "Found 1 SCIM group" in text
    for secret in (USER, "Finance", "department"):
        assert secret not in text, secret


def test_the_shown_groups_are_capped(monkeypatch, tenant):
    """CWE-770 · ASVS V5.1.4: the result shows at most SHOWN_GROUPS group names, with the count."""
    monkeypatch.setattr(zi, "SHOWN_GROUPS", 1)
    st = run(tenant, {"idp": "idp1", "user": OTHER})
    assert st["identity"]["group_count"] == 2 and len(st["identity"]["groups"]) == 1


# ── the API: scope before sign-in, the result, the pickers ─────────────
def _with_scim(api, **kw):
    sdk = api["sdk"]
    inner = sdk.zpa
    sdk.scim = Scim(**kw)

    class Zpa:
        def __getattr__(self, name):
            return sdk.scim if name in ("scim_groups", "scim_attributes") else getattr(inner, name)
    sdk.zpa = Zpa()
    sdk.zpa_t.data = data()
    return sdk


@pytest.mark.parametrize("body,detail", [
    (dict(destination="git.corp.example", scopes=["dlp"], channels=CHANNELS, identity={"zpa": {"idp": "idp1", "user": USER}}), "tick ZPA"),
    (dict(destination="git.corp.example", scopes=["dlp"], channels=CHANNELS, identity={"zpa": {"attributes": "department=Finance"}}), "tick ZPA"),
    (dict(destination="git.corp.example", scopes=["zpa"], identity={"zpa": {"user": USER}}), "Pick the IdP"),
    (dict(destination="git.corp.example", scopes=["zpa"], identity={"zpa": {"idp": "idp1", "attributes": "nonsense"}}), "Name=value"),
])
def test_a_zpa_identity_out_of_scope_or_invalid_is_refused_before_sign_in(api, body, detail):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a ZPA identity while ZPA is not ticked, or one that is not valid, is a 400 before anything is signed in to or read."""
    r = api["post"](**body)
    assert r.status_code == 400 and detail in r.json()["detail"] and "Nothing was read" in r.json()["detail"], r.text
    assert api["built"] == [] and api["raw"].reads == 0


def test_the_analysis_evaluates_zpa_for_the_identity_and_says_why(api):
    """ASVS V4.1.3 · CWE-863 · CWE-532: the start endpoint looks the user's SCIM groups up during the run, the verdict names the condition that decided, and the logs and result carry no secret."""
    _with_scim(api)
    api["sdk"].zpa_t.data = data()
    r = api["post"](destination="git.corp.example", scopes=["zpa"], identity={"zpa": {"idp": "idp1", "user": USER}})
    assert r.status_code == 200, r.text
    res = api["result"]()
    assert res["verdict"]["outcome"] == "zpa_allowed" and "because SCIM group “Finance” matched" in res["verdict"]["headline"]
    z = res["zpa_identity"]
    assert z["idp"] == {"id": "idp1", "name": "Okta"} and z["user"] == USER and [g["name"] for g in z["groups"]] == ["Finance"]
    assert "facts" not in z
    logs = "\n".join(res["logs"])
    assert USER not in logs
    # A group name is logged only as part of the verdict the result shows.
    assert all(line.startswith(("ZPA: ", "Verdict: ")) for line in res["logs"] if "Finance" in line), res["logs"]
    assert SECRET not in json.dumps(res)
    # A kept ZPA read is reused, and the run still looks the user up (a new client for this run).
    api["built"].clear()
    api["sdk"].scim.calls.clear()
    r2 = api["post"](destination="git.corp.example", scopes=["zpa"], zpa_report_id=res["zpa_report_id"], identity={"zpa": {"idp": "idp1", "user": USER}})
    assert r2.status_code == 200 and api["built"] == ["sdk"]
    assert any(x[2].get("scim_user_name") == USER for x in api["sdk"].scim.calls)
    assert api["result"]()["verdict"]["outcome"] == "zpa_allowed"


def test_the_pickers_need_zpa_in_scope_and_only_read(api):
    """ASVS V4.1.3 · CWE-863 · CWE-200: the IdP list and the user preview are 400 before sign-in without ZPA ticked or with bad input; with it they only read and cap what they return."""
    url = "/api/path-analyzer/zpa-identity"
    c = TestClient(__import__("dlp_api_server").app)
    no = c.post(url, json=dict(CREDS, from_page=True, scopes=["dlp"], action="idps"))
    assert no.status_code == 400 and "tick ZPA" in no.json()["detail"] and api["built"] == []
    for bad in ({"action": "user", "idp": "idp1; DROP", "user": USER}, {"action": "user", "idp": "123", "user": ""}, {"action": "write"}):
        r = c.post(url, json=dict(CREDS, from_page=True, scopes=["zpa"], **bad))
        assert r.status_code == 400, (bad, r.text)
    assert api["built"] == []
    _with_scim(api)
    api["sdk"].zpa_t.data["idps"][0]["id"] = "216196257331281111"
    idps = c.post(url, json=dict(CREDS, from_page=True, scopes=["zpa"], action="idps")).json()
    assert [i["name"] for i in idps["idps"]] == ["Okta", "Entra"] and idps["saml_attributes"][0]["name"] == "Department_Okta"
    assert set(idps["idps"][0]) <= {"id", "name", "enabled", "scim_enabled", "scim_policy", "saml_policy_disabled"}
    GROUPS["216196257331281111"] = GROUPS["idp1"]
    try:
        u = c.post(url, json=dict(CREDS, from_page=True, scopes=["zpa"], action="user", idp="216196257331281111", user=USER)).json()
    finally:
        GROUPS.pop("216196257331281111")
    assert u["group_count"] == 1 and u["groups"][0]["name"] == "Finance" and u["error"] is None
    assert not api["sdk"].zpa_t.writes


# ── Test a list: the identity columns ───────────────────────────────────
LIST = ("destination,port,idp,scim user,attributes,expected\n"
        f"git.corp.example,443,Okta,{USER},,allow\n"
        f"git.corp.example,443,Okta,{OTHER},,block\n"
        "git.corp.example,443,Okta,,department=Finance,allow\n"
        f"git.corp.example,443,Okta,{USER},,allow\n"
        "git.corp.example,443,,jane@x,,allow\n")


def test_a_list_row_is_evaluated_for_its_zpa_identity_with_one_lookup_per_user():
    """ASVS V4.1.3 · CWE-863 · CWE-770: Test a list reads idp, SCIM user and attributes columns, evaluates each row's ZPA answer for that identity, looks each user up once per run and says why a bad identity is ignored."""
    parsed = bulk_test.parse(LIST)
    assert parsed.entries[0]["zpa_identity"] == ("Okta", USER, ())
    assert "zpa_identity" not in parsed.entries[4] and "ZPA identity ignored: Pick the IdP" in parsed.entries[4]["notes"][0]
    sn, prof = snap()
    c = IdClient()
    rn = bulk_test.run(None, parsed, scope={"read": []}, zpa={"snapshot": sn, "profiles": prof, "client": c})
    rows = list(rn.rows())
    # Row 3 gives an attribute but no SCIM user: the SCIM group rules before it stay unknown, so it is not verified.
    assert [r["result"] for r in rows[:4]] == ["allowed", "blocked", "unverified", "allowed"], [r["result"] for r in rows]
    assert "because SCIM group “Finance” matched" in rows[0]["notes"] and rows[1]["rule"] == "Contractors blocked"
    assert rows[0]["zpa_identity"] == f"IdP Okta; SCIM user {USER}"
    asked = [x[2]["scim_user_name"] for x in c.scim.calls if x[0] == "list_scim_groups" and x[2]["scim_user_name"] != zi.PROBE_USER]
    assert sorted(asked) == sorted([USER, OTHER]), "one lookup per user per run"
    assert rows[4]["meets"] is not None


def test_a_list_with_a_zpa_identity_needs_zpa_in_scope_before_sign_in(api, monkeypatch):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a list carrying ZPA identity columns while ZPA is not ticked is a 400 before sign-in."""
    import dlp_api_server as srv
    c = TestClient(srv.app)
    r = c.post("/api/bulk-test/start", json=dict(CREDS, from_page=True, scopes=["dlp", "zia_extras"], channels=CHANNELS, text=LIST))
    assert r.status_code == 400 and "tick ZPA" in r.json()["detail"] and api["built"] == []


# ── the ZPA builder: access rules over SCIM groups and SAML values ──────
ZPA_SCOPE = ao.scope_for(["zpa"], {})
ASSESSOR = "Jane Doe"


@pytest.fixture
def builder(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    ao.load_plugins()
    c = BuilderClient()
    t = c.tenant
    t.add("idp", {"id": "7001", "name": "Okta", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": True})
    t.add("idp", {"id": "7002", "name": "Entra", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": False})
    t.add("saml_attribute", {"id": "7101", "name": "Department_Okta", "samlName": "department", "idpId": "7001"})
    t.add("scim_group", {"id": "7201", "name": "Finance", "idpId": "7001", "members": [USER]})
    t.add("scim_group", {"id": "7202", "name": "HR", "idpId": "7001"})
    t.add("scim_group", {"id": "7203", "name": "Engineers", "idpId": "7002"})
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "1-65535"}})
    assert c.tenant.names("segment")
    return c


def _apply(c, spec):
    p = ao.plan(c, spec, scope=ZPA_SCOPE, tenant_label="acme")
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA_SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") or "")
    return p, r


IDENT_SPEC = {"type": "zpa_policies", "prefix": "pov1", "access": True,
              "access_scim_groups": [{"idp_id": "7001", "id": "7201"}, {"idp_id": "7001", "id": "7202"}],
              "access_saml": [{"id": "7101", "value": "Finance"}]}


def test_the_builder_creates_an_access_rule_for_scim_groups_and_saml_values_the_sdk_way(builder):
    """ASVS V1.4.1 · CWE-841 · CWE-20: the access rule names the picked SCIM groups and SAML value in the preview, is created through the gates with the SDK's v1 condition template (one OR condition per kind, ANDed), reads back as asked and a re-run changes nothing."""
    p, r = _apply(builder, IDENT_SPEC)
    item = next(u for u in p["items"] if u["kind"] == "access_rule")
    assert "SCIM group Finance (Okta) or SCIM group HR (Okta)" in item["value"] and "SAML Department_Okta = Finance" in item["value"]
    assert any("needs both" in w for w in p["warnings"])
    assert r["status"] == "applied" and r["verification"]["confirmed"] >= 1 and not r["verification"]["mismatched"]
    rule = builder.tenant.by_name("rule:access", "pov1-access")
    from zscaler.zpa.models.policyset_controller_v1 import PolicySetControllerV1
    model = PolicySetControllerV1(copy.deepcopy(rule))
    kinds = [sorted({o.object_type for o in c.operands}) for c in model.conditions]
    assert ["SCIM_GROUP"] in kinds and ["SAML"] in kinds and ["APP"] in kinds
    scim_ops = next(c for c in model.conditions if c.operands[0].object_type == "SCIM_GROUP")
    assert scim_ops.operator == "OR" and sorted((o.lhs, o.rhs) for o in scim_ops.operands) == [("7001", "7201"), ("7001", "7202")]
    saml_ops = next(c for c in model.conditions if c.operands[0].object_type == "SAML")
    assert [(o.lhs, o.rhs) for o in saml_ops.operands] == [("7101", "Finance")]
    assert ops_zpa.state("access_rule", rule)["scim_groups"] == ["7001:7201", "7001:7202"]
    assert ao.plan(builder, IDENT_SPEC, scope=ZPA_SCOPE, tenant_label="acme")["status"] == "nothing_to_do"
    # What the builder evaluates: the Path analyzer reads the same rule back and Finance users match it.
    toks = [t for c in rule["conditions"] for o in c["operands"] for t in zpa_reader._operand_tokens(o)]
    assert {("SCIM_GROUP", "7001", "7201"), ("SAML", "7101", "Finance")} <= {(t["type"], t["lhs"], t["rhs"]) for t in toks}


def test_narrowing_an_existing_rule_is_an_update_with_an_undo_that_restores_everyone(builder):
    """ASVS V1.4.1 · CWE-841: limiting an existing access rule is an in-place update (before and after named); its Undo puts the rule back to every user."""
    _apply(builder, {"type": "zpa_policies", "prefix": "pov1", "access": True})
    p, r = _apply(builder, dict(IDENT_SPEC, access_saml=[]))
    changes = [(u["field"], u["before"], u["after"]) for u in p["items"] if u["status"] == "change"]
    assert changes == [("scim_groups", "(none)", "SCIM group Finance (Okta), SCIM group HR (Okta)")], changes
    assert r["status"] == "applied" and r["inverse"]["restore"][0]["before"] == {"scim_groups": []}
    undo = r["inverse"]
    up, ur = _apply(builder, undo)
    assert ur["status"] == "applied"
    assert ops_zpa.state("access_rule", builder.tenant.by_name("rule:access", "pov1-access"))["scim_groups"] == []


@pytest.mark.parametrize("extra,msg", [
    ({"access_scim_groups": [{"idp_id": "x", "id": "7201"}]}, "pick it from the list"),
    ({"access_scim_groups": [{"idp_id": "7001", "id": "7201"}] * 0 + [{"idp_id": "7001", "id": str(i)} for i in range(21)]}, "at most 20"),
    ({"access_saml": [{"id": "7101", "value": "a\x00b"}]}, "no control characters"),
    ({"access_saml": [{"id": "7101", "value": ""}]}, "1 to 200"),
    ({"access_saml": [{"id": "7101", "value": "v" * 201}]}, "1 to 200"),
    ({"access_saml": "7101=Finance"}, "Pick the SCIM groups"),
    ({"access": False, "timeout": True}, "tick Access"),
])
def test_bad_identity_picks_are_refused_before_anything_is_read(builder, extra, msg):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: SCIM groups and SAML values are checked (ids, caps, value length and characters, Access ticked) before a read."""
    builder.tenant.reads.clear()
    with pytest.raises(ao.OperationError, match=msg):
        ao.plan(builder, dict(IDENT_SPEC, **extra), scope=ZPA_SCOPE)
    assert builder.tenant.reads == [] and builder.tenant.writes[-1][2] != "pov1-access"


def test_a_pick_the_tenant_no_longer_has_blocks_the_plan(builder):
    """ASVS V1.4.1 · CWE-367: the preview checks each pick against the tenant now: a SCIM group gone or under another IdP, or a SAML attribute gone, blocks the plan and nothing is written."""
    for spec in (dict(IDENT_SPEC, access_scim_groups=[{"idp_id": "7001", "id": "7999"}]),
                 dict(IDENT_SPEC, access_scim_groups=[{"idp_id": "7001", "id": "7203"}]),
                 dict(IDENT_SPEC, access_saml=[{"id": "7199", "value": "Finance"}])):
        p = ao.plan(builder, spec, scope=ZPA_SCOPE, tenant_label="acme")
        assert p["status"] == "blocked" and p["blockers"], spec
    warn = ao.plan(builder, dict(IDENT_SPEC, access_scim_groups=[{"idp_id": "7002", "id": "7203"}], access_saml=[]), scope=ZPA_SCOPE)
    assert any("SCIM-based policy off" in w for w in warn["warnings"])


def test_the_builder_form_lists_idps_saml_attributes_and_capped_scim_groups(builder, monkeypatch):
    """ASVS V4.1.3 · CWE-770: the form's read-only lists carry the IdPs, SAML attributes and SCIM groups (per SCIM-enabled IdP, capped and marked when cut); out of scope it reads nothing."""
    res = ao.read_objects(builder, ops_zpa.FAMILY, ZPA_SCOPE)
    assert [i["name"] for i in res["idps"]] == ["Okta", "Entra"] and res["saml_attributes"][0]["name"] == "Department_Okta"
    assert {g["name"] for g in res["scim_groups"]} == {"Finance", "HR", "Engineers"} and res["scim_truncated"] is False
    assert all("members" not in g for g in res["scim_groups"])
    monkeypatch.setattr(ops_zpa, "MAX_PICK_SCIM", 2)
    assert ao.read_objects(builder, ops_zpa.FAMILY, ZPA_SCOPE)["scim_truncated"] is True
    builder.tenant.reads.clear()
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.read_objects(builder, ops_zpa.FAMILY, ao.scope_for(["dlp"], {"web_dlp": "zscaler"}))
    assert builder.tenant.reads == []


# ── the page ────────────────────────────────────────────────────────────
def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_every_new_control_is_labelled_and_has_help():
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2 · SC 4.1.2: the ZPA identity fields and the builder's pickers have labels and a help entry each."""
    html = _read("static/report_path.html")
    for cid in ("paWiZ_idp", "paWiZ_user", "paWiZ_attrs"):
        assert re.search(r'<label[^>]*>(?:(?!</label>).)*id="' + cid + '"', html, re.S), cid
    cat = _read("static/help_catalog.js")
    assert cat == _read("browser_extension/help_catalog.js")
    for sel in ("#paWiZ_idp", "#paWiZ_load", "#paWiZ_user", "#paWiZ_find", "#paWiZ_attrs", "#zbWhoAll", "#zbWhoSome", "#zbScimFind",
                "#zbSamlAttr", "#zbSamlVal", "#zbSamlAdd"):
        assert json.dumps(sel) + ": {" in cat, sel
    wi, oz = _read("static/path_whatif.js"), _read("static/ops_zpa.js")
    drawn = wi[wi.index("function zpaSection"):wi.index("The \"Show more\" button")] + wi[wi.index("function initZpa"):wi.index("const found = {}")] \
        + oz[oz.index("function whoBlock"):oz.index("function wireWho")].replace("const shown = groups.filter(g => !q || `${g.name} ${g.idp}`", "")
    # Every tenant string drawn into the page goes through E().
    for name in ("g.name", "g.idp", "i.name", "a.name", "m.rule", "m.why", "a.value", "z.sentence", "z.label"):
        assert not re.search(r"\$\{" + re.escape(name) + r"\}", drawn), name
