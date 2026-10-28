"""ASVS V4.1.3 · CWE-272 · OWASP A01:2021: the Path analyzer's what-if evaluates identity-scoped rules and reads names only when in scope.

What-if (path_whatif): a user, group, department and location can be
given; rules scoped to them apply, rules scoped to others are skipped and
the rest stay conditional. Without an identity the result lists "Policy
action also depends on": each scoped rule that would change a section's
action. Names are looked up in ZIA only when ZIA platform is in scope on
the Scope page, one bounded page at a time. Fakes only; no network.
"""
from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient

import data_flow as df
import dlp_api_server as srv
import path_analyzer as pa
import path_whatif as pw
import ssl_flow as sf
from test_data_flow import ROUTES
from test_path_analyzer import LookupCl
from test_ssl_flow import CATALOGUE

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
SCOPE_ALL = {"scopes": ["dlp", "zia_extras", "zcc"], "from_page": True,
             "channels": {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "email_dlp": "zscaler", "saas_casb": "zscaler",
                          "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}}

SOCIAL = [
    {"id": 22, "name": "Block social for interns", "order": 1, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["SOCIAL_NETWORKING"],
     "groups": [{"id": 7, "name": "Interns"}], "users": [{"id": 70, "name": "Jane Doe (jane@acme.example)"}]},
    {"id": 23, "name": "Caution social for sales after hours", "order": 2, "state": "ENABLED", "action": "CAUTION", "urlCategories": ["SOCIAL_NETWORKING"],
     "departments": [{"id": 3, "name": "Sales"}], "timeWindows": [{"id": 1, "name": "After hours"}]},
    {"id": 24, "name": "Isolate social on low trust", "order": 3, "state": "ENABLED", "action": "ISOLATE", "urlCategories": ["SOCIAL_NETWORKING"],
     "deviceTrustLevels": ["LOW_TRUST"]},
    {"id": 25, "name": "Allow social at HQ", "order": 4, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["SOCIAL_NETWORKING"],
     "locations": [{"id": 9, "name": "HQ"}]},
    {"id": 26, "name": "Allow social", "order": 5, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["SOCIAL_NETWORKING"]},
]
DEST = {"label": "social.example", "host": "social.example", "kind": "host", "categories": ["SOCIAL_NETWORKING"], "applications": [], "app_classes": []}


def _zia(url_rules=SOCIAL):
    zia = {k: [] for k in ("ssl", "url", "cac", "ftc", "dlp", "endpoint", "saas", "email")}
    zia["ssl"] = [sf.normalize_ssl_rule({"id": 10, "name": "Decrypt", "action": "DECRYPT"})]
    zia["url"] = [df._norm_generic(r) for r in url_rules]
    return zia


def _zcc():
    return {"app_profiles": [{"id": 1, "name": "App", "platform": "windows", "active": True, "priority": 1, "forwarding_profile": 2,
                              "bypass": {"domains": [], "apps": [], "ips": []}, "strict_enforcement": True, "ssl_cert": True, "endpoint_dlp": True}],
            "forwarding_profiles": [{"id": 2, "name": "Fwd", "actions": {"off": {"mode_kind": "tunnel", "mode_label": "Z-Tunnel 2.0"}}}],
            "pac_files": [], "errors": []}


def _url_hop(ident):
    zia, _ = pw.apply_identity(_zia(), pw.normalize_identity(ident))
    t = df.trace(copy.deepcopy(DEST), "off", "windows", _zcc(), zia)
    return next(h for h in t["hops"] if h["key"] == "url")


# ── The rule's scope, named ────────────────────────────────────────────
def test_the_read_keeps_each_rules_scope_by_name():
    """ASVS V5.1.3 · CWE-20: each normalised rule keeps its scope as names, from camelCase or SDK snake_case fields."""
    url = df._norm_generic(SOCIAL[0])
    assert url["scope_items"]["groups"] == [{"id": 7, "name": "Interns"}] and url["scoped"]
    ssl = sf.normalize_ssl_rule({"id": 1, "action": "DECRYPT", "time_windows": [{"id": 4, "name": "Weekends"}], "device_trust_levels": ["HIGH_TRUST"]})
    assert ssl["scope_items"] == {"time_windows": [{"id": 4, "name": "Weekends"}], "device_trust": [{"id": None, "name": "HIGH_TRUST"}]}
    dlp = sf.normalize_dlp_rule({"id": 2, "action": "BLOCK", "locationGroups": [{"id": 5, "name": "Branches"}]})
    assert dlp["scope_items"] == {"location_groups": [{"id": 5, "name": "Branches"}]}
    assert df._norm_generic({"id": 3, "action": "ALLOW"})["scope_items"] == {}


def test_scope_items_are_bounded():
    """ASVS V12.1.1 · CWE-770: a rule naming thousands of users keeps at most MAX_ITEMS names of bounded length."""
    items = pw.scope_items({"users": [{"id": i, "name": "u" * 999} for i in range(5000)]})
    assert len(items["users"]) == pw.MAX_ITEMS and all(len(i["name"]) == pw.MAX_NAME for i in items["users"])


# ── The identity ───────────────────────────────────────────────────────
def test_the_identity_is_normalised_and_bounded():
    """ASVS V5.1.3 · ASVS V5.1.4 · CWE-20: typed names and ZIA picks become one bounded identity; nothing given is None."""
    assert pw.normalize_identity({}) is None and pw.normalize_identity({"user": "  "}) is None and pw.normalize_identity("x") is None
    i = pw.normalize_identity({"user": {"id": 70, "name": "Jane Doe", "email": "jane@acme.example"}, "group": "Interns, Staff ,", "location": "HQ"})
    assert i["user"] == {"id": 70, "name": "Jane Doe", "email": "jane@acme.example"}
    assert [g["name"] for g in i["groups"]] == ["Interns", "Staff"] and i["location"]["name"] == "HQ" and i["department"] is None
    many = pw.normalize_identity({"group": ",".join(f"g{n}" for n in range(500)), "user": "x" * 5000})
    assert len(many["groups"]) == pw.MAX_GROUPS and len(many["user"]["name"]) == pw.MAX_NAME


@pytest.mark.parametrize("ident,state", [
    ({"group": "Interns"}, True),
    ({"group": "interns"}, True),
    ({"user": "jane@acme.example"}, True),
    ({"user": {"id": 70, "name": "someone"}}, True),
    ({"group": "Staff"}, None),                 # the user is not given: it may still be Jane
    ({"user": "bob@acme.example"}, None),       # groups not given: the group criterion stays open
    ({"user": "bob@acme.example", "group": "Staff"}, False),
    ({"location": "HQ"}, None),
    (None, None),
])
def test_users_groups_and_departments_are_alternatives(ident, state):
    """ASVS V4.1.3 · CWE-863: within a rule, a user, group or department match is enough; a missing kind stays undecided."""
    applies, crit = pw.rule_criteria(df._norm_generic(SOCIAL[0]), pw.normalize_identity(ident))
    assert applies is state
    assert {c["dim"] for c in crit} == {"users", "groups"}


def test_kinds_of_criteria_must_all_hold():
    """ASVS V4.1.3 · CWE-863: department and time window must both hold; a time window is never assumed."""
    rule = df._norm_generic(SOCIAL[1])
    assert pw.rule_criteria(rule, pw.normalize_identity({"department": "Finance"}))[0] is False
    applies, crit = pw.rule_criteria(rule, pw.normalize_identity({"department": "Sales"}))
    assert applies is None and [(c["dim"], c["state"]) for c in crit] == [("departments", "match"), ("time_windows", "unknown")]


# ── What-if on the trace ───────────────────────────────────────────────
def test_without_an_identity_the_scoped_rules_stay_conditional():
    """ASVS V4.1.3 · CWE-863: no identity, no guess: a scoped block ahead of the global rule leaves URL filtering conditional."""
    assert _url_hop(None)["status"] == "conditional"


def test_a_rule_for_the_identity_decides_the_path():
    """ASVS V4.1.3 · CWE-863: an intern is blocked by the interns' rule, named."""
    h = _url_hop({"group": "Interns"})
    assert h["status"] == "blocked" and h["decided_by"]["name"] == "Block social for interns"


def test_rules_for_others_are_skipped_but_open_ones_stay_conditional():
    """ASVS V4.1.3 · CWE-863: rules for others are skipped; a rule depending on a time window or device trust stays conditional."""
    h = _url_hop({"user": "bob@acme.example", "group": "Staff", "department": "Finance"})
    assert h["status"] == "conditional"   # the low-trust isolation rule is still ahead of the global allow
    rules = [r for r in SOCIAL if r["id"] != 24]
    zia, counts = pw.apply_identity(_zia(rules), pw.normalize_identity({"user": "bob@acme.example", "group": "Staff", "department": "Finance", "location": "Branch"}))
    t = df.trace(copy.deepcopy(DEST), "off", "windows", _zcc(), zia)
    h = next(h for h in t["hops"] if h["key"] == "url")
    assert h["status"] == "pass" and h["decided_by"]["name"] == "Allow social"
    assert counts == {"applies": 0, "skipped": 3, "open": 0}


def test_a_skipped_rule_is_still_found_by_the_policy_pack_overlay():
    """ASVS V4.1.3 · CWE-863: skipping a rule for this identity never makes a deployed pack rule look missing or disabled."""
    zia, _ = pw.apply_identity(_zia(), pw.normalize_identity({"group": "Staff", "user": "bob"}))
    skipped = next(r for r in zia["url"] if r["id"] == 22)
    assert skipped["enabled"] is False and skipped["state"] == "ENABLED" and skipped["whatif"] == "skipped"


# ── Policy action also depends on ──────────────────────────────────────
def test_depends_on_lists_each_condition_that_changes_the_action_most_disruptive_first():
    """ASVS V4.1.3 · CWE-863: every scoped rule that would change the action is listed with its condition and the action it gives."""
    deps = pw.depends_on(_zia(), DEST)
    assert [d["rule"]["name"] for d in deps] == ["Block social for interns", "Caution social for sales after hours", "Isolate social on low trust"]
    first = deps[0]
    assert set(first) >= {"module", "verdict", "rule", "overlaps", "criteria", "notes"}
    assert first["module"] == "url" and first["verdict"] == "BLOCK" and first["otherwise"] == "ALLOW" and first["otherwise_rule"] == "Allow social"
    assert {c["name"] for c in first["criteria"]} == {"user: Jane Doe (jane@acme.example)", "group: Interns"}
    assert all(c["state"] == "unknown" for d in deps for c in d["criteria"])
    kinds = {c["kind"] for d in deps for c in d["conditions"]}
    assert {"time window", "device trust level", "department", "group", "user"} <= kinds
    assert "Allow social at HQ" not in [d["rule"]["name"] for d in deps], "a rule giving the same action changes nothing"


def test_with_an_identity_met_conditions_show_and_excluded_rules_go():
    """ASVS V4.1.3 · CWE-863: with an identity, conditions it meets read 'match' and rules for others are not listed."""
    ident = pw.normalize_identity({"department": "Sales", "group": "Staff", "user": "bob"})
    zia, _ = pw.apply_identity(_zia(), ident)
    deps = pw.depends_on(zia, DEST, ident)
    names = [d["rule"]["name"] for d in deps]
    assert "Block social for interns" not in names
    sales = next(d for d in deps if d["rule"]["name"] == "Caution social for sales after hours")
    assert [(c["name"], c["state"]) for c in sales["criteria"]] == [("department: Sales", "match"), ("time window: After hours", "unknown")]


def test_nothing_depends_on_identity_says_why():
    """WCAG 2.2 SC 3.3.2 · ASVS V4.1.3: an empty list is explained, never an empty table."""
    w = pw.whatif(_zia([SOCIAL[-1]]), DEST, None, {"applies": 0, "skipped": 0, "open": 0})
    assert w["depends_on"] == [] and "No rule on this path is scoped" in w["empty_reason"]


def test_depends_on_skips_sections_not_in_scope():
    """ASVS V4.1.3 · CWE-272: a section not in scope on the Scope page is never listed as a condition."""
    assert pw.depends_on(_zia(), DEST, None, {"url": "Not in scope"}) == []


# ── Through the analyzer and its endpoint ──────────────────────────────
class SocialCl(LookupCl):
    LOOKUP = dict(LookupCl.LOOKUP, **{"social.example": {"urlClassifications": ["SOCIAL_NETWORKING"]}})


def _social_client():
    routes = dict(ROUTES, **{"/zia/urlFilteringRules": SOCIAL})
    return SocialCl(routes, CATALOGUE)


def test_analyze_returns_the_what_if_and_states_the_assumption():
    """ASVS V4.1.3 · CWE-863: analyze() evaluates the identity, keeps the tenant read unchanged and says what it assumed."""
    c = _social_client()
    plain = pa.analyze(c, "social.example", "off", "windows", scope=pa.full_path_scope())
    assert plain["whatif"]["identity"] is None and plain["whatif"]["depends_on"][0]["rule"]["name"] == "Block social for interns"
    assert plain["assumptions"][0].startswith("Any user")
    snap = plain["snapshot_for_cache"]
    intern = pa.analyze(c, "social.example", "off", "windows", scope=pa.full_path_scope(), snapshot=snap, identity={"group": "Interns"})
    assert intern["verdict"]["outcome"] == "blocked" and intern["verdict"]["blocked_by"] == "Block social for interns"
    assert intern["whatif"]["identity_label"] == "group Interns" and intern["assumptions"][0].startswith("Evaluated for group Interns")
    kept = next(r for r in snap["snapshot"]["zia"]["url"] if r["id"] == 22)
    assert kept["scoped"] and "whatif" not in kept, "the kept read is never changed by a what-if"


def test_the_endpoint_passes_the_identity(monkeypatch):
    """ASVS V4.1.3 · CWE-863: POST /api/path-analyzer takes the optional identity and returns the what-if."""
    c = _social_client()
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    r = TestClient(srv.app).post("/api/path-analyzer", json=dict(CREDS, **SCOPE_ALL, destination="social.example",
                                                                 identity={"group": "Interns", "department": "Sales"}))
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["whatif"]["identity_label"] == "group Interns; department Sales" and body["verdict"]["outcome"] == "blocked"
    assert "secret-secret-secret" not in r.text


# ── Looking names up in ZIA ────────────────────────────────────────────
class NamesCl:
    """A signed-in client that answers one page of users, groups, departments or locations."""

    def __init__(self, n=3):
        self.calls = []
        self.n = n

    def get(self, ep, p=None):
        self.calls.append((ep, dict(p or {})))
        if ep == "/zia/users":
            return [{"id": i, "name": f"Jo {i}", "email": f"jo{i}@acme.example", "department": {"id": 3, "name": "Sales"},
                     "groups": [{"id": 7, "name": "Interns"}], "password": "never-shown"} for i in range(self.n)], 200
        return [{"id": i, "name": f"{ep.rsplit('/', 1)[-1]} {i}"} for i in range(self.n)], 200


def _lookup(monkeypatch, body, client=None):
    cl = client or NamesCl()
    built = []
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(1) or cl)
    r = TestClient(srv.app).post("/api/path-analyzer/identities", json=dict(CREDS, **body))
    return r, cl, built


@pytest.mark.parametrize("scopes", [[], ["dlp"], ["zcc", "dlp"]])
def test_lookup_is_refused_before_sign_in_unless_zia_platform_is_in_scope(monkeypatch, scopes):
    """ASVS V4.1.3 · ASVS V4.1.5 · CWE-272 · WSTG-ATHZ-02: no ZIA platform on the Scope page, no sign-in and no read."""
    r, cl, built = _lookup(monkeypatch, {"scopes": scopes, "channels": {}, "from_page": True, "kind": "user", "query": "jo"})
    assert r.status_code == 400 and "ZIA platform" in r.json()["detail"]
    assert built == [] and cl.calls == []


@pytest.mark.parametrize("kind,query", [("admin", "jo"), ("user", "j"), ("user", "x" * 65), ("user", "jo\nhn"), ("", "jo")])
def test_lookup_input_is_validated_before_sign_in(monkeypatch, kind, query):
    """ASVS V5.1.3 · ASVS V5.1.4 · CWE-20: an unknown kind or a query outside 2 to 64 printable characters is a 400; nothing read."""
    r, cl, built = _lookup(monkeypatch, {"scopes": ["zia_extras"], "from_page": True, "kind": kind, "query": query})
    assert r.status_code == 400 and built == [] and cl.calls == []


@pytest.mark.parametrize("kind,endpoint,param", [("user", "/zia/users", "name"), ("group", "/zia/groups", "search"),
                                                 ("department", "/zia/departments", "search"), ("location", "/zia/locations", "search")])
def test_lookup_reads_one_bounded_page(monkeypatch, kind, endpoint, param):
    """ASVS V4.1.3 · ASVS V12.1.1 · CWE-770 · CWE-200: one GET with a 20-row page, never a bulk listing."""
    r, cl, _ = _lookup(monkeypatch, {"scopes": ["zia_extras"], "from_page": True, "kind": kind, "query": "jo"})
    assert r.status_code == 200, r.text[:300]
    assert cl.calls == [(endpoint, {param: "jo", "page": 1, "pageSize": pw.SEARCH_LIMIT})]
    assert len(r.json()["results"]) == 3 and not r.json()["capped"]


def test_a_user_found_brings_department_and_groups_but_nothing_else(monkeypatch):
    """ASVS V8.3.4 · CWE-200 · CWE-359: a user row carries name, email, department and groups only, never other fields."""
    r, _, _ = _lookup(monkeypatch, {"scopes": ["zia_extras"], "from_page": True, "kind": "user", "query": "jo"})
    row = r.json()["results"][0]
    assert set(row) == {"id", "name", "email", "department", "groups"}
    assert row["department"]["name"] == "Sales" and row["groups"][0]["name"] == "Interns"
    assert "never-shown" not in r.text and "secret-secret-secret" not in r.text


def test_a_full_page_is_capped_and_says_so(monkeypatch):
    """ASVS V12.1.1 · CWE-770: at most SEARCH_LIMIT names come back, flagged so the page asks for a narrower name."""
    r, _, _ = _lookup(monkeypatch, {"scopes": ["zia_extras"], "from_page": True, "kind": "group", "query": "jo"}, NamesCl(n=50))
    assert len(r.json()["results"]) == pw.SEARCH_LIMIT and r.json()["capped"] is True


def test_a_refused_lookup_is_reported_not_invented():
    """ASVS V7.4.1 · CWE-209: an HTTP error is reported in words without the answer's body."""
    class Refuses:
        def get(self, ep, p=None):
            return {"error": "forbidden: token abc"}, 403
    out = pw.search_identities(Refuses(), "user", "jo")
    assert out["results"] == [] and out["error"] == "ZIA answered HTTP 403"


# ── The page ───────────────────────────────────────────────────────────
def test_the_page_loads_the_what_if_script():
    """WCAG 2.2 SC 1.3.1 · SC 4.1.2: the Path analyzer page loads the what-if inputs, labelled, with a live status region."""
    html = TestClient(srv.app).get("/report/path").text
    assert '<script src="/static/path_whatif.js"></script>' in html
    js = TestClient(srv.app).get("/static/path_whatif.js").text
    assert 'role="status" aria-live="polite"' in js and '<label class="df-ctl">' in js and 'aria-expanded' in js
    assert "Policy action also depends on" in js and 'class="df-table"' in js and "df-chip" in js
    assert "/api/path-analyzer/identities" in js and "zia_extras" in js
