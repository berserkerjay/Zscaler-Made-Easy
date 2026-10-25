"""Shadowed and unreachable rules: every variant on small fixtures, the
no-false-positive rule for criteria that cannot be compared, the Inline
Web DLP evaluation modes, the tenant reader (only what is in scope, GET
only, Stop honoured), the API job and the page conventions."""
from __future__ import annotations

import csv
import io
import os
import re
import time

import pytest

import shadow_rules as sr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _r(rid, name, order, action="ALLOW", state="ENABLED", **kw):
    return dict({"id": rid, "name": name, "order": order, "action": action, "state": state}, **kw)


def _kinds(res, policy=None):
    return [(f["rule"], f["kind"]) for f in res["findings"] if policy is None or f["policy"] == policy]


def _one(res, rule, kind=None):
    hits = [f for f in res["findings"] if f["rule"] == rule and (kind is None or f["kind"] == kind)]
    assert len(hits) == 1, (rule, kind, res["findings"])
    return hits[0]


# ── First match: shadowed, after a catch-all, duplicate, disabled ────────
def test_a_rule_below_a_broader_terminal_rule_is_shadowed_with_one_plain_sentence():
    rules = [_r(1, "Block uploads to file hosts", 2, "BLOCK", urlCategories=["FILE_HOST", "ONLINE_STORAGE"], protocols=["HTTPS_RULE", "HTTP_RULE"]),
             _r(2, "Web-Projects", 3, "ALLOW", urlCategories=["FILE_HOST"], protocols=["HTTPS_RULE"], groups=[{"id": 7, "name": "Eng"}])]
    res = sr.analyse({"url_filtering": rules})
    f = _one(res, "Web-Projects")
    assert f["kind"] == "shadowed" and f["policy"] == "url_filtering" and f["order"] == 3
    assert f["shadowed_by"] == {"name": "Block uploads to file hosts", "order": 2}
    assert f["reason"] == ("Rule 'Web-Projects' can never match: rule 'Block uploads to file hosts' (order 2) above it matches "
                           "everything it does and blocks.")
    assert f["reason"].count(".") == 1 and f["fix"] and f["severity"] == "medium"
    for k in ("policy", "rule", "order", "kind", "shadowed_by", "reason", "severity", "fix"):
        assert k in f
    # A stricter rule hidden below a laxer one is the worst case: high.
    flipped = sr.analyse({"url_filtering": [dict(rules[0], action="ALLOW"), dict(rules[1], action="BLOCK")]})
    assert _one(flipped, "Web-Projects")["severity"] == "high"
    # The same action is dead weight: low. Order decides, not list position.
    same = sr.analyse({"url_filtering": [dict(rules[1], action="BLOCK"), rules[0]]})
    assert _one(same, "Web-Projects")["severity"] == "low"


def test_a_narrower_rule_above_does_not_shadow_a_broader_one_below():
    rules = [_r(1, "Eng only", 1, "BLOCK", urlCategories=["FILE_HOST"], groups=[{"id": 7}]),
             _r(2, "Everyone", 2, "CAUTION", urlCategories=["FILE_HOST"])]
    assert sr.analyse({"url_filtering": rules})["findings"] == []


def test_everything_below_an_enabled_catch_all_is_unreachable_even_with_criteria_we_cannot_compare():
    rules = [_r(1, "Allow all", 5, "ALLOW", urlCategories=["ANY"], protocols=["ANY_RULE"]),
             _r(2, "Block gambling", 6, "BLOCK", urlCategories=["GAMBLING"]),
             _r(3, "Odd one", 7, "BLOCK", urlCategories=["X"], someFutureField={"id": 1}),
             _r(4, "Earlier", 1, "BLOCK", urlCategories=["WEB_MAIL"])]
    res = sr.analyse({"url_filtering": rules})
    assert sorted(_kinds(res)) == [("Block gambling", "after_catch_all"), ("Odd one", "after_catch_all")]
    f = _one(res, "Block gambling")
    assert f["severity"] == "high" and "matches all traffic and allows" in f["reason"] and f["shadowed_by"]["order"] == 5
    # A catch-all that carries a criterion we cannot read is not a catch-all.
    rules[0] = dict(rules[0], someFutureField=True)
    assert sr.analyse({"url_filtering": rules})["findings"] == []
    # A disabled catch-all hides nothing; a rule with a quota is not compared.
    rules[0] = _r(1, "Allow all", 5, "ALLOW", state="DISABLED")
    assert _kinds(sr.analyse({"url_filtering": rules})) == [("Allow all", "disabled")]


def test_a_duplicate_has_the_same_criteria_and_action():
    a = _r(1, "Block social", 1, "BLOCK", urlCategories=["SOCIAL_NETWORKING"], groups=[{"id": 3, "name": "Staff"}])
    b = dict(a, id=2, name="Block social (copy)", order=4, groups=[{"id": 3, "name": "Staff renamed"}])
    res = sr.analyse({"url_filtering": [a, b]})
    f = _one(res, "Block social (copy)")
    assert f["kind"] == "duplicate" and f["severity"] == "low" and "same criteria and the same action" in f["reason"]


def test_disabled_rules_are_information_and_never_hide_anything():
    rules = [_r(1, "Old block", 1, "BLOCK", state="DISABLED"), _r(2, "Live", 2, "ALLOW", urlCategories=["NEWS"])]
    res = sr.analyse({"url_filtering": rules})
    assert _kinds(res) == [("Old block", "disabled")]
    f = _one(res, "Old block")
    assert f["severity"] == "info" and f["shadowed_by"] is None and f["reason"] == "Rule 'Old block' is disabled, so it never matches."


# ── Never a false positive ──────────────────────────────────────────────
@pytest.mark.parametrize("a_extra,b_extra", [
    ({"someNewCriterion": ["X"]}, {}),                       # unknown field on the earlier rule
    ({}, {"someNewCriterion": ["X"]}),                       # unknown field on the later rule
    ({"timeWindows": [{"id": 1}, {"id": 2}]}, {"timeWindows": [{"id": 1}]}),   # windows are not assumed to be a union
    ({"groups": [{"id": 7}]}, {"groups": [{"id": 7}], "users": [{"id": 9}]}),  # who: safe under AND and OR
    ({"enforceTimeValidity": True}, {"enforceTimeValidity": True, "validityStartTime": 2}),
    ({"sizeQuota": 100}, {}),
    ({"excludedUsers": [{"id": 1}]}, {}),                     # the earlier rule leaves someone out
])
def test_criteria_that_cannot_be_compared_safely_mean_not_shadowed(a_extra, b_extra):
    a = _r(1, "A", 1, "BLOCK", urlCategories=["FILE_HOST"], **a_extra)
    b = _r(2, "B", 2, "ALLOW", urlCategories=["FILE_HOST"], **b_extra)
    assert sr.analyse({"url_filtering": [a, b]})["findings"] == [], (a_extra, b_extra)


def test_dlp_engines_must_be_the_same_and_content_inspection_matters():
    base = dict(urlCategories=["FILE_HOST"], protocols=["ANY_RULE"])
    a = _r(1, "PCI block", 1, "BLOCK", dlpEngines=[{"id": 60, "name": "PCI"}, {"id": 61, "name": "PII"}], **base)
    b = _r(2, "PCI monitor", 2, "ALLOW", dlpEngines=[{"id": 60, "name": "PCI"}], **base)
    assert sr.analyse({"web_dlp": [a, b]}, web_dlp_mode="rule_order")["findings"] == [], "a superset of engines is not assumed to cover"
    same = dict(b, dlpEngines=[{"id": 61}, {"id": 60}])
    f = _one(sr.analyse({"web_dlp": [a, same]}, web_dlp_mode="rule_order"), "PCI monitor")
    assert f["kind"] == "shadowed" and f["policy"] == "web_dlp" and "(if the tenant" not in f["reason"]
    # Without content inspection the earlier rule matches any content.
    wci = dict(a, dlpEngines=[], withoutContentInspection=True)
    assert _one(sr.analyse({"web_dlp": [wci, b]}, web_dlp_mode="rule_order"), "PCI monitor")["kind"] == "shadowed"
    # ... but a later rule without content inspection is wider than any engine.
    assert sr.analyse({"web_dlp": [a, dict(b, dlpEngines=[], withoutContentInspection=True)]}, web_dlp_mode="rule_order")["findings"] == []
    # A rule that also inspects GET requests is wider than one that does not.
    assert sr.analyse({"web_dlp": [a, dict(same, inspectHttpGetEnabled=True)]}, web_dlp_mode="rule_order")["findings"] == []


# ── Inline Web DLP evaluation modes ─────────────────────────────────────
def _dlp_pair():
    a = _r(1, "Block PCI everywhere", 1, "BLOCK", dlpEngines=[{"id": 60, "name": "PCI"}])
    b = _r(2, "Monitor PCI to webmail", 2, "ALLOW", dlpEngines=[{"id": 60, "name": "PCI"}], urlCategories=["WEB_MAIL"])
    return a, b


def test_web_dlp_by_rule_order_is_shadowed_and_an_unknown_mode_says_its_assumption():
    a, b = _dlp_pair()
    known = sr.analyse({"web_dlp": [a, b]}, web_dlp_mode="rule_order")
    assert _one(known, "Monitor PCI to webmail")["kind"] == "shadowed" and "By Rule Order" in known["notes"]["web_dlp"]
    unknown = sr.analyse({"web_dlp": [a, b]}, web_dlp_mode="unknown")
    f = _one(unknown, "Monitor PCI to webmail")
    assert f["kind"] == "shadowed" and "(if the tenant evaluates Inline Web DLP By Rule Order, the default; the mode could not be read)." in f["reason"]
    assert "could not be read" in unknown["notes"]["web_dlp"]


def test_web_dlp_under_evaluate_all_reports_superseded_never_shadowed():
    a, b = _dlp_pair()
    res = sr.analyse({"web_dlp": [b, dict(a, order=9)]}, web_dlp_mode="evaluate_all")
    f = _one(res, "Monitor PCI to webmail")
    assert f["kind"] == "superseded" and f["shadowed_by"]["name"] == "Block PCI everywhere"
    assert "stricter action (block) wins under Evaluate All Rules" in f["reason"] and "Evaluate All Rules" in res["notes"]["web_dlp"]
    assert not any(x["kind"] in ("shadowed", "after_catch_all") for x in res["findings"])
    # A stricter rule BELOW the covering laxer one is not superseded: it wins.
    res2 = sr.analyse({"web_dlp": [dict(b, dlpEngines=a["dlpEngines"], urlCategories=[]), dict(a, urlCategories=["WEB_MAIL"], order=2)]},
                      web_dlp_mode="evaluate_all")
    assert res2["findings"] == []
    # The same action: the lower order wins the tie.
    tie = sr.analyse({"web_dlp": [dict(a, action="ALLOW"), b]}, web_dlp_mode="evaluate_all")
    assert "same action and wins on its lower order" in _one(tie, "Monitor PCI to webmail")["reason"]
    # A parent with exception rules is left out: a matching child replaces its action.
    parent = dict(a, subRules=[{"id": 5}])
    assert sr.analyse({"web_dlp": [parent, b]}, web_dlp_mode="evaluate_all")["findings"] == []


def test_child_rules_are_first_match_among_their_siblings():
    parent = _r(1, "Block PCI", 1, "BLOCK", dlpEngines=[{"id": 60}], subRules=[{"id": 2}, {"id": 3}])
    c1 = _r(2, "Exception: finance", 1, "ALLOW", dlpEngines=[{"id": 60}], parentRule={"id": 1}, departments=[{"id": 4}])
    c2 = _r(3, "Exception: finance EU", 2, "ALLOW", dlpEngines=[{"id": 60}], parentRule={"id": 1}, departments=[{"id": 4}], locations=[{"id": 8}])
    res = sr.analyse({"web_dlp": [parent, c1, c2]}, web_dlp_mode="evaluate_all")
    assert _kinds(res) == [("Exception: finance EU", "shadowed")]


def test_endpoint_dlp_evaluates_all_rules_so_nothing_is_shadowed_by_position():
    a = _r(1, "Block USB PCI", 1, "BLOCK", dlpEngines=[{"id": 60}])
    b = _r(2, "Monitor USB PCI for Eng", 2, "ALLOW", dlpEngines=[{"id": 60}], groups=[{"id": 7}])
    res = sr.analyse({"endpoint_dlp": [b, dict(a, order=3)]})
    assert _kinds(res) == [("Monitor USB PCI for Eng", "superseded")]
    f = _one(res, "Monitor USB PCI for Eng")
    assert "Endpoint DLP" in res["notes"]["endpoint_dlp"] and f["shadowed_by"]["name"] == "Block USB PCI" and "never decides the outcome" in f["reason"]
    # A stricter rule that covers less never supersedes a wider laxer one.
    assert sr.analyse({"endpoint_dlp": [dict(a, groups=[{"id": 7}]), dict(b, groups=[])]})["findings"] == []


def test_email_dlp_ties_are_not_claimed_and_saas_is_checked_for_duplicates_only():
    a = _r(1, "Block PII mail", 1, "BLOCK", dlpEngines=[{"id": 62}])
    b = _r(2, "Block PII mail to partners", 2, "BLOCK", dlpEngines=[{"id": 62}], emailRecipientProfiles=[{"id": 1}])
    assert sr.analyse({"email_dlp": [a, b]})["findings"] == []
    assert _kinds(sr.analyse({"email_dlp": [a, dict(b, action="ALLOW")]})) == [("Block PII mail to partners", "superseded")]
    s1 = _r(1, "Scan Box", 1, "BLOCK", dlpEngines=[{"id": 62}], type="OFLCASB_DLP_FILE")
    s2 = dict(s1, id=2, name="Scan Box again", order=2)
    s3 = dict(s1, id=3, name="Scan Box for Eng", order=3, groups=[{"id": 7}])
    res = sr.analyse({"saas_dlp": [s1, s2, s3]})
    assert _kinds(res) == [("Scan Box again", "duplicate")] and "repeats rule 'Scan Box'" in res["findings"][0]["reason"]


# ── Objects that no longer exist ────────────────────────────────────────
def test_rules_naming_engines_or_categories_that_no_longer_exist():
    engines = [{"id": 60, "name": "PCI"}, {"id": 61, "name": "PII"}]
    cats = [{"id": "FILE_HOST", "configuredName": "File Host"}, {"id": "CUSTOM_01", "configuredName": "Partners"}]
    rules = [_r(1, "Gone engines", 1, "BLOCK", dlpEngines=[{"id": 90, "name": "Old engine"}]),
             _r(2, "Half gone", 2, "BLOCK", dlpEngines=[{"id": 60, "name": "PCI"}, {"id": 91, "name": "Retired"}]),
             _r(3, "Fine", 3, "BLOCK", dlpEngines=[{"id": 61}], urlCategories=["FILE_HOST"])]
    res = sr.analyse({"web_dlp": rules}, web_dlp_mode="rule_order", engines=engines, categories=cats)
    f = _one(res, "Gone engines", "missing_reference")
    assert f["severity"] == "high" and f["reason"] == "Rule 'Gone engines' can never act: none of its DLP engines (Old engine) exist in the tenant any more."
    assert _one(res, "Half gone", "missing_reference")["severity"] == "medium"
    assert not [x for x in res["findings"] if x["rule"] == "Fine"]
    url = sr.analyse({"url_filtering": [_r(1, "Partners", 1, "ALLOW", urlCategories=["CUSTOM_09"])]}, categories=cats)
    g = _one(url, "Partners")
    assert g["kind"] == "missing_reference" and g["severity"] == "high" and "can never match" in g["reason"] and "CUSTOM_09" in g["reason"]
    # Without the tenant's lists nothing is claimed.
    assert sr.analyse({"web_dlp": rules}, web_dlp_mode="rule_order")["findings"] == []


# ── The other policy types ──────────────────────────────────────────────
def test_cloud_app_control_compares_within_one_type_and_only_the_activities_named():
    a = _r(1, "Block uploads", 1, actions=["BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"], type="FILE_SHARE",
           applications=["DROPBOX", "BOX"])
    b = _r(2, "Allow Box uploads for Eng", 2, actions=["ALLOW_FILE_SHARE_UPLOAD"], type="FILE_SHARE", applications=["BOX"], groups=[{"id": 7}])
    c = _r(3, "Box share", 3, actions=["BLOCK_FILE_SHARE_SHARE"], type="FILE_SHARE", applications=["BOX"])
    d = _r(4, "Other type", 2, actions=["ALLOW_FILE_SHARE_UPLOAD"], type="WEBMAIL", applications=["BOX"])
    e = _r(5, "No apps", 6, actions=["ALLOW_FILE_SHARE_UPLOAD"], type="FILE_SHARE")
    for r in (a, b, c, d, e):
        r.pop("action")
    res = sr.analyse({"cloud_app_control": [a, b, c, d, e]})
    assert _kinds(res) == [("Allow Box uploads for Eng", "shadowed")]
    f = res["findings"][0]
    assert "decides file share upload, file share view" in f["reason"] and f["severity"] == "medium"


def test_ssl_inspection_reuses_its_normaliser_and_skips_zscaler_maintained_and_default_rules():
    zs = _r(1, "Zscaler Recommended Exemptions", 1, action={"type": "DO_NOT_DECRYPT"}, predefined=True)
    dec = _r(2, "Decrypt all", 2, action={"type": "DECRYPT"}, urlCategories=["ANY"])
    below = _r(3, "Exempt banking", 3, action={"type": "DO_NOT_DECRYPT"}, urlCategories=["FINANCE"])
    default = _r(4, "Default SSL Rule", 99, action={"type": "DO_NOT_DECRYPT"}, defaultRule=True)
    res = sr.analyse({"ssl_inspection": [default, below, dec, zs]})
    assert _kinds(res) == [("Exempt banking", "after_catch_all")]
    assert "matches all traffic and decrypts" in res["findings"][0]["reason"]


def test_cloud_firewall_hands_over_on_evaluate_network_app_and_compares_its_criteria():
    ev = _r(1, "Evaluate apps", 1, "EVAL_NWAPP")
    allow = _r(2, "Allow DNS", 2, "ALLOW", nwServices=[{"id": 5, "name": "DNS"}])
    block = _r(3, "Block DNS from guests", 3, "BLOCK_DROP", nwServices=[{"id": 5}], locations=[{"id": 9}])
    res = sr.analyse({"firewall": [ev, allow, block]})
    f = _one(res, "Block DNS from guests")
    assert f["kind"] == "shadowed" and f["shadowed_by"]["name"] == "Allow DNS" and f["severity"] == "high" and f["policy_label"] == "Cloud Firewall"
    assert sr.analyse({"firewall": [dict(allow, excludeSrcCountries=True, sourceCountries=["US"]), block]})["findings"] == []


def test_counts_and_the_index_by_rule():
    rules = [_r(1, "Allow all", 1, "ALLOW"), _r(2, "Block x", 2, "BLOCK", urlCategories=["X"]), _r(3, "Off", 3, state="DISABLED")]
    res = sr.analyse({"url_filtering": rules, "firewall": []})
    c = res["counts_by_policy"]["url_filtering"]
    assert c["rules"] == 3 and c["enabled"] == 2 and c["findings"] == 2 and c["by_kind"]["disabled"] == 1 and c["by_severity"]["high"] == 1
    assert res["counts_by_policy"]["firewall"]["rules"] == 0
    idx = sr.index_by_rule(res["findings"])
    assert set(idx) == {("url_filtering", "Block x"), ("url_filtering", "Off")} and idx[("url_filtering", "Off")][0]["kind"] == "disabled"
    assert sr.index_by_rule([]) == {} and sr.index_by_rule([{"x": 1}]) == {}


def test_csv_export_neutralises_formula_cells():
    res = sr.analyse({"url_filtering": [_r(1, "Allow all", 1, "ALLOW"), _r(2, "=HYPERLINK(\"x\")", 2, "BLOCK", urlCategories=["X"])]})
    rows = list(csv.reader(io.StringIO(sr.to_csv(res))))
    assert rows[0] == list(sr.CSV_COLUMNS)
    assert rows[1][3].startswith("'=") and rows[1][2] == "after_catch_all"


# ── What is in scope, and the reader ────────────────────────────────────
WEB_ONLY = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}}
ALL = {"scopes": ["dlp", "zia_extras"], "channels": {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "email_dlp": "zscaler", "saas_casb": "zscaler",
                                                     "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}}


def test_scope_decides_which_policies_are_read():
    s = sr.scope_for(**WEB_ONLY)
    assert "web_dlp" in s["read"] and "firewall" not in s["read"] and "endpoint_dlp" not in s["read"]
    assert "ZIA platform is not ticked" in s["not_in_scope"]["firewall"] and "Endpoint DLP" in s["not_in_scope"]["endpoint_dlp"]
    assert set(sr.scope_for(**ALL)["read"]) == set(sr.POLICIES)
    nothing = sr.scope_for([], {})
    assert nothing["read"] == [] and nothing["summary"] == sr.NOTHING_IN_SCOPE


class ReadOnlyClient:
    """A fake tenant: GET answers from `routes`; anything else is a write
    and fails the test. Every call is recorded."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append(("GET", endpoint))
        if endpoint in self.routes:
            v = self.routes[endpoint]
            return (v[0], v[1]) if isinstance(v, tuple) else (v, 200)
        return {"error": "not found"}, 404

    def __getattr__(self, name):
        if name in ("post", "put", "patch", "delete", "zia", "_zs"):
            raise AssertionError(f"the analysis tried a write or SDK call: {name}")
        raise AttributeError(name)


ROUTES = {
    "/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False},
    "/zia/webDlpRules": [_r(1, "Block PCI", 1, "BLOCK", dlpEngines=[{"id": 60, "name": "PCI"}]),
                         _r(2, "Monitor PCI webmail", 2, "ALLOW", dlpEngines=[{"id": 60, "name": "PCI"}], urlCategories=["WEB_MAIL"]),
                         _r(3, "Retired engine rule", 3, "BLOCK", dlpEngines=[{"id": 99, "name": "Gone"}], urlCategories=["WEB_MAIL"])],
    "/zia/dlpEngines": [{"id": 60, "name": "PCI"}],
    "/zia/urlCategories": [{"id": "WEB_MAIL", "configuredName": "Web Mail"}],
    "/zia/urlFilteringRules": [_r(10, "Allow all", 1, "ALLOW"), _r(11, "Block gambling", 2, "BLOCK", urlCategories=["GAMBLING"])],
    "/zia/firewallFilteringRules": [_r(20, "Allow DNS", 1, "ALLOW", nwServices=[{"id": 5}]), _r(21, "Block DNS", 2, "BLOCK_DROP", nwServices=[{"id": 5}])],
    "/zia/sslInspectionRules": [], "/zia/cloudApplicationRules": [], "/zia/endPointDlpRules": [], "/zia/emailDlpRules": [],
    "/zia/casbDlpRules/all": [],
}


def test_the_reader_reads_only_what_is_in_scope_with_get_requests():
    c = ReadOnlyClient(ROUTES)
    logs = []
    out = sr.run(c, sr.scope_for(**WEB_ONLY), log=logs.append)
    eps = [e for _, e in c.calls]
    scope = sr.scope_for(**WEB_ONLY)
    assert all(m == "GET" for m, _ in c.calls)
    # Inline Web DLP on Zscaler brings its prerequisites (SSL inspection, ...)
    # into scope, as on every other page; Cloud Firewall and the other DLP
    # channels stay out.
    assert eps == (["/zia/webDlpGlobalOptions"] + [sr.POLICIES[k]["endpoint"] for k in scope["read"]]
                   + ["/zia/dlpEngines", "/zia/urlCategories"]), eps
    assert not {"/zia/firewallFilteringRules", "/zia/endPointDlpRules", "/zia/emailDlpRules", "/zia/casbDlpRules/all"} & set(eps)
    assert out["mode"] == {"web_dlp": "rule_order", "source": "read", "detail": "Read from DLP Advanced Settings (enableEvaluateAllDlpRules = false)."}
    assert sorted((f["rule"], f["kind"]) for f in out["findings"] if f["policy"] == "web_dlp") == [
        ("Monitor PCI webmail", "shadowed"), ("Retired engine rule", "missing_reference")]
    assert out["policy_labels"]["saas_dlp"] == "SaaS Security API DLP"
    assert "firewall" in out["not_in_scope"] and out["read_errors"] == {} and out["missing_checked"] == {"engines": True, "categories": True}
    assert any(l.startswith("Reading the Inline Web DLP rules") for l in logs) and logs[-1].startswith("Done:")


def test_a_declared_mode_is_not_read_and_a_failed_read_is_not_an_empty_policy():
    routes = dict(ROUTES, **{"/zia/firewallFilteringRules": ({"error": "forbidden"}, 403)})
    c = ReadOnlyClient(routes)
    out = sr.run(c, sr.scope_for(**ALL), declared_mode="evaluate_all")
    assert "/zia/webDlpGlobalOptions" not in [e for _, e in c.calls]
    assert out["mode"]["web_dlp"] == "evaluate_all" and out["mode"]["source"] == "declared"
    assert "HTTP 403" in out["read_errors"]["firewall"] and "firewall" not in out["counts_by_policy"]
    assert not any(f["kind"] == "shadowed" and f["policy"] == "web_dlp" for f in out["findings"])
    assert ("Block gambling", "after_catch_all") in [(f["rule"], f["kind"]) for f in out["findings"]]
    # An unreadable mode is "unknown": rule order is assumed and said.
    c2 = ReadOnlyClient(dict(ROUTES, **{"/zia/webDlpGlobalOptions": ({"error": "no"}, 404)}))
    out2 = sr.run(c2, sr.scope_for(**WEB_ONLY))
    assert out2["mode"]["web_dlp"] == "unknown" and out2["mode"]["source"] == "unread"
    assert all("(if the tenant evaluates" in f["reason"] for f in out2["findings"] if f["kind"] == "shadowed")


def test_stop_ends_the_read_before_the_next_request():
    import threading
    c = ReadOnlyClient(ROUTES)
    stop = threading.Event()
    seen = []

    def log(line):
        seen.append(line)
        if line.startswith("Reading the Inline Web DLP rules"):
            stop.set()
    with pytest.raises(sr.Stopped, match="You clicked Stop"):
        sr.run(c, sr.scope_for(**ALL), log=log, cancel=stop)
    assert [e for _, e in c.calls] == ["/zia/webDlpGlobalOptions"], c.calls


# ── API ─────────────────────────────────────────────────────────────────
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}


def _wait(t, job):
    deadline = time.time() + 20
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("the job never ended")


def _api(monkeypatch, client):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    signed = []

    def sign_in(req):
        signed.append(1)
        return client
    monkeypatch.setattr(srv, "_build_client", sign_in)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no SDK client")))
    return TestClient(srv.app), signed


def test_the_api_runs_as_a_read_only_job_with_exports(monkeypatch):
    c = ReadOnlyClient(ROUTES)
    t, signed = _api(monkeypatch, c)
    body = dict(CREDS, **ALL, from_page=True)
    r = t.post("/api/shadow-rules/start", json=body)
    assert r.status_code == 200 and r.json()["kind"] == "shadow", r.text
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done", snap
    res = snap["result"]
    for k in ("findings", "counts_by_policy", "read_errors", "not_in_scope", "mode"):
        assert k in res
    assert res["tenant_label"] == "acme (production)" and res["status"] == "done"
    assert set(res["counts_by_policy"]) == set(sr.POLICIES) and all(m == "GET" for m, _ in c.calls)
    assert "secret-secret-secret" not in str(res) and "secret-secret-secret" not in "\n".join(snap["logs"])
    job = r.json()["job_id"]
    csv_r = t.get(f"/api/shadow-rules/jobs/{job}/export?format=csv")
    assert csv_r.status_code == 200 and csv_r.headers["content-type"].startswith("text/csv") and "Block gambling" in csv_r.text
    js = t.get(f"/api/shadow-rules/jobs/{job}/export?format=json")
    assert js.status_code == 200 and js.json()["findings"] == res["findings"] and "logs" not in js.json()
    assert t.get("/api/shadow-rules/jobs/nope/export").status_code == 404
    # The waiting endpoint, for scripts.
    w = t.post("/api/shadow-rules", json=dict(CREDS, **WEB_ONLY, from_page=True, web_dlp_mode="rule_order"))
    assert w.status_code == 200 and w.json()["mode"]["source"] == "declared" and "firewall" in w.json()["not_in_scope"]


def test_the_api_refuses_before_signing_in(monkeypatch):
    t, signed = _api(monkeypatch, ReadOnlyClient(ROUTES))
    r = t.post("/api/shadow-rules/start", json=dict(CREDS, scopes=[], channels={}, from_page=True))
    assert r.status_code == 400 and r.json()["detail"] == sr.NOTHING_IN_SCOPE
    r = t.post("/api/shadow-rules", json=dict(CREDS, **WEB_ONLY, from_page=True, web_dlp_mode="sometimes"))
    assert r.status_code == 400 and "web_dlp_mode" in r.json()["detail"]
    assert signed == []


def test_a_stop_sent_while_the_start_signs_in_reads_nothing(monkeypatch):
    import pack_jobs
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    c = ReadOnlyClient(ROUTES)
    token = "tokshadow0123456789"

    def sign_in(req):
        pack_jobs.stop_before_start(token)
        return c
    monkeypatch.setattr(srv, "_build_client", sign_in)
    t = TestClient(srv.app)
    r = t.post("/api/shadow-rules/start", json=dict(CREDS, **ALL, from_page=True), headers={"X-Start-Token": token})
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "cancelled" and (snap.get("result") or {}).get("status") == "stopped", snap
    assert c.calls == [] and any("before the run started" in line for line in snap["logs"])
    assert t.get(f"/api/shadow-rules/jobs/{r.json()['job_id']}/export").status_code == 409


# ── The page ────────────────────────────────────────────────────────────
def _read(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()


def test_the_page_is_served_wired_and_explained():
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    r = TestClient(srv.app).get("/report/shadow")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', '<a class="rp-btn" href="/">← Back to the assessment</a>',
                   '<main class="rp-card">', 'id="liveRegion" class="sr-only" role="status" aria-live="polite"', 'role="log"', 'id="shStop"',
                   '/api/shadow-rules/start', '/api/dlp-packs/jobs/', 'stop-before-start', "'X-Start-Token'", 'window.opener.migrateCredBody',
                   '/api/tenant-profiles', 'zassess_scopes_live_v1', 'id="expCsv"', 'id="expJson"', '/export?format=csv', '<th scope="col">',
                   'aria-pressed', 'id="shMode"'):
        assert needle in html, needle
    order = [html.index(f'<script src="/static/{s}"></script>') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order) and order[-1] < html.index("<script>\n")
    assert "<h3" not in html and "prefers-color-scheme" not in html and not re.search(r"#[0-9a-fA-F]{3,6}\b", html.split("</head>")[1])
    css = _read("static/reports.css")
    sh = css[css.index("/* ── Shadowed rules"):]
    assert ".sh-filter" in sh and "#" not in sh.split("\n", 1)[1], "colours come from the theme tokens"
    index = _read("static/index.html")
    assert index.index('onclick="openShadowRulesTab()"') < index.index("onclick=\"openToolTab('efficacy')\"")
    assert "window.open('/report/shadow', '_blank')" in index
    explain = _read("static/explain.js")
    assert re.search(r"^  X\.shadow = \{", explain, re.M) and explain.index("  X.shadow = {") < explain.index("  X.efficacy = {")
    assert "'/report/shadow': 'shadow'" in explain and "'sslflow', 'shadow', 'efficacy'" in explain
    assert "group: 'Find the gaps', name: 'Shadowed rules'" in explain
    src = _read("dlp_api_server.py")
    stale = src[src.index('request.url.path in ("/", "/app.css"'):]
    assert '"/report/shadow"' in stale[:stale.index(")")], "the page is never served stale"
    server = _read("dlp_api_server.py")
    assert server.index('@app.post("/api/shadow-rules/start")') < server.index("# ── Path Analyzer ─────")
