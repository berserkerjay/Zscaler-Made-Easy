"""ZIA security baseline and SSL certificate manager: two operation types on
the Bulk changes engine (ops_zia_baseline), and the ZIA policy framework
part of Export from tenant. Fakes only: a recording ZIA with the SDK's
service and method names; no network, no clock, no real tenant."""
from __future__ import annotations

import copy
import io
import json
import zipfile

import pytest
from conftest import read_store_text
from fastapi.testclient import TestClient

import admin_ops as ao
import dlp_api_server as srv
import ops_zia_baseline as zb
import pack_channels as pc
import pack_export

# ---------------------------------------------------------------------------
# The fake tenant
# ---------------------------------------------------------------------------


class Rules:
    """One rule service (list_rules / get_rule / add_rule / update_rule / delete_rule)."""

    def __init__(self, t, name, rows=()):
        self.t, self.name, self.rows, self.next_id = t, name, [copy.deepcopy(r) for r in rows], 900

    def _find(self, rid):
        return next((r for r in self.rows if str(r["id"]) == str(rid)), None)

    def list_rules(self, *a, **k):
        self.t.reads.append(f"{self.name}.list_rules")
        return [copy.deepcopy(r) for r in self.rows], None, None

    def get_rule(self, rid):
        self.t.reads.append(f"{self.name}.get_rule")
        r = self._find(rid)
        return (copy.deepcopy(r), None, None) if r else (None, None, {"message": "not found", "status": 404})

    def add_rule(self, **kw):
        self.t.writes.append((self.name, "add_rule", kw.get("name")))
        self.next_id += 1
        row = dict(copy.deepcopy(kw), id=self.next_id)
        # ZIA keeps orders contiguous: a rule at order n pushes the others down.
        for r in self.rows:
            if not r.get("default_rule") and int(r.get("order") or 0) >= int(kw.get("order") or 0):
                r["order"] = int(r["order"]) + 1
        self.rows.append(row)
        return copy.deepcopy(row), None, None

    def update_rule(self, rid, **kw):
        self.t.writes.append((self.name, "update_rule", kw.get("name")))
        r = self._find(rid)
        old = int(r.get("order") or 0)
        new = int(kw.get("order") or old)
        if new != old:
            for x in self.rows:
                o = int(x.get("order") or 0)
                if x is not r and not x.get("default_rule") and old < o <= new:
                    x["order"] = o - 1
        r.clear()
        r.update(copy.deepcopy(kw), id=int(rid) if str(rid).isdigit() else rid)
        return copy.deepcopy(r), None, None

    def delete_rule(self, rid, *a):
        self.t.writes.append((self.name, "delete_rule", rid))
        self.rows = [r for r in self.rows if str(r["id"]) != str(rid)]
        return None, None, None


class Cac(Rules):
    def list_rules(self, rule_type=None, *a, **k):
        self.t.reads.append(f"{self.name}.list_rules")
        return [copy.deepcopy(r) for r in self.rows if r.get("type") == rule_type], None, None

    def get_rule(self, rule_type, rid):
        return Rules.get_rule(self, rid)

    def add_rule(self, rule_type, **kw):
        return Rules.add_rule(self, **kw)

    def update_rule(self, rule_type, rid, **kw):
        return Rules.update_rule(self, rid, **kw)

    def delete_rule(self, rule_type, rid):
        return Rules.delete_rule(self, rid)


class Lister:
    def __init__(self, t, name, method, rows):
        self.t, self.name, self.rows = t, name, rows
        setattr(self, method, self._list)

    def _list(self, *a, **k):
        self.t.reads.append(self.name)
        return copy.deepcopy(self.rows), None, None


class Atp:
    def __init__(self, t):
        self.t = t
        self.settings = {k: True for k, _ in zb.ATP_SETTINGS}
        self.settings.update(crypto_mining_blocked=False, risk_tolerance=40)

    def get_atp_settings(self):
        self.t.reads.append("atp_policy.get_atp_settings")
        return copy.deepcopy(self.settings), None, None

    def update_atp_settings(self, **kw):
        self.t.writes.append(("atp_policy", "update_atp_settings", None))
        self.settings = copy.deepcopy(kw)
        return copy.deepcopy(kw), None, None


SSL_DEFAULT = {"id": 1, "name": "Default SSL Inspection Rule", "order": -1, "default_rule": True, "action": {"type": "DO_NOT_DECRYPT"}}
SSL_PREDEF = {"id": 2, "name": "Zscaler Recommended Exemptions", "order": 1, "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}}
SSL_OWN = {"id": 3, "name": "Inspect Finance", "order": 2, "state": "ENABLED", "url_categories": ["FINANCE"],
           "action": {"type": "DECRYPT", "override_default_certificate": False}}
SSL_OTHER = {"id": 4, "name": "Inspect Marketing", "order": 3, "state": "ENABLED", "users": [{"id": 77, "name": "someone"}],
             "action": {"type": "DECRYPT", "override_default_certificate": True, "ssl_interception_cert": {"id": 51, "name": "Old CA"}}}
URL_OWN = {"id": 11, "name": "Block Gambling", "order": 1, "state": "ENABLED", "action": "BLOCK", "url_categories": ["GAMBLING", "CUSTOM_01"],
           "protocols": ["ANY_RULE"], "locations": [{"id": 5, "name": "HQ"}]}
URL_DEFAULT = {"id": 12, "name": "Default URL Filtering Rule", "order": 127, "default_rule": True, "action": "ALLOW"}
CERTS = [{"id": 50, "name": "Zscaler Intermediate CA", "default_certificate": True, "status": "ENABLED", "type": "ZSCALER",
          "public_key": "MIIB-not-shown"},
         {"id": 51, "name": "Old CA", "status": "ENABLED", "type": "CUSTOM", "public_key": "MIIB-not-shown"},
         {"id": 52, "name": "New CA 2026", "status": "ENABLED", "type": "CUSTOM", "cert_exp_date": 1893456000, "public_key": "MIIB-not-shown"}]


class Tenant:
    def __init__(self, *, categories=None, apps=None, profiles=True, ztr=True, ssl=None, url=None):
        self.reads, self.writes = [], []
        z = type("Zia", (), {})()
        cats = categories if categories is not None else sorted({c for r in zb.CATALOG for c in r["fields"].get("url_categories", [])}
                                                                   | {"GAMBLING", "CUSTOM_01"})
        nw = apps if apps is not None else sorted({a for r in zb.CATALOG for a in r["fields"].get("nw_applications", [])})
        cloud = sorted({a for r in zb.CATALOG for a in r["fields"].get("applications", []) if r["area"] == "cac"})
        z.url_filtering = Rules(self, "url_filtering", [URL_OWN, URL_DEFAULT] if url is None else url)
        z.ssl_inspection_rules = Rules(self, "ssl_inspection_rules", [SSL_DEFAULT, SSL_PREDEF, SSL_OWN, SSL_OTHER] if ssl is None else ssl)
        z.cloud_firewall_rules = Rules(self, "cloud_firewall_rules", [{"id": 21, "name": "Default Firewall Filtering Rule", "order": -1,
                                                                      "default_rule": True, "action": "ALLOW"}])
        z.sandbox_rules = Rules(self, "sandbox_rules", [])
        z.cloud_firewall_dns = Rules(self, "cloud_firewall_dns", [])
        z.file_type_control_rule = Rules(self, "file_type_control_rule", [])
        z.cloudappcontrol = Cac(self, "cloudappcontrol", [])
        z.atp_policy = Atp(self)
        z.url_categories = Lister(self, "url_categories.list_categories_lite", "list_categories_lite", [{"id": c} for c in cats])
        z.cloud_firewall = Lister(self, "cloud_firewall.list_network_apps", "list_network_apps", [{"id": a} for a in nw])
        z.cloud_applications = Lister(self, "cloud_applications.list_cloud_app_policy", "list_cloud_app_policy", [{"app": a} for a in cloud])
        z.cloud_browser_isolation = Lister(self, "cloud_browser_isolation.list_isolation_profiles", "list_isolation_profiles",
                                           [{"id": "p1", "name": "Default Isolation", "url": "https://cbi.example/p1", "default_profile": True}] if profiles else [])
        z.dns_gatways = Lister(self, "dns_gatways.list_dns_gateways", "list_dns_gateways",
                               [{"id": 9, "name": "Zscaler Trusted Resolver", "nat_ztr_gateway": True}] if ztr else [])
        z.intermediate_certificates = Lister(self, "intermediate_certificates.list_ready_to_use", "list_ready_to_use", CERTS)
        self.zia, self.zpa = z, None


FULL = ao.scope_for(["dlp", "zia_extras"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
WEB_ONLY = ao.scope_for(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "alternative", "cloud_app_control": "alternative"})  # URL filtering and File Type Control only
PLATFORM_ONLY = ao.scope_for(["zia_extras"], {})
NOTHING = ao.scope_for([], {})


@pytest.fixture(autouse=True)
def _no_activation(monkeypatch):
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    return acts


def plan(t, spec, scope=FULL):
    return ao.plan(t, spec, scope=scope, tenant_label="acme (zscalertwo)")


def apply(t, spec, scope=FULL, prepared=None):
    prepared = prepared or plan(t, spec, scope)
    return ao.execute(t, spec, plan_hash=prepared["plan_hash"], scope=scope, writes_enabled=True, assessor="Jane Doe",
                      confirm_text=prepared["confirm_phrase"], tenant_label="acme (zscalertwo)")


def by_name(items):
    out = {}
    for u in items:
        out.setdefault(u["object"].get("name"), []).append(u)
    return out


# ---------------------------------------------------------------------------
# Review: tiers, choices, locks, names, citations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier", list(zb.TIERS))
def test_every_tier_builds_named_cited_rules_within_31_characters(tier):
    """ASVS V5.1.3 · CWE-20: every rule of every tier has a unique name within ZIA's 31 characters, even with the longest prefix, and cites a source."""
    rv = zb.review({"tier": tier, "prefix": "ABCDEFGHIJ"})
    names = [(r["area"], r["fields"].get("type"), r["name"]) for r in rv["rules"]]
    assert rv["rules"] and all(len(n) <= zb.MAX_NAME and n.startswith("ABCDEFGHIJ-") for _a, _t, n in names)
    assert len(set(names)) == len(names)
    assert all(r["sources"] and all(s["url"].startswith("https://") for s in r["sources"]) for r in rv["rules"])


def test_block_all_never_touches_the_locked_allow_web_and_ntp_rules():
    """ASVS V1.4.1 · CWE-1188: Allow-Web and Allow-NTP stay on and Allow whatever the operator chooses."""
    rv = zb.review({"tier": "strict", "mode": "block_all", "rules": {"fw.allow_web": {"on": False, "action": "BLOCK"}}})
    rules = {r["key"]: r for r in rv["rules"]}
    for k in ("fw.allow_web", "fw.allow_ntp"):
        assert rules[k]["on"] is True and rules[k]["action"] == "ALLOW" and rules[k]["locked"] and rules[k]["choices"] == []
    assert rules["fw.collab"]["action"] == "BLOCK_DROP"
    assert rules["dns.resolver"]["action"] == "REDIR_REQ_KEEP_SENDER", "the redirect is never turned into a block"


def test_allow_all_and_switching_off_are_flagged_as_weaker_than_the_tier():
    """ASVS V1.4.1 · CWE-693: a rule weakened against its tier (Allow instead of Block, or switched off) is flagged."""
    rv = zb.review({"tier": "strict", "mode": "allow_all", "rules": {"url.legal": {"action": "TIER"}, "ftc.scripts": {"on": False}},
                    "atp": {"tor_blocked": False}})
    rules = {r["key"]: r for r in rv["rules"]}
    assert rules["url.privacy"]["weakened"] == "Block → Allow"
    assert rules["cac.webmail"]["action"] == ["ALLOW_WEBMAIL_VIEW", "ALLOW_WEBMAIL_ATTACHMENT_SEND", "ALLOW_WEBMAIL_SEND"]
    assert rules["ftc.scripts"]["weakened"] == "switched off"
    assert rules["fw.allow_web"]["weakened"] == ""
    assert next(s for s in rv["atp"] if s["key"] == "tor_blocked")["weakened"]


def test_block_choice_on_cloud_app_control_uses_the_deny_verbs_where_zia_wants_them():
    """ASVS V5.1.3 · CWE-20: Block on Cloud App Control maps each action to its BLOCK_ or DENY_ form."""
    rv = zb.review({"tier": "balanced", "rules": {"cac.fileshare_view": {"action": "BLOCK"}, "cac.ai_ml": {"action": "BLOCK"}}})
    rules = {r["key"]: r for r in rv["rules"]}
    assert rules["cac.fileshare_view"]["action"] == ["DENY_FILE_SHARE_VIEW", "DENY_FILE_SHARE_UPLOAD"]
    assert rules["cac.ai_ml"]["action"] == ["DENY_AI_ML_WEB_USE"]


def test_overlays_cite_framework_controls_and_their_documents():
    """ASVS V1.1.1 · CWE-1059: each overlay control names its framework document (compliance_mapping for HIPAA and PCI, cited here for CJIS)."""
    rv = zb.review({"tier": "healthcare", "overlays": ["HIPAA", "CJIS", "PCI", "HITRUST", "SOX", "FERPA", "GDPR", "NIST_800_53", "NIST_800_171"]})
    ssl = next(r for r in rv["rules"] if r["key"] == "ssl.catch_all")
    got = {c["overlay"]: c for c in ssl["controls"]}
    assert any("164.312(e)(1)" in c for c in got["HIPAA"]["controls"]) and got["HIPAA"]["source"]["url"].startswith("https://www.ecfr.gov/")
    assert any(c.startswith("5.10.1.2") for c in got["CJIS"]["controls"]) and "fbi.gov" in got["CJIS"]["source"]["url"]
    assert "FERPA" not in got, "FERPA maps to access controls only, not to TLS inspection"
    assert ssl["catch_all"] is True


@pytest.mark.parametrize("bad,why", [({"tier": "lenient"}, "Unknown tier"), ({"prefix": "has space"}, "prefix"), ({"overlays": ["ISO"]}, "overlay"),
                                     ({"areas": ["email"]}, "area"), ({"mode": "chaos"}, "mode"), ({"rules": {"x": {"action": "DROP"}}}, "action"),
                                     ({"atp": {"not_a_setting": True}}, "atp")])
def test_a_baseline_that_cannot_be_built_is_refused(bad, why):
    """ASVS V5.1.3 · CWE-20: unknown tiers, overlays, areas, prefixes and choices are refused with the reason."""
    with pytest.raises(ao.OperationError, match=why):
        zb.normalize(dict({"type": "zia_baseline"}, **bad))


# ---------------------------------------------------------------------------
# Scope (user rule 1)
# ---------------------------------------------------------------------------

def test_nothing_in_scope_is_refused_before_anything_is_read():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: with nothing in scope the baseline and the certificate manager are refused before any read."""
    t = Tenant()
    for spec in ({"type": "zia_baseline", "tier": "strict"}, {"type": "ssl_certificate_move", "rules": [3], "certificate": 52}):
        with pytest.raises(ao.OperationError, match="scope"):
            plan(t, spec, NOTHING)
    with pytest.raises(ao.OperationError, match="scope"):
        ao.read_objects(t, "ssl_certificates", WEB_ONLY)
    assert t.reads == [] and t.writes == []


def test_an_explicit_area_out_of_scope_is_refused_before_reading():
    """ASVS V4.1.3 · CWE-639: naming an area that is not in scope never widens the scope."""
    t = Tenant()
    with pytest.raises(ao.OperationError, match="Not in scope.*Cloud Firewall"):
        plan(t, {"type": "zia_baseline", "tier": "strict", "areas": ["url", "firewall"]}, WEB_ONLY)
    assert t.reads == []


def test_part_in_scope_reads_only_that_part():
    """ASVS V4.1.3 · CWE-272: with only DLP ticked, URL filtering and File Type Control are read; firewall, SSL, sandbox, DNS, ATP are not."""
    t = Tenant()
    p = plan(t, {"type": "zia_baseline", "tier": "strict"}, WEB_ONLY)
    assert p["areas"] == ["url", "ftc"]
    assert not [r for r in t.reads if any(x in r for x in ("firewall", "ssl_", "sandbox", "dns", "atp", "cloudapp", "cloud_applications"))], t.reads
    assert any("Cloud Firewall" in n for n in p["notes"])


# ---------------------------------------------------------------------------
# Preview: tenant fit and field diffs
# ---------------------------------------------------------------------------

def test_what_the_tenant_lacks_is_dropped_with_warnings_and_never_widens_a_rule():
    """ASVS V1.4.1 · CWE-1188: missing categories and apps are left out; a rule left with nothing to match is dropped, not created as match-all."""
    t = Tenant(categories=["GAMBLING", "HEALTH", "FINANCE"] + zb.LEGAL_LIABILITY[:-1] + zb.MISC_UNKNOWN, apps=["HTTP", "HTTPS", "NTP", "DNS", "SSL", "HTTP2"],
               profiles=False, ztr=False)
    p = plan(t, {"type": "zia_baseline", "tier": "strict", "areas": ["url", "firewall", "dns", "sandbox"]})
    items = by_name(p["items"])
    assert any("WEAPONS_AND_BOMBS" in w for w in p["warnings"])
    assert items["BL-URL-Privacy-Risk"][0]["status"] == "excluded" and "match everything" in items["BL-URL-Privacy-Risk"][0]["reason"]
    assert items["BL-FW-Block-QUIC"][0]["status"] == "excluded", "a QUIC block without the QUIC app would drop all traffic"
    assert items["BL-FW-Allow-Web"][0]["status"] == "change"
    assert items["BL-DNS-Trusted-Resolver"][0]["status"] == "excluded" and "Trusted Resolver" in items["BL-DNS-Trusted-Resolver"][0]["reason"]
    assert any("Caution page instead of isolating" in w for w in p["warnings"])
    misc = next(g for g in p["groups"] if g["target"]["name"] == "BL-URL-Misc-Unknown")
    assert misc["target"]["payload"]["action"] == "CAUTION"
    assert t.writes == []


def test_a_rerun_matches_rules_by_name_and_shows_field_diffs():
    """ASVS V1.4.1 · CWE-841: a second preview after applying is all 'already as asked'; a field changed by hand shows before and after."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "balanced", "areas": ["url", "ftc"]}
    first = apply(t, spec)
    assert first["status"] == "applied"
    again = plan(t, spec)
    assert again["counts"]["change"] == 0 and again["status"] == "nothing_to_do"
    rule = next(r for r in t.zia.url_filtering.rows if r["name"] == "BL-URL-Legal-Liability")
    rule["url_categories"] = ["GAMBLING"]
    rule["state"] = "ENABLED"
    third = plan(t, spec)
    diff = [u for u in third["items"] if u["status"] == "change"]
    assert [u["field"] for u in diff] == ["url_categories"] and diff[0]["before"] == "GAMBLING"
    assert third["groups"][0]["handler"] == "zb_update"
    res = apply(t, spec, prepared=third)
    assert res["status"] == "applied" and rule["state"] == "ENABLED", "an update in place never changes the rule's state"


# ---------------------------------------------------------------------------
# Apply: disabled, ordered, catch-all last, activation once, read-back
# ---------------------------------------------------------------------------

def test_apply_creates_disabled_rules_below_the_tenants_with_the_ssl_catch_all_last(_no_activation):
    """ASVS V1.4.1 · V11.1.1 · CWE-1188: new rules arrive disabled, after the tenant's own, the SSL catch-all goes last, ZIA is activated once."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "balanced", "areas": ["ssl"]}
    res = apply(t, spec)
    assert res["status"] == "applied" and _no_activation == [1]
    rows = t.zia.ssl_inspection_rules.rows
    ours = [r for r in rows if r["name"].startswith("BL-")]
    assert ours and all(r["state"] == "DISABLED" for r in ours)
    ordered = sorted((r for r in rows if not r.get("default_rule")), key=lambda r: int(r["order"]))
    assert ordered[-1]["name"] == "BL-SSL-Catch-All" and ordered[0]["name"] == "Zscaler Recommended Exemptions"
    catch = ordered[-1]
    assert catch["action"]["decrypt_sub_actions"]["min_client_tls_version"] == "CLIENT_TLS_1_2"
    assert res["verification"]["confirmed"] == res["verification"]["checked"] > 0
    assert res["inverse"]["action"] == "revert" and all(s["op"] == "delete" for s in res["inverse"]["steps"])


def test_rules_are_enabled_only_when_the_operator_says_so():
    """ASVS V1.4.1 · CWE-1188: enable_rules=true is the only way the baseline creates enabled rules."""
    t = Tenant()
    apply(t, {"type": "zia_baseline", "tier": "strict", "areas": ["ftc"], "enable_rules": True})
    assert {r["state"] for r in t.zia.file_type_control_rule.rows} == {"ENABLED"}


def test_an_existing_catch_all_that_is_no_longer_last_is_moved_to_the_bottom():
    """ASVS V1.4.1 · CWE-696: a re-run puts the SSL catch-all back below every other rule."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "strict", "areas": ["ssl"]}
    apply(t, spec)
    rows = t.zia.ssl_inspection_rules.rows
    rows.append({"id": 99, "name": "Added later", "order": max(int(r["order"]) for r in rows) + 1, "action": {"type": "DECRYPT"}})
    p = plan(t, spec)
    moves = [u for u in p["items"] if u["field"] == "order"]
    assert len(moves) == 1 and moves[0]["after"] == "last" and moves[0]["status"] == "change"
    res = apply(t, spec, prepared=p)
    assert res["status"] == "applied"
    ordered = sorted((r for r in rows if not r.get("default_rule")), key=lambda r: int(r["order"]))
    assert ordered[-1]["name"] == "BL-SSL-Catch-All"


def test_a_tenant_that_changed_since_the_preview_is_not_written():
    """ASVS V11.1.1 · CWE-367: the plan is checked again before writing; a tenant that moved gives plan_changed and nothing is written."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "strict", "areas": ["ftc"]}
    p = plan(t, spec)
    t.zia.file_type_control_rule.rows.append({"id": 5, "name": "BL-FTC-Scripts", "order": 1, "filtering_action": "ALLOW"})
    res = ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL, writes_enabled=True, assessor="Jane Doe", confirm_text=p["confirm_phrase"])
    assert res["status"] == "plan_changed" and t.writes == []


def test_write_mode_off_writes_nothing():
    """ASVS V4.1.3 · CWE-862: without write mode the engine refuses before writing anything."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "strict", "areas": ["ftc"]}
    p = plan(t, spec)
    with pytest.raises(PermissionError):
        ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL, writes_enabled=False, confirm_text=p["confirm_phrase"])
    assert t.writes == []


# ---------------------------------------------------------------------------
# The typed phrase on every apply that creates or enables rules or changes ATP
# (admin_ops._finish confirm_always), whatever the count of changes
# ---------------------------------------------------------------------------

def _execute(t, spec, p, confirm_text):
    return ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL, writes_enabled=True, assessor="Jane Doe",
                      confirm_text=confirm_text, tenant_label="acme (zscalertwo)")


@pytest.mark.parametrize("spec, phrase", [
    ({"type": "zia_baseline", "tier": "strict", "areas": ["ftc"]}, "APPLY 4 CHANGES"),                     # creates rules (4: under the count rule's 10)
    ({"type": "zia_baseline", "tier": "permissive", "areas": ["atp"]}, "APPLY 2 CHANGES"),                  # changes ATP, live at activation
    ({"type": "ssl_certificate_move", "rules": [3], "certificate": 52}, "APPLY 1 CHANGE"),                 # boundary: one change
])
def test_a_risky_plan_asks_for_the_typed_phrase_whatever_the_count(spec, phrase):
    """ASVS V11.1.1 · V1.4.1 · CWE-841 · CWE-1188: creating rules, changing ATP or moving certificates needs the typed phrase even under 10 changes."""
    p = plan(Tenant(), spec)
    assert p["counts"]["change"] <= ao.CONFIRM_ABOVE and p["confirm_phrase"] == phrase


@pytest.mark.parametrize("typed", ["", "APPLY 3 CHANGES", "apply 4 change"])
def test_a_baseline_that_creates_rules_is_not_written_without_the_exact_phrase(typed):
    """ASVS V11.1.1 · CWE-841 · CWE-352: a missing or wrong phrase writes nothing (fail closed), even for 4 changes."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "strict", "areas": ["ftc"]}
    p = plan(t, spec)
    res = _execute(t, spec, p, typed)
    assert res["status"] == "refused" and "APPLY 4 CHANGES" in res["message"] and t.writes == []


def test_the_phrase_is_compared_without_case_and_then_the_baseline_is_written():
    """ASVS V11.1.1 · CWE-841: the typed phrase is accepted in any case and the baseline is then applied."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "strict", "areas": ["ftc"]}
    p = plan(t, spec)
    res = _execute(t, spec, p, "apply 4 changes")
    assert res["status"] == "applied" and t.writes


def test_atp_is_not_changed_without_the_phrase():
    """ASVS V11.1.1 · CWE-841 · CWE-1188: an ATP change (no disabled state, live at activation) is refused without the phrase."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "permissive", "areas": ["atp"]}
    before = dict(t.zia.atp_policy.settings)
    res = _execute(t, spec, plan(t, spec), "")
    assert res["status"] == "refused" and t.zia.atp_policy.settings == before and t.writes == []


def test_a_rerun_that_turns_rules_on_asks_for_the_phrase():
    """ASVS V11.1.1 · CWE-841: a re-run with "Create the rules enabled" switches existing rules on, so it needs the phrase."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "balanced", "areas": ["url", "ftc"]}
    apply(t, spec)
    p = plan(t, dict(spec, enable_rules=True))
    assert {u["after"] for u in p["items"] if u["status"] == "change"} == {"ENABLED"}
    assert p["confirm_phrase"] == f"APPLY {p['counts']['change']} CHANGES"


def test_a_small_field_update_keeps_the_count_rule():
    """ASVS V11.1.1 · CWE-841: updating a field of an existing rule (no create, no enable, no ATP) under 10 changes needs no phrase."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "balanced", "areas": ["url", "ftc"]}
    apply(t, spec)
    next(r for r in t.zia.url_filtering.rows if r["name"] == "BL-URL-Legal-Liability")["url_categories"] = ["GAMBLING"]
    p = plan(t, spec)
    assert p["counts"]["change"] == 1 and p["confirm_phrase"] == ""
    assert _execute(t, spec, p, "")["status"] == "applied"


def test_undo_that_puts_atp_back_asks_for_the_phrase():
    """ASVS V11.1.1 · CWE-841: the Undo of an ATP change changes ATP again, so it needs the phrase too."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "permissive", "areas": ["atp"]}
    res = apply(t, spec)
    u = plan(t, res["inverse"])
    assert u["confirm_phrase"] == "APPLY 2 CHANGES"
    assert _execute(t, res["inverse"], u, "")["status"] == "refused"


def test_a_certificate_move_is_not_written_without_the_phrase():
    """ASVS V11.1.1 · CWE-841: moving one Inspect rule to another certificate is refused without the phrase; nothing is written."""
    t = Tenant()
    spec = {"type": "ssl_certificate_move", "rules": [3], "certificate": 52}
    res = _execute(t, spec, plan(t, spec), "")
    assert res["status"] == "refused" and t.writes == []
    assert t.zia.ssl_inspection_rules._find(3)["action"].get("ssl_interception_cert", {}).get("id") != 52


def test_nothing_to_change_asks_for_no_phrase():
    """ASVS V11.1.1 · CWE-841: a plan with no change (boundary: 0) has no phrase to type."""
    t = Tenant()
    p = plan(t, {"type": "ssl_certificate_move", "rules": [3], "certificate": 666})
    assert p["counts"]["change"] == 0 and p["confirm_phrase"] == ""


def test_atp_is_changed_only_when_picked_and_undo_puts_it_back():
    """ASVS V1.4.1 · V11.1.1 · CWE-1188: ATP settings change only when their area is picked; Undo restores the values the baseline changed."""
    t = Tenant()
    assert "atp" not in plan(t, {"type": "zia_baseline", "tier": "strict"})["areas"]
    spec = {"type": "zia_baseline", "tier": "permissive", "areas": ["atp"]}
    p = plan(t, spec)
    changes = {u["field"]: (u["before"], u["after"]) for u in p["items"] if u["status"] == "change"}
    assert changes == {"crypto_mining_blocked": (False, True), "ssh_tunnelling_blocked": (True, False)}
    res = apply(t, spec, prepared=p)
    assert res["status"] == "applied" and t.zia.atp_policy.settings["crypto_mining_blocked"] is True
    assert t.zia.atp_policy.settings["risk_tolerance"] == 40, "settings the baseline does not manage are sent back unchanged"
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied" and t.zia.atp_policy.settings["crypto_mining_blocked"] is False
    assert t.zia.atp_policy.settings["ssh_tunnelling_blocked"] is True


def test_undo_deletes_only_what_the_baseline_made_and_leaves_renamed_rules():
    """ASVS V11.1.1 · CWE-672: Undo deletes the rules the baseline created, but not one renamed since (identity check)."""
    t = Tenant()
    res = apply(t, {"type": "zia_baseline", "tier": "strict", "areas": ["ftc"]})
    made = [r for r in t.zia.file_type_control_rule.rows if r["name"].startswith("BL-")]
    made[0]["name"] = "Renamed by an admin"
    u = plan(t, res["inverse"])
    excluded = [x for x in u["items"] if x["status"] == "excluded"]
    assert len(excluded) == 1 and "now called" in excluded[0]["reason"]
    done = apply(t, res["inverse"], prepared=u)
    assert done["status"] == "applied"
    assert [r["name"] for r in t.zia.file_type_control_rule.rows] == ["Renamed by an admin"]
    assert done["inverse"] is None, "an undo of a deletion is not offered (it would re-create rules blindly)"


def test_undo_restores_fields_only_while_they_hold_what_the_baseline_set():
    """ASVS V11.1.1 · CWE-367: Undo of an update restores the field, unless someone changed it again (then it is left)."""
    t = Tenant()
    spec = {"type": "zia_baseline", "tier": "balanced", "areas": ["url"]}
    apply(t, spec)
    rule = next(r for r in t.zia.url_filtering.rows if r["name"] == "BL-URL-Legal-Liability")
    rule["url_categories"] = ["GAMBLING"]
    rule["description"] = "hand edit"
    upd = apply(t, spec)
    assert upd["status"] == "applied"
    rule = next(r for r in t.zia.url_filtering.rows if r["name"] == "BL-URL-Legal-Liability")
    rule["description"] = "edited again"
    u = plan(t, upd["inverse"])
    st = {x["field"]: x["status"] for x in u["items"]}
    assert st == {"url_categories": "change", "description": "excluded"}
    apply(t, upd["inverse"], prepared=u)
    rule = next(r for r in t.zia.url_filtering.rows if r["name"] == "BL-URL-Legal-Liability")
    assert rule["url_categories"] == ["GAMBLING"] and rule["description"] == "edited again"


def test_every_write_goes_through_the_shared_path_and_is_audited(tmp_path, monkeypatch):
    """ASVS V7.1.3 · CWE-778: each create and update of the baseline leaves an object_write audit entry."""
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    t = Tenant()
    apply(t, {"type": "zia_baseline", "tier": "strict", "areas": ["ftc", "sandbox", "dns", "firewall"]})
    lines = [json.loads(x) for x in read_store_text(tmp_path / "audit.log").splitlines() if x.strip()]
    writes = [x for x in lines if x.get("event") == "object_write" or x.get("action") == "object_write" or x.get("type") == "object_write"]
    assert len(writes) == len(t.writes) > 10
    assert {w[0] for w in t.writes} == {"file_type_control_rule", "sandbox_rules", "cloud_firewall_dns", "cloud_firewall_rules"}


# ---------------------------------------------------------------------------
# SSL certificate manager
# ---------------------------------------------------------------------------

def test_the_certificate_list_never_carries_a_key():
    """ASVS V8.3.4 · CWE-200: the certificate manager lists names, status and dates, never a key or certificate body."""
    t = Tenant()
    out = ao.read_objects(t, "ssl_certificates", FULL)
    assert "MIIB" not in json.dumps(out)
    rows = {r["name"]: r for r in out["ssl_rules"]}
    assert rows["Inspect Marketing"]["certificate"] == "Old CA" and rows["Inspect Finance"]["certificate_id"] == "default"
    assert rows["Zscaler Recommended Exemptions"]["locked"]


def test_moving_inspect_rules_to_another_certificate_and_back():
    """ASVS V1.4.1 · V11.1.1 · CWE-841: only Inspect rules move; the move is previewed, applied, read back and reversible."""
    t = Tenant()
    spec = {"type": "ssl_certificate_move", "rules": [3, 4, 2, 1], "certificate": 52}
    p = plan(t, spec)
    st = {u["object"]["name"]: u["status"] for u in p["items"]}
    assert st == {"Inspect Finance": "change", "Inspect Marketing": "change", "Zscaler Recommended Exemptions": "excluded",
                  "Default SSL Inspection Rule": "excluded"}
    res = apply(t, spec, prepared=p)
    assert res["status"] == "applied" and res["verification"]["confirmed"] == 2
    fin = t.zia.ssl_inspection_rules._find(3)
    assert fin["action"]["override_default_certificate"] is True and fin["action"]["ssl_interception_cert"]["id"] == 52
    assert t.zia.ssl_inspection_rules._find(4)["users"] == [{"id": 77, "name": "someone"}], "the rest of the rule is sent back as read"
    back = apply(t, res["inverse"])
    assert back["status"] == "applied"
    assert t.zia.ssl_inspection_rules._find(3)["action"]["override_default_certificate"] is False
    assert t.zia.ssl_inspection_rules._find(4)["action"]["ssl_interception_cert"]["id"] == 51


def test_a_certificate_that_is_not_ready_to_use_is_refused():
    """ASVS V5.1.3 · CWE-20: a certificate id the tenant does not list as ready to use is excluded, nothing is written."""
    t = Tenant()
    p = plan(t, {"type": "ssl_certificate_move", "rules": [3], "certificate": 666})
    assert p["status"] == "nothing_to_do" and "not a ready-to-use" in p["items"][0]["reason"]


# ---------------------------------------------------------------------------
# Framework capture and load
# ---------------------------------------------------------------------------

def test_capture_reads_only_in_scope_areas_and_leaves_tenant_objects_out():
    """ASVS V4.1.3 · CWE-201: the framework holds the tenant's own rules in scope, without defaults, predefined rules, people or locations."""
    t = Tenant()
    cap = zb.capture(t, zb.capture_scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "alternative"}), tenant_label="acme")
    fw = cap["framework"]
    assert cap["status"] == "ready" and list(fw["areas"]) == ["url"]
    rule = fw["areas"]["url"][0]
    assert rule["name"] == "Block Gambling" and rule["fields"]["url_categories"] == ["GAMBLING"]
    assert "HQ" not in json.dumps(fw) and "someone" not in json.dumps(fw)
    reasons = " ".join(x["reason"] for x in fw["not_exported"])
    assert "custom URL categories" in reasons and "locations" in reasons
    assert not [r for r in t.reads if "ssl" in r or "firewall" in r]


def test_a_captured_framework_applies_to_another_tenant_disabled():
    """ASVS V1.4.1 · CWE-1188: a framework captured from one tenant builds the same rules in another, disabled."""
    src = Tenant()
    fw = zb.capture(src, ["url", "ssl"], tenant_label="acme")["framework"]
    dst = Tenant(url=[URL_DEFAULT], ssl=[SSL_DEFAULT, SSL_PREDEF])
    res = apply(dst, {"type": "zia_baseline", "framework": json.loads(json.dumps(fw)), "areas": ["url", "ssl"]})
    assert res["status"] == "applied"
    names = {r["name"]: r for r in dst.zia.url_filtering.rows + dst.zia.ssl_inspection_rules.rows}
    assert {"Block Gambling", "Inspect Finance", "Inspect Marketing"} <= set(names)
    assert names["Block Gambling"]["state"] == "DISABLED" and "locations" not in names["Block Gambling"]


@pytest.mark.parametrize("fw,why", [
    ({"format": "something-else"}, "Not a ZIA policy framework"),
    ({"format": "zia-policy-framework", "format_version": 9, "areas": {"url": []}}, "newer version"),
    ({"format": "zia-policy-framework", "format_version": 1, "areas": {"email": [{}]}}, "Unknown area"),
    ({"format": "zia-policy-framework", "format_version": 1, "areas": {"url": [{"name": "<script>", "default": "BLOCK"}]}}, "usable name"),
    ({"format": "zia-policy-framework", "format_version": 1, "areas": {"url": [{"name": "x", "default": "DELETE_TENANT"}]}}, "not allowed"),
    ({"format": "zia-policy-framework", "format_version": 1, "areas": {"url": [{"name": "x", "default": "BLOCK",
                                                                                "fields": {"url_categories": ["A B; DROP"]}}]}}, "Zscaler names"),
    ({"format": "zia-policy-framework", "format_version": 1, "areas": {"url": [{"name": f"r{i}", "default": "BLOCK"} for i in range(201)]}}, "too many"),
])
def test_an_uploaded_framework_is_untrusted_and_checked(fw, why):
    """ASVS V5.1.3 · V5.5.3 · CWE-20 · CWE-502: a framework file is validated value by value; anything else is refused."""
    with pytest.raises(ao.OperationError, match=why):
        zb.load_framework(fw)


def test_export_from_tenant_carries_the_framework_as_its_own_part():
    """ASVS V4.1.3 · CWE-201: Export from tenant's "framework" part zips zia_policy_framework.json, read-only."""
    t = Tenant()
    res = pack_export.export_pack(t, parts=["framework"], name="Acme baseline", tenant_label="acme", framework_areas=["url", "ssl"])
    assert res["status"] == "ready" and res["pack"]["meta"]["counts"]["framework_rules"] == 3
    name, data, parts = pack_export.zip_export(res["pack"], "terraform")
    files = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert files == ["acme_baseline/zia_policy_framework.json"] and parts == [{"part": "framework", "format": "json", "path": files[0]}]
    fw = json.loads(pack_export.zip_member(data, files[0]))
    assert zb.load_framework(fw)["rules"] and t.writes == []


def test_the_framework_part_is_refused_when_nothing_it_reads_is_in_scope(monkeypatch):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the export endpoint refuses the framework part before signing in when nothing is in scope."""
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1))
    r = TestClient(srv.app).post("/api/dlp-packs/export/start", json={"vanity_domain": "acme", "client_id": "cid", "client_secret": "s3cret",
                                                                     "parts": ["framework"], "scopes": [], "channels": {}, "from_page": True})
    assert r.status_code == 400 and "scope" in r.json()["detail"].lower() and built == []


# ---------------------------------------------------------------------------
# Through the Bulk changes endpoints
# ---------------------------------------------------------------------------

BODY = {"scopes": ["dlp", "zia_extras"], "channels": {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"},
        "from_page": True, "client_id": "cid", "client_secret": "s3cret-value", "vanity_domain": "acme", "cloud": "zscalertwo",
        "assessor": "Jane Doe"}


def test_the_bulk_changes_page_offers_both_builders():
    """ASVS V14.3.3 · CWE-200: the plugin catalog lists the baseline and the certificate manager, with their form script."""
    r = TestClient(srv.app).get("/api/operations/plugins")
    types = {p["type"]: p for p in r.json()["plugins"]}
    assert types["zia_baseline"]["script"] == types["ssl_certificate_move"]["script"] == "ops_zia_baseline.js"
    js = TestClient(srv.app).get("/static/ops_zia_baseline.js")
    assert js.status_code == 200 and "OPS_PLUGINS.register" in js.text


def test_preview_apply_and_undo_through_the_endpoints_with_every_gate(monkeypatch):
    """ASVS V4.1.3 · V11.1.1 · CWE-862 · CWE-841: preview writes nothing; apply needs write mode, confirm, the assessor and the typed phrase; Undo is previewed."""
    t = Tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: t)
    c = TestClient(srv.app)
    op = {"type": "zia_baseline", "tier": "strict", "areas": ["ftc", "sandbox"]}
    r = c.post("/api/operations/preview", json=dict(BODY, operation=op))
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["counts"]["change"] == 7 and t.writes == [] and "s3cret" not in r.text and p["review"]
    body = dict(BODY, operation=op, plan_hash=p["plan_hash"], confirm=True)
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    assert c.post("/api/operations/apply", json=body).status_code == 403
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    assert c.post("/api/operations/apply", json=dict(body, assessor="")).status_code == 400
    assert c.post("/api/operations/apply", json=dict(body, confirm=False)).status_code == 400
    assert t.writes == []
    r = c.post("/api/operations/apply", json=dict(body, confirm_text=p["confirm_phrase"]))
    assert r.status_code == 200 and r.json()["status"] == "applied", r.text
    op_id = r.json()["operation_id"]
    u = c.post(f"/api/operations/{op_id}/undo/preview", json=BODY).json()
    assert u["counts"]["change"] == 7
    r = c.post("/api/operations/apply", json=dict(BODY, operation=u["operation"], plan_hash=u["plan_hash"], confirm=True,
                                                  confirm_text=u["confirm_phrase"], undo_of=op_id))
    assert r.status_code == 200 and r.json()["status"] == "applied"
    assert not [x for x in t.zia.file_type_control_rule.rows + t.zia.sandbox_rules.rows if x["name"].startswith("BL-")]
