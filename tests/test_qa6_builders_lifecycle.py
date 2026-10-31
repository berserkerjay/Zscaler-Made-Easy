"""Functional QA (wave 6): every builder and every change type, run through
its whole lifecycle on a stateful fake tenant at the SDK's wire level
(tests/sdk_wire_fake.py): preview -> apply -> read-back -> re-run (a no-op or
an in-place update, never a duplicate) -> Undo (the exact prior state) ->
apply again. The installed zscaler-sdk-python 1.11.3 service and model
classes sit between the app and the fake, so a method name, a signature, an
endpoint or a body field the SDK does not have fails here.

Deterministic: fixed seeds (random.Random(6)), no clock, no network, every
store in the test's own data folder (tests/conftest.py)."""
from __future__ import annotations

import copy
import json
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import offline_tenant as ot  # noqa: E402
import ops_zia_baseline as zb  # noqa: E402
import pack_channels as pc  # noqa: E402
import sdk_wire_fake as wf  # noqa: E402
from sdk_wire_fake import ZIA, ZPA1  # noqa: E402

ALL = ao.scope_for(["dlp", "zia_extras", "zpa", "zcc", "zdx", "genai", "automation", "aiguard"],
                   {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler", "endpoint_dlp": "zscaler",
                    "casb_dlp": "zscaler", "email_dlp": "zscaler"})
RNG_SEED = 6


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    import ops_zpa
    import zpa_reader
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    import zscaler.zia.url_categories as sdk_urls
    monkeypatch.setattr(sdk_urls.time, "sleep", lambda s: None)   # the SDK's own pause between URL lookups (1 s)
    ao.load_plugins()


def tenant(*extra):
    seeds = {}
    for e in extra:
        seeds.update(e)
    st = wf.WireStore(seeds)
    return st, wf.WireClient(st)


def run(client, spec, scope=ALL):
    """Preview, then apply with every gate held: (prepared, result)."""
    p = ao.plan(client, spec, scope=scope, tenant_label="Sample tenant")
    assert p["status"] != "blocked", p.get("blockers")
    r = ao.execute(client, spec, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor="Jane Doe",
                   confirm_text=p.get("confirm_phrase") or "", tenant_label="Sample tenant", settle_seconds=0)
    return p, r


def changes(prepared):
    return [(u["object"].get("name"), u["field"], u["before"], u["after"]) for u in prepared["items"] if u["status"] == "change"]


def assert_clean(st):
    assert st.violations == [], sorted(set(st.violations))[:8]


def assert_lifecycle(st, client, spec, before, scope=ALL):
    """apply -> read back -> re-run is a no-op -> Undo restores `before` -> apply again."""
    p, r = run(client, spec, scope)
    assert r["status"] == "applied", (r["status"], r["verification"], [(u["object"].get("name"), u.get("reason"), u.get("error"))
                                                                         for u in r["items"] if u["status"] not in ("applied", "noop", "excluded")])
    v = r["verification"]
    assert v["checked"] == v["confirmed"] and not v["mismatched"] and not v["unread"], v
    again = ao.plan(client, spec, scope=scope)
    assert again["counts"]["change"] == 0, changes(again)
    assert r["inverse"], "an applied change offers an Undo"
    _pu, ru = run(client, r["inverse"], scope)
    assert ru["status"] in ("applied", "nothing_to_do"), ru["status"]
    assert wf.semantic(st.state()) == before
    _p2, r2 = run(client, spec, scope)
    assert r2["status"] == "applied"
    assert_clean(st)
    return p, r


# ── The SDK model check itself ───────────────────────────────────────────

def test_the_model_check_knows_real_fields_and_flags_an_invented_one():
    """ASVS V5.1.3 · CWE-20: the payload check reads the installed SDK's models (nested ones too): a real field passes, an invented one is named."""
    from zscaler.zia.models.ssl_inspection_rules import SSLInspectionRules
    from zscaler.zia.models.url_filtering_rules import URLFilteringRule
    ok = {"name": "x", "action": "BLOCK", "urlCategories": ["GAMBLING"], "protocols": ["ANY_RULE"]}
    assert wf.unknown_fields(ok, URLFilteringRule) == []
    assert wf.unknown_fields(dict(ok, urlCategoriez=["X"]), URLFilteringRule) == ["URLFilteringRule.urlCategoriez"]
    ssl = {"name": "x", "action": {"type": "DECRYPT", "decryptSubActions": {"minClientTLSVersion": "CLIENT_TLS_1_2", "blockUndecrypt": True}}}
    assert wf.unknown_fields(ssl, SSLInspectionRules) == []
    bad = copy.deepcopy(ssl)
    bad["action"]["decryptSubActions"]["minClientTlsVersion2"] = "x"
    assert wf.unknown_fields(bad, SSLInspectionRules) == ["DecryptSubActions.action.decryptSubActions.minClientTlsVersion2"]


# ── ZIA security baseline: every tier, mode, overlay set and option ───────

TIERS_MODES = [(t, m) for t in zb.TIERS for m in ("tier", "allow_all", "block_all")]


def _choices(rng):
    """A deterministic table of per-rule choices: switch some off, set others to Allow, Block or Isolate."""
    out = {}
    for r in zb.CATALOG:
        roll = rng.random()
        if roll < 0.15:
            out[r["key"]] = {"on": False}
        elif roll < 0.45:
            out[r["key"]] = {"action": rng.choice(["ALLOW", "BLOCK", "ISOLATE"])}
    return out


@pytest.mark.parametrize("tier,mode", TIERS_MODES, ids=[f"{t}-{m}" for t, m in TIERS_MODES])
def test_zia_baseline_lifecycle_for_every_tier_and_mode(tier, mode):
    """ASVS V11.1.1 · V11.1.6 · CWE-841: each tier and mode applies, reads back exactly, re-runs as a no-op, undoes to the exact prior tenant and applies again."""
    st, cl = tenant(wf.zia_catalogues())
    before = wf.semantic(st.state())
    spec = {"type": "zia_baseline", "tier": tier, "mode": mode, "prefix": "BL", "areas": list(zb.AREA_ORDER)}
    assert_lifecycle(st, cl, spec, before)


OPTION_TABLE = [
    {"overlays": ["HIPAA", "PCI"], "enable_rules": False},
    {"overlays": list(zb.OVERLAYS), "enable_rules": True},
    {"overlays": [], "enable_rules": True, "certificate": "New CA 2026"},
    {"overlays": ["CJIS"], "isolation_profile": "Larkspur isolation", "prefix": "ABCDEFGHIJ"},
    {"overlays": ["GDPR"], "areas": ["url", "ssl"], "atp": {"crypto_mining_blocked": True}},
    {"overlays": ["FERPA"], "areas": ["atp"], "atp": {"tor_blocked": False}},
]


@pytest.mark.parametrize("row", range(len(OPTION_TABLE)))
@pytest.mark.parametrize("tier", list(zb.TIERS))
def test_zia_baseline_lifecycle_for_the_option_table_with_seeded_choices(tier, row):
    """ASVS V11.1.1 · CWE-841: overlays, enabled rules, a certificate, an isolation profile, the longest prefix, ATP and seeded per-rule choices all round-trip."""
    opts = OPTION_TABLE[row]
    rng = random.Random(f"{RNG_SEED}-{tier}-{row}")
    st, cl = tenant(wf.zia_catalogues())
    before = wf.semantic(st.state())
    spec = dict({"type": "zia_baseline", "tier": tier, "prefix": "BL", "areas": list(zb.AREA_ORDER), "rules": _choices(rng)}, **opts)
    assert_lifecycle(st, cl, spec, before)


@pytest.mark.parametrize("tier,mode", TIERS_MODES, ids=[f"{t}-{m}" for t, m in TIERS_MODES])
def test_zia_rule_constraints_hold_in_the_tenant_after_a_build(tier, mode):
    """ASVS V5.1.3 · V11.1.1 · CWE-20: names fit 31 characters and are unique per policy, orders stay 1..n, the SSL catch-all and the default deny end up last."""
    st, cl = tenant(wf.zia_catalogues())
    run(cl, {"type": "zia_baseline", "tier": tier, "mode": mode, "prefix": "ABCDEFGHIJ", "areas": list(zb.AREA_ORDER)})
    for path in [p for p in st.responses if p.startswith(ZIA) and (p.endswith("Rules") or "/webApplicationRules/" in p) and "casbDlp" not in p]:
        rows = st.rows(path)
        names = [r.get("name") for r in rows]
        assert len(names) == len(set(names)), path
        ours = [r for r in rows if str(r.get("name", "")).startswith("ABCDEFGHIJ-")]
        assert all(len(r["name"]) <= zb.MAX_NAME for r in ours), path
        live = sorted(int(r["order"]) for r in rows if "order" in r and not r.get("defaultRule") and int(r["order"]) > 0)
        assert live == list(range(1, len(live) + 1)), (path, live)
        for r in ours:
            if r["name"].endswith(("SSL-Catch-All", "FW-Default-Deny")):
                assert int(r["order"]) == max(live), (r["name"], r["order"], live)


@pytest.mark.parametrize("mode", ["tier", "allow_all", "block_all"])
def test_locked_rules_cannot_be_weakened_by_any_choice(mode):
    """ASVS V1.4.1 · CWE-1188: Allow-Web and Allow-NTP are created on and Allow whatever the mode and the per-rule choices ask."""
    st, cl = tenant(wf.zia_catalogues())
    spec = {"type": "zia_baseline", "tier": "strict", "mode": mode, "prefix": "BL", "areas": ["firewall"],
            "rules": {"fw.allow_web": {"on": False, "action": "BLOCK"}, "fw.allow_ntp": {"on": False, "action": "ISOLATE"}}}
    run(cl, spec)
    fw = {r["name"]: r for r in st.rows(f"{ZIA}/firewallFilteringRules")}
    for name in ("BL-FW-Allow-Web", "BL-FW-Allow-NTP"):
        assert fw[name]["action"] == "ALLOW", fw[name]


def test_overlays_only_add_citations_never_change_a_rule():
    """ASVS V1.4.1 · CWE-440: a compliance overlay adds control citations to the review; every payload written is the same with or without it."""
    _st, cl = tenant(wf.zia_catalogues())
    base = {"type": "zia_baseline", "tier": "balanced", "prefix": "BL", "areas": list(zb.AREA_ORDER)}
    plain = ao.plan(cl, base, scope=ALL)
    cited = ao.plan(cl, dict(base, overlays=list(zb.OVERLAYS)), scope=ALL)
    assert [g["target"] for g in plain["groups"]] == [g["target"] for g in cited["groups"]]
    assert not any(r["controls"] for r in plain["review"]) and any(r["controls"] for r in cited["review"])


def test_a_rule_the_customer_already_has_is_updated_in_place_and_undo_puts_it_back():
    """ASVS V11.1.1 · CWE-841: a rule carrying the baseline's name is updated in place (no duplicate); Undo restores its own action, categories and scope."""
    st, cl = tenant(wf.zia_catalogues())
    url = st.responses[f"{ZIA}/urlFilteringRules"]["body"]
    for r in url:
        r["order"] += 1
    url.insert(0, {"id": 7001, "name": "BL-URL-Legal-Liability", "order": 1, "rank": 7, "state": "ENABLED", "action": "ALLOW",
                   "urlCategories": ["GAMBLING"], "protocols": ["ANY_RULE"], "locations": [{"id": 5, "name": "HQ"}]})
    before = wf.semantic(st.state())
    p, _r = assert_lifecycle(st, cl, {"type": "zia_baseline", "tier": "strict", "prefix": "BL", "areas": ["url", "ssl"]}, before)
    assert ("BL-URL-Legal-Liability", "action", "ALLOW", "BLOCK") in changes(p)
    assert [r["name"] for r in st.rows(f"{ZIA}/urlFilteringRules")].count("BL-URL-Legal-Liability") == 1


def test_a_rerun_keeps_the_sandbox_isolation_profile_the_sdk_model_cannot_read():
    """ASVS V11.1.1 · CWE-221: a re-read object keeps the fields SDK 1.11.3's model drops (sandbox cbiProfile): a re-run update never clears them and the read-back confirms the build."""
    st, cl = tenant()
    spec = {"type": "zia_baseline", "tier": "balanced", "prefix": "BL", "areas": ["sandbox"]}
    _p, r = run(cl, spec)
    assert r["status"] == "applied" and r["verification"]["mismatched"] == []
    for x in st.responses[f"{ZIA}/sandboxRules"]["body"]:
        if x["name"] == "BL-SB-Office-PDF":
            x["description"] = "edited in the portal"
    p2, r2 = run(cl, spec)
    assert [c[1] for c in changes(p2)] == ["description"] and r2["status"] == "applied"
    rule = st.by_name(f"{ZIA}/sandboxRules", "BL-SB-Office-PDF")
    assert rule["firstTimeOperation"] == "QUARANTINE_ISOLATE" and rule["cbiProfile"]["id"] == "iso-1"


def test_a_captured_framework_builds_the_same_policy_on_another_tenant():
    """ASVS V11.1.1 · CWE-841: a framework captured from one tenant applies to another, re-runs as a no-op and undoes cleanly."""
    st, cl = tenant(wf.zia_catalogues())
    run(cl, {"type": "zia_baseline", "tier": "strict", "prefix": "BL", "areas": list(zb.AREA_ORDER)})
    fw = zb.capture(cl, list(zb.CAPTURE_AREAS), name="Larkspur strict")["framework"]
    st2, cl2 = tenant(wf.zia_catalogues())
    before = wf.semantic(st2.state())
    assert_lifecycle(st2, cl2, {"type": "zia_baseline", "framework": fw, "prefix": "FW", "areas": list(zb.CAPTURE_AREAS)}, before)


def test_ssl_certificate_move_lifecycle():
    """ASVS V11.1.1 · CWE-841: moving an Inspect rule to another certificate reads back and its Undo puts the default back exactly."""
    st, cl = tenant(wf.zia_catalogues())
    st.responses[f"{ZIA}/sslInspectionRules"]["body"].insert(2, {
        "id": 704, "name": "Inspect finance", "order": 3, "rank": 7, "state": "ENABLED", "urlCategories": ["FINANCE"],
        "action": {"type": "DECRYPT", "overrideDefaultCertificate": False,
                   "decryptSubActions": {"serverCertificates": "BLOCK", "ocspCheck": True, "minClientTLSVersion": "CLIENT_TLS_1_2"}}})
    before = wf.semantic(st.state())
    assert_lifecycle(st, cl, {"type": "ssl_certificate_move", "certificate": 52, "rules": [704]}, before)
    assert st.by_name(f"{ZIA}/sslInspectionRules", "Inspect finance")["action"]["sslInterceptionCert"]["id"] == 52


# ── ZPA builder ─────────────────────────────────────────────────────────

CSV = "name,domains,tcp_ports,udp_ports,description\nHR portal,hr.corp.example.com,443,,HR\nFiles,files.corp.example.com;share.corp.example.com,445;139,,SMB\n"
ZPA_VARIANTS = [
    {"wildcard": {"domain": "corp.example.com", "tcp": "1-65535"}},
    {"wildcard": {"domain": "corp.example.com", "tcp": "80,443", "udp": "53"}, "enable": True},
    {"preset": {"vertical": "healthcare", "domain": "hosp.example.org"}},
    {"preset": {"vertical": "finance", "domain": "bank.example.org"}, "enable": True},
    {"preset": {"vertical": "education", "domain": "uni.example.edu"}},
    {"preset": {"vertical": "general", "domain": "corp.example.com"}},
    {"csv": CSV},
    {"browser_access": {"domain": "web.corp.example.com", "port": "443", "certificate_id": "6001"}},
    {"pra": {"rdp_host": "rdp.corp.example.com", "ssh_host": "ssh.corp.example.com", "portal_id": "6101"}},
]
POLICY_SPEC = {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": True, "inspection": True, "isolation_profile_id": "6201",
               "reauth_timeout": "86400", "reauth_idle_timeout": "900"}


@pytest.mark.parametrize("variant", range(len(ZPA_VARIANTS)))
def test_zpa_builder_lifecycle_for_every_template(variant):
    """ASVS V11.1.1 · CWE-841: connector group, segments (wildcard, every preset, CSV, Browser Access, PRA) and policies build, re-run as no-ops and undo to the exact prior tenant."""
    st, cl = tenant(wf.zpa_builder_lists())
    before = wf.semantic(st.state())
    steps = [{"type": "zpa_connector_group", "prefix": "pov1"}, dict({"type": "zpa_app_segments", "prefix": "pov1"}, **ZPA_VARIANTS[variant]), POLICY_SPEC]
    results = []
    for spec in steps:
        _p, r = run(cl, spec)
        assert r["status"] == "applied" and r["verification"]["checked"] == r["verification"]["confirmed"], r["status"]
        assert ao.plan(cl, spec, scope=ALL)["counts"]["change"] == 0
        results.append(r)
    for r in reversed(results):
        assert run(cl, r["inverse"])[1]["status"] == "applied"
    assert wf.semantic(st.state()) == before
    assert_clean(st)


def test_zpa_rerun_with_new_options_updates_in_place_and_undo_restores_them():
    """ASVS V11.1.1 · CWE-841: a re-run with other ports or timeouts updates the same objects; their Undo restores the earlier values."""
    st, cl = tenant(wf.zpa_builder_lists())
    run(cl, {"type": "zpa_connector_group", "prefix": "pov1"})
    run(cl, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "1-65535"}})
    run(cl, {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": True})
    mid = wf.semantic(st.state())
    seg_count = len(st.rows(f"{ZPA1}/application"))
    p1, r1 = run(cl, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "443", "udp": "53"}, "enable": True})
    p2, r2 = run(cl, {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": True, "reauth_timeout": "3600", "reauth_idle_timeout": "900"})
    assert {c[1] for c in changes(p1)} == {"enabled", "tcp", "udp"} and {c[1] for c in changes(p2)} == {"reauth_timeout", "reauth_idle_timeout"}
    assert len(st.rows(f"{ZPA1}/application")) == seg_count
    run(cl, r2["inverse"])
    run(cl, r1["inverse"])
    assert wf.semantic(st.state()) == mid
    assert_clean(st)


# ── Client Connector profiles ────────────────────────────────────────────

ZCC_TABLE = [(plat, ft, at) for plat in ("windows", "macos") for ft in ("best_practice", "portal_default", "existing")
             for at in ("best_practice", "portal_default")]


@pytest.mark.parametrize("plat,ft,at", ZCC_TABLE, ids=["-".join(x) for x in ZCC_TABLE])
def test_zcc_profile_lifecycle_for_every_template(plat, ft, at):
    """ASVS V11.1.1 · CWE-841: each platform and template builds, reads back, a re-run makes no duplicate, Undo deletes exactly what was made."""
    import ops_zcc as oz
    st, cl = tenant()
    before = wf.semantic(st.state())
    fwd = ({"template": "existing", "id": str(st.rows(wf.ZCC_FWD)[0]["id"])} if ft == "existing" else {"template": ft, "name": "QA forwarding"})
    spec = {"type": oz.BUILD, "platform": plat, "forwarding": fwd, "app": {"template": at, "name": f"QA {plat}"}}
    p, r = run(cl, spec)
    assert r["status"] == "applied" and r["verification"]["checked"] == r["verification"]["confirmed"]
    again = ao.plan(cl, spec, scope=ALL)
    assert again["status"] == "blocked" and any("already exists" in b for b in again["blockers"])   # never a duplicate
    _pu, ru = run(cl, r["inverse"])
    assert ru["status"] == "applied"
    assert wf.semantic(st.state()) == before
    assert_clean(st)


# ── ZDX probe setup (the ZDX configuration API is not in the SDK: its fake) ─

@pytest.mark.parametrize("template", ["best_practice", "microsoft_365"])
@pytest.mark.parametrize("interval,cloudpath", [(5, True), (30, False)])
def test_zdx_probe_setup_lifecycle(template, interval, cloudpath):
    """ASVS V11.1.1 · CWE-841: a ZDX setup re-runs as a no-op; Undo deletes the custom apps and probes and turns the predefined apps off (ZDX cannot delete those); it applies again."""
    import ops_zdx as oz
    import test_ops_zdx as T
    fake = T.FakeZdx()
    fake.supported += [{"provider": "OUTLOOK", "name": "Outlook", "host": "outlook.office365.com"},
                       {"provider": "SHAREPOINT", "name": "SharePoint", "host": "<prefix>.sharepoint.com"},
                       {"provider": "ONEDRIVE", "name": "OneDrive", "host": "<prefix>-my.sharepoint.com"}]
    fake.cols.append({"id": 1, "name": "Custom Apps Collection", "type": "END_USER"})
    keep = fake.add_app("Existing portal", active=True)
    fake.add_mon(keep, "Existing Web", url="https://portal.example.com/")
    cl = T.client_for(fake)
    scope = ao.scope_for(["zdx"], {})
    tpl = oz.TEMPLATES[template]
    spec = {"type": "zdx_probes", "template": template, "interval_minutes": interval, "protocol": "ADAPTIVE",
            "predefined": [dict(p, cloudpath=cloudpath, **({"prefix": "larkspur"} if p["provider"] in ("SHAREPOINT", "ONEDRIVE") else {}))
                           for p in tpl["predefined"]],
            "custom": [{"name": "Intranet", "url": "https://intranet.example.com/home", "cloudpath": cloudpath}]}
    before_custom = copy.deepcopy(([a for a in fake.apps], [m for m in fake.mons]))
    _p, r = run(cl, spec, scope)
    assert r["status"] == "applied"
    assert ao.plan(cl, spec, scope=scope)["counts"]["change"] == 0
    _pu, ru = run(cl, r["inverse"], scope)
    assert ru["status"] == "applied"
    customs = ([a for a in fake.apps if a["type"] == "CUSTOM"], [m for m in fake.mons if m.get("class") == "CUSTOM"])
    assert json.dumps(customs, sort_keys=True, default=str) == json.dumps(before_custom, sort_keys=True, default=str)
    assert all(not a["active"] for a in fake.apps if a["type"] == "PREDEFINED")
    assert all(not m["active"] for m in fake.mons if m.get("class") == "ZSCALER")
    assert run(cl, spec, scope)[1]["status"] == "applied"


# ── AI Guard builders ────────────────────────────────────────────────────

AIG_SCOPE = ao.scope_for(["zia_extras", "aiguard", "dlp"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})


@pytest.mark.parametrize("apps", [["chatgpt", "claude", "m365copilot"], ["gemini"]])
@pytest.mark.parametrize("licensed", [True, False])
def test_aiguard_routing_lifecycle(apps, licensed):
    """ASVS V11.1.1 · CWE-841: AI Guard routing (existing certificate, proxy and gateway) applies through the SDK, re-runs as a no-op and undoes exactly."""
    st, cl = tenant(wf.aiguard_lists(proxy=True, gateway=True, licensed=licensed))
    before = wf.semantic(st.state())
    assert_lifecycle(st, cl, {"type": "aiguard_routing", "apps": apps, "cert": {"mode": "existing", "id": 11}}, before, AIG_SCOPE)


@pytest.mark.parametrize("cert", [{"mode": "upload", "pem": "PEM"}, {"mode": "existing", "id": 11}], ids=["upload", "existing"])
def test_aiguard_routing_creates_the_certificate_and_proxy_and_undoes_them(cert):
    """ASVS V11.1.1 · CWE-841: with no proxy yet the routing uploads (or reuses) the root certificate and creates the proxy; the gateway stays a portal step; Undo removes what it made."""
    import test_ops_aiguard as A
    lists = wf.aiguard_lists()
    if cert["mode"] == "upload":
        lists[f"{ZIA}/rootCertificates"] = []
        cert = dict(cert, pem=A.PEM)
    st, cl = tenant(lists)
    before = wf.semantic(st.state())
    p, _r = assert_lifecycle(st, cl, {"type": "aiguard_routing", "apps": ["chatgpt"], "cert": cert}, before, AIG_SCOPE)
    status = {u["object"].get("name"): u["status"] for u in p["items"]}
    assert status["AIG-Proxy"] == "change" and status["AIG-Gateway"] == "excluded" and status["AIG-Forward"] == "excluded"


@pytest.mark.parametrize("profile", ["HIPAA", "PCI", "GDPR", "general"])
def test_aiguard_detection_policy_lifecycle(profile):
    """ASVS V11.1.1 · CWE-841: an AI Guard detection policy and its match rule apply through the SDK, re-run as a no-op and undo exactly."""
    st, cl = tenant(wf.aiguard_lists())
    before = wf.semantic(st.state())
    assert_lifecycle(st, cl, {"type": "aiguard_detection_policy", "profile": profile, "apps": ["chatgpt", "claude"]}, before, AIG_SCOPE)


# ── The classic Bulk changes types ───────────────────────────────────────

CLASSIC_SCOPE = ao.scope_for(["dlp", "zia_extras", "zpa"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler",
                                                           "endpoint_dlp": "zscaler", "email_dlp": "zscaler", "casb_dlp": "zscaler"})
CAT2 = {"id": "CUSTOM_02", "configuredName": "Blocked extra", "superCategory": "USER_DEFINED", "customCategory": True, "urls": ["bad.example.net"]}
WIKI = {"id": "2203", "name": "Wiki", "enabled": True, "domainNames": ["wiki.other.example"], "tcpPortRanges": ["8080", "8080"], "udpPortRanges": [],
        "segmentGroupId": "2101", "serverGroups": [{"id": "2301"}], "bypassType": "NEVER", "healthReporting": "ON_ACCESS", "isCnameEnabled": True,
        "icmpAccessType": "NONE"}


def _classic_tenant():
    st, cl = tenant()
    st.responses[f"{ZIA}/urlCategories"]["body"].append(copy.deepcopy(CAT2))
    seg = st.responses[f"{ZPA1}/application"]["body"]["list"]
    seg.append(copy.deepcopy(WIKI))
    seg[0]["domainNames"].append("ledger.larkspur-freight.example")
    return st, cl


def _sem(state):
    """As semantic(), with URL and domain lists as sets and the names ZPA fills in itself (segment group, server group) left out."""
    def walk(v, key=""):
        if isinstance(v, dict):
            return {k: walk(x, k) for k, x in v.items() if k != "segmentGroupName" and not (key == "serverGroups" and k == "name")}
        if isinstance(v, list):
            items = [walk(x, key) for x in v]
            return sorted(items, key=lambda x: json.dumps(x, sort_keys=True)) if key in ("urls", "urlCategories", "domainNames") else items
        return v
    return walk(wf.semantic(state))


def _rule_state(st, cl):
    o = ao.read_objects(cl, "rules", CLASSIC_SCOPE)
    targets = [{"policy": g["policy"], "id": r["id"], **({"rule_type": r["rule_type"]} if r.get("rule_type") else {})}
               for g in o["policies"] for r in g["rules"] if not r.get("locked") and r.get("state") == "ENABLED"]
    return {"type": "rule_state", "value": "DISABLED", "targets": targets[:100]}


CLASSIC = {
    "rule_state": _rule_state,
    "reorder_url": lambda st, cl: {"type": "reorder", "policy": "url_filtering",
                                   "order": [r["id"] for r in sorted(st.rows(f"{ZIA}/urlFilteringRules"), key=lambda r: -r["order"])]},
    "reorder_firewall": lambda st, cl: {"type": "reorder", "policy": "firewall",
                                        "order": [r["id"] for r in sorted((x for x in st.rows(f"{ZIA}/firewallFilteringRules") if not x.get("defaultRule") and not x.get("predefined")),
                                                                          key=lambda r: -r["order"])]},
    "urls_add": lambda st, cl: {"type": "url_categories", "action": "add", "target": "CUSTOM_01", "urls": ["new.example.com", "two.example.org"]},
    "urls_remove": lambda st, cl: {"type": "url_categories", "action": "remove", "source": "CUSTOM_01", "urls": ["portal.harborline-logistics.example"]},
    "urls_move": lambda st, cl: {"type": "url_categories", "action": "move", "source": "CUSTOM_01", "target": "CUSTOM_02",
                                 "urls": ["portal.harborline-logistics.example"]},
    "urls_copy_new": lambda st, cl: {"type": "url_categories", "action": "copy", "source": "CUSTOM_01", "create_target": {"name": "QA copy"},
                                     "urls": ["portal.harborline-logistics.example"]},
    "zpa_move": lambda st, cl: {"type": "zpa_domains", "action": "move", "source": "2201", "target": "2203", "domains": ["billing.larkspur-freight.example"]},
    "zpa_copy": lambda st, cl: {"type": "zpa_domains", "action": "copy", "source": "2201", "target": "2203", "domains": ["billing.larkspur-freight.example"]},
    "zpa_clone_move": lambda st, cl: {"type": "zpa_domains", "action": "clone", "move": True, "source": "2201", "name": "QA clone",
                                      "domains": ["billing.larkspur-freight.example"]},
}


@pytest.mark.parametrize("kind", list(CLASSIC))
def test_classic_bulk_change_lifecycle(kind):
    """ASVS V11.1.1 · V11.1.6 · CWE-841: each Bulk changes type applies through the SDK, reads back, re-runs without a further change and its Undo restores the tenant."""
    st, cl = _classic_tenant()
    before = _sem(st.state())
    spec = CLASSIC[kind](st, cl)
    _p, r = run(cl, spec, CLASSIC_SCOPE)
    assert r["status"] == "applied", (r["status"], [(u["object"].get("name"), u.get("reason")) for u in r["items"] if u["status"] != "applied"])
    assert r["verification"]["checked"] == r["verification"]["confirmed"]
    again = ao.plan(cl, spec, scope=CLASSIC_SCOPE)
    assert again["counts"]["change"] == 0 or again["status"] == "blocked", changes(again)   # a new category or clone: its name is taken now
    _pu, ru = run(cl, r["inverse"], CLASSIC_SCOPE)
    assert ru["status"] == "applied"
    assert _sem(st.state()) == before
    assert_clean(st)


@pytest.mark.parametrize("spec", [
    {"type": "zpa_domains", "action": "move", "source": "2201", "target": "2203", "domains": ["billing.larkspur-freight.example"]},
    {"type": "zpa_domains", "action": "clone", "move": True, "source": "2201", "name": "QA clone", "domains": ["billing.larkspur-freight.example"]},
], ids=["move", "clone-move"])
def test_moving_a_segments_last_domain_is_refused_in_the_preview_and_nothing_is_written(spec):
    """ASVS V11.1.1 · CWE-841 · CWE-440: ZPA keeps one domain per segment, so a move that would empty the source is excluded in the preview (never half done: no copy, no empty clone)."""
    st, cl = tenant()
    st.responses[f"{ZPA1}/application"]["body"]["list"].append(copy.deepcopy(WIKI))
    before = st.state()
    p = ao.plan(cl, spec, scope=CLASSIC_SCOPE)
    assert p["counts"]["change"] == 0 and p["status"] == "nothing_to_do"
    assert any(ao.LAST_DOMAIN in u["reason"] for u in p["items"])
    r = ao.execute(cl, spec, plan_hash=p["plan_hash"], scope=CLASSIC_SCOPE, writes_enabled=True, assessor="Jane Doe", settle_seconds=0)
    assert r["status"] == "nothing_to_do" and st.write_log() == [] and st.state() == before


# ── Policy packs: deploy, re-run, Undo ───────────────────────────────────

@pytest.mark.parametrize("pack_id,channel", [("cjis_policy_pack", "web"), ("cjis_policy_pack", "email"), ("healthcare_phi_baseline", "endpoint")])
def test_pack_deploy_rerun_and_undo_restore_the_tenant_including_confidence_tweaks(pack_id, channel):
    """ASVS V11.1.1 · CWE-841 · CWE-221: a pack deploys through the SDK, a re-run creates nothing, and Undo deletes what it made and puts back the confidence a tweak changed."""
    import deployments
    import pack_deploy as pd
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pack = {"id": pack_id, "dir": os.path.join(root, pack_id)}
    st, cl = tenant()
    for d in st.responses[f"{ZIA}/dlpDictionaries"]["body"]:
        d.setdefault("customPhraseMatchType", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY")
    before = wf.semantic(st.state())
    ct = {pack_id: [channel]}
    rep = pd.preflight(cl, [pack], writes_enabled=True, channel_targets=ct)
    res = pd.apply(cl, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, assessor="Jane Doe", settle_seconds=0, channel_targets=ct)
    assert res["status"] == "applied"
    again = pd.preflight(cl, [pack], writes_enabled=True, channel_targets=ct)
    assert not any((c.get("create") or 0) for c in (again["summary"].get("channels") or {}).values()), again["summary"]
    assert not any((again["summary"].get(k) or {}).get("create") for k in ("dictionary", "engine", "policy"))
    rec = deployments.from_apply(res, tenant_label="Sample tenant", packs=[pack_id], options={}, channel_targets=ct, by="Jane Doe")
    undo = pd.undo(cl, rec, writes_enabled=True, settle_seconds=0)
    assert undo["status"] == "undone" and undo["complete"], undo.get("summary")
    assert wf.semantic(st.state()) == before
    assert_clean(st)


@pytest.mark.parametrize("how", ["pack", "selected"])
def test_removing_a_deployed_pack_or_its_rules_restores_the_tenant(how):
    """ASVS V11.1.1 · CWE-841: removing a deployed pack (or picking its rules) deletes its rules, then the engines and dictionaries only they used, and nothing else."""
    import pack_deploy as pd
    import pack_removal as pr
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pack = {"id": "cjis_policy_pack", "dir": os.path.join(root, "cjis_policy_pack")}
    ct = {"cjis_policy_pack": ["web"]}
    st, cl = tenant()
    before = wf.semantic(st.state())
    rep = pd.preflight(cl, [pack], writes_enabled=True, channel_targets=ct, apply_tweaks=False)
    res = pd.apply(cl, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, assessor="Jane Doe", settle_seconds=0, channel_targets=ct,
                   apply_tweaks=False)
    assert res["status"] == "applied"
    if how == "pack":
        plan = pr.plan_removal(cl, [pack])
        out = pr.remove(cl, [pack], plan_hash=plan["plan_hash"], writes_enabled=True, settle_seconds=0)
    else:
        picked = [{"channel": "web", "id": r["id"]} for r in res["results"] if r["kind"] == "policy" and r["status"] == "created"]
        plan = pr.plan_removal_selected(cl, picked)
        out = pr.remove_selected(cl, picked, plan_hash=plan["plan_hash"], writes_enabled=True, settle_seconds=0)
    assert plan["keep_count"] == 0 and out["status"] == "removed", (out["status"], out.get("summary"))
    assert wf.semantic(st.state()) == before
    assert_clean(st)


def test_undo_leaves_a_tweaked_dictionary_someone_changed_since():
    """ASVS V11.1.6 · CWE-367: a dictionary whose confidence was changed after the deployment is left as it is; the Undo says so and is partial."""
    import deployments
    import pack_deploy as pd
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pack = {"id": "cjis_policy_pack", "dir": os.path.join(root, "cjis_policy_pack")}
    st, cl = tenant()
    ct = {"cjis_policy_pack": ["web"]}
    rep = pd.preflight(cl, [pack], writes_enabled=True, channel_targets=ct)
    res = pd.apply(cl, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, assessor="Jane Doe", settle_seconds=0, channel_targets=ct)
    tweak = next(r for r in res["results"] if r["kind"] == "tweak")
    assert tweak["before"] and tweak["after"] and tweak["before"] != tweak["after"]
    for d in st.responses[f"{ZIA}/dlpDictionaries"]["body"]:
        if str(d["id"]) == str(tweak["id"]):
            d["confidenceThreshold"] = "CONFIDENCE_LEVEL_HIGH"
    rec = deployments.from_apply(res, tenant_label="Sample tenant", packs=["cjis_policy_pack"], options={}, channel_targets=ct, by="Jane Doe")
    undo = pd.undo(cl, rec, writes_enabled=True, settle_seconds=0)
    kept = next(r for r in undo["results"] if r["kind"] == "tweak")
    assert kept["status"] == "skipped" and "changed" in kept["reason"] and undo["status"] == "partial"
    assert next(d for d in st.rows(f"{ZIA}/dlpDictionaries") if str(d["id"]) == str(tweak["id"]))["confidenceThreshold"] == "CONFIDENCE_LEVEL_HIGH"


# ── Remediation recipes ──────────────────────────────────────────────────

@pytest.mark.parametrize("rule_type,rule_id", [("webDlpRules", 101), ("urlFilteringRules", 601), ("firewallFilteringRules", 801),
                                               ("sslInspectionRules", 702)])
def test_add_description_changes_only_the_description(monkeypatch, rule_type, rule_id):
    """ASVS V11.1.1 · CWE-221 · CWE-440: 'Add Description to a Rule' reads the rule and sends it back whole (ZIA's PUT replaces a rule): only the description changes."""
    import remediation
    monkeypatch.setenv("ENABLE_WRITE_ACTIONS", "YES_I_UNDERSTAND")
    st = wf.WireStore()
    path = {"webDlpRules": "webDlpRules", "urlFilteringRules": "urlFilteringRules", "firewallFilteringRules": "firewallFilteringRules",
            "sslInspectionRules": "sslInspectionRules"}[rule_type]
    before = next(r for r in st.rows(f"{ZIA}/{path}") if r["id"] == rule_id)
    out = remediation.execute(ot.OfflineRawClient(st, {"client_id": "x"}), "RULE-DESC",
                              {"rule_type": rule_type, "rule_id": str(rule_id), "description": "Owner: SecOps"}, dry_run=False)
    after = next(r for r in st.rows(f"{ZIA}/{path}") if r["id"] == rule_id)
    assert out["status"] == "completed"
    assert after == dict(before, description="Owner: SecOps")


def test_remediation_recipes_offer_only_values_zia_takes():
    """ASVS V5.1.3 · CWE-20: the Web DLP recipe offers ZIA's Web DLP actions (monitor by default), the URL recipe sends the protocols ZIA requires and no isolation without a profile."""
    import remediation
    dlp = {f["key"]: f for f in remediation.get_recipe("DLP-01")["fields"]}["action"]
    assert set(dlp["options"]) <= pc.CHANNELS[pc.WEB]["monitor_actions"] | pc.CHANNELS[pc.WEB]["enforcing_actions"]
    assert dlp["default"] in pc.CHANNELS[pc.WEB]["monitor_actions"]
    url = remediation.plan("URL-01", {"name": "x", "description": "y", "action": "BLOCK", "url_categories": "GAMBLING", "state": "DISABLED", "order": 1})
    assert url["ok"] and url["body"]["protocols"] == ["ANY_RULE"]
    assert url["body"]["rank"] == 7   # an optional field left out takes its default instead of failing the plan
    assert "ISOLATE" not in {f["key"]: f for f in remediation.get_recipe("URL-01")["fields"]}["action"]["options"]
    assert "firewallFilteringRules" in {f["key"]: f for f in remediation.get_recipe("RULE-DESC")["fields"]}["rule_type"]["options"]


# ── Proposals and self-healing's Heal ─────────────────────────────────────

def test_a_heal_keeps_the_fields_the_sdk_model_drops(tmp_path, monkeypatch):
    """ASVS V11.1.1 · CWE-221: applying a proposal (Heal) to an Email DLP rule keeps its incident forwarding and rank, which SDK 1.11.3's model leaves out."""
    import proposal_apply as pa
    import proposals as pr
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    st, cl = tenant()
    rule = st.rows(f"{ZIA}/emailDlpRules")[0]
    assert rule["zscalerIncidentReceiver"] is True and rule["rank"] == 7
    p = {"id": pr.proposal_id("acme", "retire_rule", "rule:email:" + rule["name"]), "tenant": pr.tenant_key("acme"), "kind": "retire_rule",
         "label": "Retire", "target": "rule:email:" + rule["name"], "title": "Disable",
         "change": {"apply": "rule", "rule_id": rule["id"], "channel": "email", "field": "state", "from": "ENABLED", "to": "DISABLED"},
         "evidence": {}, "expected_effect": "", "rollback": {"field": "state", "to": "ENABLED"}, "gate": "approve", "applies_via": "phase 3",
         "channel": "email", "rule": rule["name"]}
    pr.merge("acme", [p], source="test", resolve_missing=False)
    pr.decide("acme", p["id"], "approve", by="jane")
    out = pa.apply(cl, "acme", p["id"], writes_enabled=True, by="jane")
    assert out["status"] == "applied"
    after = st.rows(f"{ZIA}/emailDlpRules")[0]
    assert after["state"] == "DISABLED" and after["zscalerIncidentReceiver"] is True and after["rank"] == 7
    assert after["dlpEngines"] == [{"id": 60, "name": "PCI"}]
    back = pa.rollback(cl, "acme", p["id"], writes_enabled=True, by="jane")
    assert back["status"] == "rolled_back" and wf.semantic(st.rows(f"{ZIA}/emailDlpRules")[0]) == wf.semantic(rule)
    assert_clean(st)


def test_a_single_read_keeps_what_the_model_drops():
    """ASVS V11.1.1 · CWE-221: admin_ops._one (the re-read before every update) carries the raw answer's fields the SDK model leaves out."""
    st, cl = tenant()
    st.responses[f"{ZIA}/sandboxRules"]["body"].append({"id": 4401, "name": "SB", "order": 1, "rank": 7, "state": "DISABLED",
                                                         "firstTimeOperation": "QUARANTINE_ISOLATE", "cbiProfile": {"id": "iso-1", "name": "P"}})
    row, err = ao._one(cl.zia.sandbox_rules.get_rule(4401))
    assert err is None and row["cbi_profile"] == {"id": "iso-1", "name": "P"} and row["name"] == "SB"
