"""UCaaS one-click (ucaas_oneclick): the switches in URL and Cloud App
Control advanced settings as an area of the ZIA security baseline (picked
explicitly, pre-set per tier, through the Bulk changes gates, preview,
re-read, read-back and Undo), and the Path analyzer evaluating Zscaler's
predefined one-click rules against them. Fakes only: no tenant, no network."""
from __future__ import annotations

import copy

import pytest

import admin_ops as ao
import ops_zia_baseline as zb
import ucaas_oneclick as uc
import zia_path_modules as zpm
from test_ops_zia_baseline import FULL, NOTHING, PLATFORM_ONLY, WEB_ONLY, Tenant, _execute, apply, plan  # noqa: F401
from test_path_zia_modules import Tenant as PathTenant, mod, run
from test_data_flow import ROUTES
from zia_module_fixtures import MODULE_ROUTES

SPEC = {"type": "zia_baseline", "tier": "balanced", "areas": ["ucaas"]}


class Resp:
    def __init__(self, body):
        self._body = copy.deepcopy(body)

    def get_body(self):
        return copy.deepcopy(self._body)


def ucaas_tenant(settings=None, *, partial=False, fail=False):
    """The baseline's fake tenant plus the URL and Cloud App Control
    advanced settings (SDK 1.11.3 url_filtering.get_url_and_app_settings /
    update_url_and_app_settings): the raw body, every field camelCase."""
    t = Tenant()
    t.settings = dict({k: False for k in uc.KEYS}, enableChatGptPrompt=True, enableNewlyRegisteredDomains=True, considerEmbeddedSites=False,
                      **(settings or {}))
    uf = t.zia.url_filtering

    def get():
        t.reads.append("url_filtering.get_url_and_app_settings")
        if fail:
            return None, None, {"status": 403, "message": "denied"}
        return (copy.deepcopy(t.settings), None, None) if partial else (None, Resp(t.settings), None)

    def put(**kw):
        t.writes.append(("url_filtering", "update_url_and_app_settings", None))
        t.put_body = copy.deepcopy(kw)
        t.settings = copy.deepcopy(kw)
        return copy.deepcopy(kw), Resp(kw), None
    uf.get_url_and_app_settings = get
    uf.update_url_and_app_settings = put
    return t


# ── The catalogue and the review ─────────────────────────────────────
def test_every_switch_is_an_sdk_1_11_3_field_of_the_settings_model():
    """ASVS V1.1.2 · CWE-1173: the switches are the SDK 1.11.3 AdvancedUrlFilterAndCloudAppSettings fields (Teams through enableOffice365)."""
    model = pytest.importorskip("zscaler.zia.models.url_filter_cloud_app_settings")
    fields = set(model.AdvancedUrlFilterAndCloudAppSettings({}).request_format())
    assert set(uc.KEYS) <= fields
    assert uc.KEYS == ("enableUcaasZoom", "enableOffice365", "enableUcaasWebex", "enableUcaasRingCentral", "enableUcaasLogMeIn", "enableUcaasTalkdesk")


@pytest.mark.parametrize("tier,on", [("strict", False), ("balanced", True), ("permissive", True), ("healthcare", True)])
def test_the_switches_are_pre_set_per_tier(tier, on):
    """ASVS V1.4.1 · CWE-1188: on for the tiers that follow Zscaler's guidance to let calls break out; off for Strict (inspects all TLS)."""
    rev = zb.review({"type": "zia_baseline", "tier": tier, "areas": ["ucaas"]})
    assert [s["value"] for s in rev["ucaas"]] == [on] * len(uc.KEYS) and all(s["default"] is on for s in rev["ucaas"])
    cat = zb.catalog()
    assert [s["key"] for s in cat["ucaas"]] == list(uc.KEYS) and cat["ucaas_sources"][0]["url"].startswith("https://")
    assert next(a for a in cat["areas"] if a["key"] == "ucaas")["default"] is False


@pytest.mark.parametrize("bad", [{"enableChatGptPrompt": True}, {"enableUcaasZoom": "yes"}, ["enableUcaasZoom"]])
def test_only_ucaas_switches_with_true_or_false_are_accepted(bad):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: any other setting, or a value that is not true or false, is refused before anything is read."""
    with pytest.raises(ao.OperationError):
        zb.normalize(dict(SPEC, ucaas=bad))


# ── Scope ────────────────────────────────────────────────────────────
def test_the_area_is_in_scope_with_zia_platform_only_and_never_by_default():
    """ASVS V4.1.3 · V1.4.1 · CWE-285 · CWE-1188: UCaaS one-click is a ZIA platform area, changed only when picked (settings are live once activated)."""
    assert "ucaas" in zb.areas_in_scope(PLATFORM_ONLY)[0] and "ucaas" not in zb.areas_in_scope(WEB_ONLY)[0]
    assert "ucaas" not in zb.DEFAULT_AREAS
    t = ucaas_tenant()
    p = plan(t, {"type": "zia_baseline", "tier": "balanced"})
    assert "ucaas" not in p["areas"] and "url_filtering.get_url_and_app_settings" not in t.reads


def test_picking_it_out_of_scope_is_refused_before_anything_is_read():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: an explicit pick of an area out of scope is refused before sign-in reads."""
    t = ucaas_tenant()
    with pytest.raises(ao.OperationError) as e:
        plan(t, SPEC, scope=WEB_ONLY)
    assert "UCaaS one-click" in str(e.value) and t.reads == []


# ── Preview, gates, write, read-back, Undo ───────────────────────────
def test_the_preview_shows_each_switch_and_writes_nothing():
    """ASVS V1.4.1 · V11.1.1 · CWE-841: one unit per switch, before and after; switches already on are no change; nothing is written."""
    t = ucaas_tenant({"enableUcaasZoom": True})
    p = plan(t, SPEC)
    units = {u["field"]: (u["before"], u["after"], u["status"]) for u in p["items"] if u["kind"] == "ucaas_field"}
    assert units["enableUcaasZoom"] == (True, True, "noop") and units["enableUcaasWebex"] == (False, True, "change")
    assert p["counts"]["change"] == 5 and t.writes == [] and p["ucaas_review"]
    assert any("break out without SSL inspection" in w for w in p["warnings"])


def test_it_is_never_written_without_the_typed_phrase():
    """ASVS V11.1.1 · CWE-841 · CWE-1188: switches have no disabled state, so even five changes need the typed phrase; without it nothing is written."""
    t = ucaas_tenant()
    p = plan(t, SPEC)
    assert p["confirm_phrase"] == "APPLY 6 CHANGES"
    res = _execute(t, SPEC, p, "")
    assert res["status"] == "refused" and t.writes == []


def test_apply_puts_the_whole_object_back_with_only_the_switches_changed_and_reads_it_back():
    """ASVS V11.1.1 · CWE-841 · CWE-664: the write re-reads the settings and sends every field back, only the switches changed; the read-back confirms each."""
    t = ucaas_tenant()
    res = apply(t, SPEC)
    assert res["status"] == "applied" and t.writes == [("url_filtering", "update_url_and_app_settings", None)]
    assert all(t.put_body[k] is True for k in uc.KEYS)
    assert t.put_body["enableChatGptPrompt"] is True and t.put_body["enableNewlyRegisteredDomains"] is True and t.put_body["considerEmbeddedSites"] is False
    assert res["verification"]["confirmed"] == res["verification"]["checked"] == len(uc.KEYS)


def test_undo_turns_back_only_the_switches_the_baseline_changed():
    """ASVS V11.1.1 · CWE-664: Undo puts each switch back while it still holds what the baseline set; one changed since is left alone."""
    t = ucaas_tenant({"enableUcaasZoom": True})
    res = apply(t, SPEC)
    assert res["inverse"]["steps"] == [{"op": "restore_ucaas", "fields": {k: False for k in uc.KEYS if k != "enableUcaasZoom"},
                                        "expect": {k: True for k in uc.KEYS if k != "enableUcaasZoom"}}]
    t.settings["enableUcaasWebex"] = False   # someone turned Webex off since
    u = plan(t, res["inverse"])
    by = {x["field"]: x["status"] for x in u["items"]}
    assert by["enableUcaasWebex"] == "noop" and by["enableUcaasRingCentral"] == "change" and u["confirm_phrase"]
    done = apply(t, res["inverse"], prepared=u)
    assert done["status"] == "applied" and t.settings["enableUcaasZoom"] is True and t.settings["enableUcaasRingCentral"] is False


def test_a_switch_changed_after_the_preview_is_not_written():
    """ASVS V11.1.1 · CWE-367: changed before the apply, the plan no longer matches the preview and nothing is written."""
    t = ucaas_tenant()
    p = plan(t, SPEC)
    t.settings["enableUcaasZoom"] = True
    res = _execute(t, SPEC, p, p["confirm_phrase"])
    assert res["status"] == "plan_changed" and t.writes == []


def test_a_switch_changed_in_the_last_moment_is_left_as_it_is():
    """ASVS V11.1.1 · CWE-367: the write re-reads right before the PUT; a switch someone changed after the re-plan is a conflict and is not sent."""
    t = ucaas_tenant()
    p = plan(t, SPEC)
    get = t.zia.url_filtering.get_url_and_app_settings
    calls = []

    def racing():
        calls.append(1)
        if len(calls) == 2:                     # the handler's own re-read, after the engine's re-plan
            t.settings["enableUcaasWebex"] = True
        return get()
    t.zia.url_filtering.get_url_and_app_settings = racing
    res = _execute(t, SPEC, p, p["confirm_phrase"])
    webex = next(u for u in res["items"] if u.get("field") == "enableUcaasWebex")
    assert webex["status"] == "conflict" and t.put_body["enableUcaasWebex"] is True and t.put_body["enableUcaasZoom"] is True


@pytest.mark.parametrize("kw,why", [({"partial": True}, "only part of the settings"), ({"fail": True}, "could not be read")])
def test_settings_that_cannot_be_read_whole_are_never_written(kw, why):
    """ASVS V7.4.1 · CWE-664 · CWE-252: a partial or failed read plans nothing there (a partial PUT could reset the other settings)."""
    t = ucaas_tenant(**kw)
    p = plan(t, SPEC)
    assert p["counts"]["change"] == 0 and any("UCaaS one-click" in w for w in p["warnings"])
    assert any(why in (u.get("reason") or "") for u in p["items"])


@pytest.mark.parametrize("step", [{"op": "restore_ucaas", "fields": {"enableChatGptPrompt": False}},
                                  {"op": "restore_ucaas", "fields": {"id": 1}}])
def test_an_undo_step_naming_another_setting_is_refused(step):
    """ASVS V5.1.3 · V4.1.1 · CWE-20 · CWE-639: an Undo from the page may put back only UCaaS switches."""
    with pytest.raises(ao.OperationError):
        zb.normalize({"type": "zia_baseline", "action": "revert", "steps": [step]})


def test_the_form_sends_the_switches_and_marks_what_it_leaves_uninspected():
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2: the Bulk changes form shows the switches as labelled checkboxes in a named group and sends them."""
    js = open(zb.__file__.replace("ops_zia_baseline.py", "static/ops_zia_baseline.js"), encoding="utf-8").read()
    assert "data-zb-ucaas" in js and "ucaas: z.ucaas || {}" in js and 'role="group" aria-labelledby="zbUcaasH"' in js


# ── The Path analyzer and Zscaler's predefined one-click rules ───────
ONE_CLICK = {"id": 90, "name": "UCaaS One Click Rule", "order": 2, "rank": 7, "state": "ENABLED", "predefined": True, "action": "ALLOW",
             "appServiceGroups": [{"id": 2, "name": "ZOOM"}, {"id": 3, "name": "WEBEX"}]}


@pytest.mark.parametrize("settings,state", [
    ({"enableUcaasZoom": True, "enableUcaasWebex": False}, "match"),
    ({"enableUcaasZoom": False, "enableUcaasWebex": False}, "no_match"),
    ({"enableUcaasZoom": False}, None),            # Webex not read: not settled
    (None, None),                                  # the settings were not read
])
def test_a_predefined_one_click_rule_follows_its_switches(settings, state):
    """ASVS V1.1.2 · CWE-670: a predefined one-click rule applies while a switch it names is on; all off, it never matches; not read, nothing is assumed."""
    c = uc.criterion(ONE_CLICK, settings)
    assert (c or {}).get("state") == state
    assert uc.criterion(dict(ONE_CLICK, predefined=False), {"enableUcaasZoom": True}) is None
    assert uc.criterion(dict(ONE_CLICK, name="Allow web"), {"enableUcaasZoom": True}) is None


def test_the_office_365_one_click_rule_follows_the_microsoft_365_switch():
    """ASVS V1.1.2 · CWE-670: Teams comes with Microsoft 365 one-click (enableOffice365)."""
    rule = {"name": "Office 365 One Click Rule", "predefined": True, "appServiceGroups": [{"name": "OFFICE365"}]}
    assert uc.oneclick_switches(rule) == ["enableOffice365"]
    assert uc.criterion(rule, {"enableOffice365": False})["state"] == "no_match"


def _tenant(settings, rules):
    routes = copy.deepcopy(dict(ROUTES, **MODULE_ROUTES))
    routes["/zia/firewallFilteringRules"] = rules
    if settings is not None:
        routes["/zia/advancedUrlFilterAndCloudAppSettings"] = settings
    return PathTenant(routes)


def test_the_path_analyzer_reads_the_switches_with_the_firewall_and_drops_a_switched_off_one_click_rule():
    """ASVS V1.1.2 · CWE-670 · WSTG-BUSL-01: with every switch off, the predefined UCaaS rule is no match; the firewall step names the switches."""
    block_first = [{"id": 1, "name": "Block QUIC", "order": 1, "state": "ENABLED", "action": "BLOCK_DROP", "nwServices": [{"id": 10, "name": "QUIC"}]},
                   dict(ONE_CLICK, order=0)] + [r for r in MODULE_ROUTES["/zia/firewallFilteringRules"] if r["id"] != 1]
    off = {k: False for k in uc.KEYS}
    t = _tenant(off, block_first)
    fw = mod(run("chat.openai.com", "udp", 443, tenant=t), "firewall")
    assert "/zia/advancedUrlFilterAndCloudAppSettings" in t.paths
    assert fw["rule"]["name"] == "Block QUIC" and fw["certainty"] == "definite"
    assert any(n.startswith("UCaaS one-click (URL and Cloud App Control advanced settings): Zoom off") for n in fw["notes"])
    on = dict(off, enableUcaasZoom=True)
    fw = mod(run("chat.openai.com", "udp", 443, tenant=_tenant(on, block_first)), "firewall")
    could = next(c for c in fw["could_override"] if c["name"] == "UCaaS One Click Rule")
    assert {"name": "One-click setting", "state": "match"}.items() <= next(x for x in could["criteria"] if x["name"] == "One-click setting").items()


def test_without_the_settings_the_firewall_answer_is_unchanged_and_says_nothing_missing():
    """ASVS V7.4.1 · CWE-252: a tenant without the settings (an older API, a 404) reads the firewall as before; no 'not read' note for them."""
    t = _tenant(None, MODULE_ROUTES["/zia/firewallFilteringRules"])
    fw = mod(run("chat.openai.com", "udp", 443, tenant=t), "firewall")
    assert fw["rule"]["name"] == "Block QUIC" and not any("advanced settings" in n for n in fw["notes"])


def test_the_settings_are_read_only_with_zia_platform():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: the switches are part of the Cloud Firewall read: in scope with ZIA platform only."""
    assert ("url_app_settings", "/zia/advancedUrlFilterAndCloudAppSettings", "URL and Cloud App Control advanced settings", "object") in zpm.READS["firewall"]
    import scope_permissions
    assert "/zia/advancedUrlFilterAndCloudAppSettings" in scope_permissions.SCOPE_PERMISSIONS["zia_extras"]["endpoints_used"]
