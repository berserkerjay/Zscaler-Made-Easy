"""
Endpoint DLP extras: application groups (created from Zscaler catalogue
IDs), sub-rules created under their parent, transfer methods, and the
shipped ZBP Endpoint DLP baseline built from the zbp-automation module.
"""
from __future__ import annotations

import json

import pytest

import pack_channels as pc
import pack_deploy as pd
import pack_terraform as pt
from test_baselines import BASELINE_META  # noqa: F401
from test_pack_channels import FakeChannelRules, make_client  # noqa: F401
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _dict, _engine, _policy, write_pack, items_by  # noqa: F401


class FakeRaw:
    """Stands in for pack_channels.raw_request: endpoint application groups
    and sub-rules, keyed by path."""
    def __init__(self, groups=None, fail_groups=False):
        self.groups = list(groups or [])
        self.subs = {}      # parent id -> [sub dicts]
        self.calls = []
        self.fail_groups = fail_groups
        self.client = None    # when set, created sub-rules appear on the parent rule object, as the API does
        self._next = 7000

    def __call__(self, zia, method, path, body=None):
        self.calls.append((method, path, body))
        if path == pc.APP_GROUPS_PATH:
            if self.fail_groups:
                return None, "403 Endpoint DLP not licensed"
            if method == "GET":
                return list(self.groups), None
            self._next += 1
            g = dict(body, id=self._next)
            self.groups.append(g)
            return g, None
        if path.startswith(pc.APP_GROUPS_PATH + "/") and method == "PUT":
            gid = int(path.rsplit("/", 1)[1])
            for i, g in enumerate(self.groups):
                if g["id"] == gid:
                    self.groups[i] = dict(body, id=gid)
                    return self.groups[i], None
            return None, "not found"
        if "/subRule" in path:
            parent = int(path.split("/")[2])
            if method == "POST":
                self._next += 1
                sr = dict(body, id=self._next, parentRule=parent)
                self.subs.setdefault(parent, []).append(sr)
                if self.client is not None:
                    for r in self.client.zia.endpoint_dlp_rules.items:
                        if getattr(r, "id", None) == parent:
                            subs = list(getattr(r, "sub_rules", None) or [])
                            subs.append(Obj(**{k: v for k, v in sr.items() if k != "parentRule"}, parent_rule=parent))
                            r.sub_rules = subs
                return sr, None
            if method == "PUT":
                sid = int(path.rsplit("/", 1)[1])
                return dict(body, id=sid), None
        return None, f"unexpected {method} {path}"


@pytest.fixture
def raw(monkeypatch):
    fake = FakeRaw()
    monkeypatch.setattr(pc, "raw_request", fake)
    return fake


def endpoint_pack(tmp_path, meta=None):
    pack = write_pack(
        tmp_path, "ep",
        dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict)")],
        policies=[
            {"name": "EP-USB", "channel": "endpoint", "action": "BLOCK", "state": "DISABLED", "severity": "RULE_SEVERITY_INFO",
             "engines": ["Alpha Engine"], "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER", "rank": 7,
             "sub_rules": [
                 {"name": "EP-USB-High", "action": "BLOCK", "engines": ["Alpha Engine"], "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER", "severity": "RULE_SEVERITY_INFO"},
                 {"name": "EP-USB-Low", "action": "ALLOW", "engines": ["Alpha Engine"], "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER", "severity": "RULE_SEVERITY_INFO"},
             ]},
            {"name": "EP-GenAI", "channel": "endpoint", "action": "BLOCK", "state": "DISABLED", "severity": "RULE_SEVERITY_INFO",
             "engines": ["Alpha Engine"], "data_transfer_method": "APPLICATION_FILE_ACCESS", "rank": 7,
             "endpoint_application_groups": ["GenAI Apps"]},
        ],
        meta=meta or {"name": "EP", "confidence_tweaks": []},
    )
    json.dump([{"name": "GenAI Apps", "description": "Desktop AI apps", "resources": ["500000603", "500000605"],
                "applications": [{"applicationName": "ChatGPT", "osType": "WINDOWS_OS", "zappId": "500000603"}]}],
              open(f"{pack['dir']}/configs/endpoint_application_groups.json", "w"))
    return pack


def test_expand_sub_rules_and_validation():
    flat = pc.expand_sub_rules([{"name": "P", "channel": "endpoint", "state": "DISABLED", "sub_rules": [{"name": "S1", "action": "BLOCK"}, {"name": "S2", "action": "ALLOW"}]}])
    assert [p["name"] for p in flat] == ["P", "S1", "S2"]
    assert flat[1]["parent_rule"] == "P" and flat[1]["order"] == 1 and flat[2]["order"] == 2 and flat[1]["state"] == "DISABLED"
    assert "sub_rules" not in flat[0]
    assert "data_transfer_method" in pc.validate({"name": "x", "channel": "endpoint", "data_transfer_method": "TELEPATHY", "engines": ["e"]})
    assert "endpoint channel only" in pc.validate({"name": "x", "channel": "web", "engines": ["e"], "sub_rules": [{"name": "s"}]})


def test_endpoint_pack_plans_and_applies_groups_and_sub_rules(tmp_path, raw):
    client = make_client()
    pack = endpoint_pack(tmp_path)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert rep["status"] == "ready", rep["blockers"] + rep["warnings"]
    grp = items_by(rep, "app_group")["GenAI Apps"]
    assert grp["status"] == pd.CREATE and grp["detail"]["resources"] == ["500000603", "500000605"]
    pol = items_by(rep, "policy")
    assert {n: p["status"] for n, p in pol.items()} == {"EP-USB": pd.CREATE, "EP-USB-High": pd.CREATE, "EP-USB-Low": pd.CREATE, "EP-GenAI": pd.CREATE}
    assert "policy:EP-USB" in pol["EP-USB-High"]["depends_on"] and "sub-rule of 'EP-USB'" in pol["EP-USB-High"]["reason"]
    assert "app_group:GenAI Apps" in pol["EP-GenAI"]["depends_on"]
    assert pol["EP-GenAI"]["detail"]["endpoint_application_groups"] == ["GenAI Apps"]

    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied", res
    assert res["summary"] == {"created": 7}
    # Group created from catalogue IDs, then the GenAI rule references its new id.
    posted = [c for c in raw.calls if c[0] == "POST" and c[1] == pc.APP_GROUPS_PATH]
    assert posted and posted[0][2]["resources"] == ["500000603", "500000605"]
    gid = raw.groups[-1]["id"]
    ep = {r["name"]: r for r in client.zia.endpoint_dlp_rules.added}
    assert ep["EP-GenAI"]["end_point_application_groups"] == [{"id": gid}]
    assert ep["EP-USB"]["data_transfer_method"] == "REMOVABLE_DRIVE_TRANSFER" and ep["EP-USB"]["state"] == "DISABLED"
    # Sub-rules were posted under the parent's id, in order.
    parent_id = next(r["id"] for r in res["results"] if r["name"] == "EP-USB")
    subs = raw.subs[parent_id]
    assert [s["name"] for s in subs] == ["EP-USB-High", "EP-USB-Low"] and [s["order"] for s in subs] == [1, 2]
    assert subs[0]["action"] == "BLOCK" and subs[0]["dlp_engines"]
    assert all("parent_rule" not in s for s in subs)
    created = {r["name"]: r for r in res["results"] if r["status"] == "created"}
    assert created["EP-USB-High"]["parent_id"] == parent_id


def test_existing_group_and_sub_rules_are_matched_by_name(tmp_path, raw):
    raw.groups.append({"id": 42, "name": "GenAI Apps", "description": "", "resources": ["500000603", "500000605"]})
    parent = Obj(id=8001, name="EP-USB", order=1, rank=7, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 1}],
                 data_transfer_method="REMOVABLE_DRIVE_TRANSFER", severity="RULE_SEVERITY_INFO", description="",
                 sub_rules=[Obj(id=8002, name="EP-USB-High", order=1, rank=7, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 1}],
                                data_transfer_method="REMOVABLE_DRIVE_TRANSFER", severity="RULE_SEVERITY_INFO", description="")])
    client = make_client(endpoint_rules=[parent])
    pack = endpoint_pack(tmp_path, meta=dict(BASELINE_META, name="EP Baseline"))
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert items_by(rep, "app_group")["GenAI Apps"]["status"] == pd.REUSE
    pol = items_by(rep, "policy")
    assert pol["EP-USB"]["status"] in (pd.REUSE, pd.REUSE_DIFFERS) and pol["EP-USB"]["position"] == "enforcing"
    assert pol["EP-USB-High"]["status"] in (pd.REUSE, pd.REUSE_DIFFERS) and pol["EP-USB-High"]["tenant"]["parent_id"] == 8001
    assert pol["EP-USB-Low"]["status"] == pd.CREATE and pol["EP-GenAI"]["status"] == pd.CREATE
    assert rep["tenant_mode"]["mode"] == "brownfield"
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["summary"]["created"] == 4   # dictionary, engine, EP-USB-Low under the existing parent, EP-GenAI with the existing group
    assert raw.subs[8001][0]["name"] == "EP-USB-Low"
    assert {r["name"]: r for r in client.zia.endpoint_dlp_rules.added}["EP-GenAI"]["end_point_application_groups"] == [{"id": 42}]


def test_unlicensed_endpoint_groups_block_only_dependent_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(pc, "raw_request", FakeRaw(fail_groups=True))
    client = make_client()
    rep = pd.preflight(client, [endpoint_pack(tmp_path)], writes_enabled=True)
    assert items_by(rep, "app_group")["GenAI Apps"]["status"] == pd.BLOCKED_DEPENDENCY
    pol = items_by(rep, "policy")
    assert pol["EP-GenAI"]["status"] == pd.BLOCKED_DEPENDENCY and pol["EP-USB"]["status"] == pd.CREATE


def test_terraform_emits_groups_and_sub_rules(tmp_path):
    pack = endpoint_pack(tmp_path, meta=dict(BASELINE_META, name="EP Baseline"))
    files = pt.generate(pack)
    r = files["rules.tf"]
    assert 'resource "zia_endpoint_dlp_application_group" "genai_apps"' in r and 'resources                    = ["500000603", "500000605"]' in r
    assert 'resource "zia_endpoint_dlp_sub_rules" "ep_usb_high"' in r
    assert 'parent_rule                  = zia_endpoint_dlp_rules.ep_usb.rule_id' in r
    assert 'group_id = [tostring(zia_endpoint_dlp_application_group.genai_apps.group_id)]' in r
    assert "ignore_changes = [end_point_application_groups]" in r
    assert 'data_transfer_method         = "APPLICATION_FILE_ACCESS"' in r


def test_no_shipped_pack_is_endpoint_only():
    """The PCI-only endpoint baseline is gone: every shipped pack mirrors
    its inline rules onto Endpoint DLP instead."""
    from dlp_importer import discover_packs
    ids = {p["id"] for p in discover_packs()}
    assert "zbp_endpoint_dlp_baseline" not in ids
    for p in discover_packs():
        pols = json.load(open(f"{p['dir']}/configs/dlp_policies.json", encoding="utf-8"))
        chans = {pc.channel_of(x) for x in pc.expand_sub_rules(pols)}
        assert "endpoint" in chans and "web" in chans, p["id"]
