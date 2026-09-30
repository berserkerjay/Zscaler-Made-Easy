"""Regression: every shipped pack deploys the way ZBP Enterprise finally did
on a real tenant ("this finally worked; every pack needs to deploy like
that"), one channel at a time, against a fake tenant that answers the way
that tenant did:

- its SaaS tenant list holds only SharePoint ("SMOES"); the Exchange email
  tenant (also "SMOES", another id) shows up only on an existing Email DLP
  rule, DLP_Rule_1;
- it refuses a SaaS rule at rank 0 ("Rule rank is higher than the admin
  rank", 403 RBA_LIMITED) and accepts rank 7;
- it refuses an Email DLP rule without an email tenant ("One or more Email
  tenants is required", 400).

For every pack: each channel deploys in full (as many rules as the pack
has Web DLP rules), no rule fails, and the only refused requests are the
first SaaS rank-0 attempt of the run. A burst of refused writes is what
got the API client blocked (Resource Access Blocked)."""
from __future__ import annotations

import pytest

import pack_deploy as pd
from dlp_importer import discover_packs
from test_pack_channels import FakeCasbRules, FakeChannelRules, add_control_services, make_client, tenant

SHAREPOINT_ID, EXCHANGE_ID = 177648211, 171656574
DLP_RULE_1 = {"id": 4242, "name": "DLP_Rule_1", "order": 1, "action": "ALLOW", "state": "ENABLED",
              "email_tenants": [{"id": EXCHANGE_ID, "name": "SMOES"}]}
CHANNELS = ("web", "endpoint", "saas", "email")      # the order the one-channel note gives


class StrictCasbRules(FakeCasbRules):
    """SaaS rules: rank 0 is above this API client's admin rank."""
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.refused = []

    def add_rule(self, **kw):
        if int(kw.get("rank", 7) or 0) == 0:
            self.refused.append(("saas rank 0", kw.get("name")))
            return None, None, {"status": 403, "code": "RBA_LIMITED", "message": "Rule rank is higher than the admin rank."}
        return super().add_rule(**kw)


class StrictEmailRules(FakeChannelRules):
    """Email DLP rules: at least one email tenant is required."""
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.refused = []

    def add_rule(self, **kw):
        if not kw.get("email_tenants"):
            self.refused.append(("email without tenant", kw.get("name")))
            return None, None, {"status": 400, "message": "One or more Email tenants is required"}
        return super().add_rule(**kw)


def the_tenant():
    client = make_client(casb_tenants=[tenant("SMOES", "SHAREPOINT", SHAREPOINT_ID)])
    client.zia.casb_dlp_rules = StrictCasbRules(start=8500)
    client.zia.outbound_email_dlp_rules = StrictEmailRules([DLP_RULE_1], start=8800)
    add_control_services(client)   # the cloud application catalogue (packs name app classes such as AI_ML)
    return client


PACKS = [p for p in discover_packs() if p.get("source") == "built-in"]


def test_every_pack_has_as_many_rules_on_each_channel_as_on_web():
    assert len(PACKS) >= 6
    for p in PACKS:
        ch = p["channels"]
        assert all(ch.get(c, 0) == ch.get("web", 0) > 0 for c in CHANNELS), (p["id"], ch)


@pytest.mark.parametrize("pack", PACKS, ids=[p["id"] for p in PACKS])
def test_every_pack_deploys_one_channel_at_a_time_like_zbp_enterprise(pack):
    client = the_tenant()
    want = pack["channels"]["web"]
    created = {}
    for ch in CHANNELS:
        rep = pd.preflight(client, [pack], writes_enabled=True, channel_targets={pack["id"]: [ch]})
        rules = [i for i in rep["items"] if i["kind"] == "policy" and (i.get("detail") or {}).get("channel", "web") == ch]
        blocked = [(i["name"], i["reason"]) for i in rules if i["status"] not in (pd.CREATE, pd.REUSE)]
        assert not blocked, (pack["id"], ch, blocked[:3])
        res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, channel_targets={pack["id"]: [ch]})
        failed = [(r["name"], r.get("error") or r.get("reason")) for r in res["results"] if r.get("status") == "failed"]
        assert not failed, (pack["id"], ch, failed[:3])
        created[ch] = sum(1 for r in res["results"] if r["kind"] == "policy" and r.get("status") == "created"
                          and (r.get("channel") or "web") == ch)
    assert created == {c: want for c in CHANNELS}, (pack["id"], created)
    sent_email = client.zia.outbound_email_dlp_rules.added
    assert sent_email and all([t.get("id") if isinstance(t, dict) else t for t in r["email_tenants"]] == [EXCHANGE_ID] for r in sent_email), \
        "every Email rule is scoped to the Exchange email tenant, never the SharePoint tenant of the same name"
    assert client.zia.outbound_email_dlp_rules.refused == [], "no Email request ZIA would refuse"
    assert len(client.zia.casb_dlp_rules.refused) == 1, ("one refused rank-0 attempt per run, not one per SaaS rule",
                                                          client.zia.casb_dlp_rules.refused)
    assert all(int(r.get("rank", 0)) == 7 for r in client.zia.casb_dlp_rules.added)
