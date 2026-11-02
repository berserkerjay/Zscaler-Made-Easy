"""A saved configuration template (config_backup) as a scheduled sync job's
source (sync_jobs.register_template_source): the server registers the
provider, a job may name a template, and the template is read through a
read-only stand-in client that has no write call at all. Offline: the
template is made from a fake tenant (tests/config_fake.py); state files in
tmp_path."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import config_backup as cb  # noqa: E402
import sync_jobs  # noqa: E402
from config_fake import Client, Tenant  # noqa: E402

ALL = ao.scope_for(["dlp", "zia_extras", "zpa"], {"web_dlp": "zscaler"})


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    return tmp_path


def _saved_template() -> dict:
    t = Tenant({
        "zia.rule_labels": [{"id": 1, "name": "Team A"}],
        "zia.url_categories": [{"id": "CUSTOM_01", "configured_name": "Partners", "super_category": "USER_DEFINED", "urls": ["a.example"],
                                "custom_category": True}],
        "zia.url_filtering_rules": [{"id": 10, "name": "Block partners", "order": 1, "state": "ENABLED", "action": "BLOCK",
                                     "url_categories": ["CUSTOM_01", "GAMBLING"], "labels": [{"id": 1, "name": "Team A"}]}],
        "zia.firewall_rules": [{"id": 20, "name": "Block SSH out", "order": 1, "state": "ENABLED", "action": "BLOCK_DROP"}],
    })
    got = cb.capture(Client(t), ["zia"], ALL)
    doc = cb.build_doc(got["types"], {"tenant_label": "acme", "products": ["zia"]})
    tpl = cb.make_template(doc, [{"type": "zia.url_filtering_rules", "name": "Block partners"},
                                 {"type": "zia.firewall_rules", "name": "Block SSH out"}], name="Starter")
    return cb.save_template(tpl)


def test_the_server_registers_templates_as_a_sync_source():
    """ASVS V1.14.1 · CWE-1188: with the app loaded, saved templates are offered as a sync source, with the Scope page keys their products need."""
    import dlp_api_server  # noqa: F401  (registers the provider)
    meta = _saved_template()
    src = sync_jobs.sources()
    assert src["templates_available"] is True
    assert {"id": meta["id"], "name": "Starter"} in src["templates"]
    assert cb.template_sources() == [{"id": meta["id"], "name": "Starter", "scopes": ["zia_extras"]}]


def test_a_template_reads_as_rules_with_names_and_no_prefix():
    """ASVS V5.1.3 · CWE-20: the sync's source read gets the template's rules by name (its {{prefix}} left empty), as rule_csv rows."""
    meta = _saved_template()
    client = cb.template_client(meta["id"])
    snap = sync_jobs.source_snapshot(client, ["zia_url_filtering", "zia_firewall"], {}, lambda m: None)
    assert not snap["errors"], snap["errors"]
    assert [r["name"] for r in snap["policies"]["url_filtering"]["rows"]] == ["Block partners"]
    assert [r["name"] for r in snap["policies"]["firewall"]["rows"]] == ["Block SSH out"]


def test_the_template_client_cannot_write():
    """ASVS V1.4.1 · CWE-269 · CWE-862: the stand-in client answers list calls only; an add, update or delete does not exist on it."""
    meta = _saved_template()
    zia = cb.template_client(meta["id"]).zia
    rows, resp, err = zia.url_filtering.list_rules()
    assert [r["name"] for r in rows] == ["Block partners"] and resp is None and err is None
    for svc, method in (("url_filtering", "add_rule"), ("url_filtering", "update_rule"), ("url_filtering", "delete_rule"),
                        ("cloud_firewall_rules", "add_rule"), ("cloud_firewall_rules", "delete_rule")):
        assert not hasattr(getattr(zia, svc), method), (svc, method)
    assert not hasattr(zia, "activate") and not hasattr(cb.template_client(meta["id"]), "zpa_write")
