"""Continuous evaluation, phase 4: articles are mapped to checks, packs
and channels, mapped ones become proposals once, approvals land in the
shipped checks_config.json, and stale sources are flagged."""
from __future__ import annotations

import json
import time

import guidance as g
import proposals as pr
import saas_matrix as sm


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_GUIDANCE_STATE", str(tmp_path / "guidance_state.json"))
    monkeypatch.setenv("DLP_CHECK_CHECKS_CONFIG", str(tmp_path / "checks_config.json"))
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))


def test_articles_map_to_checks_packs_and_channels():
    m = g.map_entry({"title": "Configuring Outbound Email DLP with Proofpoint", "url": "https://help.zscaler.com/zia/email-dlp-proofpoint"})
    assert m and "email_dlp" in m["topics"] and "MC.4" in m["checks"] and m["channels"] == ["email"] and m["kind"] == "update_check"
    m = g.map_entry({"title": "SaaS Security API now supports Zendesk tenants", "url": "https://help.zscaler.com/zia/saas-zendesk"})
    assert m and m["kind"] == "extend_coverage" and "saas" in m["channels"] and "MC.3" in m["checks"]
    m = g.map_entry({"title": "Best practices for Client Connector posture with CrowdStrike", "url": "https://www.crowdstrike.com/partners/zscaler/"})
    assert m and "client_connector" in m["topics"] and "1.1" in m["checks"] and "ZCC.9" in m["checks"] and "B.12" in m["checks"]
    m = g.map_entry({"title": "Protecting PHI on generative AI destinations", "url": "https://www.zscaler.com/blogs/phi-genai"})
    assert m and set(m["packs"]) == {"healthcare_phi_baseline", "zbp_source_code_baseline"} and "AI.7" in m["checks"]
    assert g.map_entry({"title": "Company picnic photos", "url": "https://www.zscaler.com/blogs/picnic"}) is None
    assert g.resolve_checks(["ZID.*"]) == ["ZID.1", "ZID.2", "ZID.3", "ZID.4", "ZID.5"]
    assert "ZID.1" in g.resolve_checks(["section:Directory"]) and g.resolve_checks(["12.4"]) == ["12.4"]


def test_first_run_baselines_and_later_runs_raise_each_article_once(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    now = time.time()
    old = {"url": "https://help.zscaler.com/zia/old-email-dlp", "title": "About Email DLP", "first_seen": now - 40 * 86400, "source_name": "Zscaler Help Portal", "tier": "official", "credibility": 100}
    new = {"url": "https://help.proofpoint.com/release-notes/2026-09", "title": "Proofpoint release notes: Email DLP API scope change", "first_seen": now - 3600,
           "source_name": "Proofpoint", "tier": "authoritative", "credibility": 80}
    junk = {"url": "https://www.zscaler.com/blogs/picnic", "title": "Company picnic", "first_seen": now - 3600, "source_name": "Zscaler Blogs"}
    r = g.evaluate([old, new, junk], now=now)
    assert r["first_run"] and r["baselined"] == 1 and r["no_action"] == 1 and len(r["raised"]) == 1
    q = pr.list_queue(g.APP_TENANT)
    assert len(q) == 1 and q[0]["kind"] == "update_check" and q[0]["applies_via"] == "guidance"
    assert q[0]["change"]["article"] == new["url"] and "MC.4" in q[0]["change"]["checks"] and q[0]["evidence"]["source"] == "Proofpoint"
    # The same library on the next run raises nothing new; a fresh article does.
    r2 = g.evaluate([old, new, junk], now=now + 60)
    assert not r2["first_run"] and r2["raised"] == [] and r2["no_action"] == 0 and r2["baselined"] == 0
    newer = {"url": "https://help.zscaler.com/zia/nss-dlp-fields", "title": "NSS feed: new DLP fields", "first_seen": now + 30, "source_name": "Zscaler Help Portal"}
    r3 = g.evaluate([old, new, junk, newer], now=now + 120)
    assert len(r3["raised"]) == 1 and "logging" in r3["raised"][0]["topics"] or r3["raised"][0]["checks"][0] == "12.8"
    assert len(pr.list_queue(g.APP_TENANT)) == 2
    state = g.load_state()
    assert state["seen"][junk["url"]]["action"] == "none" and state["seen"][old["url"]]["action"] == "baseline"


def test_approval_records_the_reference_in_checks_config(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    now = time.time()
    art = {"url": "https://help.zscaler.com/zia/workflow-automation-itsm", "title": "Workflow Automation: ServiceNow tickets", "first_seen": now, "source_name": "Zscaler Help Portal"}
    g.evaluate([art], now=now)
    p = pr.list_queue(g.APP_TENANT)[0]
    out = g.record_approval(p, by="jane")
    assert "12.7" in out["checks"] and "12.4" in out["checks"]
    cfg = json.load(open(tmp_path / "checks_config.json"))
    assert cfg["checks"]["12.7"]["references"][0]["url"] == art["url"] and cfg["checks"]["12.7"]["references"][0]["by"] == "jane"
    assert g.references_for("12.7")[0]["url"] == art["url"] and g.config_summary()["references"] >= 10
    # Recording twice does not duplicate.
    g.record_approval(p, by="jane")
    assert len(g.references_for("12.7")) == 1


def test_stale_sources_are_flagged_not_silently_kept(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    now = time.time()
    g.update_source_health([{"source_id": "help_zscaler", "reached": True, "matched_count": 40}, {"source_id": "proofpoint_docs", "reached": False, "error": "HTTP 403"}], now=now - 8 * 86400)
    g.update_source_health([{"source_id": "servicenow_docs", "reached": False, "error": "timeout"}], now=now - 3600)
    g.update_source_health([{"source_id": "help_zscaler", "reached": True, "matched_count": 41}], now=now)
    h = {s["id"]: s for s in g.source_health(now=now)}
    assert not h["help_zscaler"]["stale"] and h["help_zscaler"]["last_reached_at"]
    assert h["proofpoint_docs"]["stale"] and h["proofpoint_docs"]["last_error"] == "HTTP 403" and h["proofpoint_docs"]["affects"] == ["email_dlp", "workflow_automation"]
    assert h["sentinelone_docs"]["watched"] is False and h["sentinelone_docs"]["note"] and not h["sentinelone_docs"]["stale"]
    assert h["okta_help"]["affects"] == ["identity"]
    assert not h["servicenow_docs"]["stale"] and h["servicenow_docs"]["checked"], "one failed attempt an hour ago is not stale yet"
    assert not h["ping_docs"]["checked"] and not h["ping_docs"]["stale"], "never tried: not yet checked, not stale"


# ── SaaS capability matrix ───────────────────────────────────────────
PAGE = """<html><body><h1>Supported capabilities</h1>
<table><tr><th>SaaS Application</th><th>Type</th><th>DLP</th><th>Malware</th><th>App Governance</th><th>SSPM</th></tr>
<tr><td>Microsoft OneDrive</td><td>File</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Box</td><td>File</td><td>Yes</td><td>Yes</td><td>Yes</td><td>No</td></tr>
<tr><td>Gmail</td><td>Email</td><td>Yes</td><td>Yes</td><td>No</td><td>No</td></tr>
<tr><td>Notion</td><td>Collaboration</td><td>Yes</td><td>No</td><td>No</td><td>No</td></tr>
<tr><td>Salesforce</td><td>CRM</td><td>✓</td><td>✓</td><td></td><td>✓</td></tr>
<tr><td>ServiceNow</td><td>ITSM</td><td>Yes</td><td>Yes</td><td></td><td></td></tr>
<tr><td>GitHub</td><td>Repository</td><td>Yes</td><td>Yes</td><td></td><td>Yes</td></tr>
<tr><td>Amazon S3</td><td>Storage</td><td>Yes</td><td>Yes</td><td></td><td></td></tr>
<tr><td>ChatGPT Enterprise</td><td>Generative AI</td><td>Yes</td><td></td><td></td><td></td></tr>
</table></body></html>"""


def test_matrix_seed_parse_and_refresh(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_SAAS_MATRIX", str(tmp_path / "saas_apps.local.json"))
    seed = sm.load()
    assert seed["path"].endswith("saas_apps.json") and len(seed["applications"]) >= 30 and seed["types"]["OFLCASB_DLP_EMAIL"] == "Email"
    apps = sm.parse_matrix(PAGE)
    by = {a["name"]: a for a in apps}
    assert by["Box"]["type"] == "OFLCASB_DLP_FILE" and by["Box"]["capabilities"] == ["DLP", "Malware", "App Governance"]
    assert by["Salesforce"]["capabilities"] == ["DLP", "Malware", "SSPM"] and by["Notion"]["type"] == "OFLCASB_DLP_COLLAB"
    assert by["ChatGPT Enterprise"]["type"] == "OFLCASB_DLP_GENAI"
    # A refresh that parses fewer applications than the seed keeps the seed.
    # help.zscaler.com pages are an empty shell: the table is read from the
    # help center's article API (fetch-data), never from the page itself.
    asked = []
    art = json.dumps({"data": {"info": {"status": 200}, "body": {"title": "Capabilities", "content": PAGE}}}).encode()
    r = sm.refresh(lambda url: asked.append(url) or ((art, 200, "") if "/zapi/fetch-data?" in url else (b"<html>shell</html>", 200, "")),
                   pages=["https://help.zscaler.com/x"])
    assert r["ok"] and r["applications"] == 9 and "Notion" in r["new_since_seed"]
    assert len(asked) == 1 and "/zapi/fetch-data?url_alias=/x&" in asked[0]
    # The shell (or any answer that is not an article) is not parsed.
    r = sm.refresh(lambda url: (PAGE.encode(), 200, ""), pages=["https://help.zscaler.com/x"])
    assert not r["ok"] and "not an article" in r["errors"][0]
    # Another host is read as the page itself.
    r = sm.refresh(lambda url: (PAGE.encode(), 200, ""), pages=["https://example.com/x"])
    assert r["ok"] and r["applications"] == 9
    assert sm.load()["refreshed_from_pages"] and any(a["name"] == "Notion" for a in sm.load()["applications"])
    r = sm.refresh(lambda url: (None, 403, "forbidden"), pages=["https://help.zscaler.com/x"])
    assert not r["ok"] and "forbidden" in r["errors"][0]


def test_tenant_findings_name_reauthorisation_limits_and_candidates():
    tenants = [{"id": 1, "name": "Acme OneDrive", "app": "ONEDRIVE", "status": "ACTIVE", "type": "OFLCASB_DLP_FILE"},
               {"id": 2, "name": "Acme Box", "app": "BOX", "status": "AUTH_EXPIRED", "type": "OFLCASB_DLP_FILE"}] + \
              [{"id": 100 + i, "name": f"Slack {i}", "app": "SLACK", "status": "ACTIVE", "type": "OFLCASB_DLP_COLLAB"} for i in range(16)]
    f = sm.tenant_findings(tenants, pack_channels=("saas", "email"))
    assert f["tenants"] == 18 and f["active"] == 17 and f["not_active"][0]["name"] == "Acme Box" and f["at_limit"] == ["SLACK"]
    assert any("Email mirrors have no onboarded email tenant" in gap for gap in f["gaps"])
    names = {c["name"] for c in f["onboard_candidates"]}
    assert "Gmail" in names and "Microsoft OneDrive" not in names and "Box" not in names and "Slack" not in names
    empty = sm.tenant_findings([], pack_channels=("saas",))
    assert empty["gaps"] and empty["onboard_candidates"]
