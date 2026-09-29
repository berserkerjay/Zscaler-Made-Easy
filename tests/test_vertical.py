"""The profile's industry scopes what the app suggests: frameworks, packs, deficiencies."""
from fastapi.testclient import TestClient

import vertical as v
import dlp_api_server as srv
import security


def test_scope_from_industry_and_profile_packs():
    s = v.scope_for({"industry": "Healthcare"})
    assert s["scoped"] and s["frameworks"][0] == "HIPAA" and s["packs"] == ["healthcare_phi_baseline", "zbp_enterprise_baseline"] and s["packs_from"] == "industry"
    s = v.scope_for({"industry": "Financial services", "baseline_packs": ["global_banking_baseline"]})
    assert s["packs"] == ["global_banking_baseline"] and s["packs_from"] == "profile" and "PCI_DSS" in s["frameworks"] and "GLBA" in s["frameworks"]
    s = v.scope_for({"industry": "Other"}, all_frameworks=["HIPAA", "SOC_2"], all_packs=["a", "b"])
    assert not s["scoped"] and s["frameworks"] == ["HIPAA", "SOC_2"] and s["packs"] == ["a", "b"] and s["packs_from"] == "all"
    assert v.scope_for(None)["scoped"] is False and v.scope_for({})["industry"] == ""
    # Free-text industries normalise.
    assert v.normalize_industry("hospital network") == "Healthcare" and v.normalize_industry("DoD contractor") == "Federal"
    assert v.normalize_industry("Police department") == "Law enforcement (CJIS)" and v.normalize_industry("regional bank") == "Financial services"
    # Unknown packs and frameworks are dropped, never invented.
    s = v.scope_for({"industry": "Healthcare"}, all_frameworks=["HIPAA", "GDPR"], all_packs=["zbp_enterprise_baseline"])
    assert s["frameworks"] == ["HIPAA"] and s["packs"] == ["zbp_enterprise_baseline"]


def test_vertical_scope_endpoint_and_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    c = TestClient(srv.app); c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.get("/api/vertical-scope?industry=Healthcare")
    assert r.status_code == 200
    s = r.json()
    assert s["scoped"] and s["frameworks"][0] == "HIPAA" and "healthcare_phi_baseline" in s["packs"] and s["pack_names"][0].startswith("Healthcare") and "Healthcare" in s["industries"]
    assert c.get("/api/vertical-scope?profile_id=nope").status_code == 404
    assert c.get("/api/vertical-scope").json()["scoped"] is False
    # The page and the studio pick the scope up.
    assert "_gdApplyScope" in c.get("/static/guide.js").text and "gdScopeNote" in c.get("/static/guide.js").text
    js = c.get("/static/deploy_studio.js").text
    assert "GD.scope" in js and "showAllPacks" in js


def test_the_industry_pre_selects_its_packs_on_the_form_and_in_the_studio(tmp_path, monkeypatch):
    """"If I select the industry in the tenant config it should auto select
    the packs (which I can add more if needed)": choosing an industry ticks
    its packs on the profile form and refreshes the scope at once; Deploy
    policy packs opens with the scope's packs selected and re-selects only
    when the scope changes, so the operator's own additions and removals
    stand."""
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    c = TestClient(srv.app); c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    s = c.get("/api/vertical-scope?industry=Healthcare").json()
    assert s["industry_packs"] == [p for p in v.INDUSTRY_PACKS["Healthcare"] if p in s["packs"] or True][:len(s["industry_packs"])] and set(s["industry_packs"]) <= set(v.INDUSTRY_PACKS["Healthcare"])
    assert c.get("/api/vertical-scope").json()["industry_packs"] == []
    guide = c.get("/static/guide.js").text
    assert 'id="gdProfIndustry" onchange="_gdIndustryChanged(this.value)"' in guide and "async function _gdIndustryChanged(industry)" in guide
    assert "cb.checked = sc.scoped && sc.packs.includes(cb.value)" in guide, "the industry's packs are ticked on the form"
    assert 'class="gd-prof-pack" value="${_gdE(p.id)}"' in guide and 'onchange="_gdProfPacksChanged()"' in guide and "function _gdProfPacksChanged()" in guide
    assert "GD.scope.packs = ticked.length ? ticked : industryPacks" in guide and "function _gdStudioFollowScope()" in guide
    assert "pre-selects them in Deploy policy packs; add more packs as needed" in guide
    assert "GD.packs = [...(pr.packs || [])].sort((a, b) => (a.baseline ? 0 : 1) - (b.baseline ? 0 : 1))" in guide, "every installed pack is tickable on the form, so the Fed and CJIS industries can tick theirs"
    js = c.get("/static/deploy_studio.js").text
    assert "function _dzAutoSelectFromScope()" in js and "if (DZ.autoKey === key) return false;" in js, "one turn per scope; the operator's changes stand"
    assert js.index("_dzAutoSelectFromScope();") < js.index("function _dzAutoSelectFromScope()") or "_dzAutoSelectFromScope();\n" in js.split("async function openDlpPacksModal()")[1].split("\n}\n")[0], "the sheet pre-selects when it opens"
    assert "function _dzAutoNoteHtml()" in js and "Pre-selected for ${_dzE(sc.industry)}" in js and "${_dzAutoNoteHtml()}" in js
    assert "(pre-selected for ${_dzE(DZ.autoIndustry || '')})" in js
