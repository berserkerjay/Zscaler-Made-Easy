"""Review & Remediate: recipes answer real assessment check ids."""
from fastapi.testclient import TestClient

import remediation
import dlp_api_server as srv
from dlp_assessment_full_auto import REG


def test_recipes_name_real_assessment_checks():
    ids = {r[0] for r in REG}
    mapped = remediation.remediable_checks()
    assert mapped, "no recipe answers any assessment check"
    unknown = [c for c in mapped if c not in ids]
    assert not unknown, f"recipes name checks the assessment does not have: {unknown}"
    # The findings the user actually sees resolve to a recipe.
    assert remediation.get_recipe("4.1")["check_id"] == "SSL-01"
    assert remediation.get_recipe("A.1")["check_id"] == "DLP-01"
    assert remediation.get_recipe("E.9")["check_id"] == "URL-01"
    assert remediation.get_recipe("SSL-01.x")["check_id"] == "SSL-01" and remediation.get_recipe("1.1") is None


def test_catalog_exposes_the_check_ids_and_the_page_matches_on_them():
    c = TestClient(srv.app)
    import security
    cat = c.get("/api/remediation/catalog", cookies={security.UI_TOKEN_COOKIE: security.ui_token()}).json()["catalog"]
    by = {r["check_id"]: r for r in cat}
    assert "4.1" in by["SSL-01"]["checks"] and "5.3" in by["DLP-01"]["checks"]
    html = c.get("/", cookies={security.UI_TOKEN_COOKIE: security.ui_token()}).text
    assert "(r.checks || []).includes(cid)" in html and "...(r.checks || [])" in html
