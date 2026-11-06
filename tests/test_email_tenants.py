"""ASVS V1.14.6 · CWE-1023 · WSTG-CONF-05: deploy and Check D.1 decide "is an email tenant onboarded?" with one function."""
from __future__ import annotations

import email_tenants as et
import pack_channels as pc
import saas_email_checks as se
from tests.test_saas_email_checks import EXO, SP, FakeCl, _email_rule

EMAIL_ROW = {"tenantId": 22, "tenantName": "Corp mail", "saasApplication": "MSEXCHANGE"}
RULE = {"name": "Mail PII", "emailTenants": [{"id": 22, "name": "Corp mail"}]}


def _ids(rows):
    return [t["id"] for t in rows]


def test_email_list_alone_finds_the_tenant():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: Zscaler's own appType=EMAIL tenant list on its own finds an onboarded email tenant."""
    out = et.onboarded_email_tenants([], [EMAIL_ROW], [])
    assert _ids(out) == [22] and out[0]["found_by"] == "Zscaler email list" and out[0]["name"] == "Corp mail"


def test_application_name_alone_finds_the_tenant():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: an active SaaS tenant whose application says email is found when the typed list is empty."""
    out = et.onboarded_email_tenants([EXO, SP], [], [])
    assert _ids(out) == [22] and out[0]["found_by"] == "application name"


def test_rule_scope_alone_finds_the_tenant():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: an email tenant named only on an Email DLP rule is found (the tenant list can omit it)."""
    out = et.onboarded_email_tenants([SP], [], [RULE])
    assert _ids(out) == [22] and out[0]["found_by"] == "used by Email DLP rule Mail PII"


def test_snake_and_camel_spellings_agree():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: API (camelCase) and SDK (snake_case) field spellings give the same tenants."""
    snake = et.onboarded_email_tenants([{"tenant_id": 22, "tenant_name": "Corp mail", "saas_application": "MSEXCHANGE"}], [],
                                       [{"name": "r", "email_tenants": [{"id": 23, "name": "SEG"}]}])
    camel = et.onboarded_email_tenants([{"tenantId": 22, "tenantName": "Corp mail", "saasApplication": "MSEXCHANGE"}], [],
                                       [{"name": "r", "emailTenants": [{"id": 23, "name": "SEG"}]}])
    assert snake == camel and _ids(snake) == [22, 23]


def test_deleted_tenants_are_excluded_from_every_source():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: a tenant marked deleted is never reported as onboarded, whichever source names it."""
    gone = dict(EMAIL_ROW, tenantDeleted=True)
    assert et.onboarded_email_tenants([dict(EXO, tenant_deleted=True)], [gone], []) == []
    assert et.onboarded_email_tenants([gone], [], [RULE]) == []


def test_a_tenant_found_twice_is_listed_once_with_the_first_source():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: a tenant found by several sources is listed once, with the first source that found it."""
    out = et.onboarded_email_tenants([EXO], [EMAIL_ROW], [RULE])
    assert _ids(out) == [22] and out[0]["found_by"] == "Zscaler email list"


def _live_cl(rules_answer):
    return FakeCl({("/zia/casbTenant/lite", None): ([SP], 200), ("/zia/casbTenant/lite", "EMAIL"): ([], 200),
                   "/zia/emailDlpRules": rules_answer})


def test_d1_passes_when_only_sharepoint_is_listed_and_a_rule_is_scoped_to_exchange():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: check D.1 passes on the live-tenant case: only SharePoint listed, an Email DLP rule scoped to Exchange."""
    cl = _live_cl(([_email_rule(email_tenants=[{"id": 22, "name": "Corp mail"}])], 200))
    r = se.c_d1(cl)
    assert r.status == "PASS" and "Corp mail" in r.detail and "used by Email DLP rule ZBP-US PII [Email]" in r.detail


def test_d1_still_fails_when_nothing_finds_a_tenant_and_survives_a_404_on_rules():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: check D.1 still fails when no source finds a tenant, and a 404 on the rules read does not break it."""
    r = se.c_d1(_live_cl(([], 404)))
    assert r.status == "FAIL" and "Exchange, Gmail or secure email gateway" in r.detail


def test_deploy_and_d1_agree_on_the_same_fixture():
    """ASVS V1.14.6 · CWE-1284 · WSTG-INFO-02: pack deploy and check D.1 report the same email tenants for the same tenant data."""
    rule = _email_rule(email_tenants=[{"id": 22, "name": "Corp mail"}])
    cl = _live_cl(([rule], 200))
    d1, _ = se._email_tenants(cl, with_rules=True)
    state = {"casb_tenants_raw": [SP], "email_tenant_rows_raw": [], "email_rules_raw": [rule]}
    assert [(t["id"], t["found_by"]) for t in pc.email_tenants(state)] == [(t["id"], t["found_by"]) for t in d1]
