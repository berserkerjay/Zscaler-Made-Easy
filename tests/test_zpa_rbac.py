"""Work package zpa-rbac: the ZPA administration and RBAC checks
(RBAC.13 to RBAC.23), their paths against the installed SDK, the snapshot
capture of the new lists, and the sample tenant's data for them.

Every test is offline: checks read through small fakes or the made-up
sample tenant. No real tenant, no network, no real clock."""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import beacon_scope  # noqa: E402
import dlp_assessment_full_auto as fa  # noqa: E402
import offline_tenant as ot  # noqa: E402
import plain_english  # noqa: E402
import sample_tenant  # noqa: E402
import scope_permissions  # noqa: E402
import zscaler_rbac_checks as rb  # noqa: E402
from dlp_assessment_full_auto import R  # noqa: E402

NOW = 1_790_000_000.0          # a fixed clock (October 2026)
DAY = 86400
ZPA_ROWS = [row for row in rb.RBAC_REG if row[1] == "RBAC — ZPA" and row[0] != "RBAC.9"]

# Secret values a live tenant may send back; none may reach a result.
SECRETS = ("S3cr3t-client-value", "P@ssw0rd-value", "3|api.private.zscaler.com|provkey-value", "tok-value-123", "-----BEGIN KEY-----")
PEOPLE = ("dana.reyes@corp.example", "Dana Reyes")


def _zpa(items, pages=1):
    return {"totalPages": str(pages), "totalCount": str(len(items)), "list": items}


class Fake:
    """The engine Client's read interface: get(ep, params) -> (body, code)."""

    def __init__(self, table=None, default=({"error": "not found"}, 404)):
        self.table = dict(table or {})
        self.default = default
        self.reads = []

    def get(self, ep, params=None):
        self.reads.append((ep, dict(params or {})))
        v = self.table.get(ep, self.default)
        return v(params) if callable(v) else v


def _sdk_source(module):
    path = os.path.join(os.path.dirname(fa.__file__), ".venv", "lib", "python3.11", "site-packages", "zscaler", "zpa", module + ".py")
    if not os.path.exists(path):
        import zscaler.zpa as zpa_pkg
        path = os.path.join(os.path.dirname(zpa_pkg.__file__), module + ".py")
    return open(path, encoding="utf-8").read()


# ── paths ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("short,module,base,suffix", [
    (rb.ZPA_ADMINS, "administrator_controller", "mgmtconfig/v1", "administrators"),
    (rb.ZPA_ROLES, "role_controller", "mgmtconfig/v1", "roles"),
    (rb.ZPA_SSO, "admin_sso_controller", "mgmtconfig/v1", "v2/ssoLoginOptions"),
    (rb.ZPA_API_KEYS, "api_keys", "mgmtconfig/v1", "apiKeys"),
    (rb.ZPA_EMERGENCY, "emergency_access", "mgmtconfig/v1", "emergencyAccess/users"),
    (rb.ZPA_MICROTENANTS, "microtenants", "mgmtconfig/v1", "microtenants"),
    (rb.ZPA_PROV_KEYS[0], "provisioning", "mgmtconfig/v1", "associationType/CONNECTOR_GRP/provisioningKey"),
    (rb.ZPA_PROV_KEYS[1], "provisioning", "mgmtconfig/v1", "associationType/SERVICE_EDGE_GRP/provisioningKey"),
    (rb.ZPA_PRA_CREDENTIALS, "pra_credential", "mgmtconfig/v1", "credential"),
    (rb.ZPA_PRA_POOLS, "pra_credential_pool", "waap-pra-config/v1", "credential-pool"),
    (rb.ZPA_PRA_APPROVALS, "pra_approval", "mgmtconfig/v1", "approval"),
])
def test_every_zpa_admin_path_resolves_to_the_sdk_path(short, module, base, suffix):
    """ASVS V14.2.1 · CWE-1104 · SSDF PW.4.1: each new ZPA read resolves to the base and path the installed SDK 1.11.3 uses."""
    # Act
    real = fa._resolve_ep(short, "42")
    src = _sdk_source(module)
    # Assert
    assert real == f"/zpa/{base}/admin/customers/42/{suffix}"
    assert f'f"/zpa/{base}/admin/customers/{{customer_id}}' in src
    last = suffix.rsplit("/", 1)[-1]
    assert f"/{last}" in src, (module, last)


def test_the_pra_pool_path_is_normalised_like_every_zpa_path():
    """ASVS V12.3.1 · CWE-22: the waap-pra-config base has its customer id replaced, so snapshots and the sample look it up."""
    # Act
    p = ot.normalize_path("https://x.invalid/zpa/waap-pra-config/v1/admin/customers/987/credential-pool?page=1")
    # Assert
    assert p == "/zpa/waap-pra-config/v1/admin/customers/{customerId}/credential-pool" and ot.valid_path(p)


def test_existing_zpa_paths_are_unchanged():
    """ASVS V14.2.1 · CWE-1104: adding a service base to the map leaves the existing v1/v2 paths as they were."""
    # Act / Assert
    assert fa._resolve_ep("/zpa/application", "42") == "/zpa/mgmtconfig/v1/admin/customers/42/application"
    assert fa._resolve_ep("/zpa/idp", "42") == "/zpa/mgmtconfig/v2/admin/customers/42/idp"
    assert fa._resolve_ep("/zpa/credential-pool") == "/zpa/waap-pra-config/v1/credential-pool"


# ── the checks, one by one ─────────────────────────────────────────────

def _admin(i, **kw):
    a = {"id": str(i), "username": f"admin{i}@corp.example", "isEnabled": True, "localLoginDisabled": True,
         "twoFactorAuthEnabled": True, "role": {"id": "1", "name": "Super Admin"}, "microtenantId": "0"}
    a.update(kw)
    return a


FULL = {"id": "1", "name": "Super Admin", "classPermissionGroups": [{"classPermissions": [
    {"classType": {"friendlyName": "Policy"}, "permission": {"type": "FULL"}}]}]}
READ = {"id": "2", "name": "Auditors", "classPermissionGroups": [{"classPermissions": [
    {"classType": {"friendlyName": "Policy"}, "permission": {"type": "VIEW_ONLY"}}]}]}
SCOPED = {"id": "3", "name": "Segment team", "classPermissionGroups": [{"classPermissions": [
    {"classType": {"friendlyName": "Application Segment"}, "permission": {"type": "FULL"}},
    {"classType": {"friendlyName": "Policy"}, "permission": {"type": "VIEW_ONLY"}}]}]}


@pytest.mark.parametrize("admins,status", [
    ([_admin(1)], R.WARN),
    ([_admin(i) for i in range(3)], R.PASS),
    ([_admin(i) for i in range(21)], R.WARN),
    ([_admin(1), _admin(2, isEnabled=False), _admin(3, isDeleted=True)], R.WARN),   # disabled and deleted do not count
    ([], R.INFO),
])
def test_rbac13_admin_count(admins, status):
    """ASVS V1.4.1 · CWE-284 · WSTG-IDNT-01: enabled ZPA admins are counted (disabled and deleted ones are not): one or more than 20 is a finding."""
    # Act
    r = rb.rbac_zpa_admin_count(Fake({rb.ZPA_ADMINS: (_zpa(admins), 200)}))
    # Assert
    assert r.status == status, r.detail


@pytest.mark.parametrize("admins,status", [
    ([_admin(1, localLoginDisabled=False, twoFactorAuthEnabled=False), _admin(2)], R.FAIL),
    ([_admin(1, localLoginDisabled=False, twoFactorAuthEnabled=True)], R.PASS),
    ([_admin(1), _admin(2)], R.PASS),
    ([_admin(1, localLoginDisabled=False, twoFactorAuthEnabled=False, isEnabled=False)], R.INFO),
])
def test_rbac14_local_admins_need_a_second_factor(admins, status):
    """ASVS V2.2.1 · CWE-308 · WSTG-ATHN-11: an enabled ZPA admin who can sign in locally without two-factor authentication fails."""
    # Act
    r = rb.rbac_zpa_admin_mfa(Fake({rb.ZPA_ADMINS: (_zpa(admins), 200)}))
    # Assert
    assert r.status == status, r.detail


@pytest.mark.parametrize("body,status", [
    ({"ssologinonly": True}, R.PASS), ({"ssologinonly": False}, R.WARN), ({"ssoLoginOnly": "true"}, R.PASS), ({}, R.INFO),
])
def test_rbac15_admin_sign_in_is_sso_only(body, status):
    """ASVS V2.1.1 · CWE-287 · WSTG-ATHN-01: ZPA admin login that is not SSO-only is a finding; an answer without the field is not judged."""
    # Act
    r = rb.rbac_zpa_sso_only(Fake({rb.ZPA_SSO: (body, 200)}))
    # Assert
    assert r.status == status, r.detail


def test_rbac16_full_access_share():
    """ASVS V1.4.3 · CWE-250 · WSTG-ATHZ-03: most admins holding a full-access role is a finding; a few is not."""
    # Arrange
    roles = (_zpa([FULL, READ, SCOPED]), 200)
    many = [_admin(i) for i in range(5)] + [_admin(9, role={"id": "2"})]
    few = [_admin(1), _admin(2), _admin(3, role={"id": "3"}), _admin(4, role={"id": "2"}), _admin(5, role={"id": "3"})]
    # Act
    r_many = rb.rbac_zpa_super_admin_share(Fake({rb.ZPA_ADMINS: (_zpa(many), 200), rb.ZPA_ROLES: roles}))
    r_few = rb.rbac_zpa_super_admin_share(Fake({rb.ZPA_ADMINS: (_zpa(few), 200), rb.ZPA_ROLES: roles}))
    r_unknown = rb.rbac_zpa_super_admin_share(Fake({rb.ZPA_ADMINS: (_zpa([_admin(1, role={"id": "77"})]), 200), rb.ZPA_ROLES: roles}))
    # Assert
    assert (r_many.status, r_few.status, r_unknown.status) == (R.WARN, R.PASS, R.INFO)


@pytest.mark.parametrize("roles,status", [
    ([FULL], R.WARN), ([FULL, READ], R.WARN), ([FULL, READ, SCOPED], R.PASS),
    ([{"id": "9", "name": "ZPA Read Only"}, {"id": "8", "name": "Super Admin"}, {"id": "7", "name": "Ops"}], R.PASS),
])
def test_rbac17_read_only_and_scoped_roles(roles, status):
    """ASVS V1.4.3 · CWE-269 · WSTG-ATHZ-02: a ZPA tenant with no read-only role, or only full and read-only roles, needs review."""
    # Act
    r = rb.rbac_zpa_least_privilege_roles(Fake({rb.ZPA_ROLES: (_zpa(roles), 200)}))
    # Assert
    assert r.status == status, r.detail


@pytest.mark.parametrize("keys,status", [
    ([], R.PASS),
    ([{"id": "k", "name": "ci", "enabled": True, "roleId": "1", "tokenExpiryTimeInSec": "3600"}], R.WARN),
    ([{"id": "k", "name": "ci", "enabled": True, "roleId": "2", "tokenExpiryTimeInSec": "604800"}], R.WARN),
    ([{"id": "k", "name": "ci", "enabled": True, "roleId": "2", "tokenExpiryTimeInSec": "3600"}], R.PASS),
    ([{"id": "k", "name": "ci", "enabled": False, "roleId": "1", "tokenExpiryTimeInSec": "604800"}], R.PASS),
])
def test_rbac18_api_keys(keys, status):
    """ASVS V2.10.1 · CWE-798 · WSTG-ATHZ-03: an enabled ZPA API key with a full-access role or tokens valid for more than a day is a finding."""
    # Act
    r = rb.rbac_zpa_api_keys(Fake({rb.ZPA_API_KEYS: (_zpa(keys), 200), rb.ZPA_ROLES: (_zpa([FULL, READ]), 200)}))
    # Assert
    assert r.status == status, r.detail


@pytest.mark.parametrize("users,status", [
    ([], R.WARN),
    ([{"userId": "1", "userStatus": "ACTIVE", "lastLoginTime": str(int(NOW - 200 * DAY))}], R.PASS),
    ([{"userId": "1", "userStatus": "ACTIVE", "lastLoginTime": str(int((NOW - 2 * DAY) * 1000))}], R.WARN),   # milliseconds too
    ([{"userId": str(i), "userStatus": "ACTIVE"} for i in range(4)], R.WARN),
])
def test_rbac19_emergency_access(monkeypatch, users, status):
    """ASVS V2.5.1 · CWE-306 · WSTG-ATHN-03: no break-glass account, more than three active, or one used in the last 30 days needs review."""
    # Arrange
    monkeypatch.setattr(rb, "_now", lambda: NOW)
    # Act
    r = rb.rbac_zpa_emergency_access(Fake({rb.ZPA_EMERGENCY: (_zpa(users), 200)}))
    # Assert
    assert r.status == status, r.detail


def test_rbac20_reads_admins_per_microtenant_and_finds_one_without():
    """ASVS V1.4.4 · CWE-284 · WSTG-ATHZ-02: admins are read once per microtenant (microtenantId), and a microtenant with no admin of its own is named."""
    # Arrange
    mts = [{"id": "11", "name": "Unit A", "enabled": True}, {"id": "12", "name": "Unit B", "enabled": True},
           {"id": "13", "name": "Unit C", "enabled": False}]
    admins = [_admin(1, microtenantId="11"), _admin(2, microtenantId="0")]
    cl = Fake({rb.ZPA_MICROTENANTS: (_zpa(mts), 200), rb.ZPA_ADMINS: (_zpa(admins), 200)})
    # Act
    r = rb.rbac_zpa_microtenant_admins(cl)
    # Assert
    assert r.status == R.WARN and "Unit B" in r.detail and "Unit A" not in r.detail
    asked = sorted(p.get("microtenantId") for ep, p in cl.reads if ep == rb.ZPA_ADMINS)
    assert asked == ["11", "12"], "one read per enabled microtenant, the disabled one is skipped"


def test_rbac20_caps_the_per_microtenant_reads_and_says_na_without_microtenants():
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: at most 20 microtenants are read one by one; none in use is N/A, not a finding."""
    # Arrange
    mts = [{"id": str(100 + i), "name": f"U{i}", "enabled": True} for i in range(30)]
    cl = Fake({rb.ZPA_MICROTENANTS: (_zpa(mts), 200), rb.ZPA_ADMINS: (_zpa([]), 200)})
    # Act
    r = rb.rbac_zpa_microtenant_admins(cl)
    none = rb.rbac_zpa_microtenant_admins(Fake({rb.ZPA_MICROTENANTS: (_zpa([]), 200)}))
    # Assert
    assert sum(1 for ep, _p in cl.reads if ep == rb.ZPA_ADMINS) == rb._MAX_MICROTENANTS and "first 20 of 30" in r.detail
    assert none.status == R.INFO and "N/A" in none.detail


@pytest.mark.parametrize("keys,status", [
    ([], R.PASS),
    ([{"id": "p", "enabled": True, "maxUsage": "100", "usageCount": "2", "creationTime": str(int(NOW - DAY))}], R.WARN),
    ([{"id": "p", "enabled": True, "maxUsage": "5", "usageCount": "0", "creationTime": str(int(NOW - 60 * DAY))}], R.WARN),
    ([{"id": "p", "enabled": True, "maxUsage": "5", "usageCount": "3", "creationTime": str(int(NOW - 60 * DAY))}], R.PASS),
    ([{"id": "p", "enabled": False, "maxUsage": "500", "usageCount": "0", "creationTime": "1"}], R.PASS),
])
def test_rbac21_provisioning_keys(monkeypatch, keys, status):
    """ASVS V2.10.4 · CWE-262 · WSTG-CONF-05: an enabled provisioning key with room for many more enrolments, or never used in 30 days, needs review."""
    # Arrange
    monkeypatch.setattr(rb, "_now", lambda: NOW)
    cl = Fake({rb.ZPA_PROV_KEYS[0]: (_zpa(keys), 200), rb.ZPA_PROV_KEYS[1]: (_zpa([]), 200)})
    # Act
    r = rb.rbac_zpa_provisioning_keys(cl)
    # Assert
    assert r.status == status, r.detail
    assert {ep for ep, _p in cl.reads} == set(rb.ZPA_PROV_KEYS), "App Connector and Service Edge keys both"


@pytest.mark.parametrize("creds,pools,status", [
    ([{"id": "c", "lastCredentialResetTime": str(int(NOW - 10 * DAY))}], [{"id": "p", "credentialMappingCount": "1"}], R.PASS),
    ([{"id": "c", "lastCredentialResetTime": str(int(NOW - 200 * DAY))}], [{"id": "p", "credentialMappingCount": "1"}], R.WARN),
    ([{"id": "c", "lastCredentialResetTime": str(int(NOW - 10 * DAY))}], [], R.WARN),
    ([], [], R.INFO),
])
def test_rbac22_pra_credentials(monkeypatch, creds, pools, status):
    """ASVS V2.10.4 · CWE-262 · WSTG-ATHN-07: stored PRA credentials not reset in 90 days, or not in any pool, need review; none stored is N/A."""
    # Arrange
    monkeypatch.setattr(rb, "_now", lambda: NOW)
    cl = Fake({rb.ZPA_PRA_CREDENTIALS: (_zpa(creds), 200), rb.ZPA_PRA_POOLS: (_zpa(pools), 200)})
    # Act
    r = rb.rbac_zpa_pra_credentials(cl)
    # Assert
    assert r.status == status, r.detail


@pytest.mark.parametrize("approvals,status", [
    ([{"id": "a", "status": "ACTIVE", "startTime": str(int(NOW - DAY)), "endTime": str(int(NOW + 90 * DAY))}], R.WARN),
    ([{"id": "a", "status": "ACTIVE", "startTime": str(int(NOW - DAY)), "endTime": str(int(NOW + 2 * DAY))}], R.PASS),
    ([{"id": "a", "status": "EXPIRED", "startTime": "1", "endTime": str(int(NOW + 900 * DAY))}], R.PASS),
    ([], R.INFO),
])
def test_rbac23_standing_pra_approvals(monkeypatch, approvals, status):
    """ASVS V1.4.3 · CWE-269 · WSTG-ATHZ-02: a PRA approval open for more than 30 days is standing privileged access; an expired one is not."""
    # Arrange
    monkeypatch.setattr(rb, "_now", lambda: NOW)
    # Act
    r = rb.rbac_zpa_pra_standing_approvals(Fake({rb.ZPA_PRA_APPROVALS: (_zpa(approvals), 200)}))
    # Assert
    assert r.status == status, r.detail


# ── safety: no secret, no person, refused and unlicensed reads ─────────

def _leaky_table():
    secret_fields = {"password": SECRETS[1], "clientSecret": SECRETS[0], "provisioningKey": SECRETS[2], "tokenId": SECRETS[3],
                     "privateKey": SECRETS[4], "passphrase": SECRETS[1]}
    admin = dict(_admin(1, username=PEOPLE[0], displayName=PEOPLE[1], email=PEOPLE[0], localLoginDisabled=False,
                        twoFactorAuthEnabled=False), **secret_fields)
    row = dict({"id": "x", "name": "obj", "enabled": True, "roleId": "1", "maxUsage": "100", "usageCount": "1",
                "userName": PEOPLE[0], "emailId": PEOPLE[0], "emailIds": [PEOPLE[0]], "userStatus": "ACTIVE"}, **secret_fields)
    return {ep: (_zpa([dict(row)]), 200) for ep in (rb.ZPA_API_KEYS, rb.ZPA_EMERGENCY, rb.ZPA_PRA_CREDENTIALS, rb.ZPA_PRA_POOLS,
                                                   rb.ZPA_PRA_APPROVALS) + rb.ZPA_PROV_KEYS} | {
        rb.ZPA_ADMINS: (_zpa([admin, dict(admin, id="2")]), 200), rb.ZPA_ROLES: (_zpa([FULL]), 200),
        rb.ZPA_SSO: ({"ssologinonly": False}, 200), rb.ZPA_MICROTENANTS: (_zpa([{"id": "5", "name": "Unit", "enabled": True}]), 200)}


@pytest.mark.parametrize("cid,sec,label,fn", ZPA_ROWS, ids=[r[0] for r in ZPA_ROWS])
def test_no_secret_value_or_person_reaches_a_result(cid, sec, label, fn):
    """ASVS V8.3.4 · CWE-200 · CWE-532 · WSTG-INFO-05: key, password, secret, token and provisioning-key values and admins' names and e-mails never appear in a result or its plain-English text."""
    # Act
    r = fn(Fake(_leaky_table()))
    text = json.dumps({"detail": r.detail, "data": r.data, "plain": plain_english.explain(
        {"id": cid, "section": sec, "label": label, "status": r.status, "detail": r.detail})})
    # Assert
    for value in SECRETS + PEOPLE:
        assert value not in text, (cid, value)


def test_the_list_reader_scrubs_before_any_check_sees_a_row():
    """ASVS V8.3.4 · CWE-312: _zpa_rows hands checks rows whose secret fields read "(set)", never the value."""
    # Act
    rows, code = rb._zpa_rows(Fake(_leaky_table()), rb.ZPA_API_KEYS)
    # Assert
    assert code == 200 and rows[0]["clientSecret"] == "(set)" and rows[0]["provisioningKey"] == "(set)" and rows[0]["password"] == "(set)"
    assert rows[0]["tokenId"] == "(set)"


def test_a_token_lifetime_is_kept_but_a_token_is_not():
    """ASVS V8.3.4 · CWE-312: scrub keeps a numeric token lifetime (tokenExpiryTimeInSec) so RBAC.18 can judge it, and still masks token text."""
    # Act
    out = ot.scrub({"tokenExpiryTimeInSec": "604800", "tokenId": "abc", "token": "123", "authTokenExpirySeconds": "x9"})
    # Assert
    assert out == {"tokenExpiryTimeInSec": "604800", "tokenId": "(set)", "token": "(set)", "authTokenExpirySeconds": "(set)"}


@pytest.mark.parametrize("cid,sec,label,fn", ZPA_ROWS, ids=[r[0] for r in ZPA_ROWS])
def test_a_refused_read_is_not_permitted_and_unlicensed_is_na(cid, sec, label, fn):
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: a 403 is "Not permitted" (never judged) and a 404 is INFO saying not licensed or N/A."""
    # Arrange
    guarded = dict((row[0], row[3]) for row in rb.RBAC_REG)[cid]
    # Act
    denied = guarded(Fake(default=({"code": "FORBIDDEN"}, 403)))
    missing = guarded(Fake(default=({"error": "not found"}, 404)))
    # Assert
    import permissions
    assert denied.status == R.INFO and permissions.is_denied(denied.detail) and "not judged" in denied.detail, denied.detail
    assert missing.status == R.INFO and ("not licensed" in missing.detail.lower() or "n/a" in missing.detail.lower()), missing.detail


def test_paging_is_bounded():
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: a list that claims endless pages is read at most ten pages deep."""
    # Arrange
    cl = Fake({rb.ZPA_ADMINS: (_zpa([_admin(1)], pages=9999), 200)})
    # Act
    rows, _code = rb._zpa_rows(cl, rb.ZPA_ADMINS)
    # Assert
    assert len(cl.reads) == 10 and len(rows) == 10


def test_a_list_cut_short_is_not_judged():
    """ASVS V11.1.2 · CWE-754 · WSTG-ERRH-01: when page 2 of the admin list fails, the check says it could not read the list instead of judging page 1 alone."""
    # Arrange
    def admins(params):
        if params.get("page", 1) == 1:
            return (_zpa([_admin(1), _admin(2)], pages=2), 200)
        return ({"error": "busy"}, 503)
    cl = Fake({rb.ZPA_ADMINS: admins})
    # Act
    r = rb.rbac_zpa_admin_mfa(cl)
    rows, code = rb._zpa_rows(cl, rb.ZPA_ADMINS)
    # Assert
    assert r.status == R.INFO and "HTTP 503" in r.detail and (rows, code) == ([], 503)


def test_no_zpa_rbac_check_writes():
    """ASVS V4.1.3 · CWE-284 · WSTG-CONF-06: the checks only call get(); a client without post/put/delete is enough."""
    # Arrange
    class GetOnly:
        def __init__(self):
            self.inner = Fake(_leaky_table())

        def get(self, ep, params=None):
            return self.inner.get(ep, params)
    # Act / Assert (an AttributeError would mean a write was tried)
    for _cid, _sec, _label, fn in ZPA_ROWS:
        assert fn(GetOnly()).status in (R.PASS, R.WARN, R.FAIL, R.INFO)


def test_every_new_check_has_a_why_and_a_where():
    """ASVS V1.1.1 · CWE-1059: every ZPA RBAC check has its own why-it-matters sentence and the ZPA portal path to fix it."""
    # Arrange
    import report_docx
    # Act / Assert
    for cid, sec, label, _fn in ZPA_ROWS:
        plain = plain_english.explain({"id": cid, "section": sec, "label": label, "status": "REVIEW", "detail": "x. Best Practice: y."})
        assert plain["means"] == report_docx._WHY_BY_CHECK[cid]
        assert "ZPA Admin Portal" in plain["do"], cid


# ── scope, snapshot and the sample tenant ──────────────────────────────

def test_the_rbac_scope_lists_every_endpoint_its_checks_read():
    """ASVS V1.4.4 · CWE-1059: the Scope page's RBAC entry names every endpoint the ZPA RBAC checks read."""
    # Arrange
    listed = set(scope_permissions.get_scope_permissions("rbac")["endpoints_used"])
    # Act
    read = set()
    for _cid, _sec, _label, fn in ZPA_ROWS:
        read |= beacon_scope.function_endpoints(fn)
    # Assert
    assert read and read <= listed, read - listed


def test_snapshot_reads_zpa_admin_lists_only_with_rbac_ticked():
    """ASVS V1.4.4 · CWE-284 · WSTG-ATHZ-02: the snapshot plan reads the ZPA admin lists for RBAC, never for ZPA alone."""
    # Act
    with_rbac = set(ot.capture_plan(["zpa", "rbac"]))
    zpa_only = set(ot.capture_plan(["zpa"]))
    # Assert
    new = {rb.ZPA_ADMINS, rb.ZPA_ROLES, rb.ZPA_SSO, rb.ZPA_API_KEYS, rb.ZPA_EMERGENCY, rb.ZPA_MICROTENANTS, rb.ZPA_PRA_CREDENTIALS,
           rb.ZPA_PRA_POOLS, rb.ZPA_PRA_APPROVALS, *rb.ZPA_PROV_KEYS}
    assert new <= with_rbac and not (new & zpa_only)


def test_snapshot_without_zpa_ticked_sends_no_zpa_request():
    """ASVS V1.4.4 · CWE-284: with RBAC ticked but not ZPA, the service guard refuses the ZPA admin reads before any request."""
    # Arrange
    cl = Fake(_leaky_table())
    # Act
    out = ot.capture(cl, ["rbac"], {}, lambda _m: None)
    # Assert
    assert not [ep for ep, _p in cl.reads if str(ep).startswith("/zpa/")]
    assert out["counts"]["out_of_scope"] >= 11


def test_saved_snapshot_keeps_no_secret_value():
    """ASVS V8.3.4 · CWE-312 · CWE-532 · WSTG-INFO-05: a snapshot of the ZPA admin lists keeps whether a secret is set, never its value."""
    # Arrange
    cl = Fake(_leaky_table())
    # Act
    out = ot.capture(cl, ["zpa", "rbac"], {}, lambda _m: None)
    doc = ot.dumps(ot.build_snapshot(out["responses"], {"scopes": ["zpa", "rbac"]}))
    # Assert
    assert "/zpa/mgmtconfig/v1/admin/customers/{customerId}/apiKeys" in doc
    assert "/zpa/waap-pra-config/v1/admin/customers/{customerId}/credential-pool" in doc
    assert '"ssologinonly":false' in doc.replace(" ", ""), "the settings object is kept whole, not turned into a list"
    for value in SECRETS:
        assert value not in doc, value


def test_sample_tenant_answers_every_new_check_with_its_planted_gaps():
    """ASVS V1.14.6 · CWE-1059: the made-up sample tenant answers every ZPA RBAC check offline, showing the gaps it plants."""
    # Arrange
    cl = ot.OfflineRawClient(ot.sample_store(reset=True), {})
    # Act
    got = {cid: fn(cl).status for cid, _sec, _label, fn in rb.RBAC_REG if cid in {r[0] for r in ZPA_ROWS}}
    # Assert
    assert got == {"RBAC.13": R.PASS, "RBAC.14": R.FAIL, "RBAC.15": R.WARN, "RBAC.16": R.PASS, "RBAC.17": R.PASS, "RBAC.18": R.WARN,
                   "RBAC.19": R.PASS, "RBAC.20": R.WARN, "RBAC.21": R.WARN, "RBAC.22": R.WARN, "RBAC.23": R.WARN}


def test_sample_tenant_holds_no_secret_field_value():
    """ASVS V8.3.4 · CWE-798: the sample's ZPA administration data has no secret-named field with a value."""
    # Act
    bodies = [b for p, b in sample_tenant.responses().items() if "/zpa/" in p]
    # Assert
    assert ot.scrub(bodies) == bodies
