"""Readiness (readiness.py, /api/readiness/*, Required API access, the
Start page summary): what the API client can do, read from the OneAPI
token (decoded, never verified, never shown) and a few reads in scope.

Every test uses fakes: fake tokens (well formed, malformed, huge, nested,
hostile), a fake SDK client and a synchronous job runner. No network, no
clock (time is injected), no files outside tmp_path. Each docstring names
the controls it checks (OWASP ASVS 4.0.3 L2, CWE, OWASP Top 10 2021, WSTG,
WCAG 2.2)."""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import threading
import time
import types
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import permissions
import readiness as rd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = 1_800_000_000.0   # injected clock (2027-01-15)
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "7210000000000"}
CANARY_SIG = "CANARYsigQ9w8e7r6t5y4u3i2o1p"
CANARY_CLAIM = "CANARYclaimZx81"


def _b64(obj: Any) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwt(payload: Any, sig: str = CANARY_SIG) -> str:
    return _b64({"alg": "RS256", "typ": "JWT"}) + "." + _b64(payload) + "." + sig


SERVICE_INFO = [
    {"prd": "ZIA", "tnt": "1234", "ext": {"rnm": "Assessment API role", "rid": "4711"}},
    {"prd": "ZCC", "ext": {"rnm": "Read Only Admin", "rid": 9}},
    {"prd": "ZPA", "ext": {"rnm": "API Full Access", "rid": "216"}},
    {"prd": "ZINSIGHTS", "ext": {"rnm": "ZINSIGHTS Reader"}},
]
GOOD = jwt({"service-info": SERVICE_INFO, "scope": "zia.read zcc.read", "exp": NOW + 3600, "iat": NOW, "secret_thing": CANARY_CLAIM})
TOKEN_PARTS = GOOD.split(".")


# ── Fake SDK client ──────────────────────────────────────────────────────

class Resp:
    def __init__(self, body: Any, code: int = 200) -> None:
        self.body, self.code = body, code

    def get_body(self) -> Any:
        return self.body

    def get_status(self) -> int:
        return self.code


class ApiError(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(f"HTTP {code} you sent {CANARY_SIG}")   # an error that echoes the request
        self.status_code = code


FULL_ROLE = {"id": 4711, "name": "Assessment API role", "policyAccess": "READ_WRITE",
             "featurePermissions": {k: "READ_WRITE" for k in rd.ZIA_PERMS}}
SUBS = [{"id": "ZDLP_WEB", "status": "ACTIVE", "subscribed": True, "endDate": NOW + 400 * 86400},
        {"id": "URL_FILTER", "subscribed": True},
        {"id": "Z_DLP_ENDPOINT", "subscribed": True, "endDate": (NOW + 5 * 86400) * 1000},
        {"id": "Z_CASB", "subscribed": True}, {"id": "ZS_DP_EMAIL", "subscribed": True},
        {"id": "ZS_DP_GEN_AI", "status": "EXPIRED", "subscribed": True}]


class Fake:
    """What _build_sdk_client returns: the token on _auth_token, the ZIA,
    Client Connector, ZPA, ZDX and Z-Insights services the readiness reads,
    every call recorded."""

    def __init__(self, token: Optional[str] = GOOD, *, role: Any = FULL_ROLE, subs: Any = SUBS, deny: tuple = (),
                 zcc_roles: Any = None, zpa_roles: Any = None) -> None:
        self._auth_token = token
        self.calls: List[str] = []
        self.closed = False

        def answer(name: str, body: Any):
            def call(*a, **k):
                self.calls.append(name)
                if name.split(".")[0] in deny or name in deny:
                    return None, Resp(None, 403), ApiError(403)
                return None, Resp(body), None
            return call
        ns = types.SimpleNamespace
        self.zia = ns(admin_roles=ns(get_role=answer("zia.get_role", role),
                                     list_roles=answer("zia.list_roles", [{"id": 4711, "name": "Assessment API role"}])))
        self.zcc = ns(company=ns(get_company_info=answer("zcc.company", {"name": "Acme Corp", "supportAdminEmail": "it@acme.example",
                                                                         "zpnEnabled": True, "upmEnabled": False, "dlpEnabled": True})),
                      admin_user=ns(list_admin_roles=answer("zcc.roles", zcc_roles if zcc_roles is not None else
                                                            [{"id": 9, "roleName": "Read Only Admin", "deviceOverview": 1, "forwardingProfile": 1}])))
        self.zpa = ns(role_controller=ns(list_roles=answer("zpa.roles", zpa_roles if zpa_roles is not None else
                                                           [{"id": "216", "name": "API Full Access", "classPermissionGroups": [
                                                               {"classPermissions": [{"classType": {"friendlyName": "Application Segment"},
                                                                                      "permission": {"type": "FULL"}}]}]}])))
        self.zdx = ns(admin=ns(list_departments=answer("zdx.departments", [])))
        self.zins = ns(web_traffic=ns(get_no_grouping=answer("zins.web", [{"total": 5}])))
        self._subs = subs
        self._deny = deny

    def get_request_executor(self):
        fake = self

        class Ex:
            def create_request(self, method, path, body, headers, **k):
                return (method, path), None

            def execute(self, request):
                fake.calls.append("zia.subscriptions " + request[1])
                if "zia" in fake._deny or "zia.subscriptions" in fake._deny:
                    return Resp(None, 403), ApiError(403)
                return Resp(fake._subs), None
        return Ex()

    def close(self) -> None:
        self.closed = True


def facts_for(client: Fake, scopes: List[str], **kw) -> Dict[str, Any]:
    return rd.evaluate(rd.read(client, scopes, customer_id=kw.pop("customer_id", "7210000000000"), now=NOW, **kw))


def by_key(result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {f["key"]: f for f in result["scopes"] + result["writes"]}


def _no_canary(text: str) -> List[str]:
    return [x for x in (GOOD, CANARY_SIG, CANARY_CLAIM, TOKEN_PARTS[1], TOKEN_PARTS[0], TOKEN_PARTS[1][:24]) if x in text]


# ── Decoding the token ───────────────────────────────────────────────────

def test_a_well_formed_token_gives_products_roles_scopes_and_validity():
    """ASVS V5.1.3 · CWE-20: the service-info claim gives each product with its role name and id; scopes and expiry are read."""
    # Act
    c = rd.decode_claims(GOOD)
    # Assert
    assert c["ok"] and c["products_listed"]
    assert [(p["product"], p["role"], p["role_id"]) for p in c["products"]] == [
        ("ZIA", "Assessment API role", "4711"), ("ZCC", "Read Only Admin", "9"), ("ZPA", "API Full Access", "216"), ("ZINSIGHTS", "ZINSIGHTS Reader", "")]
    assert c["scopes"] == ["zia.read", "zcc.read"]
    assert c["expires_at"] == "2027-01-15T09:00:00Z" and c["issued_at"] == "2027-01-15T08:00:00Z"


MALFORMED = {
    "none": None, "empty": "", "number": 12345, "one-part": "abcdef", "two-parts": "a.b", "four-parts": "a.b.c.d",
    "bad-alphabet": "aaa.!!!$.ccc", "padding-in-the-middle": "aaa.ab=cd.ccc", "length-mod-4-is-1": "aaa.abcde.ccc",
    "not-json": "aaa." + _b64(b"hello there") + ".sig", "json-array": jwt([1, 2, 3]), "json-string": jwt("claims"),
    "bad-utf8": "aaa." + _b64(b"\xff\xfe\xfd{}") + ".sig", "nan-constant": "aaa." + _b64(b'{"exp": NaN}') + ".sig",
    "empty-payload": "aaa..sig",
}


@pytest.mark.parametrize("token", list(MALFORMED.values()), ids=list(MALFORMED))
def test_a_malformed_token_is_refused_in_words_without_raising(token):
    """ASVS V5.1.3 · ASVS V7.4.1 · CWE-20 · CWE-209 · WSTG-INPV-13: a malformed token gives ok=False and a reason that quotes nothing from it."""
    # Act
    c = rd.decode_claims(token)
    # Assert
    if token == MALFORMED["nan-constant"]:
        assert c["ok"] and c["expires_at"] is None   # a NaN is no date, and nothing breaks
        return
    assert c["ok"] is False and c["products"] == [] and c["why"]
    assert not (isinstance(token, str) and len(token) > 8 and any(len(seg) > 2 and seg in c["why"] for seg in token.split(".")))


def test_a_huge_token_is_refused_before_it_is_decoded():
    """ASVS V5.1.4 · CWE-400 · CWE-770: a token over the size limit is refused at once, without decoding it."""
    # Arrange
    huge = "a." + "A" * (rd.MAX_TOKEN_CHARS + 10) + ".b"
    t0 = time.perf_counter()
    # Act
    c = rd.decode_claims(huge)
    # Assert
    assert c["ok"] is False and "too large" in c["why"]
    assert time.perf_counter() - t0 < 0.5


def test_a_token_at_the_size_limit_is_still_read_when_its_payload_fits():
    """ASVS V5.1.4 · CWE-770: the boundary: a token just under the limit with a payload under the payload limit decodes."""
    # Arrange: pad with a long signature, the payload stays small
    t = jwt({"service-info": [{"prd": "ZIA"}]}, sig="s" * 100)
    t = t + "s" * (rd.MAX_TOKEN_CHARS - len(t))
    # Act / Assert
    assert len(t) == rd.MAX_TOKEN_CHARS and rd.decode_claims(t)["ok"] is True


def test_a_payload_over_the_payload_limit_is_refused():
    """ASVS V5.1.4 · CWE-770: a payload bigger than MAX_PAYLOAD_BYTES is refused even when the token fits."""
    t = jwt({"pad": "x" * (rd.MAX_PAYLOAD_BYTES + 10)}, sig="s")
    assert len(t) <= rd.MAX_TOKEN_CHARS
    c = rd.decode_claims(t)
    assert c["ok"] is False and "too large" in c["why"]


@pytest.mark.parametrize("depth,ok", [(rd.MAX_DEPTH, True), (rd.MAX_DEPTH + 1, False), (4000, False)])
def test_nesting_is_bounded_and_never_recurses_deeply(depth, ok):
    """ASVS V5.1.4 · CWE-674 · CWE-400: claims nested past MAX_DEPTH are refused by a linear scan before json parsing; the limit itself is accepted."""
    # Arrange: depth counts the claims object itself
    inner = "1"
    for _ in range(depth - 1):
        inner = "[" + inner + "]"
    raw = ('{"n": ' + inner + "}").encode()
    t = "aaa." + _b64(raw) + ".sig"
    if len(t) > rd.MAX_TOKEN_CHARS:
        t = "aaa." + _b64(raw[: rd.MAX_PAYLOAD_BYTES - 10]) + ".sig"
    # Act
    c = rd.decode_claims(t)
    # Assert
    assert c["ok"] is ok
    if not ok:
        assert "nested" in c["why"] or "too large" in c["why"]


def test_brackets_inside_strings_do_not_count_as_nesting():
    """ASVS V5.1.4 · CWE-20: the nesting scan skips strings (with escaped quotes), so a claim with many brackets in text is read."""
    c = rd.decode_claims(jwt({"note": "[[[[[[[[[[[[[[[[[[[[\\\"{{{{{{{{{{{{{{{{{{", "service-info": [{"prd": "ZIA"}]}))
    assert c["ok"] and c["products"][0]["product"] == "ZIA"


def test_hostile_claim_values_are_cleaned_bounded_and_never_trusted():
    """ASVS V5.1.3 · ASVS V5.3.3 · CWE-20 · CWE-79: odd types, markup, control characters, long names and long lists are cleaned or dropped."""
    # Arrange
    si = ([{"prd": "<script>", "ext": {"rnm": "x"}}, "not-a-dict", {"prd": 7}, {"prd": "ZIA", "ext": "nope"},
           {"prd": "zdx", "ext": {"rnm": "Role\u0000\u0007\n" + "r" * 500, "rid": "12; DROP"}}, {"prd": "ZIA", "ext": {"rnm": "second"}}]
          + [{"prd": f"P{i}"} for i in range(200)])
    c = rd.decode_claims(jwt({"service-info": si, "scope": ["ok.scope", "has space", 5, "x" * 300] + [f"s{i}" for i in range(500)],
                              "exp": True, "iat": 10 ** 30}))
    # Assert
    prods = {p["code"]: p for p in c["products"]}
    assert "<SCRIPT>" not in prods and len(c["products"]) <= rd.MAX_SERVICES
    assert prods["ZIA"]["role"] == ""                       # the first ZIA entry wins; "nope" ext is ignored
    assert prods["ZDX"]["product"] == "ZDX" and prods["ZDX"]["role"].startswith("Role") and len(prods["ZDX"]["role"]) <= 120
    assert all(ch.isprintable() for ch in prods["ZDX"]["role"]) and prods["ZDX"]["role_id"] == ""
    assert c["scopes"][0] == "ok.scope" and "has space" not in c["scopes"] and len(c["scopes"]) == rd.MAX_SCOPES
    assert c["expires_at"] is None and c["issued_at"] is None


def test_a_token_without_service_info_lists_nothing_and_blocks_nothing():
    """ASVS V1.4.4 · CWE-284: with no service-info claim the products are unknown, so nothing is greyed out on the token's word alone."""
    # Arrange
    client = Fake(jwt({"sub": "x"}))
    # Act
    r = facts_for(client, ["zcc"])
    # Assert
    c = rd.decode_claims(client._auth_token)
    assert c["ok"] and not c["products_listed"]
    assert by_key(r)["zdx"]["status"] != "blocked" and by_key(r)["insights"]["status"] != "blocked"


# ── The token is never shown, logged or stored ───────────────────────────

def test_the_token_never_reaches_the_answer_or_the_log():
    """ASVS V8.3.4 · ASVS V7.1.1 · CWE-200 · CWE-532 · A09:2021: decode output, the readiness answer and every log line hold no part of the token."""
    # Arrange
    lines: List[str] = []
    client = Fake(deny=("zdx",))
    # Act
    out = rd.run(client, ["dlp", "zcc", "zpa", "zdx", "insights"], customer_id="7210000000000", log=lines.append, now=NOW)
    # Assert
    text = json.dumps(out) + "\n".join(lines) + json.dumps(rd.token_access(client))
    assert _no_canary(text) == []
    assert "Assessment API role" in text      # role names are shown, they are not secret


def test_the_answer_keeps_no_customer_names_from_client_connector():
    """ASVS V8.3.4 · CWE-359: of the Client Connector company info only the on/off switches are kept, never names or e-mail addresses."""
    out = facts_for(Fake(), ["zcc"])
    text = json.dumps(out)
    assert "Acme Corp" not in text and "it@acme.example" not in text
    assert out["licences"]["zcc_flags"] == {"ZPA enabled": True, "ZDX enabled": False, "Endpoint DLP enabled": True}


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Arrange: an isolated app whose sign-in returns the fake client and whose jobs run in the request."""
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setattr(srv, "_READINESS", type(srv._READINESS)())
    state: Dict[str, Any] = {"client": Fake(), "built": 0}

    def build(creds):
        state["built"] += 1
        state["creds"] = dict(creds)
        return state["client"]
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    import pack_jobs

    class Job:
        def __init__(self, kind, result):
            self.id, self.kind, self.status, self.result = "rdjob", kind, "done", result

    def start(kind, fn, **k):
        logs: List[str] = []
        res = fn(logs.append, threading.Event())
        state["logs"] = logs
        return Job(kind, res)
    monkeypatch.setattr(pack_jobs, "start", start)
    state["http"] = TestClient(srv.app)
    return state


def test_sign_in_returns_what_the_token_says_and_never_the_token(app, capsys):
    """ASVS V8.3.4 · ASVS V7.1.1 · CWE-200 · CWE-532 · WSTG-INFO-05: /api/tenant/check adds the products and roles, and no part of the token reaches the body, the audit log or the console."""
    # Act
    r = app["http"].post("/api/tenant/check", json=CREDS)
    # Assert
    assert r.status_code == 200
    acc = r.json()["access"]
    assert acc["ok"] and [p["product"] for p in acc["products"]] == ["ZIA", "ZCC", "ZPA", "ZINSIGHTS"]
    assert app["client"].calls == []     # sign-in only: nothing in the tenant was read
    out = capsys.readouterr()
    audit = open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read() if os.path.exists(os.environ["DLP_CHECK_AUDIT"]) else ""
    assert _no_canary(r.text + audit + out.out + out.err) == []


def test_the_readiness_route_reads_in_scope_and_keeps_no_token(app, capsys):
    """ASVS V8.3.4 · ASVS V4.1.3 · CWE-200 · CWE-532 · CWE-272: the job answers, keeps the latest result in memory and no part of the token is in its result, its log, /latest or /permissions."""
    # Arrange
    body = dict(CREDS, scopes=["dlp", "zcc"], from_page=True)
    # Act
    r = app["http"].post("/api/readiness/start", json=body)
    latest = app["http"].get("/api/readiness/latest")
    page = app["http"].get("/permissions")
    # Assert
    assert r.status_code == 200 and r.json()["job_id"] == "rdjob"
    assert app["client"].closed is True
    calls = app["client"].calls
    assert calls and not [c for c in calls if c.startswith(("zpa", "zdx", "zins"))]
    res = latest.json()["results"]
    assert len(res) == 1 and res[0]["status"] == "done" and res[0]["tenant_label"]
    out = capsys.readouterr()
    assert _no_canary(r.text + latest.text + page.text + "\n".join(app["logs"]) + out.out + out.err) == []
    assert "What this API client can do now" in page.text and "Assessment API role" in page.text


@pytest.mark.parametrize("scopes", [[], ["zidentity"], ["compliance"], ["ZIA_EXTRAS"]])
def test_nothing_readiness_reads_in_scope_is_refused_before_sign_in(app, scopes):
    """ASVS V4.1.3 · ASVS V4.1.5 · CWE-272 · WSTG-ATHZ-02: with no product it reads in scope the route answers 400 and signs in to nothing."""
    r = app["http"].post("/api/readiness/start", json=dict(CREDS, scopes=scopes, from_page=True))
    assert r.status_code == 400 and "not in scope" in r.json()["detail"]
    assert app["built"] == 0


def test_a_bad_zpa_customer_id_is_refused_before_sign_in(app):
    """ASVS V5.1.3 · CWE-20: the ZPA customer ID is validated before anything is signed in to."""
    r = app["http"].post("/api/readiness/start", json=dict(CREDS, customer_id="12; DROP", scopes=["zpa"], from_page=True))
    assert r.status_code in (400, 422) and app["built"] == 0


def test_the_zpa_customer_id_reaches_the_sdk_client(app):
    """ASVS V4.1.3 · CWE-272: the ZPA customer ID in the body goes to the sign-in (ZPA paths are built from it) and ZPA alone is read."""
    r = app["http"].post("/api/readiness/start", json=dict(CREDS, scopes=["zpa"], from_page=True))
    assert r.status_code == 200 and app["creds"]["customer_id"] == "7210000000000"
    assert app["client"].calls == ["zpa.roles"]


def test_the_latest_answers_are_bounded(app):
    """ASVS V11.1.4 · CWE-770: the server keeps the latest answer of at most _READINESS_MAX tenants, in memory only."""
    for i in range(srv._READINESS_MAX + 3):
        app["http"].post("/api/readiness/start", json=dict(CREDS, vanity_domain=f"acme{i}", scopes=["zcc"], from_page=True))
    res = app["http"].get("/api/readiness/latest").json()["results"]
    assert len(res) == srv._READINESS_MAX and "acme" in res[0]["tenant_label"]


# ── Reads: only in scope, few, Stop honoured ─────────────────────────────

@pytest.mark.parametrize("scopes,expected", [
    (["dlp"], {"zia.subscriptions /zia/api/v1/subscriptions", "zia.get_role"}),
    (["zcc"], {"zcc.company", "zcc.roles"}),
    (["zpa"], {"zpa.roles"}),
    (["zdx"], {"zdx.departments"}),
    (["insights"], {"zins.web"}),
])
def test_only_the_products_in_scope_are_read(scopes, expected):
    """ASVS V4.1.3 · ASVS V1.4.4 · CWE-272: each product is read only when one of its Scope page keys is ticked, with one or two calls."""
    client = Fake()
    rd.read(client, scopes, customer_id="7210000000000", now=NOW)
    assert set(client.calls) == expected and len(client.calls) <= 2


def test_zpa_is_not_read_without_a_customer_id_and_says_what_to_do():
    """ASVS V4.1.3 · CWE-272: without the ZPA customer ID nothing of ZPA is read; the ZPA scope says to enter it."""
    client = Fake()
    out = facts_for(client, ["zpa"], customer_id="")
    assert client.calls == []
    f = by_key(out)["zpa"]
    assert f["status"] == "blocked" and any("customer ID" in s for s in f["steps"])


def test_stop_ends_the_check_with_no_partial_result():
    """ASVS V11.1.1 · CWE-400: Stop before the reads gives status stopped, nothing read and no verdict."""
    client, ev = Fake(), threading.Event()
    ev.set()
    out = rd.run(client, ["dlp", "zcc"], cancel=ev, now=NOW)
    assert out == {"status": "stopped", "tenant_label": ""} and client.calls == []


def test_the_classic_sign_in_reads_licences_only_and_says_the_rest_needs_oneapi():
    """ASVS V1.4.4 · CWE-284: the classic ZIA API sign-in has no token and no API role: ZIA licences are read, ZPA, ZCC and Z-Insights are not."""
    client = Fake(token=None)
    out = rd.evaluate(rd.read(client, ["dlp", "zcc", "insights"], auth_method="legacy", now=NOW))
    assert client.calls == ["zia.subscriptions /zia/api/v1/subscriptions"]
    prods = {p["product"]: p for p in out["products"]}
    assert prods["ZCC"]["access"] == "none" and "OneAPI" in prods["ZCC"]["why"]
    assert by_key(out)["insights"]["status"] == "blocked"


# ── The verdict ──────────────────────────────────────────────────────────

def _role(**perms) -> Dict[str, Any]:
    return {"id": 4711, "name": "Assessment API role", "policyAccess": "READ_WRITE", "featurePermissions": perms}


def test_a_full_role_with_the_licences_makes_everything_in_scope_work():
    """ASVS V1.4.4 · CWE-284: a role with every permission at full and the licences present: every checked feature works."""
    out = facts_for(Fake(), ["dlp", "zia_extras", "zcc", "zpa", "insights"])
    k = by_key(out)
    for key in ("dlp", "zia_extras", "deploy_packs", "remove_packs", "rule_migration", "self_heal", "bulk_changes", "insights"):
        assert k[key]["status"] == "ok", (key, k[key])
    assert k["zdx"]["status"] == "blocked"   # the token lists no ZDX role
    assert out["licences"]["ending_soon"] == ["Z_DLP_ENDPOINT"]


def test_a_read_only_dlp_role_assesses_but_cannot_deploy_and_says_what_to_ask_for():
    """ASVS V1.4.4 · ASVS V4.1.3 · CWE-284: read-only DLP permissions: the DLP scope works, deploying is read only with steps naming the role and the permission."""
    client = Fake(role=_role(INLINE_DLP="READ_ONLY", DLP_DICTIONARIES_ENGINES="READ_ONLY"))
    k = by_key(facts_for(client, ["dlp"]))
    assert k["dlp"]["status"] == "ok"
    dep = k["deploy_packs"]
    assert dep["status"] == "read_only"
    steps = " ".join(dep["steps"])
    assert "Role Management" in steps and "Assessment API role" in steps and "DLP dictionaries and engines to full" in steps


def test_a_role_without_dlp_blocks_the_dlp_scope_and_one_missing_permission_makes_a_scope_partial():
    """ASVS V1.4.4 · CWE-284: no DLP permission blocks the DLP scope; one of three ZIA platform permissions missing leaves it partial (the rest runs)."""
    client = Fake(role=_role(URL_CLOUD_APP_CONTROL="READ_ONLY", SSL_POLICY="READ_ONLY", FIREWALL_CONTROL="NONE"))
    k = by_key(facts_for(client, ["dlp", "zia_extras"]))
    assert k["dlp"]["status"] == "blocked" and "Inline DLP" in k["dlp"]["why"]
    assert k["zia_extras"]["status"] == "partial" and "Firewall control" in k["zia_extras"]["why"]


def test_the_split_url_and_cloud_app_permission_names_are_both_understood():
    """ASVS V1.4.4 · CWE-284: a role showing URL_FILTERING_CONTROL instead of URL_CLOUD_APP_CONTROL still satisfies URL filtering."""
    client = Fake(role=_role(URL_FILTERING_CONTROL="READ_WRITE", SSL_POLICY="READ_ONLY", FIREWALL_CONTROL="READ_ONLY"))
    k = by_key(facts_for(client, ["zia_extras"]))
    assert k["zia_extras"]["status"] == "ok"


def test_a_role_without_feature_permissions_falls_back_to_its_policy_access():
    """ASVS V1.4.4 · CWE-284: a role that lists no feature permissions is judged by its policy access (read only: assess, not change)."""
    client = Fake(role={"id": 4711, "name": "Assessment API role", "policyAccess": "READ_ONLY"})
    k = by_key(facts_for(client, ["dlp"]))
    assert k["dlp"]["status"] == "ok" and k["deploy_packs"]["status"] == "read_only"


def test_a_missing_licence_greys_out_the_feature_with_who_to_ask():
    """ASVS V1.4.4 · CWE-284: no DLP subscription among the licences: the DLP scope and deploying are not licensed, with the subscription ids to ask for."""
    client = Fake(subs=[{"id": "URL_FILTER", "subscribed": True}])
    k = by_key(facts_for(client, ["dlp"]))
    assert k["dlp"]["status"] == "not_licensed" and "ZDLP_WEB" in " ".join(k["dlp"]["steps"])
    assert k["deploy_packs"]["status"] == "not_licensed"


@pytest.mark.parametrize("subs", [[], None, {"list": []}, "garbage", [None, 5, {"id": "<b>"}]])
def test_an_empty_or_odd_licence_list_never_greys_anything_out(subs):
    """ASVS V5.1.3 · CWE-20 · CWE-754: an empty, missing or malformed licence list is not evidence: no feature is marked not licensed."""
    k = by_key(facts_for(Fake(subs=subs), ["dlp"]))
    assert k["dlp"]["status"] == "ok" and k["deploy_packs"]["status"] == "ok"


def test_licence_rows_are_cleaned_and_their_end_dates_read():
    """ASVS V5.1.3 · CWE-20: subscription rows: ids validated, expired ones inactive, end dates in seconds or milliseconds, ending soon flagged."""
    rows = rd.parse_subscriptions(SUBS + [{"id": "x" * 100}, {"id": True}, {"id": "ZIA_ISO_25"}], now=NOW)
    ids = {r["id"]: r for r in rows}
    assert set(ids) == {"ZDLP_WEB", "URL_FILTER", "Z_DLP_ENDPOINT", "Z_CASB", "ZS_DP_EMAIL", "ZS_DP_GEN_AI", "ZIA_ISO_25"}
    assert ids["ZS_DP_GEN_AI"]["active"] is False and ids["Z_DLP_ENDPOINT"]["ending_soon"] is True
    assert ids["ZDLP_WEB"]["ends_on"] == "2028-02-19" and ids["ZIA_ISO_25"]["area"] == "Isolation"


def test_a_refused_product_has_no_access_and_the_steps_to_add_it():
    """ASVS V1.4.4 · CWE-284 · CWE-209: a product that answers 403 has no access, the steps say how to add its role, and the error text is not kept."""
    out = facts_for(Fake(deny=("zcc",)), ["zcc"])
    p = {x["product"]: x for x in out["products"]}["ZCC"]
    assert p["access"] == "none" and "403" in p["why"] and "API Clients" in " ".join(p["steps"])
    assert CANARY_SIG not in json.dumps(out)
    assert by_key(out)["zcc"]["status"] == "blocked"


def test_a_product_missing_from_the_token_is_blocked_even_out_of_scope():
    """ASVS V1.4.4 · CWE-284: the token lists no ZDX role: the ZDX scope is greyed out on the token's word without reading ZDX."""
    client = Fake()
    k = by_key(facts_for(client, ["zcc"]))
    assert k["zdx"]["status"] == "blocked" and "ZIdentity" in " ".join(k["zdx"]["steps"])
    assert not [c for c in client.calls if c.startswith("zdx")]


def test_a_view_only_zpa_role_cannot_move_segments():
    """ASVS V1.4.4 · CWE-284: a ZPA role with view-only application segments: ZPA reads work, moving domains between segments is read only."""
    zpa = [{"id": "216", "name": "API Full Access", "classPermissionGroups": [{"classPermissions": [
        {"classType": {"friendlyName": "Application Segment"}, "permission": {"type": "VIEW_ONLY"}}]}]}]
    k = by_key(facts_for(Fake(zpa_roles=zpa), ["zpa"]))
    assert k["zpa"]["status"] == "ok" and k["zpa_segment_moves"]["status"] == "read_only"


class _AiGuard(types.ModuleType):
    def __init__(self, fn):
        super().__init__("ai_guard")
        self.readiness = fn


@pytest.mark.parametrize("fn,state", [
    (lambda c: {"ok": True, "detail": "AI Guard answered"}, "ok"),
    (lambda c: (_ for _ in ()).throw(ApiError(403)), "denied"),
    (lambda c: "not a dict", "error"),
])
def test_ai_guard_uses_its_own_readiness_when_installed(monkeypatch, fn, state):
    """ASVS V5.1.3 · CWE-20 · CWE-209: ai_guard.readiness(client) is called through importlib when present; its answer is reduced to safe fields."""
    monkeypatch.setitem(sys.modules, "ai_guard", _AiGuard(fn))
    out = rd.read(Fake(), ["aiguard"], now=NOW)
    assert out["probes"]["ZGUARD"]["state"] == state
    assert CANARY_SIG not in json.dumps(out)


def test_ai_guard_without_its_module_is_judged_from_the_token(monkeypatch):
    """ASVS V1.4.4 · CWE-754: without the ai_guard module the check still runs; AI Guard is not asked."""
    monkeypatch.setitem(sys.modules, "ai_guard", None)   # import raises ImportError
    out = rd.read(Fake(), ["aiguard"], now=NOW)
    assert out["probes"]["ZGUARD"]["state"] == "not_checked"


# ── The catalogue: every Scope page key and every write feature ──────────

def _read(*parts):
    return open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def test_every_scope_page_key_and_every_write_kind_is_mapped():
    """ASVS V1.4.4 · SSDF PW.1.1 · CWE-1059: a new Scope page checkbox or write kind without a readiness mapping fails CI."""
    keys = set(re.findall(r'class="scope-cb" value="([a-z_]+)"', _read("static", "index.html")))
    assert keys and keys <= set(rd.SCOPE_FEATURES)
    assert set(permissions.WRITE_PERMISSIONS) == set(rd.WRITE_KINDS)
    for spec in rd.WRITE_FEATURES.values():
        assert set(spec.get("kinds", ())) | set(spec.get("optional_kinds", ())) <= set(rd.WRITE_KINDS)


def test_every_zia_permission_named_is_documented_by_the_sdk():
    """ASVS V1.14.6 · SSDF PW.4.1 · CWE-1104: the first spelling of every ZIA permission readiness checks is listed in the installed SDK's admin_roles."""
    import zscaler.zia.admin_roles as ar
    doc = open(ar.__file__, encoding="utf-8").read()
    needs = [alts for s in list(rd.SCOPE_FEATURES.values()) + list(rd.WRITE_KINDS.values())
             for alts in s.get("needs", []) + s.get("optional", [])]
    assert needs
    missing = sorted({alts[0] for alts in needs if f"`{alts[0]}`" not in doc})
    assert missing == []


def test_the_required_api_access_answer_carries_the_catalogue():
    """ASVS V1.4.4 · CWE-1059: /api/permissions/required (scope_permissions) carries the readiness map of every scope and write feature."""
    req = TestClient(srv.app).get("/api/permissions/required").json()
    cat = req["readiness"]
    assert {s["key"] for s in cat["scopes"]} == set(rd.SCOPE_FEATURES)
    assert {w["key"] for w in cat["writes"]} == set(rd.WRITE_FEATURES)
    assert "signature" in cat["note"]


# ── Required API access page and the Start page ──────────────────────────

def test_the_page_says_why_there_is_nothing_live_yet(monkeypatch):
    """WCAG 2.2 SC 3.3.2 · SC 1.3.1: with no readiness answer the page says why the live part is empty and what to do."""
    monkeypatch.setattr(srv, "_READINESS", type(srv._READINESS)())
    page = TestClient(srv.app).get("/permissions").text
    assert "No readiness check has run on this server yet" in page and "Authenticate" in page


def test_the_page_escapes_everything_the_tenant_says(monkeypatch):
    """ASVS V5.3.3 · CWE-79 · A03:2021 · WSTG-INPV-02: role names and licence names from the tenant are escaped on /permissions."""
    monkeypatch.setattr(srv, "_READINESS", type(srv._READINESS)())
    evil = "<img src=x onerror=alert(1)>"
    token = jwt({"service-info": [{"prd": "ZIA", "ext": {"rnm": evil, "rid": "1"}}]})
    out = rd.run(Fake(token, role=dict(FULL_ROLE, name=evil), subs=[{"id": "ZDLP_WEB", "sku": evil}]), ["dlp"], now=NOW, label="acme")
    srv._READINESS["acme"] = out
    page = TestClient(srv.app).get("/permissions").text
    assert evil not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


def test_the_page_tables_have_headers_captions_and_reflow():
    """WCAG 2.2 SC 1.3.1 · SC 1.4.10: the live tables have captions and header cells, and sit in a scrollable region so the page never scrolls sideways."""
    out = rd.run(Fake(), ["dlp", "zcc"], now=NOW, label="acme")
    html = rd.html_section([out])
    assert html.count("<caption>") == 2 and 'scope="col"' in html and 'scope="row"' in html
    assert html.count('class="rd-wrap" tabindex="0" role="region"') == 2


def test_the_start_page_runs_readiness_after_sign_in_and_greys_out_what_will_fail():
    """WCAG 2.2 SC 4.1.3 · SC 3.3.2 · ASVS V1.4.4: the guide starts readiness after a good sign-in; the summary is a status region linking to Required API access; blocked scopes are disabled with the steps."""
    guide, js = _read("static", "guide.js"), _read("static", "readiness.js")
    assert "window.dlpReadiness.signedIn(data.access)" in guide and "host.id = 'rdConnect'" in js and "closest('.actions')" in js
    assert 'role="status" aria-live="polite"' in js and 'href="/permissions"' in js
    assert "cb.disabled = true" in js and "aria-describedby', 'rdScopeNote'" in js
    assert "sessionStorage" in js and "localStorage" not in js      # this tab only
    assert ("readiness.js", "script") in srv.GUI_ADDONS


def test_deploy_studio_asks_readiness_before_a_write():
    """ASVS V1.4.4 · CWE-284: Deploy to tenant and the removal ask readiness first; a write the role cannot make is stopped with the steps."""
    dz = _read("static", "deploy_studio.js")
    assert "window.dlpReadiness.allowWrite('deploy_packs')" in dz and "window.dlpReadiness.allowWrite('remove_packs')" in dz
    assert "${_dzReadinessBlocks('deploy_packs') ? 'disabled aria-describedby=\"dzRdNote\" ' : ''}" in dz


def test_no_separate_readiness_page_or_toolbar_entry_exists():
    """WCAG 2.2 SC 3.2.4 · interface guide: readiness lives in Required API access and the Start page; there is no second page or toolbar button for it."""
    assert not os.path.exists(os.path.join(ROOT, "static", "report_readiness.html"))
    assert not [r for r in srv.app.routes if getattr(r, "path", "") == "/report/readiness"]
    assert "openReadinessTab" not in _read("static", "index.html")
    assert "X.readiness" not in _read("static", "explain.js")
