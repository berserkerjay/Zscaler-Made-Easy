"""The team server's additions: encryption at rest for every local store
with key rotation (store_crypto.py), FIPS mode, the idle-timeout warning,
the HTTP to HTTPS redirect, ownership and sharing of templates and saved
plans, and Let's Encrypt certificates through ACME dns-01 on Cloudflare
(server_acme.py) against a fake ACME server and a fake Cloudflare API.
No network: every outbound call goes to the fakes below."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

import audit
import change_queue
import deployments
import dlp_api_server as srv
import proposals
import server_acme
import server_tls
import sso
import store_crypto
import team_server as team
import tenant_profiles
import workspace_notes

from tests.test_team_server import ORIGIN, PW, _login, _profile, _user, team_on, world  # noqa: F401 - fixtures


# ── encryption at rest and key rotation ─────────────────────────────────
def _fill_every_store(tmp_path):
    pid = _profile("Secretco", "secretco.example")
    tenant_profiles.save_snapshot(json.dumps({"responses": {"marker": "SNAPSHOT-PLAIN"}}), {"label": "secretco"}, pid)
    team.create_user(username="enc-user", role="viewer", password=PW)
    change_queue.file_request(kind="pack_deploy", tenant="secretco.example", tenant_label="CQ-PLAIN", title="CQ-PLAIN", summary={},
                              items=[], plan_hash="p" * 64, requested_by="enc-user", payload={})
    deployments.add({"id": "dep-enc", "tenant_label": "DEP-PLAIN", "created": []})
    workspace_notes.apply("NOTES-PLAIN", "rule", "1", "add_tag", by="enc-user", tag="t")
    with proposals._locked():
        proposals._write(dict(proposals._read(), marker="PROP-PLAIN"))
    audit.record("enc_test", marker="AUDIT-PLAIN")
    # (wave 9) configuration backups with their index, a template and a configuration cache, and scheduled sync jobs
    import config_backup as cb
    import sync_jobs
    doc = cb.build_doc({"zia.rule_labels": [{"id": 1, "name": "BK-PLAIN label"}]}, {"tenant_label": "BK-PLAIN", "profile_id": pid})
    cb.save_backup(doc)
    cb.save_template(cb.make_template(doc, [{"type": "zia.rule_labels", "name": "BK-PLAIN label"}], name="TPL-PLAIN"), profile_id=pid)
    cb.refresh_cache(pid, {"zia.rule_labels": [{"id": 1, "name": "CACHE-PLAIN label"}]}, {"tenant_label": "CACHE-PLAIN"})
    with sync_jobs._locked():
        sync_jobs._write({"version": 1, "jobs": {"job-enc": {"id": "job-enc", "name": "SYNC-PLAIN"}}})
    return pid


def _store_files():
    return [e["path"] for e in store_crypto._store_paths()]


def sync_jobs_name():
    import sync_jobs
    return os.path.basename(sync_jobs.store_path())


def test_a_sealed_backup_list_without_its_key_is_an_error_not_an_empty_list(world, monkeypatch):
    """ASVS V6.2.2 · V7.4.1 · CWE-311 · CWE-459: a sealed backup index whose key is not here refuses (409 on the list) instead of reading as empty, and a new backup never replaces it."""
    import config_backup as cb
    monkeypatch.setenv("DLP_CHECK_STORE_ENCRYPTION", "1")
    doc = cb.build_doc({"zia.rule_labels": [{"id": 1, "name": "L"}]}, {"tenant_label": "acme"})
    cb.save_backup(doc)
    index = os.path.join(cb.backups_dir(), "index.json")
    with open(index, "w", encoding="utf-8") as f:
        f.write("ZMEENC1:deadbeef:AAAA")   # sealed with a key this computer does not hold
    with pytest.raises(cb.BackupError, match="encrypted"):
        cb.list_backups()
    with pytest.raises(cb.BackupError):
        cb.save_backup(doc)
    assert open(index, encoding="utf-8").read() == "ZMEENC1:deadbeef:AAAA", "the sealed list was not replaced"
    r = _login("root").get("/api/config-backups")
    assert r.status_code == 409 and "encrypted" in r.json()["detail"]


def test_sealed_sync_jobs_without_their_key_are_never_overwritten(team_on, monkeypatch):
    """ASVS V6.2.2 · CWE-311 · CWE-459: a sealed sync job store whose key is not here raises instead of reading as no jobs, so a write never replaces it."""
    import sync_jobs
    monkeypatch.setenv("DLP_CHECK_STORE_ENCRYPTION", "1")
    os.makedirs(os.path.dirname(sync_jobs.store_path()), exist_ok=True)
    with open(sync_jobs.store_path(), "w", encoding="utf-8") as f:
        f.write("ZMEENC1:deadbeef:AAAA")
    with pytest.raises(store_crypto.StoreLocked):
        sync_jobs._read()


def test_every_store_is_sealed_readable_and_survives_key_rotation(team_on, monkeypatch, tmp_path):
    """ASVS V6.1.1 · V6.2.1 · V6.4.2 · CWE-311 · CWE-312 · WSTG-CRYP-04: with encryption on every store is AES-256-GCM sealed (no plain text on disk), reads back, and survives a key rotation that re-seals all of them and forgets the old key."""
    monkeypatch.setenv("DLP_CHECK_STORE_ENCRYPTION", "1")
    pid = _fill_every_store(tmp_path)
    files = _store_files()
    names = {os.path.basename(p) for p in files}
    for want in ("tenant_profiles.json", "change_requests.json", "deployments.json", "proposals.json", "team_server.json", "audit.log"):
        assert want in names, (want, names)
    assert any(n.startswith("snap-") for n in names) and any("workspace_notes" in n for n in names)
    assert {"index.json", sync_jobs_name()} <= names, names
    for prefix in ("bk-", "tpl-", "cache-"):
        assert any(n.startswith(prefix) for n in names), (prefix, names)
    key_file = store_crypto.key_file()
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    old_key = store_crypto.status()["key"]
    for p in files:
        raw = open(p, encoding="utf-8").read()
        assert "PLAIN" not in raw and "Secretco" not in raw and PW not in raw, p
        assert all(ln.startswith(f"ZMEENC1:{old_key}:") for ln in raw.splitlines() if ln.strip()), p

    def read_everything():
        assert tenant_profiles.get(pid)["name"] == "Secretco"
        snap = tenant_profiles.list_snapshots(pid)[0]["id"]
        assert b"SNAPSHOT-PLAIN" in tenant_profiles.read_snapshot(snap, 1_000_000)
        assert team.find_user("enc-user")
        assert change_queue.list_requests("secretco.example")[0]["title"] == "CQ-PLAIN"
        assert deployments.get("dep-enc")["tenant_label"] == "DEP-PLAIN"
        assert workspace_notes.list_notes("NOTES-PLAIN")
        assert proposals._read()["marker"] == "PROP-PLAIN"
        assert any(e.get("marker") == "AUDIT-PLAIN" for e in audit.tail(50))
        import config_backup as cb
        import sync_jobs
        (bk,) = cb.list_backups(pid)
        assert bk["tenant_label"] == "BK-PLAIN" and cb.load_backup(bk["id"])["types"]["zia.rule_labels"][0]["name"] == "BK-PLAIN label"
        (tpl,) = cb.list_templates()
        assert tpl["name"] == "TPL-PLAIN" and cb.load_template(tpl["id"])["meta"]["name"] == "TPL-PLAIN"
        assert cb.read_cache(pid)["meta"]["tenant_label"] == "CACHE-PLAIN"
        assert sync_jobs._read()["jobs"]["job-enc"]["name"] == "SYNC-PLAIN"
    team._CACHE.update(key=None, data=None)
    read_everything()
    out = store_crypto.rotate()
    assert out["old_key"] == old_key and out["new_key"] != old_key
    assert set(store_crypto._load_ring()["keys"]) == {out["new_key"]}
    for p in _store_files():
        raw = open(p, encoding="utf-8").read()
        assert all(ln.startswith(f"ZMEENC1:{out['new_key']}:") for ln in raw.splitlines() if ln.strip()), p
    team._CACHE.update(key=None, data=None)
    read_everything()
    assert any(e.get("event") == "store_key_rotated" for e in audit.tail(50))
    # turning the setting off (the opt-out) never locks data away: sealed stores still read
    monkeypatch.setenv("DLP_CHECK_STORE_ENCRYPTION", "0")
    team._CACHE.update(key=None, data=None)
    read_everything()


def test_a_tampered_or_keyless_store_is_refused_and_self_healing_does_not_eat_sealed_stores(team_on, monkeypatch):
    """ASVS V6.2.2 · CWE-353 · CWE-354: a changed sealed store fails its authentication tag; self-healing reads sealed stores as what they hold instead of moving them aside."""
    monkeypatch.setenv("DLP_CHECK_STORE_ENCRYPTION", "1")
    _profile("Healco", "healco.example")
    p = tenant_profiles.store_path()
    raw = open(p, encoding="utf-8").read()
    import self_heal
    assert self_heal._valid_file(p, None)[0]
    res = self_heal.check_stores()
    assert not any("Tenant profiles" in a for a in res.get("actions") or []), res
    body = raw[raw.rindex(":") + 1:]
    flipped = raw[:raw.rindex(":") + 1] + ("A" if body[0] != "A" else "B") + body[1:]   # always a different first character
    with pytest.raises(store_crypto.StoreLocked):
        store_crypto.open_text(flipped)
    with pytest.raises(store_crypto.StoreLocked):
        store_crypto.open_text("ZMEENC1:deadbeef:AAAA")


def test_store_encryption_opt_out_keeps_plain_json(team_on, monkeypatch):
    """ASVS V14.1.1 · CWE-1188: with the opt-out (DLP_CHECK_STORE_ENCRYPTION=0; on is the default, tests/test_store_encryption_default.py) every store is the plain JSON it always was."""
    monkeypatch.setenv("DLP_CHECK_STORE_ENCRYPTION", "0")
    _profile("Plainco", "plainco.example")
    assert json.load(open(tenant_profiles.store_path(), encoding="utf-8"))["profiles"]["plainco"]["name"] == "Plainco"
    assert store_crypto.seal_text("x") == "x"


# ── FIPS mode ───────────────────────────────────────────────────────────
def test_fips_mode_uses_pbkdf2_refuses_scrypt_and_non_approved_token_algorithms(world, monkeypatch):
    """ASVS V2.4.3 · V6.2.2 · CWE-327: FIPS mode hashes passwords with PBKDF2-HMAC-SHA256, refuses the scrypt hashes made before (an administrator resets them), drops EdDSA ID tokens, and says honestly it is not a validated module."""
    monkeypatch.setenv("DLP_CHECK_FIPS_MODE", "1")
    h = team.hash_password(PW)
    assert h.startswith(f"pbkdf2_sha256${team.PBKDF2_ITERATIONS}$") and team.verify_password(PW, h)
    c = TestClient(srv.app)
    assert c.post("/api/auth/team/login", json={"username": "vic", "password": PW}).status_code == 401
    line = [e for e in audit.tail(50) if e.get("event") == "team_login_failed"][-1]
    assert "FIPS" in line["reason"]
    team.set_password(world["users"]["vic"]["id"], PW, by="root")
    assert c.post("/api/auth/team/login", json={"username": "vic", "password": PW}).status_code == 200
    assert "EdDSA" not in store_crypto.FIPS_ID_TOKEN_ALGORITHMS
    st = store_crypto.fips_status()
    assert st["on"] and "not" in st["honest_note"] and "validated" in st["honest_note"]


# ── idle-timeout warning ────────────────────────────────────────────────
def test_status_gives_the_idle_and_absolute_clock_and_every_page_warns(world):
    """ASVS V3.3.2 · CWE-613 · WCAG 2.2 SC 2.2.1: a signed-in status says how long the session may idle and when it ends, and the shared sign-in script warns before the idle sign-out with a way to stay."""
    st = _login("vic").get("/api/auth/status").json()
    assert st["idle_seconds"] == team.idle_seconds() and 0 < st["expires_in"] <= team.session_seconds()
    js = open(os.path.join(srv.STATIC_DIR, "ui_auth.js"), encoding="utf-8").read()
    assert "Still there?" in js and "Stay signed in" in js and "IDLE_WARN_S = 120" in js and "startIdleWatch(s)" in js
    assert "idle_seconds" not in TestClient(srv.app).get("/api/auth/status").json()


# ── HTTP → HTTPS redirect ───────────────────────────────────────────────
def test_plain_http_only_redirects_to_https(monkeypatch):
    """ASVS V9.1.1 · CWE-319 · CWE-601 · WSTG-CRYP-03: the plain-HTTP port answers only a 308 to the same path over HTTPS on the same host, and a bad Host gets 400, never a redirect elsewhere."""
    from starlette.testclient import TestClient as Raw
    c = Raw(server_tls.redirect_app(8443), base_url="http://team.example")
    r = c.get("/report/team?x=1", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "https://team.example:8443/report/team?x=1"
    assert "set-cookie" not in r.headers
    r = c.get("/", headers={"host": "evil.example/@x"}, follow_redirects=False)
    assert r.status_code == 400
    monkeypatch.setenv("ZSCALER_TLS", "self-signed")
    monkeypatch.setenv("ZSCALER_TLS_REDIRECT_PORT", "8080")
    assert server_tls.redirect_port() == 8080
    monkeypatch.delenv("ZSCALER_TLS")
    assert server_tls.redirect_port() is None


# ── ownership and sharing ───────────────────────────────────────────────
def test_saved_plans_are_private_until_shared_and_sharing_never_crosses_a_tenant(world):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a saved plan is its maker's; shared with someone who may read its tenant profile it opens for them; shared with someone who may not, it still does not."""
    olga = team.find_user("olga")
    tok = team.restore({"user": olga["id"], "username": "olga", "profile": world["a"], "action": "plan"})
    try:
        rid = srv._remember_plan({"status": "ready", "packs": []}, "olga")
    finally:
        team.reset(tok)
    url = f"/api/dlp-packs/plan/{rid}/export?format=json"
    vic, bea = _login("vic"), _login("bea")
    assert vic.get(url).status_code == 404                     # read on A, but not shared
    assert rid not in json.dumps(vic.get("/api/exports/plans").json())
    o = _login("olga")
    assert rid in json.dumps(o.get("/api/exports/plans").json())
    assert vic.post("/api/team/share", json={"kind": "plan", "id": rid, "principals": []}, headers=ORIGIN).status_code == 403
    r = o.post("/api/team/share", json={"kind": "plan", "id": rid, "principals": [f"user:{world['users']['vic']['id']}",
                                                                                f"user:{world['users']['bea']['id']}"]}, headers=ORIGIN)
    assert r.status_code == 200
    assert rid in json.dumps(vic.get("/api/exports/plans").json())
    assert vic.get(url).status_code != 404
    assert bea.get(url).status_code == 404                     # shared, but bea may not read profile A
    assert any(e.get("event") == "team_shared" for e in audit.tail(50))


def test_templates_are_owned_listed_for_owner_and_shares_and_deleted_by_owner_only(world, monkeypatch):
    """ASVS V4.2.1 · CWE-639 · CWE-285: a POV template a person saves on a team server is listed for them and whom they share it with, and only they or an administrator delete it."""
    import pov
    olga = team.find_user("olga")
    tok = team.restore({"user": olga["id"], "username": "olga", "profile": world["a"], "action": "plan"})
    try:
        t = pov.save_template({"intake": {"vertical": "general", "products": ["zia"]}, "criteria": []}, "Olga's plan", "", by="olga")
        team.set_owner("template", t["id"])
    finally:
        team.reset(tok)
    o, v = _login("olga"), _login("vic")
    assert t["id"] in json.dumps(o.get("/api/pov/catalog").json()["templates"])
    assert t["id"] not in json.dumps(v.get("/api/pov/catalog").json()["templates"])
    assert v.delete(f"/api/pov/templates/{t['id']}", headers=ORIGIN).status_code == 403
    o.post("/api/team/share", json={"kind": "template", "id": t["id"], "principals": [f"user:{world['users']['vic']['id']}"]}, headers=ORIGIN)
    assert t["id"] in json.dumps(v.get("/api/pov/catalog").json()["templates"])
    assert v.delete(f"/api/pov/templates/{t['id']}", headers=ORIGIN).status_code == 403
    assert o.delete(f"/api/pov/templates/{t['id']}", headers=ORIGIN).status_code == 200


# ── ACME dns-01 on Cloudflare (fakes) ───────────────────────────────────
ACME = "https://acme.fake.test"
CF_TOKEN = "cf-test-token-0123456789"


class _R:
    def __init__(self, status=200, body=None, headers=None, raw=None):
        self.status_code = status
        self.headers = headers or {}
        self.content = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FakeNet:
    """A fake ACME CA (RFC 8555) and Cloudflare API. Checks every JWS
    signature and nonce, and validates dns-01 against the TXT records the
    client made through the fake Cloudflare."""

    def __init__(self, other_host_directory=False):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake test CA")])
        now = dt.datetime.now(dt.timezone.utc)
        self.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.ca_key.public_key())
                   .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
                   .sign(self.ca_key, hashes.SHA256()))
        self.nonces, self.accounts, self.txt, self.authz, self.order, self.cert_pem = set(), {}, {}, {}, None, None
        self.other_host_directory = other_host_directory
        self.cf_calls, self.n = [], 0

    def _nonce(self):
        self.n += 1
        n = f"nonce{self.n}"
        self.nonces.add(n)
        return {"Replay-Nonce": n}

    def get(self, url, params=None, headers=None, **kw):
        if url == ACME + "/directory":
            base = "https://elsewhere.test" if self.other_host_directory else ACME
            return _R(200, {"newNonce": base + "/nonce", "newAccount": ACME + "/acct", "newOrder": ACME + "/order"})
        if url.startswith(server_acme.CLOUDFLARE_API):
            return self._cf("GET", url, params, headers, None)
        raise AssertionError(f"unexpected GET {url}")

    def head(self, url, **kw):
        assert url == ACME + "/nonce"
        return _R(200, headers=self._nonce())

    def delete(self, url, headers=None, **kw):
        return self._cf("DELETE", url, None, headers, None)

    def _cf(self, method, url, params, headers, data):
        assert headers["Authorization"] == f"Bearer {CF_TOKEN}"
        self.cf_calls.append((method, url))
        path = url[len(server_acme.CLOUDFLARE_API):]
        if method == "GET" and path == "/zones":
            return _R(200, {"success": True, "result": [{"id": "z1"}] if params["name"] == "example.test" else []})
        if method == "POST" and path == "/zones/z1/dns_records":
            rec = json.loads(data)
            rid = f"r{len(self.txt) + 1}"
            self.txt[rid] = rec
            return _R(200, {"success": True, "result": {"id": rid}})
        if method == "DELETE" and path.startswith("/zones/z1/dns_records/"):
            self.txt.pop(path.rsplit("/", 1)[1], None)
            return _R(200, {"success": True, "result": {}})
        raise AssertionError(f"unexpected Cloudflare {method} {path}")

    def _verify(self, body):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        jws = json.loads(body)
        prot = json.loads(_b64d(jws["protected"]))
        assert prot["alg"] == "ES256" and prot["nonce"] in self.nonces
        self.nonces.discard(prot["nonce"])
        jwk = prot.get("jwk") or self.accounts[prot["kid"]]
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"), ec.SECP256R1()).public_key()
        sig = _b64d(jws["signature"])
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                   f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
        payload = json.loads(_b64d(jws["payload"])) if jws["payload"] else None
        return prot, jwk, payload

    def post(self, url, data=None, headers=None, **kw):
        if url.startswith(server_acme.CLOUDFLARE_API):
            return self._cf("POST", url, None, headers, data)
        prot, jwk, payload = self._verify(data)
        assert prot["url"] == url
        h = self._nonce()
        path = url[len(ACME):]
        if path == "/acct":
            self.accounts[ACME + "/acct/1"] = jwk
            return _R(201, {"status": "valid"}, dict(h, Location=ACME + "/acct/1"))
        if path == "/order":
            names = [i["value"] for i in payload["identifiers"]]
            for i, n in enumerate(names):
                self.authz[str(i)] = {"name": n, "token": f"tok{i}", "status": "pending", "jwk": jwk}
            self.order = {"status": "pending", "authorizations": [f"{ACME}/authz/{i}" for i in range(len(names))], "finalize": ACME + "/finalize", "names": names}
            return _R(201, self.order, dict(h, Location=ACME + "/order/1"))
        if path.startswith("/authz/"):
            a = self.authz[path.rsplit("/", 1)[1]]
            return _R(200, {"status": a["status"], "identifier": {"type": "dns", "value": a["name"]},
                            "challenges": [{"type": "http-01", "url": ACME + "/x", "token": "no"},
                                           {"type": "dns-01", "url": f"{ACME}/chall/{path.rsplit('/', 1)[1]}", "token": a["token"]}]}, h)
        if path.startswith("/chall/"):
            a = self.authz[path.rsplit("/", 1)[1]]
            thumb = base64.urlsafe_b64encode(hashlib.sha256(json.dumps({k: a["jwk"][k] for k in ("crv", "kty", "x", "y")}, sort_keys=True, separators=(",", ":")).encode()).digest()).rstrip(b"=").decode()
            want = base64.urlsafe_b64encode(hashlib.sha256(f"{a['token']}.{thumb}".encode()).digest()).rstrip(b"=").decode()
            ok = any(r["name"] == f"_acme-challenge.{a['name']}" and r["content"] == want and r["type"] == "TXT" for r in self.txt.values())
            a["status"] = "valid" if ok else "invalid"
            return _R(200, {"status": "processing"}, h)
        if path == "/finalize":
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            csr = x509.load_der_x509_csr(_b64d(payload["csr"]))
            assert all(a["status"] == "valid" for a in self.authz.values())
            now = dt.datetime.now(dt.timezone.utc)
            leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.ca.subject).public_key(csr.public_key())
                    .serial_number(2).not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
                    .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical=False)
                    .sign(self.ca_key, hashes.SHA256()))
            self.cert_pem = leaf.public_bytes(serialization.Encoding.PEM) + self.ca.public_bytes(serialization.Encoding.PEM)
            self.order.update(status="valid", certificate=ACME + "/cert/1")
            return _R(200, self.order, h)
        if path == "/order/1":
            return _R(200, self.order, h)
        if path == "/cert/1":
            return _R(200, raw=self.cert_pem, headers=h)
        raise AssertionError(f"unexpected POST {url}")


@pytest.fixture
def acme_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ZSCALER_TLS", "acme")
    monkeypatch.setenv("ZSCALER_ACME_DOMAINS", "team.example.test")
    monkeypatch.setenv("ZSCALER_ACME_DIRECTORY", ACME + "/directory")
    monkeypatch.setenv("DLP_CHECK_TLS_DIR", str(tmp_path / "tls"))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.setattr(server_acme, "_sleep", lambda s: None)
    server_acme.set_cloudflare_token(CF_TOKEN)
    return tmp_path / "tls"


def test_acme_dns01_issues_a_certificate_through_cloudflare_and_cleans_up(acme_env):
    """ASVS V9.2.1 · V6.4.1 · CWE-295 · CWE-522: dns-01 sets the right TXT record through Cloudflare, every request is a valid ES256 JWS with a fresh nonce, the certificate matches the key and names, the TXT record is removed, keys and the token are owner-only and the token is never logged."""
    net = FakeNet()
    info = server_acme.ensure(session=net, log=lambda *a: None)
    assert info["acme"] and info["generated"] and not net.txt
    from cryptography import x509
    leaf = x509.load_pem_x509_certificates(open(info["cert"], "rb").read())[0]
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["team.example.test"]
    for f in (info["key"], os.path.join(acme_env, server_acme.ACCOUNT_KEY_FILE), os.path.join(acme_env, server_acme.TOKEN_FILE)):
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600, f
    assert CF_TOKEN not in open(audit.path(), encoding="utf-8").read()
    assert any(e.get("event") == "acme_certificate_issued" for e in audit.tail(20))
    again = server_acme.ensure(session=FakeNet(), log=lambda *a: None)       # still valid: reused, nothing fetched
    assert not again["generated"] and again["fingerprint"] == info["fingerprint"]


def test_acme_refuses_plain_http_other_hosts_and_a_missing_token(acme_env, monkeypatch):
    """ASVS V12.6.1 · V9.2.1 · CWE-918 · CWE-319: the ACME directory must be https, every address it names must be on its own host, and with no token stored nothing is issued."""
    monkeypatch.setenv("ZSCALER_ACME_DIRECTORY", "http://acme.fake.test/directory")
    with pytest.raises(server_acme.AcmeError, match="https"):
        server_acme.issue(session=FakeNet())
    monkeypatch.setenv("ZSCALER_ACME_DIRECTORY", ACME + "/directory")
    with pytest.raises(server_acme.AcmeError, match="own host"):
        server_acme.issue(session=FakeNet(other_host_directory=True))
    os.unlink(os.path.join(acme_env, server_acme.TOKEN_FILE))
    with pytest.raises(server_acme.AcmeError, match="Cloudflare API token"):
        server_acme.issue(session=FakeNet())
    monkeypatch.delenv("DLP_CHECK_SECRET_STORE")
    with pytest.raises(server_acme.AcmeError, match="credential store"):
        server_acme.set_cloudflare_token(CF_TOKEN)
    monkeypatch.setenv("ZSCALER_ACME_DOMAINS", "bad name!")
    with pytest.raises(server_acme.AcmeError):
        server_acme.domains()


def test_acme_is_off_by_default():
    """ASVS V14.1.1 · CWE-1188: no ACME and no outbound call unless ZSCALER_TLS=acme."""
    assert not server_acme.requested() and server_tls.ensure() is None


# ── ACME renewal while the server runs (renew_once, the daily check) ─────
def _cert_with_days_left(folder, days):
    """A served certificate (and its key) in the TLS folder that has `days` left."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "team.example.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - dt.timedelta(days=60)).not_valid_after(now + dt.timedelta(days=days, hours=1))
            .sign(key, hashes.SHA256()))
    os.makedirs(folder, exist_ok=True)
    cert_path, key_path = os.path.join(folder, server_tls.CERT_FILE), os.path.join(folder, server_tls.KEY_FILE)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return server_tls.fingerprint(cert_path)


class _FakeTlsContext:
    """Stands in for the running server's ssl.SSLContext: records the
    certificate chains loaded into it."""

    def __init__(self):
        self.loaded = []

    def load_cert_chain(self, certfile, keyfile=None):
        self.loaded.append((certfile, keyfile))


def test_acme_renew_once_renews_a_certificate_with_29_days_left_and_reloads_the_served_context(acme_env, monkeypatch):
    """ASVS V9.1.2 · V14.1.1 · CWE-298 · WSTG-CRYP-01: with 29 days left the check renews through the fake ACME server, loads the new certificate into the running TLS context (no restart) and audits it."""
    old_fp = _cert_with_days_left(str(acme_env), 29)
    ctx = _FakeTlsContext()
    monkeypatch.setattr(server_acme, "_CONTEXTS", [])
    server_acme.register_context(ctx)
    out = server_acme.renew_once(session=FakeNet(), log=lambda *a: None)
    assert out["renewed"] and out["reloaded"] == 1 and not out["restart_needed"] and out["days_left"] > 30
    assert out["fingerprint"] != old_fp
    assert ctx.loaded == [(os.path.join(str(acme_env), server_tls.CERT_FILE), os.path.join(str(acme_env), server_tls.KEY_FILE))]
    ev = [e for e in audit.tail(20) if e.get("event") == "acme_certificate_reloaded"]
    assert ev and ev[-1]["contexts"] == 1
    assert CF_TOKEN not in open(audit.path(), encoding="utf-8").read()


def test_acme_renew_once_with_a_failed_renewal_keeps_the_old_certificate_and_audits_it(acme_env, monkeypatch):
    """ASVS V7.2.2 · V9.1.2 · CWE-298 · CWE-778: a renewal that fails (no Cloudflare token) keeps serving the old certificate, reloads nothing and writes an audit event."""
    old_fp = _cert_with_days_left(str(acme_env), 29)
    os.unlink(os.path.join(str(acme_env), server_acme.TOKEN_FILE))
    ctx = _FakeTlsContext()
    monkeypatch.setattr(server_acme, "_CONTEXTS", [])
    server_acme.register_context(ctx)
    out = server_acme.renew_once(session=FakeNet(), log=lambda *a: None)
    assert not out["renewed"] and out["reloaded"] == 0 and out["fingerprint"] == old_fp and 28 < out["days_left"] <= 30
    assert server_tls.fingerprint(os.path.join(str(acme_env), server_tls.CERT_FILE)) == old_fp and ctx.loaded == []
    assert any(e.get("event") == "acme_renewal_failed" for e in audit.tail(20))


def test_acme_renew_once_says_restart_needed_when_no_context_can_be_reloaded(acme_env, monkeypatch):
    """ASVS V14.1.1 · CWE-298: a renewal with no reloadable TLS context says a restart is needed and audits that."""
    _cert_with_days_left(str(acme_env), 29)
    monkeypatch.setattr(server_acme, "_CONTEXTS", [])
    out = server_acme.renew_once(session=FakeNet(), log=lambda *a: None)
    assert out["renewed"] and out["restart_needed"] and out["reloaded"] == 0
    assert any(e.get("event") == "acme_certificate_renewed_restart_needed" for e in audit.tail(20))


def test_acme_a_certificate_with_more_than_30_days_left_is_not_renewed(acme_env, monkeypatch):
    """ASVS V9.1.2 · CWE-298: with 45 days left the check fetches nothing and reloads nothing."""
    fp = _cert_with_days_left(str(acme_env), 45)
    ctx = _FakeTlsContext()
    monkeypatch.setattr(server_acme, "_CONTEXTS", [ctx])
    net = FakeNet()
    out = server_acme.renew_once(session=net, log=lambda *a: None)
    assert not out["renewed"] and out["fingerprint"] == fp and ctx.loaded == [] and net.n == 0


def test_acme_the_check_runs_daily_by_default_within_bounds(monkeypatch):
    """ASVS V14.1.1 · CWE-1188: the background check runs every 24 hours unless set, held between 1 and 168 hours."""
    monkeypatch.delenv("ZSCALER_ACME_CHECK_HOURS", raising=False)
    assert server_acme.check_seconds() == 24 * 3600
    for raw, hours in (("6", 6), ("0", 1), ("9999", 168), ("soon", 24)):
        monkeypatch.setenv("ZSCALER_ACME_CHECK_HOURS", raw)
        assert server_acme.check_seconds() == hours * 3600, raw
