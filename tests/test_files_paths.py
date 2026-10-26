"""File and path handling (QA check T11): uploads (Client Connector log
bundles, PAC files, packs, vendor migration exports), the ids and names that
reach the filesystem, archive bombs and the permissions of what the app
writes. Everything runs in memory or in the test's own tmp folder."""
from __future__ import annotations

import base64
import bz2
import io
import json
import lzma
import os
import re
import stat
import tarfile
import tempfile
import zipfile

import pytest
from fastapi.testclient import TestClient

import log_analyzer as la
import pack_library
import safe_files
import vendor_migrate


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


LOG_LINE = "2026-09-01 08:00:04.100(-0500)[1234:11] ERR ZSATunnel: Tunnel to gateway.zscalerthree.net failed\n"


class _CountingDecompressor:
    """Wraps a real bz2 / lzma decompressor and adds every byte it hands out to `counter`."""

    def __init__(self, real, counter, *args, **kwargs):
        self._real, self._counter = real(*args, **kwargs), counter

    def decompress(self, data, max_length=-1):
        out = self._real.decompress(data, max_length)
        self._counter["bytes"] += len(out)
        return out

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
def inflated(monkeypatch):
    """How many bytes bz2 and lzma decompressors produced during the test."""
    counter = {"bytes": 0}
    real_bz2, real_lzma = bz2.BZ2Decompressor, lzma.LZMADecompressor
    monkeypatch.setattr(bz2, "BZ2Decompressor", lambda *a, **k: _CountingDecompressor(real_bz2, counter, *a, **k))
    monkeypatch.setattr(lzma, "LZMADecompressor", lambda *a, **k: _CountingDecompressor(real_lzma, counter, *a, **k))
    return counter


def _zip(members, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


# ── Archive bombs: ZIP members ───────────────────────────────────────────
ZEROS = b"\0" * (2 * 1024 * 1024)
POLICY = json.dumps({"policyName": "P1", "rules": []}).encode()


def _read_logs(data):
    members, notes = la.expand([{"name": "bundle.zip", "content": _b64(data), "encoding": "base64"}])
    return [n for n, _ in members], notes


def _read_pack(data):
    return [n for n, _ in pack_library._expand([{"name": "pack.zip", "content": _b64(data), "encoding": "base64"}])], []


def _read_vendor(data):
    return [n for n, _ in vendor_migrate._unzip(data, "export.zip")], []


READERS = [("logs", _read_logs, "zcc.log"), ("packs", _read_pack, "dlp_engines.json"), ("vendor", _read_vendor, "policy.json")]


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA], ids=["bzip2", "lzma"])
@pytest.mark.parametrize("reader,read,member", READERS, ids=[r[0] for r in READERS])
def test_zip_members_compressed_with_bzip2_or_lzma_are_never_inflated(reader, read, member, method, inflated):
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: a BZIP2/LZMA member, which zipfile inflates a whole block at a time before any size cap applies, is refused unread."""
    data = _zip([(member, ZEROS)], method)
    if reader == "logs":
        names, notes = read(data)
        assert names == []
        assert any(member in n and "only stored and deflate" in n for n in notes)
    else:
        with pytest.raises(ValueError, match="only stored and deflate"):
            read(data)
    assert inflated["bytes"] == 0


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED], ids=["stored", "deflate"])
@pytest.mark.parametrize("reader,read,member", READERS, ids=[r[0] for r in READERS])
def test_stored_and_deflate_members_are_still_read(reader, read, member, method):
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: the methods real bundles, packs and exports use keep working."""
    payload = {"logs": LOG_LINE.encode(), "packs": b"[]", "vendor": POLICY}[reader]
    names, _ = read(_zip([(member, payload)], method))
    assert [os.path.basename(n) for n in names] == [member]


@pytest.mark.parametrize("size,ok", [(64, True), (65, False)], ids=["at-limit", "one-past"])
def test_zip_member_reads_up_to_its_limit_and_no_further(size, ok):
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: the limit is inclusive and one byte more is refused."""
    z = zipfile.ZipFile(io.BytesIO(_zip([("a.log", b"x" * size)])))
    if ok:
        assert safe_files.zip_member(z, z.infolist()[0], 64) == b"x" * 64
    else:
        with pytest.raises(safe_files.ArchiveRefused):
            safe_files.zip_member(z, z.infolist()[0], 64)


@pytest.mark.parametrize("reader,read,member", READERS, ids=[r[0] for r in READERS])
def test_a_zip_member_that_lies_about_its_size_is_refused_not_a_server_error(reader, read, member):
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: data longer than the declared size is never returned past the claim; the CRC mismatch is a refusal."""
    data = bytearray(_zip([(member, b"x" * 4096)]))
    z = zipfile.ZipFile(io.BytesIO(bytes(data)))
    info = z.infolist()[0]
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 24:cd + 28] = (10).to_bytes(4, "little")   # central directory: uncompressed size 10
    if reader == "logs":
        names, notes = read(bytes(data))
        assert names == [] and any(member in n and "damaged" in n for n in notes)
    else:
        with pytest.raises(ValueError, match="damaged"):
            read(bytes(data))
    assert info.file_size == 4096


def test_an_encrypted_zip_member_is_refused():
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: a password-protected member is refused with a reason, not a server error."""
    z = zipfile.ZipFile(io.BytesIO(_zip([("a.log", b"x")])))
    info = z.infolist()[0]
    info.flag_bits |= 0x1
    with pytest.raises(safe_files.ArchiveRefused, match="password"):
        safe_files.zip_member(z, info, 64)


# ── Archive bombs: compressed tar streams ───────────────────────────────
def _tar_bz2(members) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as t:
        for info, data in members:
            t.addfile(info, io.BytesIO(data))
    return bz2.compress(raw.getvalue(), 9)


def _member(name, data, **pax):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.pax_headers = pax
    return info, data


@pytest.fixture
def small_caps(monkeypatch):
    monkeypatch.setattr(la, "MAX_TOTAL_BYTES", 256 * 1024)
    monkeypatch.setattr(la, "MAX_MEMBER_BYTES", 128 * 1024)


def test_skipping_a_huge_tar_member_never_inflates_past_the_total_cap(small_caps, inflated):
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: a member the budget refuses is not decompressed just to step over it."""
    big = 4 * 1024 * 1024
    data = _tar_bz2([_member("huge.log", b"\0" * big), _member("after.log", LOG_LINE.encode())])
    members, notes = la.expand([{"name": "bundle.tar", "content": _b64(data), "encoding": "base64"}])
    assert [n for n, _ in members] == []
    assert any("stopped after" in n and "rest was not read" in n for n in notes)
    assert inflated["bytes"] < la.MAX_TOTAL_BYTES + la._TAR_SLACK + 64 * 1024 < big


def test_a_huge_pax_header_is_never_inflated_past_the_total_cap(small_caps, inflated):
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: an extended header tarfile would read whole is cut at the cap."""
    big = 4 * 1024 * 1024
    data = _tar_bz2([_member("a.log", LOG_LINE.encode(), comment="x" * big)])
    members, notes = la.expand([{"name": "bundle.tar", "content": _b64(data), "encoding": "base64"}])
    assert members == []
    assert any("stopped after" in n for n in notes)
    assert inflated["bytes"] < la.MAX_TOTAL_BYTES + la._TAR_SLACK + 64 * 1024 < big


def test_a_tar_stops_at_the_member_cap_instead_of_walking_the_rest(monkeypatch):
    """ASVS V12.1.3 · CWE-409 · A04:2021 · WSTG-BUSL-09: past the member cap the archive is left, not walked to its end."""
    monkeypatch.setattr(la, "MAX_MEMBERS", 2)
    data = _tar_bz2([_member(f"f{i}.log", LOG_LINE.encode()) for i in range(6)])
    members, notes = la.expand([{"name": "bundle.tar", "content": _b64(data), "encoding": "base64"}])
    assert len(members) == 2
    assert sum("stopped after 2 files" in n for n in notes) == 1


@pytest.mark.parametrize("compress,name", [
    (lambda b: b, "logs.tar"), (lambda b: __import__("gzip").compress(b), "logs.tgz"),
    (lambda b: bz2.compress(b), "logs.tar"), (lambda b: lzma.compress(b), "logs.tar"),
], ids=["plain", "gzip", "bzip2", "xz"])
def test_tar_bundles_in_every_compression_are_still_read(compress, name):
    """ASVS V12.1.2 · CWE-409 · A04:2021 · WSTG-BUSL-09: the capped stream still reads plain, gzip, bzip2 and xz tar bundles."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as t:
        info, data = _member("logs/ZSATunnel.log", LOG_LINE.encode())
        t.addfile(info, io.BytesIO(data))
    members, notes = la.expand([{"name": name, "content": _b64(compress(raw.getvalue())), "encoding": "base64"}])
    assert [n for n, _ in members] == ["ZSATunnel.log"], notes


# ── XML and JSON in vendor migration exports ─────────────────────────────
DTD_XML = ('<?xml version="1.0" encoding="{enc}"?><!DOCTYPE x [<!ENTITY e "EXPANDED">]>'
           '<policies><policy id="1" name="&e;"><rules/></policy></policies>')
EXT_DTD_XML = '<?xml version="1.0" encoding="{enc}"?><!DOCTYPE x SYSTEM "file:///etc/passwd"><policies><policy id="1" name="n"/></policies>'


@pytest.mark.parametrize("enc", ["utf-8", "utf-16", "utf-16-be"])
@pytest.mark.parametrize("doc", [DTD_XML, EXT_DTD_XML], ids=["internal-entity", "external-dtd"])
@pytest.mark.parametrize("vendor", ["symantec", "skyhigh"])
def test_a_dtd_is_refused_in_any_encoding(vendor, doc, enc):
    """ASVS V5.5.2 · CWE-611 · CWE-776 · A05:2021 · WSTG-INPV-07: DOCTYPE and entities are refused whether the export is UTF-8 or UTF-16."""
    text = doc.format(enc="UTF-16" if enc.startswith("utf-16") else enc.upper())
    data = (b"\xfe\xff" + text.encode("utf-16-be")) if enc == "utf-16-be" else text.encode(enc)   # big-endian, with its BOM
    with pytest.raises(ValueError, match="DTD/entities are not accepted"):
        vendor_migrate.inventory_export(vendor, data, "export.xml")


@pytest.mark.parametrize("enc", ["utf-8", "utf-16"])
def test_an_xml_export_without_a_dtd_is_read_in_utf8_and_utf16(enc):
    """ASVS V5.5.2 · CWE-611 · A05:2021 · WSTG-INPV-07: the guard refuses DTDs only; a plain UTF-16 export is still read."""
    xml = f'<?xml version="1.0" encoding="{enc.upper()}"?><policies><policy id="7" name="Card numbers"/></policies>'
    snap = vendor_migrate.inventory_bytes(xml.encode(enc), "export.xml")
    assert [p["name"] for p in snap["policies"]] == ["Card numbers"]


DEEP_JSON = "[" * 100000 + "]" * 100000


@pytest.mark.parametrize("vendor", sorted(v for v, m in vendor_migrate.VENDORS.items() if m["status"] == "available" and ".json" in m["accepts"]))
def test_deeply_nested_json_exports_are_refused_not_a_server_error(vendor):
    """ASVS V7.4.1 · CWE-674 · A04:2021 · WSTG-ERRH-01: a JSON export nested past what the parser walks is a 400 with a reason, never a 500."""
    import dlp_api_server as srv
    r = TestClient(srv.app, raise_server_exceptions=False).post(
        "/api/vendor-migrate/inventory", json={"vendor": vendor, "export": {"name": "export.json", "content": DEEP_JSON}})
    assert r.status_code == 400 and "nested too deeply" in r.json()["detail"]


def test_a_deeply_nested_decisions_file_is_refused_not_a_server_error():
    """ASVS V7.4.1 · CWE-674 · A04:2021 · WSTG-ERRH-01: the decisions upload is read with the same guard."""
    xml = '<policies><policy id="7" name="Card numbers"/></policies>'
    with pytest.raises(ValueError, match="nested too deeply"):
        vendor_migrate.compile_upload("symantec", {"name": "export.xml", "content": xml}, {"name": "d.json", "content": DEEP_JSON})


DEEP_TF = {"list": 'resource "zia_dlp_engines" "a" {\n x = ' + "[" * 50000 + "]" * 50000 + "\n}\n",
           "block": 'resource "zia_dlp_engines" "a" ' + "{ a = " * 20000 + "1" + " }" * 20000 + "\n"}


@pytest.mark.parametrize("route", ["/api/pack-library/preview", "/api/pack-library/upload"])
@pytest.mark.parametrize("shape", sorted(DEEP_TF))
def test_deeply_nested_terraform_in_a_pack_upload_is_refused_not_a_server_error(route, shape, isolated_app):
    """ASVS V7.4.1 · CWE-674 · A04:2021 · WSTG-ERRH-01: an HCL file nested past what the reader walks is refused with a reason, never a 500."""
    client, tmp, _canary = isolated_app
    r = client.post(route, json={"files": [{"name": "main.tf", "content": DEEP_TF[shape]}], "pack_id": "deep"})
    assert r.status_code in (200, 400), r.text
    body = r.json()
    assert "nested too deeply" in (body.get("detail") or " ".join(body.get("problems") or []))
    assert not (tmp / "user_packs" / "deep").exists()


@pytest.fixture
def csv_limit():
    """The csv module's field limit is process-wide (another module raises it): pinned to its default here."""
    import csv
    old = csv.field_size_limit(131072)
    try:
        yield 131072
    finally:
        csv.field_size_limit(old)


@pytest.mark.parametrize("extra", [0, 1, 250000], ids=["at-csv-limit", "one-past", "far-past"])
def test_a_csv_export_with_an_oversized_field_is_refused_not_a_server_error(extra, csv_limit):
    """ASVS V7.4.1 · CWE-755 · A04:2021 · WSTG-ERRH-01: a field past the csv module's limit is a 400 with a reason, never a 500."""
    import dlp_api_server as srv
    text = "policy,rule\n" + "a" * (csv_limit + extra) + ",x\n"
    r = TestClient(srv.app, raise_server_exceptions=False).post(
        "/api/vendor-migrate/inventory", json={"vendor": "netskope", "export": {"name": "export.csv", "content": text}})
    assert r.status_code == 400, r.text
    if extra:
        assert "not a CSV export this reader can read" in r.json()["detail"]


def test_each_log_line_is_read_only_up_to_its_cap(monkeypatch):
    """ASVS V12.1.2 · CWE-400 · A04:2021 · WSTG-BUSL-09: a crafted megabyte-long line costs the signatures no more than MAX_LINE_CHARS."""
    longest = {"n": 0}

    class _Spy:
        def __init__(self, pat):
            self._pat = pat

        def search(self, text, *a):
            longest["n"] = max(longest["n"], len(text))
            return self._pat.search(text, *a)

    monkeypatch.setattr(la, "_COMPILED", [(s, _Spy(p), x) for s, p, x in la._COMPILED])
    line = "2026-09-01 08:00:01 ERR password=" + "a" * (la.MAX_LINE_CHARS * 64)
    la.analyze([{"name": "one.log", "content": line + "\n" + LOG_LINE}])
    assert 0 < longest["n"] <= la.MAX_LINE_CHARS


# ── Temporary copies of the assessment ───────────────────────────────────
def test_a_failed_word_report_leaves_no_temporary_copy(monkeypatch, tmp_path):
    """ASVS V8.1.2 · CWE-459 · A04:2021 · WSTG-CONF-09: the temporary .docx is removed when generation fails, as it is after a download."""
    import dlp_api_server as srv
    import report_docx

    def half_written(results, cfg, path, *a, **k):
        with open(path, "wb") as f:
            f.write(b"partial assessment")
        raise KeyError("label")
    monkeypatch.setattr(report_docx, "generate_report", half_written)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    r = TestClient(srv.app, raise_server_exceptions=False).post(
        "/api/report/docx", json={"checks": [{"id": "x", "status": "FAIL"}], "metadata": {"org": "Acme"}})
    assert r.status_code == 500
    assert list(tmp_path.iterdir()) == []


# ── Permissions of everything the app writes ─────────────────────────────
@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def _pack():
    return {"meta": {"name": "Probe pack"}, "dictionaries": [{"name": "D1", "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "secret"}]}],
            "engines": [{"name": "E1", "expression": "((D:D1 > 0))"}],
            "policies": [{"name": "R1", "engines": ["E1"], "state": "DISABLED", "action": "ALLOW"}]}


def _w_digest(d, mp):
    import continuous_eval
    mp.setenv("DLP_CHECK_DIGESTS", str(d / "digests"))
    continuous_eval.write_digest({"id": "20260101-000000", "at": "2026-01-01T00:00:00+00:00", "summary": {}, "tenants": [], "errors": []})


def _w_ssl_history(d, mp):
    import ssl_coverage
    ssl_coverage.record("Acme", {"summary": {}}, path=str(d / "cache" / "ssl_coverage_history.json"))


def _w_beacon(d, mp):
    import beacon
    beacon.save_history([{"at": "2026-01-01"}], path=str(d / "cache" / "beacon_state.json"))


def _w_guidance(d, mp):
    import guidance
    mp.setenv("DLP_CHECK_GUIDANCE_STATE", str(d / "data" / "guidance_state.json"))
    (d / "data").mkdir(mode=0o700)
    guidance.save_state({"seen": {}, "sources": {}})


def _w_pack_upload(d, mp):
    pack_library.save_pack(_pack(), root=str(d / "packs"))


def _w_pack_terraform(d, mp):
    import pack_terraform
    pack_terraform.write_workspace({"main.tf": "# x\n", "README.md": "x\n"}, str(d / "packs" / "p" / "terraform"))


def _w_pack_from_tenant(d, mp):
    import pack_from_tenant
    pack_from_tenant.write_pack(str(d / "pack"), [{"name": "Python Signal"}], [{"name": "E", "expression": "((D:Python Signal > 0))"}])


def _w_caches(d, mp):
    import bp_crawler
    import zscaler_best_practices
    import zscaler_update_check
    mp.setenv("XDG_CACHE_HOME", str(d / "xdg"))
    bp_crawler._save_cache({"a": 1})
    zscaler_best_practices.save_discovered([{"url": "https://example.invalid/t11", "title": "t"}])
    zscaler_update_check._save_cache({"a": 1})


def _w_stores_in_a_new_folder(d, mp):
    import change_queue
    import deployments
    import posture_plus
    import tenant_profiles
    import workspace_notes
    for env, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLPCHECK_CHANGE_QUEUE_FILE", "change_requests.json"), ("DLP_CHECK_WORKSPACE_NOTES", "workspace_notes.json"),
                      ("DLP_CHECK_POSTURE_SETTINGS", "posture_settings.json")):
        mp.setenv(env, str(d / "new" / env.lower() / name))
    tenant_profiles.upsert({"name": "Acme", "cloud": "zscaler", "vanity_domain": "acme"})
    deployments.add({"id": "d1", "packs": ["x"]})
    with change_queue._locked():
        change_queue._write({"version": 1, "requests": {}})
    workspace_notes.apply("t", "check", "c1", "add_comment", by="me", text="hello")
    posture_plus.save_settings({})


WRITERS = [_w_digest, _w_ssl_history, _w_beacon, _w_guidance, _w_pack_upload, _w_pack_terraform, _w_pack_from_tenant, _w_caches,
           _w_stores_in_a_new_folder]


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
@pytest.mark.parametrize("writer", WRITERS, ids=[w.__name__[3:] for w in WRITERS])
def test_everything_the_app_writes_is_owner_only(writer, tmp_path, monkeypatch, umask_022):
    """ASVS V12.4.1 · CWE-732 · CWE-276 · A01:2021 · WSTG-CONF-09: files are 0600 and folders the app creates 0700, whatever the umask."""
    root = tmp_path / "w"
    root.mkdir(mode=0o700)
    writer(root, monkeypatch)
    wide = []
    for dp, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(dp, n)
            mode = stat.S_IMODE(os.lstat(p).st_mode)
            if mode & 0o077:
                wide.append(f"{os.path.relpath(p, root)} {mode:04o}")
    assert any(os.scandir(root)), "the writer wrote nothing"
    assert wide == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_private_open_tightens_a_file_that_already_existed(tmp_path, umask_022):
    """ASVS V12.4.1 · CWE-732 · A01:2021 · WSTG-CONF-09: rewriting a 0644 file leaves it 0600."""
    p = tmp_path / "old.json"
    p.write_text("{}")
    os.chmod(p, 0o644)
    with safe_files.private_open(str(p)) as f:
        f.write("[]")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600 and p.read_text() == "[]"


# ── Path traversal through ids, names and the ?file= download ─────────────
@pytest.fixture
def isolated_app(tmp_path, monkeypatch):
    """The app with every store, cache and pack library in the test's tmp folder, and a canary file outside them."""
    for env, rel in (("DLP_CHECK_PROFILES", "data/tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "data/deployments.json"),
                     ("DLPCHECK_PROPOSALS_FILE", "data/proposals.json"), ("DLP_CHECK_WORKSPACE_NOTES", "data/workspace_notes.json"),
                     ("DLP_CHECK_GUIDANCE_STATE", "data/guidance.json"), ("DLP_CHECK_SSL_COVERAGE_STATE", "data/ssl.json"),
                     ("DLP_CHECK_BEACON_STATE", "data/beacon.json"), ("DLP_CHECK_POSTURE_SETTINGS", "data/posture.json"),
                     ("DLP_CHECK_DIGESTS", "digests"), ("DLP_CHECK_SELF_HEAL_STATE", "data/self_heal.json"),
                     ("DLP_CHECK_USER_PACKS", "user_packs"), ("XDG_CACHE_HOME", "xdg"), ("DLP_CHECK_SAAS_MATRIX", "data/saas.json")):
        monkeypatch.setenv(env, str(tmp_path / rel))
    canary = tmp_path / "canary"
    canary.mkdir()
    (canary / "secret.json").write_text(json.dumps({"id": "20260101-000000", "c": "CANARY-T11"}))
    (canary / "digest-20260101-000000.json").write_text(json.dumps({"id": "20260101-000000", "c": "CANARY-T11"}))
    import dlp_api_server as srv
    return TestClient(srv.app, raise_server_exceptions=False), tmp_path, canary


def _traversal_payloads(canary):
    secret = str(canary / "secret.json")
    rel = os.path.relpath(secret, os.path.dirname(os.path.abspath(pack_library.__file__)))
    return ["../../../../../../etc/passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd", "..\\..\\..\\windows\\win.ini", "C:%5CWindows%5Cwin.ini",
            "%5C%5Cserver%5Cshare%5Cx", "\\\\server\\share\\x", secret.replace("/", "%2F"), rel.replace("/", "%2F"),
            "..%c0%af..%c0%afetc%c0%afpasswd", "a%00b", "..", "%2e%2e"]


def _get_routes_with_path_params():
    import dlp_api_server as srv
    return sorted({r.path for r in srv.app.routes if "GET" in (getattr(r, "methods", None) or ()) and "{" in r.path})


@pytest.mark.parametrize("route", _get_routes_with_path_params())
def test_no_get_route_reads_a_file_named_by_a_traversal_id(route, isolated_app):
    """ASVS V12.3.1 · CWE-22 · A01:2021 · WSTG-ATHZ-01: every id in a GET path (report, job, pack, profile, digest...) is looked up, never joined into a path."""
    client, _tmp, canary = isolated_app
    for payload in _traversal_payloads(canary):
        r = client.get(re.sub(r"\{[^}]+\}", lambda _m: payload, route))
        assert r.status_code < 500, (payload, r.status_code)
        assert b"CANARY-T11" not in r.content and b"root:x:" not in r.content and b"[fonts]" not in r.content, payload


def test_the_export_file_parameter_names_only_a_listed_part(isolated_app, monkeypatch):
    """ASVS V12.3.1 · CWE-22 · A01:2021 · WSTG-ATHZ-01: ?file= picks one of the job's own part files and nothing else, even from its own zip."""
    import pack_jobs
    client, _tmp, canary = isolated_app
    zipped = _zip([("p/configs/dlp_engines.json", "[]"), ("../../evil.json", "x")])
    job = pack_jobs.Job(id="j1", kind="export", status=pack_jobs.DONE, artifact=("p.zip", "application/zip", zipped),
                        result={"part_files": [{"path": "p/configs/dlp_engines.json", "part": "engines", "format": "json"}]})
    monkeypatch.setattr(pack_jobs, "get", lambda jid: job if jid == "j1" else None)
    for f in ("../../evil.json", "p/../../evil.json", str(canary / "secret.json"), "..%2F..%2Fevil.json", "P/CONFIGS/DLP_ENGINES.JSON"):
        r = client.get("/api/dlp-packs/jobs/j1/download", params={"file": f})
        assert r.status_code == 404, f
    r = client.get("/api/dlp-packs/jobs/j1/download", params={"file": "p/configs/dlp_engines.json"})
    assert r.status_code == 200 and r.content == b"[]"
    assert re.fullmatch(r'attachment; filename="p-engines\.json"', r.headers["content-disposition"])


UPLOAD_NAMES = [{"pack_id": "../../canary/evil"}, {"pack_name": "../../../canary/evil2"}, {"pack_id": "..\\..\\canary\\evil3"},
                {"pack_id": "C:\\canary\\evil4"}, {"pack_id": "\\\\server\\share\\evil5"}, {"pack_id": "%2e%2e%2fcanary"}]


@pytest.mark.parametrize("names", UPLOAD_NAMES, ids=[next(iter(n.values())) for n in UPLOAD_NAMES])
def test_a_pack_upload_never_writes_outside_the_pack_library(names, isolated_app):
    """ASVS V12.3.1 · CWE-22 · A01:2021 · WSTG-BUSL-09: pack ids, pack names and member names (zip slip) become a slug inside user_packs, never a path."""
    client, tmp, canary = isolated_app
    zipped = _zip([("../../../canary/evil_engines.json", json.dumps([{"name": "E1", "expression": "((D:NONE > 0))"}])),
                   ("/abs/evil_policies.json", json.dumps([{"name": "R1", "engines": ["E1"], "state": "DISABLED", "action": "ALLOW"}])),
                   ("C:\\evil\\dlp_dictionaries.json", "[]")])
    before = sorted(p.name for p in canary.iterdir())
    r = client.post("/api/pack-library/upload", json={"files": [{"name": "../../x.zip", "content": _b64(zipped), "encoding": "base64"}], **names})
    assert r.status_code == 200, r.text
    pid = r.json()["pack"]["id"]
    assert re.fullmatch(r"[a-z0-9_]{1,64}", pid)
    assert os.path.realpath(r.json()["dir"]) == os.path.realpath(tmp / "user_packs" / pid)
    assert sorted(p.name for p in canary.iterdir()) == before
    assert [p.name for p in tmp.iterdir() if p.name not in ("user_packs", "canary", "data", "xdg", "digests")] == []


@pytest.mark.parametrize("pack_id", ["../canary", "..%2Fcanary", "..", "%2e%2e", "...", "user_packs"])
def test_removing_a_pack_by_a_traversal_id_removes_nothing(pack_id, isolated_app):
    """ASVS V12.3.1 · CWE-22 · A01:2021 · WSTG-ATHZ-01: remove only ever deletes a folder inside the pack library."""
    client, tmp, canary = isolated_app
    r = client.post(f"/api/pack-library/{pack_id}/remove")
    assert r.status_code in (404, 405)
    assert (canary / "secret.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_a_symlinked_pack_in_the_library_cannot_take_remove_outside_it(isolated_app):
    """ASVS V12.3.1 · CWE-59 · A01:2021 · WSTG-ATHZ-01: a link in user_packs pointing elsewhere is not followed by remove."""
    client, tmp, canary = isolated_app
    lib = tmp / "user_packs"
    lib.mkdir(exist_ok=True)
    (lib / "linked").symlink_to(canary, target_is_directory=True)
    r = client.post("/api/pack-library/linked/remove")
    assert r.status_code == 404
    assert (canary / "secret.json").exists()
