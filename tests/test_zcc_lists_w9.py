"""Client Connector bulk removal lists (wave 9): an Excel workbook as the
list (xlsx_reader: zip-bomb, XXE and size safe) and the download of one
user domain's enrolled user names (personal data, an explicit opt-in, CSV
cells made safe for spreadsheets).

Offline: workbooks are built in memory here; the routes use the admin
fakes; no tenant, no network."""
from __future__ import annotations

import base64
import io
import json
import os
import sys
import zipfile

import pytest
from conftest import read_store_text
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dlp_api_server as srv  # noqa: E402
import ops_zcc_admin as zadm  # noqa: E402
import xlsx_reader  # noqa: E402
from admin_fakes import ZccClient  # noqa: E402

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "7210000000000"}
NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'


def scope(*s):
    return {"scopes": list(s), "channels": {}, "from_page": True}


def _sheet(rows):
    out = []
    for i, r in enumerate(rows, 1):
        cells = "".join(f'<c r="{chr(65 + j)}{i}" t="inlineStr"><is><t>{v}</t></is></c>' for j, v in enumerate(r))
        out.append(f'<row r="{i}">{cells}</row>')
    return f'<?xml version="1.0" encoding="UTF-8"?><worksheet {NS}><sheetData>{"".join(out)}</sheetData></worksheet>'


def _book(rows=None, sheet=None, extra=None, method=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("xl/worksheets/sheet1.xml", sheet if sheet is not None else _sheet(rows or []))
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


@pytest.fixture()
def api(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    c = ZccClient()
    c.tenant.seed()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or c)
    return TestClient(srv.app), c, built, tmp_path


# ── the workbook reader ────────────────────────────────────────────────

def test_a_normal_workbook_gives_its_first_sheet_and_shared_strings():
    """ASVS V5.1.3 · V12.1.1 · CWE-20: the portal's device export (a header row with a UDID and user column) is read as text cells; shared strings resolve."""
    # Arrange
    shared = f'<sst {NS}><si><t>VMW-1:AAA</t></si></sst>'
    sheet = (f'<worksheet {NS}><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>UDID</t></is></c>'
             f'<c r="B1" t="inlineStr"><is><t>User</t></is></c></row><row r="2"><c r="A2" t="s"><v>0</v></c>'
             f'<c r="B2" t="inlineStr"><is><t>jdoe@acme.com</t></is></c></row></sheetData></worksheet>')
    data = _book(sheet=sheet, extra={"xl/sharedStrings.xml": shared})
    # Act
    rows = xlsx_reader.read_rows(data)
    text = zadm.xlsx_list_text(data)
    # Assert
    assert rows == [["UDID", "User"], ["VMW-1:AAA", "jdoe@acme.com"]]
    assert text == "VMW-1:AAA"


def test_a_zip_bomb_part_is_refused_by_its_expansion_ratio():
    """ASVS V12.1.1 · V12.1.2 · CWE-409 · WSTG-BUSL-09: a sheet that expands more than MAX_RATIO times its compressed size (5 MB of padding) is refused as a zip bomb, never parsed."""
    # Arrange
    sheet = _sheet([["jdoe@acme.com"]]).replace("<sheetData>", "<sheetData>" + " " * (5 * 1024 * 1024))
    data = _book(sheet=sheet)
    assert len(data) < xlsx_reader.MAX_FILE_BYTES
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match="zip bomb"):
        xlsx_reader.read_rows(data)


def test_a_workbook_whose_parts_add_up_past_the_total_cap_is_refused(monkeypatch):
    """ASVS V12.1.1 · CWE-409 · CWE-400: members whose declared sizes add up past MAX_TOTAL_BYTES are refused before any part is opened."""
    # Arrange
    monkeypatch.setattr(xlsx_reader, "MAX_TOTAL_BYTES", 4096)
    data = _book([["a"]], extra={f"xl/media/pad{i}.bin": "x" * 1024 for i in range(5)})
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match="expands to more than"):
        xlsx_reader.read_rows(data)


def test_too_many_parts_are_refused(monkeypatch):
    """ASVS V12.1.1 · CWE-400: a package with more than MAX_PARTS members is refused."""
    # Arrange
    monkeypatch.setattr(xlsx_reader, "MAX_PARTS", 5)
    data = _book([["a"]], extra={f"xl/p{i}.xml": "<a/>" for i in range(6)})
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match="more than 5 parts"):
        xlsx_reader.read_rows(data)


@pytest.mark.parametrize("xml", [
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><worksheet ' + NS + '><sheetData><row><c t="inlineStr"><is><t>&b;</t></is></c></row></sheetData></worksheet>',
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY x SYSTEM "file:///etc/passwd">]><worksheet ' + NS + '><sheetData><row><c t="inlineStr"><is><t>&x;</t></is></c></row></sheetData></worksheet>',
])
def test_an_xml_entity_or_external_reference_is_refused(xml):
    """ASVS V5.5.2 · CWE-611 · CWE-776 · WSTG-INPV-07: a sheet with a DTD, an entity expansion or an external entity is refused by the hardened parser."""
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match="DTD or entities"):
        xlsx_reader.read_rows(_book(sheet=xml))


def test_an_oversize_workbook_is_refused_before_it_is_opened():
    """ASVS V12.1.1 · CWE-400 · CWE-770: a file over MAX_FILE_BYTES is refused by size, as is the same through the matcher."""
    # Arrange
    data = b"PK\x03\x04" + b"\0" * xlsx_reader.MAX_FILE_BYTES
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match="larger than 8 MB"):
        xlsx_reader.read_rows(data)
    with pytest.raises(zadm.ao.OperationError, match="at most 8 MB"):
        zadm.parse_list(data)


def test_a_sheet_past_the_row_cap_is_refused_not_cut_short(monkeypatch):
    """ASVS V12.1.1 · V5.1.4 · CWE-770 · CWE-1284: a sheet with more than MAX_ROWS rows is refused with the reason (a list read in part would plan a partial removal without saying so); exactly MAX_ROWS rows is read whole (boundary); the matcher passes the reason on."""
    # Arrange
    monkeypatch.setattr(xlsx_reader, "MAX_ROWS", 3)
    over = _book([[f"u{i}@acme.com"] for i in range(4)])
    at = _book([[f"u{i}@acme.com"] for i in range(3)])
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match="more than 3 rows"):
        xlsx_reader.read_rows(over)
    with pytest.raises(zadm.ao.OperationError, match="could not be read: the first sheet has more than 3 rows; split it"):
        zadm.xlsx_list_text(over)
    assert xlsx_reader.read_rows(at) == [["u0@acme.com"], ["u1@acme.com"], ["u2@acme.com"]]


@pytest.mark.parametrize("cap,value,rows,why", [
    ("MAX_CELLS", 5, [["a", "b"], ["c", "d"], ["e", "f"]], "more than 5 filled cells"),
    ("MAX_COLS", 2, [["a", "b", "c"]], "a value past column B"),
    ("MAX_SHARED", 1, None, "more than 1 distinct text values"),
])
def test_a_sheet_past_the_cell_column_or_shared_string_cap_is_refused(monkeypatch, cap, value, rows, why):
    """ASVS V12.1.1 · CWE-770 · CWE-1284: a sheet with more filled cells than MAX_CELLS, a value past column MAX_COLS, or more shared strings than MAX_SHARED is refused, never cut short."""
    # Arrange
    monkeypatch.setattr(xlsx_reader, cap, value)
    shared = f'<sst {NS}><si><t>one</t></si><si><t>two</t></si></sst>'
    data = _book(rows, sheet=None if rows else f'<worksheet {NS}><sheetData><row r="1"><c r="A1" t="s"><v>1</v></c></row></sheetData></worksheet>',
                 extra={"xl/sharedStrings.xml": shared})
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match=why):
        xlsx_reader.read_rows(data)


def test_a_large_sheet_is_refused_early_with_bounded_memory_and_work(monkeypatch):
    """ASVS V12.1.1 · V11.1.4 · CWE-400 · CWE-770 · WSTG-BUSL-09: a large upload (60,000 rows: over the default row cap, every size and ratio cap passed) is refused, its sheet is streamed and reading stops at the cap (well under half the sheet inflated), and peak memory stays small (the whole part is never held or parsed into a tree)."""
    # Arrange
    import tracemalloc
    data = _book([[f"user{i:06d}@acme.example", f"HOST-{i:06d}"] for i in range(60_000)])
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        part = z.getinfo("xl/worksheets/sheet1.xml").file_size
    assert len(data) < xlsx_reader.MAX_FILE_BYTES and part < xlsx_reader.MAX_PART_BYTES and part > 6 * 1024 * 1024
    inflated = []
    real_read = xlsx_reader._Stream.read
    def counted(self, n=-1):
        chunk = real_read(self, n)
        inflated.append((self.name, len(chunk)))
        return chunk
    monkeypatch.setattr(xlsx_reader._Stream, "read", counted)
    # Act
    tracemalloc.start()
    try:
        with pytest.raises(xlsx_reader.XlsxRefused, match=f"more than {xlsx_reader.MAX_ROWS} rows") as got:
            xlsx_reader.read_rows(data)
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # Assert
    assert "split it" in str(got.value)
    read = sum(n for name, n in inflated if name == "xl/worksheets/sheet1.xml")
    assert 0 < read < part / 2, (read, part)
    assert peak < 24 * 1024 * 1024 + len(data), peak


@pytest.mark.parametrize("data,why", [(b"", "empty"), (b"name,host\n", "not an Excel"), (b"PK\x03\x04garbage", "damaged")])
def test_a_file_that_is_not_a_workbook_is_refused_in_words(data, why):
    """ASVS V5.1.3 · CWE-20 · CWE-209: an empty file, a CSV renamed .xlsx and a broken ZIP are refused with a plain reason."""
    # Act / Assert
    with pytest.raises(xlsx_reader.XlsxRefused, match=why):
        xlsx_reader.read_rows(data)


def test_parse_list_takes_a_workbook_and_counts_a_malformed_cell():
    """ASVS V5.1.3 · V5.1.4 · CWE-20: parse_list reads an .xlsx (no header: every cell an entry); a cell with markup is kept as an invalid entry (counted), never matched."""
    # Arrange
    data = _book([["jdoe@acme.com"], ["OTHER"], ["&lt;script&gt;"]])
    # Act
    entries = zadm.parse_list(data)
    # Assert
    assert [e["kind"] for e in entries] == ["user", "name", "invalid"]


def test_the_lookup_route_matches_an_uploaded_workbook(api):
    """ASVS V5.1.3 · V12.1.1 · CWE-20 · WSTG-INPV-01: the page's Excel file (base64) is matched like a pasted list; a broken upload is a 400."""
    # Arrange
    c, _sdk, _built, _tmp = api
    b64 = base64.b64encode(_book([["Hostname"], ["JDOE-LT"], ["NOPE-PC"]])).decode()
    # Act
    r = c.post("/api/operations/lookup", json=dict(CREDS, **scope("zcc"), family="zcc_admin", what="match", xlsx_b64=b64, mode="remove"))
    bad = c.post("/api/operations/lookup", json=dict(CREDS, **scope("zcc"), family="zcc_admin", what="match", xlsx_b64="%%%", mode="remove"))
    # Assert
    assert r.status_code == 200, r.text
    assert r.json()["counts"]["planned"] == 1 and r.json()["not_found"] == [{"entry": "NOPE-PC"}]
    assert bad.status_code == 400 and "did not arrive whole" in bad.json()["detail"]


# ── a domain's user names ──────────────────────────────────────────────

def test_the_domain_user_names_need_the_explicit_personal_data_opt_in(api):
    """ASVS V8.3.1 · V8.3.4 · CWE-359 · WSTG-BUSL-01: without personal_data_ok the download is a 400 naming personal data, before any sign-in."""
    # Arrange
    c, _sdk, built, _tmp = api
    # Act
    r = c.post("/api/operations/zcc/domain-users.csv", json=dict(CREDS, **scope("zcc"), domain="acme.com"))
    # Assert
    assert r.status_code == 400 and "personal data" in r.json()["detail"] and built == []


def test_the_domain_user_names_are_refused_out_of_scope_before_sign_in(api):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: with Client Connector not ticked on the Scope page the download is a 400 before any sign-in."""
    # Arrange
    c, _sdk, built, _tmp = api
    # Act
    r = c.post("/api/operations/zcc/domain-users.csv", json=dict(CREDS, **scope("zia_extras"), domain="acme.com", personal_data_ok=True))
    # Assert
    assert r.status_code == 400 and built == []


def test_the_domain_user_names_are_a_safe_labelled_csv_and_the_audit_holds_only_the_count(api):
    """ASVS V5.3.10 · V8.3.4 · CWE-1236 · CWE-359 · WSTG-INPV-11: with the opt-in the CSV lists the domain's users (and no other domain's), a formula-looking user is made inert, the file name says personal data, it is no-store, and the audit record holds the count, never a name."""
    # Arrange
    c, sdk, _built, tmp = api
    sdk.tenant.devices.append({"udid": "X-1", "user": "=HYPERLINK(1)@acme.com", "machineHostname": "EVIL", "registrationState": "Registered"})
    sdk.tenant.devices.append({"udid": "X-2", "user": "ann@else.org", "machineHostname": "ELSE", "registrationState": "Registered"})
    # Act
    r = c.post("/api/operations/zcc/domain-users.csv", json=dict(CREDS, **scope("zcc"), domain="@ACME.com", personal_data_ok=True))
    # Assert
    assert r.status_code == 200, r.text
    lines = r.text.strip().splitlines()
    assert lines[0] == "user,devices,device states,last seen"
    assert any(ln.startswith("jdoe@acme.com,2,") for ln in lines) and any(ln.startswith("other@acme.com,1,") for ln in lines)
    assert "else.org" not in r.text
    evil = next(ln for ln in lines if "hyperlink" in ln.lower())
    assert not evil.startswith("=") and evil.startswith(("'", '"\''))
    assert "personal-data" in r.headers["content-disposition"] and "no-store" in r.headers["cache-control"]
    assert r.headers.get("x-content-type-options") == "nosniff"
    audit = read_store_text(tmp / "audit.log")
    rec = [json.loads(x) for x in audit.splitlines() if "zcc_domain_users_export" in x][-1]
    assert rec.get("users") == 3 or rec.get("details", {}).get("users") == 3
    assert "jdoe@acme.com" not in audit


def test_the_page_offers_the_download_only_behind_a_personal_data_tick():
    """ASVS V8.3.1 · CWE-359 · WCAG 2.2 SC 3.3.2: the bulk removal form labels the download as personal data and checks the tick before it asks; the list file accepts .xlsx."""
    # Arrange
    js = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_admin.js"), encoding="utf-8").read()
    # Act
    fn = js.split("async function domainUsers", 1)[1].split("function matchHtml", 1)[0]
    # Assert
    assert 'id="admUsersOk"' in js and "(personal data)" in js and 'accept=".txt,.csv,.xlsx"' in js
    assert fn.index("admUsersOk") < fn.index("fetch(") and "personal_data_ok: true" in fn
