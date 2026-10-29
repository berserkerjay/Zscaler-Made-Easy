"""Cloud QA wave 6, misc area: the MCP server tools, url_tools,
console_index, workspace_notes, beacon, discover_endpoints,
zscaler_clouds, engine_explain, plain_english, corpus_engines,
native_zscaler, guidance and vertical.

Every test is offline and deterministic: fake clients and fake
transports only, never a real tenant, no sleeps, no real clock.
"""
from __future__ import annotations

import json
import os
import stat
from typing import Any, Dict, List

import pytest


# ── The MCP server tools ──────────────────────────────────────────────

SECRET = "mcp-secret-not-real-7f3a"


class _FakeSdk:
    """What dlp_mcp_server builds instead of the SDK adapter: records how it
    was made and closed; signs in as told."""
    made: List[Dict[str, Any]] = []
    closed = 0
    auth_answer: Any = True

    def __init__(self, **kw: Any) -> None:
        type(self).made.append(kw)
        self._config = {"cloud": kw.get("cloud") or "production"}
        self._creds = {"client_secret": kw.get("client_secret"), "password": kw.get("password"), "api_key": kw.get("api_key")}

    def auth(self):
        return type(self).auth_answer

    def close(self) -> None:
        type(self).closed += 1

    def get(self, ep: str, params: Any = None):
        return [], 200


@pytest.fixture
def mcp(monkeypatch):
    import dlp_mcp_server as m
    for k, v in {"ZSCALER_CLIENT_ID": "cid-mcp", "ZSCALER_CLIENT_SECRET": SECRET, "ZSCALER_VANITY_DOMAIN": "acme",
                 "ZSCALER_CLOUD": "production"}.items():
        monkeypatch.setenv(k, v)
    for k in ("ZSCALER_AUTH_METHOD", "ZSCALER_USERNAME", "ZSCALER_PASSWORD", "ZSCALER_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    _FakeSdk.made, _FakeSdk.closed, _FakeSdk.auth_answer = [], 0, True
    monkeypatch.setattr(m, "SdkClient", _FakeSdk)
    return m


def _tool(m, name):
    t = getattr(m, name)
    return getattr(t, "fn", t)


@pytest.mark.parametrize("cloud", ["zscalergovv", "evil.example", "zscaler.net/x"])
def test_mcp_unknown_cloud_argument_is_refused_before_sign_in(mcp, cloud):
    """ASVS V5.1.3 · A04:2021 · CWE-1188 · WSTG-INPV-01: an MCP tool's unknown cloud is refused, never signed in to the commercial cloud."""
    out = _tool(mcp, "run_section")(section="CC Portal", cloud=cloud)

    assert "Unknown Zscaler cloud" in out["error"] and _FakeSdk.made == []


def test_mcp_unknown_cloud_in_the_environment_is_refused(mcp, monkeypatch):
    """ASVS V14.1.3 · CWE-636 · WSTG-CONF-02: a mistyped ZSCALER_CLOUD fails closed instead of falling back to production."""
    monkeypatch.setenv("ZSCALER_CLOUD", "zscalergovus-typo")

    out = _tool(mcp, "run_assessment")()

    assert "Unknown Zscaler cloud" in out["error"] and _FakeSdk.made == []


def test_mcp_known_cloud_spelling_still_signs_in(mcp):
    """ASVS V5.1.3 · CWE-20: an accepted spelling of a cloud (admin host form) still runs the section."""
    out = _tool(mcp, "run_section")(section="CC Portal", cloud="admin.zscalertwo.net")

    assert "error" not in out and _FakeSdk.made and out["checks"]


def test_mcp_bad_auth_method_in_the_environment_is_a_plain_error(mcp, monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: an unknown ZSCALER_AUTH_METHOD is a plain error, not an exception out of the tool."""
    monkeypatch.setenv("ZSCALER_AUTH_METHOD", "kerberos")

    out = _tool(mcp, "run_assessment")()

    assert "Unknown sign-in method" in out["error"] and SECRET not in json.dumps(out)


def test_mcp_check_exception_detail_masks_the_client_secret(mcp, monkeypatch):
    """ASVS V7.1.1 · A09:2021 · CWE-209 · CWE-532: a check that raises with the secret in its message reports it masked."""
    def leaky(cl):
        raise RuntimeError(f"400 from token endpoint: client_secret={SECRET}")
    monkeypatch.setattr(mcp, "REG", [("T.1", "Test section", "Leaky check", leaky)])

    out = _tool(mcp, "run_section")(section="Test")

    assert out["checks"][0]["status"] == "ERROR" and SECRET not in json.dumps(out)
    assert "[redacted client_secret]" in out["checks"][0]["detail"]


@pytest.mark.parametrize("section", ["", "   "])
def test_mcp_empty_section_is_refused_not_every_check(mcp, section):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an empty section name is refused instead of matching every section."""
    out = _tool(mcp, "run_section")(section=section)

    assert out["error"].startswith("Name a section") and out["available"] and _FakeSdk.made == []


@pytest.mark.parametrize("field", ["org_name", "assessor"])
def test_mcp_oversized_argument_is_refused(mcp, field):
    """ASVS V5.1.4 · CWE-400 · WSTG-INPV-01: an argument over the cap is refused before sign-in."""
    out = _tool(mcp, "run_assessment")(**{field: "x" * (mcp.MAX_ARG_LEN + 1)})

    assert "too long" in out["error"] and _FakeSdk.made == []


def test_mcp_argument_at_the_cap_is_accepted(mcp):
    """ASVS V5.1.4 · CWE-20: an argument exactly at the cap is accepted (boundary)."""
    out = _tool(mcp, "run_section")(section="CC Portal", org_name="o" * mcp.MAX_ARG_LEN)

    assert out["metadata"]["org"] == "o" * mcp.MAX_ARG_LEN


def test_mcp_control_characters_in_an_argument_are_refused(mcp):
    """ASVS V5.1.3 · CWE-117 · WSTG-INPV-01: a newline in an argument (log forging) is refused."""
    out = _tool(mcp, "run_section")(section="CC Portal\nFAKE LOG LINE")

    assert "control characters" in out["error"] and _FakeSdk.made == []


def test_mcp_client_is_closed_when_sign_in_fails(mcp):
    """ASVS V7.4.1 · CWE-404: a failed sign-in still closes the client."""
    _FakeSdk.auth_answer = (False, "Invalid client")

    out = _tool(mcp, "run_section")(section="CC Portal")

    assert out == {"error": "Authentication failed: (False, 'Invalid client')"} and _FakeSdk.closed == 1


def test_mcp_tools_take_no_write_or_secret_argument():
    """ASVS V1.4.1 · A01:2021 · CWE-841 · CWE-522: the MCP server exposes only read tools and none takes a secret or a write switch."""
    import asyncio
    import dlp_mcp_server as m

    tools = {t.name: t for t in asyncio.run(m.mcp.list_tools())}

    schemas = [getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {} for t in tools.values()]
    params = {p for sc in schemas for p in (sc.get("properties") or {})}
    assert set(tools) == {"get_health", "list_checks", "run_assessment", "run_section"}
    assert not params & {"client_secret", "password", "api_key", "token", "confirm", "write", "apply", "assessor_confirm"}


# ── url_tools: parsing, categorisation, IDN, the custom category analyzer ──

KIND_ORACLE = [
    ("10.0.0.1", "IP address or range"), ("10.0.0.0/8", "IP address or range"), ("2001:db8::/32", "IP address or range"),
    ("10.0.0.1-10.0.0.9", "IP address or range"), ("10.0.0.1 - 10.0.0.9", "IP address or range"), ("::1-::5", "IP address or range"),
    ("ad-fe.cc", "Domain"), ("dead-beef.cc", "Domain"), ("face-feed.de", "Domain"), ("cafe.de", "Domain"),
    ("bücher.de", "Domain"), ("xn--bcher-kva.de", "Domain"), ("*.example.com", "Domain"), ("example.com/path", "URL"),
    ("https://example.com/", "Domain"), ("https://example.com/a", "URL"), ("10.0.0.1-cafe.de", "Domain"),
]


@pytest.mark.parametrize("value,kind", KIND_ORACLE)
def test_url_tools_kind_of_oracle(value, kind):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: kind_of names IPs, ranges, domains (IDN too) and URLs as the oracle table says."""
    import url_tools as ut

    assert ut.kind_of(value) == kind


def test_url_tools_list_kind_wins_over_shape():
    """ASVS V5.1.3 · CWE-20: a keyword or regex list entry keeps its list's kind whatever it looks like."""
    import url_tools as ut

    assert (ut.kind_of("10.0.0.1", "keyword"), ut.kind_of("a-b", "regex"), ut.kind_of("x", "ip")) == ("Keyword", "Regex", "IP address or range")


@pytest.mark.parametrize("field", ["urls", "keywords", "ipRanges"])
def test_url_tools_collect_ignores_a_non_list_field(field):
    """ASVS V5.1.4 · CWE-20 · CWE-755: a category field that is a string (a damaged snapshot) yields no rows, never one row per character."""
    import url_tools as ut
    snap = {"categories": [{"id": "CUSTOM_01", "customCategory": True, "configuredName": "Mine", field: "abc.example"}]}

    assert ut.collect(snap) == []


def test_url_tools_collect_survives_wrong_shapes_everywhere():
    """ASVS V5.1.4 · CWE-755 · WSTG-ERRH-01: wrong types in every source are skipped, not a crash."""
    import url_tools as ut
    snap = {"categories": "x", "url_rules": [{"urlCategories": 5}], "ssl_rules": {"a": 1}, "firewall_rules": [{"destAddresses": "1.2.3.4"}],
            "ip_groups": None, "advanced": ["x"], "client_connector": {"app_profiles": ["p", {"bypass": "x"}], "pac_files": [3]}}

    assert ut.collect(snap) == []


def test_url_tools_idn_answer_in_punycode_is_matched():
    """ASVS V5.1.3 · CWE-176 · WSTG-INPV-01: a URL sent in Unicode is found when the lookup answers it in IDNA form (assumed spelling)."""
    import url_tools as ut

    class C:
        def post(self, ep, body):
            return [{"url": "xn--bcher-kva.de", "urlClassifications": ["SHOPPING"]}], 200

    found, missed, _ = ut.lookup_batches(C(), ["https://bücher.de"], pace=0, sleep=lambda s: None)

    assert found == {"https://bücher.de": {"categories": ["SHOPPING"], "security_alerts": []}} and missed == {}


def test_url_tools_match_key_keeps_ascii_and_path():
    """ASVS V5.1.3 · CWE-176: the match key leaves an ASCII host alone and keeps the path."""
    import url_tools as ut

    assert (ut._match_key("HTTPS://Example.com/A/"), ut._match_key("bücher.de/x")) == ("example.com/a", "xn--bcher-kva.de/x")


def test_url_tools_another_custom_category_is_not_zscalers_categorisation():
    """ASVS V5.1.3 · CWE-20: a URL Zscaler leaves uncategorised but another custom category holds reads 'uncategorised', not 'redundant'."""
    import url_tools as ut
    custom = {"id": "CUSTOM_01", "superCategory": "BUSINESS_AND_ECONOMY"}

    verdict, cats = ut.classify({"categories": ["CUSTOM_02"]}, custom, {"CUSTOM_02": "BUSINESS_AND_ECONOMY"})

    assert (verdict, cats) == ("uncategorised", [])


CLASSIFY_ORACLE = [
    (None, "not_looked_up"), ({"categories": []}, "uncategorised"), ({"categories": ["MISCELLANEOUS_OR_UNKNOWN"]}, "uncategorised"),
    ({"categories": ["CUSTOM_01"]}, "uncategorised"), ({"categories": ["FINANCE"]}, "redundant"),
    ({"categories": ["GAMBLING"]}, "different"), ({"categories": ["NEW_ONE"]}, "categorised"),
]


@pytest.mark.parametrize("entry,verdict", CLASSIFY_ORACLE)
def test_url_tools_classify_oracle(entry, verdict):
    """ASVS V5.1.3 · CWE-20: every analyzer verdict from the oracle table (same super category, another one, unknown, none)."""
    import url_tools as ut
    supers = {"FINANCE": "BUSINESS_AND_ECONOMY", "GAMBLING": "GAMBLING"}

    assert ut.classify(entry, {"id": "CUSTOM_01", "superCategory": "BUSINESS_AND_ECONOMY"}, supers)[0] == verdict


def test_url_tools_unknown_picks_are_capped_in_the_note():
    """ASVS V5.1.4 · CWE-400: hundreds of unknown or huge category names are echoed capped, not whole."""
    import url_tools as ut

    class C:
        def get(self, ep, params=None):
            return ([{"id": "CUSTOM_01", "customCategory": True, "configuredName": "Mine"}], 200) if ep.endswith("/lite") else ({"urls": []}, 200)

        def post(self, ep, body):
            return [], 200

    res = ut.analyze_categories(C(), picked=["z" * 5000] + [f"n{i}" for i in range(100)], pace=0, sleep=lambda s: None)

    note = next(n for n in res["notes"] if n.startswith("Not custom"))
    assert len(note) < 2000 and "and 81 more" in note


# ── console_index: the kept index stays with its own tenant ──────────

@pytest.fixture
def ci(monkeypatch):
    import console_index
    import types
    now = {"t": 1_000_000.0}
    monkeypatch.setattr(console_index, "_clock", lambda: now["t"], raising=False)
    monkeypatch.setattr(console_index, "time", types.SimpleNamespace(time=lambda: now["t"]))
    console_index.cache_clear()
    yield console_index, now
    console_index.cache_clear()


def test_console_index_profile_named_server_never_sees_typed_sign_in(ci):
    """ASVS V4.2.1 · A01:2021 · CWE-639 · WSTG-ATHZ-04: a profile whose id is 'server' does not share the typed sign-ins' bucket."""
    m, _ = ci
    m.cache_put(m.cache_key("", ["web"]), {"tenant_label": "other (production)", "objects": [{"name": "X"}]})

    assert m.cache_latest("server") is None and m.cache_get(m.cache_key("server", ["web"])) is None


def test_console_index_cached_without_a_tenant_is_refused(ci):
    """ASVS V4.1.5 · A01:2021 · CWE-668 · WSTG-ATHZ-04: without a profile or a named tenant, no kept index answers (it may be another tenant's)."""
    m, _ = ci
    m.cache_put(m.cache_key("", ["web"]), {"tenant_label": "alpha (production)", "objects": []})

    assert m.cache_latest("") is None


def test_console_index_cached_answers_only_for_the_named_tenant(ci):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: typed sign-ins of two tenants: each tenant gets its own index, never the other's."""
    m, now = ci
    m.cache_put(m.cache_key("", ["web"]), {"tenant_label": "alpha (production)", "objects": [{"name": "A"}]})
    now["t"] += 1
    m.cache_put(m.cache_key("", ["web", "email"]), {"tenant_label": "beta (production)", "objects": [{"name": "B"}]})

    a, b = m.cache_latest("", tenant_label="alpha (production)"), m.cache_latest("", tenant_label="beta (production)")
    assert (a["objects"], b["objects"]) == ([{"name": "A"}], [{"name": "B"}])
    assert m.cache_latest("", tenant_label="gamma (production)") is None


def test_console_index_profile_and_tenant_must_both_match(ci):
    """ASVS V4.2.1 · CWE-639: a profile's kept index read for another tenant (the profile was edited) does not answer."""
    m, _ = ci
    m.cache_put(m.cache_key("p1", ["web"]), {"tenant_label": "alpha (production)", "objects": []})

    assert m.cache_latest("p1", tenant_label="beta (production)") is None and m.cache_latest("p1") is not None


@pytest.mark.parametrize("age,kept", [(0, True), (30 * 60, True), (30 * 60 + 1, False)])
def test_console_index_cache_expiry_boundary(ci, age, kept):
    """ASVS V3.3.1 · CWE-613: a kept index answers for exactly 30 minutes (boundary), on an injected clock."""
    m, now = ci
    key = m.cache_key("p1", ["web"])
    m.cache_put(key, {"tenant_label": "alpha (production)", "objects": []})
    now["t"] += age

    assert (m.cache_get(key) is not None) is kept and (m.cache_latest("p1") is not None) is kept


def test_console_index_cache_is_bounded(ci):
    """ASVS V5.1.4 · CWE-400 · CWE-770: at most 16 indexes are kept in memory, the oldest dropped first."""
    m, now = ci
    for i in range(20):
        now["t"] += 1
        m.cache_put(m.cache_key(f"p{i}", ["web"]), {"tenant_label": f"t{i}", "objects": []})

    assert len(m._CACHE) == 16 and m.cache_latest("p0") is None and m.cache_latest("p19") is not None


def test_console_index_never_holds_users_or_descriptions():
    """ASVS V8.3.4 · A01:2021 · CWE-359: a ZIA rule's users, devices and description never reach the index."""
    import console_index as m
    raw = {"name": "R1", "order": 1, "state": "ENABLED", "action": "BLOCK", "users": [{"id": 1, "name": "alice@example.com"}],
           "devices": [{"id": 2, "name": "laptop-alice"}], "description": "call alice on 555-0100", "locations": [{"id": 3, "name": "HQ"}]}

    out = m.from_inventory({"rules": [], "engines": [], "dictionaries": {}}, zia={"rules": {"url_filtering": [raw]}, "categories": []}, now=0)

    blob = json.dumps(out)
    assert "alice" not in blob and "555-0100" not in blob and '"HQ"' in blob


# ── workspace_notes: caps, escaping, a damaged store ─────────────────

@pytest.fixture
def wn(monkeypatch, tmp_path):
    import workspace_notes
    monkeypatch.setenv("DLP_CHECK_WORKSPACE_NOTES", str(tmp_path / "n" / "workspace_notes.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    return workspace_notes


def _store(wn, data):
    p = wn.store_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(data if isinstance(data, str) else json.dumps(data))


@pytest.mark.parametrize("data", [
    {"tenants": {"acme": []}}, {"tenants": {"acme": {"notes": []}}}, {"tenants": {"acme": {"notes": {"x": "y"}}}},
    {"tenants": {"acme": {"notes": {"x": {"tags": "abc", "todos": [1, None]}}}}}, "[" * 100000,
], ids=["bucket-list", "notes-list", "note-string", "fields-wrong", "deep-nesting"])
def test_workspace_notes_damaged_store_reads_as_empty_not_a_crash(wn, data):
    """ASVS V7.4.1 · CWE-755 · CWE-20 · WSTG-ERRH-01: a store of the wrong shape (or nested past the parser) never breaks the notes pages."""
    _store(wn, data)

    listed, tenants = wn.list_notes(), wn.tenants()

    assert all(isinstance(n.get("tags"), list) for n in listed) and isinstance(tenants, list)


def test_workspace_notes_damaged_bucket_still_takes_a_new_note(wn):
    """ASVS V7.4.1 · CWE-755: a tenant bucket that is not an object is replaced by the next note, not a 500."""
    _store(wn, {"version": 1, "tenants": {"acme (production)": ["junk"]}})

    note = wn.apply("acme (production)", "rule", "R1", "add_tag", by="tester", tag="pci")

    assert note["tags"] == ["pci"]


@pytest.mark.parametrize("bad", ["\u202e", "\u2066", "\u2069", "\x85", "\x9b", "\u2028"])
def test_workspace_notes_bidi_and_c1_controls_are_stripped(wn, bad):
    """ASVS V5.3.1 · A03:2021 · CWE-451 · CWE-116 · WSTG-INPV-01: bidi overrides, C1 controls and line separators never reach a stored to-do."""
    note = wn.apply("acme (production)", "rule", "R1", "add_todo", by="tester", text=f"pay{bad}exe.txt")

    assert note["todos"][0]["text"] == "payexe.txt"


def test_workspace_notes_emoji_and_accents_are_kept(wn):
    """ASVS V5.1.3 · CWE-176: ordinary Unicode text (accents, an emoji with a joiner) is kept as typed."""
    text = "Revoir la règle 👩\u200d💻"

    note = wn.apply("acme (production)", "rule", "R1", "add_comment", by="tester", text=text)

    assert note["comments"][0]["text"] == text


@pytest.mark.parametrize("tag", ["<script>", "a\"b", "x'y", "/lead", "_x", "a&b", "a\u200bb"])
def test_workspace_notes_markup_tags_are_refused(wn, tag):
    """ASVS V5.1.3 · A03:2021 · CWE-79 · WSTG-INPV-02: a tag with markup, quotes or a bidi override is refused."""
    with pytest.raises(wn.NotesError):
        wn.apply("acme (production)", "rule", "R1", "add_tag", by="tester", tag=tag)


@pytest.mark.parametrize("href", ["//evil.example/x", "https://evil.example", "javascript:alert(1)", "/\\evil.example", "/a b"])
def test_workspace_notes_off_site_link_is_refused(wn, href):
    """ASVS V5.1.5 · A01:2021 · CWE-601 · WSTG-CLNT-04: a note's link must be a path in this app."""
    with pytest.raises(wn.NotesError):
        wn.apply("acme (production)", "page", "/x", "add_tag", by="tester", tag="t", href=href)


@pytest.mark.parametrize("kind,limit", [("add_todo", 500), ("add_comment", 2000)])
def test_workspace_notes_text_cap_boundary(wn, kind, limit):
    """ASVS V5.1.4 · CWE-400 · WSTG-INPV-01: a to-do or comment exactly at its cap is kept; one more character is refused."""
    wn.apply("acme (production)", "rule", "R1", kind, by="tester", text="x" * limit)

    with pytest.raises(wn.NotesError, match="too long"):
        wn.apply("acme (production)", "rule", "R1", kind, by="tester", text="x" * (limit + 1))


def test_workspace_notes_store_full_refuses_growth(wn, monkeypatch):
    """ASVS V5.1.4 · CWE-400 · CWE-770: once the store is at its byte cap a growing change is refused and nothing is written."""
    monkeypatch.setattr(wn, "MAX_STORE_BYTES", 400)
    wn.apply("acme (production)", "rule", "R1", "add_tag", by="tester", tag="a")
    before = open(wn.store_path(), encoding="utf-8").read()

    with pytest.raises(wn.NotesError) as e:
        wn.apply("acme (production)", "rule", "R1", "add_comment", by="tester", text="y" * 300)

    assert e.value.status == 413 and open(wn.store_path(), encoding="utf-8").read() == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_workspace_notes_store_and_lock_are_owner_only(wn):
    """ASVS V8.3.1 · CWE-276 · CWE-732: the notes store and its lock file are 0600."""
    wn.apply("acme (production)", "rule", "R1", "add_tag", by="tester", tag="a")

    modes = {stat.S_IMODE(os.stat(p).st_mode) for p in (wn.store_path(), wn.store_path() + ".lock")}
    assert modes == {0o600}


def test_workspace_notes_pages_never_build_html_from_notes():
    """ASVS V5.3.3 · A03:2021 · CWE-79 · WSTG-CLNT-03: the To-do page and Find anything render notes through DOM text, never innerHTML."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    srcs = [open(os.path.join(root, "static", f), encoding="utf-8").read() for f in ("report_todo.html", "find_anything.js")]

    assert all("innerHTML" not in s and "insertAdjacentHTML" not in s and "document.write" not in s for s in srcs)
