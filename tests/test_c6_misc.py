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


# ── beacon: the outbound fetches and what the history keeps ──────────

TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLW5vdC1yZWFs"


def test_beacon_every_watched_page_is_on_the_fetch_allowlist():
    """ASVS V12.6.1 · A10:2021 · CWE-918 · WSTG-INPV-19: every help-center page Beacon fetches passes the allowlist (https, Zscaler hosts)."""
    import zscaler_update_check as zu
    urls = [s["url"] for s in zu.SOURCES if s.get("type") == "html_hash"]

    refused = {u: why for u in urls for _, why in [zu._allowed_url(u)] if why}

    assert urls and refused == {}


@pytest.mark.parametrize("url", ["http://help.zscaler.com/x", "https://127.0.0.1/", "https://help.zscaler.com.evil.example/",
                                 "https://user@help.zscaler.com/", "https://127.0.0.1\\@help.zscaler.com/"])
def test_beacon_default_fetch_refuses_off_allowlist_urls_without_a_request(url, monkeypatch):
    """ASVS V12.6.1 · A10:2021 · CWE-918 · WSTG-INPV-19: Beacon's fetch refuses http, IPs, look-alike hosts and userinfo before any request."""
    import requests
    import upstream_check
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("a request was sent"))

    text, err = upstream_check.default_fetch(url)

    assert text is None and err


def test_beacon_probe_error_from_the_client_has_tokens_redacted():
    """ASVS V7.1.1 · A09:2021 · CWE-532 · WSTG-ERRH-01: an exception echoing the Authorization header is kept with the token masked."""
    import beacon

    class C:
        def get(self, ep, p=None):
            raise RuntimeError(f"gateway said: Authorization: Bearer {TOKEN}")

    row = beacon.probe_endpoint(C(), "/zia/webDlpRules")

    assert TOKEN not in json.dumps(row) and "[redacted token]" in row["error"]


def test_beacon_probe_error_answer_has_tokens_redacted():
    """ASVS V7.1.1 · CWE-532: an error answer echoing a JWT is kept masked in the probe row."""
    import beacon

    class C:
        def get(self, ep, p=None):
            return {"error": f"invalid token {TOKEN}"}, 401

    row = beacon.probe_endpoint(C(), "/zia/webDlpRules")

    assert row["status"] == "error" and TOKEN not in row["error"]


def test_beacon_probe_with_a_non_numeric_status_is_an_error_row():
    """ASVS V7.4.1 · CWE-755 · CWE-704: a client answering a non-numeric status gives an error row, not an exception."""
    import beacon

    class C:
        def get(self, ep, p=None):
            return {"error": "odd"}, "n/a"

    assert beacon.probe_endpoint(C(), "/zia/x")["http"] == 0


def test_beacon_failed_watch_keeps_its_reason_redacted(tmp_path):
    """ASVS V7.1.1 · CWE-532: a tenant watch that raises keeps its reason with the token masked, in the saved history too."""
    import beacon

    def probe(client, endpoints, **kw):
        raise RuntimeError(f"Bearer {TOKEN}")
    path = str(tmp_path / "beacon_state.json")

    snap = beacon.run(online=False, tenant_client=object(), tenant_label="acme (production)", upstream=lambda **k: {}, path=path,
                      probe=probe, tenant_scope={"endpoints": {"/zia/x": ["m.py"]}, "scopes": ["dlp"], "channels": [], "not_in_scope": [],
                                                 "unmapped": [], "summary": "DLP"})

    assert TOKEN not in json.dumps(snap) and TOKEN not in open(path, encoding="utf-8").read()


def test_beacon_deeply_nested_state_file_is_an_empty_history(tmp_path):
    """ASVS V5.5.3 · CWE-674 · CWE-755: a state file nested past the parser's limit is an empty history, not a crash."""
    import beacon
    p = tmp_path / "beacon_state.json"
    p.write_text("[" * 100000, encoding="utf-8")

    assert beacon.load_history(str(p)) == []


@pytest.mark.parametrize("method", ["POST", "put", "DELETE", "patch", ""])
def test_beacon_tenant_probe_refuses_every_method_but_get(method):
    """ASVS V4.1.3 · A01:2021 · CWE-841 · CWE-749: the tenant watch refuses any method but GET before the client is touched."""
    import beacon

    class C:
        def __getattr__(self, n):
            pytest.fail("the client was touched")

    with pytest.raises(ValueError):
        beacon.probe_tenant(C(), {"/zia/x": ["m.py"]}, method=method)


def test_beacon_read_only_client_cannot_write():
    """ASVS V4.1.3 · CWE-841: the client the watch gets has no post, put, patch, delete or raw request."""
    import beacon

    class C:
        def post(self, *a):
            pytest.fail("a write")

    ro = beacon.ReadOnlyClient(C())

    for name in ("post", "put", "patch", "delete", "request", "_client_post"):
        with pytest.raises(PermissionError):
            getattr(ro, name)


# ── discover_endpoints: a stand-alone probe, made safe ───────────────

class _Resp:
    def __init__(self, status=200, body=None, text=None):
        self.status_code, self._body = status, body
        self.content = (text if text is not None else json.dumps(body)).encode()
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"{self.status_code} error")


@pytest.fixture
def disc(monkeypatch):
    import discover_endpoints as d
    sent: List[Dict[str, Any]] = []
    answers: Dict[str, _Resp] = {}

    def post(url, **kw):
        sent.append({"method": "POST", "url": url, **kw})
        return answers.get("token", _Resp(200, {"access_token": "tok-123"}))

    def get(url, **kw):
        sent.append({"method": "GET", "url": url, **kw})
        return answers.get(url.rsplit("/v1", 1)[-1], _Resp(404, {}))
    monkeypatch.setattr(d.requests, "post", post)
    monkeypatch.setattr(d.requests, "get", get)
    return d, sent, answers


def test_discover_keeps_field_names_and_types_never_values(disc):
    """ASVS V8.3.4 · A02:2021 · CWE-359 · CWE-532: a device row's values (a person's name, a serial) never reach the discovery output."""
    d, sent, answers = disc
    answers["/zcc/devices"] = _Resp(200, [{"user": "alice@example.com", "serial": "SN-PRIVATE-1", "id": 7}])

    rows = d.probe("https://api.zsapi.net/v1", "tok", ["/zcc/devices"], sleep=lambda s: None)

    assert rows[0]["sample_keys"] == ["user", "serial", "id"] and rows[0]["first_item_types"] == {"user": "str", "serial": "str", "id": "int"}
    assert "alice" not in json.dumps(rows) and "SN-PRIVATE" not in json.dumps(rows)


def test_discover_object_and_non_json_answers_keep_no_values(disc):
    """ASVS V8.3.4 · CWE-532: an object answer keeps keys and types; a non-JSON answer keeps its length, never its text."""
    d, sent, answers = disc
    answers["/zia/a"] = _Resp(200, {"secretish": "value-xyz"})
    answers["/zia/b"] = _Resp(200, None, text="<html>value-abc</html>")

    rows = d.probe("https://api.zsapi.net/v1", "tok", ["/zia/a", "/zia/b"], sleep=lambda s: None)

    assert rows[0]["types"] == {"secretish": "str"} and rows[1] == {"path": "/zia/b", "status": 200, "works": True, "type": "non-json", "length": 22}
    assert "value-" not in json.dumps(rows)


def test_discover_follows_no_redirect_with_the_token(disc):
    """ASVS V12.6.1 · A10:2021 · CWE-918 · CWE-601: neither the token POST nor a probe GET follows a redirect."""
    d, sent, answers = disc
    answers["/zia/x"] = _Resp(302, {})

    d.authenticate("cid", "sec", "acme", "production")
    rows = d.probe("https://api.zsapi.net/v1", "tok", ["/zia/x"], sleep=lambda s: None)

    assert all(s["allow_redirects"] is False for s in sent) and "not followed" in rows[0]["note"]


def test_discover_token_redirect_is_an_error(disc):
    """ASVS V12.6.1 · CWE-601: a token endpoint that answers a redirect fails the sign-in instead of repeating the POST elsewhere."""
    d, sent, answers = disc
    answers["token"] = _Resp(307, {})

    with pytest.raises(RuntimeError, match="redirect"):
        d.authenticate("cid", "sec", "acme", "production")


@pytest.mark.parametrize("vanity", ["evil.example/#", "a@b", "x:1"])
def test_discover_bad_vanity_never_sends_the_secret(disc, vanity):
    """ASVS V5.2.6 · A10:2021 · CWE-918 · CWE-522: a vanity domain that is not a DNS name is refused before the token POST."""
    d, sent, _ = disc

    with pytest.raises(ValueError):
        d.authenticate("cid", "sec", vanity, "production")
    assert sent == []


@pytest.mark.parametrize("cloud,host", [("production", "acme.zslogin.net"), ("zscalertwo", "acme.zslogin.net"),
                                        ("zscalerbeta", "acme.zsloginbeta.net"), ("zscalergov", "acme.zidentitygov.net"),
                                        ("zscalergovus", "acme.zidentitygov.us")])
def test_discover_token_goes_to_the_clouds_sign_in_host(disc, cloud, host):
    """ASVS V12.6.1 · CWE-918: the token POST goes to <vanity> under the cloud's ZIdentity domain (as SDK 1.11.3's _get_auth_url)."""
    d, sent, _ = disc

    d.authenticate("cid", "sec", "acme", cloud)

    assert sent[0]["url"] == f"https://{host}/oauth2/v1/token"


def test_discover_request_error_has_tokens_redacted(disc, monkeypatch):
    """ASVS V7.1.1 · CWE-532: a transport error echoing the bearer token is kept masked."""
    d, _, _ = disc

    def boom(url, **kw):
        raise d.requests.exceptions.ConnectionError(f"proxy said Authorization: Bearer {TOKEN}")
    monkeypatch.setattr(d.requests, "get", boom)

    rows = d.probe("https://api.zsapi.net/v1", "tok", ["/zia/x"], sleep=lambda s: None)

    assert TOKEN not in rows[0]["error"] and rows[0]["status"] == 0


@pytest.mark.parametrize("cfg,why", [({}, "lacks client_id, client_secret, vanity_domain"), ([], "JSON object"),
                                     ({"client_id": "a", "client_secret": "b", "vanity_domain": "x/y"}, "Invalid vanity")])
def test_discover_config_is_checked_with_a_plain_error(tmp_path, cfg, why):
    """ASVS V5.1.3 · CWE-20 · CWE-209 · WSTG-INPV-01: a config file that is not what the tool needs is refused in plain words, never echoing a value."""
    import discover_endpoints as d
    p = tmp_path / "tenant.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")

    with pytest.raises(ValueError, match=why) as e:
        d.load_config(str(p))
    assert "x/y" not in str(e.value)


def test_discover_main_writes_an_owner_only_file_without_a_cloud_in_the_config(disc, tmp_path, monkeypatch, capsys):
    """ASVS V8.3.1 · CWE-276 · CWE-732 · CWE-755: a config without a cloud runs (production) and the output is 0600."""
    d, sent, answers = disc
    monkeypatch.setattr(d, "PROBE_PATHS", {"zia_dlp_engines": ["/zia/dlpEngines"]})
    monkeypatch.setattr(d.time, "sleep", lambda s: None)
    answers["/zia/dlpEngines"] = _Resp(200, [{"name": "E", "id": 1}])
    cfg, out = tmp_path / "tenant.json", tmp_path / "discovery.json"
    cfg.write_text(json.dumps({"client_id": "cid", "client_secret": SECRET, "vanity_domain": "acme"}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["discover_endpoints.py", "--config", str(cfg), "--output", str(out)])

    d.main()

    printed = capsys.readouterr().out
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600 and SECRET not in printed + out.read_text()
    assert json.loads(out.read_text())["summary"]["working"][0]["path"] == "/zia/dlpEngines"


def test_discover_failed_sign_in_message_masks_the_secret(disc, tmp_path, monkeypatch, capsys):
    """ASVS V7.1.1 · CWE-209 · CWE-532: a sign-in error that echoes the client secret is printed masked."""
    d, sent, answers = disc
    cfg = tmp_path / "tenant.json"
    cfg.write_text(json.dumps({"client_id": "cid", "client_secret": SECRET, "vanity_domain": "acme", "cloud": "production"}), encoding="utf-8")
    monkeypatch.setattr(d, "authenticate", lambda *a: (_ for _ in ()).throw(RuntimeError(f"bad client_secret={SECRET}")))
    monkeypatch.setattr("sys.argv", ["discover_endpoints.py", "--config", str(cfg), "--output", str(tmp_path / "o.json")])

    with pytest.raises(SystemExit):
        d.main()

    assert SECRET not in capsys.readouterr().out


# ── zscaler_clouds: names and hosts against the installed SDK (1.11.3) ──

ALL_CLOUDS = ["production", "zscaler", "zscalerone", "zscalertwo", "zscalerthree", "zscloud", "zscalerten", "zscalerbeta",
              "zscalergov", "zscalergovus"]


@pytest.mark.parametrize("cloud", ALL_CLOUDS)
def test_clouds_token_url_is_the_sdks(cloud):
    """ASVS V12.6.1 · A10:2021 · CWE-918 · SSDF PW.4.1: each cloud's token URL equals SDK 1.11.3 OAuth._get_auth_url for its environment."""
    import types
    from zscaler.oneapi_oauth_client import OAuth
    import zscaler_clouds as zc
    env = zc.environment(cloud) or "production"

    assert zc.token_url("acme", cloud) == OAuth._get_auth_url(types.SimpleNamespace(), "acme", env)


@pytest.mark.parametrize("cloud", ALL_CLOUDS)
def test_clouds_api_base_is_the_sdks(cloud):
    """ASVS V12.6.1 · CWE-918 · SSDF PW.4.1: each cloud's OneAPI gateway equals SDK 1.11.3 RequestExecutor._resolve_api_base_url."""
    import types
    from zscaler.request_executor import RequestExecutor
    import zscaler_clouds as zc
    fake = types.SimpleNamespace(cloud=zc.environment(cloud) or "production", BASE_URL=RequestExecutor.BASE_URL)

    assert zc.api_base(cloud) == RequestExecutor._resolve_api_base_url(fake)


@pytest.mark.parametrize("cloud,base", [("production", "https://zsapi.zscaler.net"), ("zscalertwo", "https://zsapi.zscalertwo.net"),
                                        ("zscalerten", "https://zsapi.zscalerten.net"), ("zscloud", "https://zsapi.zscloud.net"),
                                        ("zscalerbeta", "https://zsapi.zscalerbeta.net"), ("zscalergov", "https://zsapi.zscalergov.net"),
                                        ("zscalergovus", "https://zsapi.zscalergov.us")])
def test_clouds_classic_api_host_oracle(cloud, base):
    """ASVS V12.6.1 · CWE-918: the classic ZIA API host per cloud (SDK zia/legacy.py builds zsapi.<cloud>.net; .us for govus)."""
    import zscaler_clouds as zc

    assert zc.legacy_api_base(cloud) == base


@pytest.mark.parametrize("spelling,name", [("", "production"), ("Commercial", "production"), ("admin.zscalertwo.net", "zscalertwo"),
                                           ("ZSCALERTEN", "zscalerten"), ("zscalergov.us", "zscalergovus"), ("fedramp", "zscalergov"),
                                           ("zspreview", "zscalerbeta"), (" zscloud.net ", "zscloud")])
def test_clouds_accepted_spellings(spelling, name):
    """ASVS V5.1.3 · CWE-20: every accepted spelling (admin host, .net, case, aliases) names the right cloud."""
    import zscaler_clouds as zc

    assert zc.normalize(spelling) == name


@pytest.mark.parametrize("bad", ["zscaler.com", "zscalergov.usa", "https://admin.zscaler.net", "zscalertwo.net/", "zscaler․net", "x" * 500])
def test_clouds_unknown_spelling_is_refused_and_not_echoed_whole(bad):
    """ASVS V5.1.3 · CWE-20 · CWE-117: an unknown cloud (scheme, slash, look-alike dot, huge) is refused with at most 60 characters of it."""
    import zscaler_clouds as zc

    with pytest.raises(ValueError) as e:
        zc.normalize(bad)
    assert "x" * 61 not in str(e.value)


def test_clouds_government_clouds_are_exactly_the_fedramp_ones():
    """ASVS V1.14.1 · CWE-20: only zscalergov and zscalergovus are government clouds."""
    import zscaler_clouds as zc

    assert {c for c in ALL_CLOUDS if zc.is_government(c)} == {"zscalergov", "zscalergovus"}


@pytest.mark.parametrize("vanity", ["acme", "acme-corp", "a.b", "A1"])
def test_clouds_vanity_accepts_dns_names(vanity):
    """ASVS V5.1.3 · CWE-20: RFC 1123 vanity names are accepted."""
    import zscaler_clouds as zc

    assert zc.check_vanity(vanity) == vanity


@pytest.mark.parametrize("vanity", ["", "-acme", "acme-", "a..b", "acme.", "bücher", "a" * 64, "a/b", "a\\b", "a b", "a:443", "a#"])
def test_clouds_vanity_refuses_anything_but_a_dns_name(vanity):
    """ASVS V5.1.3 · A10:2021 · CWE-918 · WSTG-INPV-19: a vanity that is not an ASCII DNS name (IDN, separators, long label) is refused."""
    import zscaler_clouds as zc

    with pytest.raises(ValueError):
        zc.check_vanity(vanity)


# ── engine_explain: every operator against an oracle table ───────────

NAMES = {"1": "SSN", "2": "CC"}
SUMMARY_ORACLE = [
    ("D1.S > 0", "at least one SSN match"), ("D1.S > 1", "more than one SSN match"), ("D1.S > 2", "more than two SSN matches"),
    ("D1.S >= 0", "any number of SSN matches, even none (always true)"), ("D1.S >= 1", "at least one SSN match"),
    ("D1.S >= 3", "at least three SSN matches"), ("D1.S < 0", "fewer than zero SSN matches (never true)"),
    ("D1.S < 1", "no SSN match"), ("D1.S < 4", "fewer than four SSN matches"), ("D1.S <= 0", "no SSN match"),
    ("D1.S <= 1", "at most one SSN match"), ("D1.S <= 5", "at most five SSN matches"), ("D1.S = 0", "no SSN match"),
    ("D1.S == 1", "exactly one SSN match"), ("D1.S = 12", "exactly 12 SSN matches"), ("D1.S != 0", "at least one SSN match"),
    ("D1.S != 2", "a number of SSN matches other than two"), ("D1.U > 1", "more than one unique SSN match"),
    ("D1.S", "at least one SSN match"), ("NOT D1.S > 0", "no SSN match"), ("NOT D1.S > 1", "not more than one SSN match"),
    ("(D1.S + D2.S) > 1", "more than one match of SSN and CC combined"),
    ("(D1.S + D2.S) >= 0", "any number of SSN and CC combined matches, even none (always true)"),
    ("D1.S > 0 AND D2.S > 0", "at least one SSN match and at least one CC match"),
    ("D1.S > 0 OR D2.S > 1", "at least one SSN match or more than one CC match"),
    ("(D1.S > 0 OR D2.S > 0) AND D1.S < 9", "either at least one SSN match or at least one CC match and fewer than nine SSN matches"),
    ("D9.S > 0", "at least one unknown dictionary 9 match"),
]


@pytest.mark.parametrize("expr,says", SUMMARY_ORACLE)
def test_engine_explain_summary_oracle(expr, says):
    """ASVS V5.1.3 · CWE-1023 · CWE-480: every comparison operator and Boolean join reads as ZIA evaluates it, the always- and never-true bounds included."""
    import engine_explain as ee

    assert ee.summary(expr, NAMES) == f"Fires when the content has {says}."


@pytest.mark.parametrize("expr", ["D1.S >", "D1.S > -1", "5", "(D1.S > 0", "D1.S > 0 AND", "D1.S >> 1", "AND D1.S", "x" * 5000])
def test_engine_explain_unparseable_gets_no_summary_but_ids_named(expr):
    """ASVS V5.1.3 · CWE-20 · CWE-755: an expression it cannot read gets no summary (never a guess) and no exception."""
    import engine_explain as ee

    out = ee.explain(expr, NAMES)

    assert out["summary"] == "" and out["parsed"] is False and out["expression"] == expr


@pytest.mark.parametrize("op", [">", ">=", "<", "<=", "=", "==", "!="])
def test_engine_explain_readable_keeps_every_operator(op):
    """ASVS V5.1.3 · CWE-1023: the readable form names the dictionary and keeps the operator ('==' as '=')."""
    import engine_explain as ee

    assert ee.readable(f"((D1.S {op} 3))", NAMES) == f"SSN count {'=' if op == '==' else op} 3"


# ── plain_english: every section reads its own outcome ───────────────

def test_plain_english_section_5_reads_the_detection_outcome():
    """ASVS V1.1.1 · CWE-1023 · CWE-670: section 5 (Endpoint DLP: rules, dictionaries, EDM) gets its own outcome, not the endpoint channel's."""
    import plain_english as pe

    assert pe.outcome_for("5.10", "5 — Endpoint DLP").startswith("Sensitive data is detected accurately")
    assert pe.outcome_for("B.1", "Ch.B — Endpoint").startswith("Sensitive data cannot leave through USB")


def test_plain_english_every_outcome_the_registry_can_reach_is_reached():
    """ASVS V1.1.1 · CWE-561: no outcome meant for an assessment section is shadowed by an earlier, broader entry."""
    import dlp_assessment_full_auto as engine
    import plain_english as pe
    reached = {pe.outcome_for(cid, sec) for cid, sec, _, _ in engine.REG}

    meant = {text for keys, text in pe.OUTCOMES if any(k.endswith(".") and any(c.lower().startswith(k) for c, *_ in engine.REG) for k in keys)}

    assert meant <= reached


@pytest.mark.parametrize("status,start", [("PASS", "Label X is configured"), ("FAIL", "Label X: action required."),
                                          ("REVIEW", "Label X needs a person"), ("ERROR", "Label X could not be checked"),
                                          ("INFO", "Label X is not configured")])
def test_plain_english_found_sentence_per_status(status, start):
    """ASVS V7.4.1 · CWE-755: each status reads its own 'found' sentence."""
    import plain_english as pe

    out = pe.enrich({"id": "5.10", "section": "5 — Endpoint DLP", "label": "Label X", "status": status, "detail": "Seen. More."})

    assert out["plain"]["found"].startswith(start) and set(out["plain"]) >= {"found", "means", "do", "outcome"}


# ── corpus_engines: Sum terms, the older D(n) form, every operator ───

@pytest.mark.parametrize("expr,want", [("(D(1) + D(2)) > 1", True), ("(D(1).S + D(2).S) > 1", True), ("(D1.S + D(2)) >= 2", True),
                                       ("(D(1) + D(2) + D(3)) = 3", True), ("(D(1) + D(2)) > 2", False)])
def test_corpus_sum_counts_every_dictionary_in_the_older_form(expr, want):
    """ASVS V5.1.3 · CWE-1023 · CWE-682: a Sum in the D(n) form adds every dictionary's count, not only the first."""
    import corpus_engines as ce

    result, ids, _ = ce.evaluate_expression(expr, {1: 1, 2: 1, 3: 1})

    assert result is want and set(ids) <= {1, 2, 3}


def test_corpus_sum_synthetic_term_is_not_a_dictionary():
    """ASVS V5.1.3 · CWE-1023: a Sum engine lists only its real dictionaries, never the internal stand-in term."""
    import corpus_engines as ce

    out = ce.engine_results([{"id": 5, "name": "E", "engineExpression": "(D1.S + D2.S) > 1"}], [], {1: 1, 2: 1}, {1: "A", 2: "B"})

    assert out[0]["dictionaries"] == ["A", "B"] and out[0]["fires"] is True


def test_corpus_sum_stand_in_never_collides_with_a_real_id():
    """ASVS V5.1.3 · CWE-1023 · CWE-694: a real dictionary numbered like the Sum stand-in keeps its own count."""
    import corpus_engines as ce

    result, _, terms = ce.evaluate_expression("(D1.S + D2.S) > 1 AND D900000.S > 0", {1: 1, 2: 1, 900000: 0})

    assert result is False and any(t.startswith("D900000.S > 0: 0") for t in terms)


@pytest.mark.parametrize("op,count,n,want", [(">", 2, 1, True), (">", 1, 1, False), (">=", 1, 1, True), (">=", 0, 1, False),
                                             ("<", 0, 1, True), ("<", 1, 1, False), ("<=", 1, 1, True), ("<=", 2, 1, False),
                                             ("=", 1, 1, True), ("==", 2, 1, False), ("!=", 2, 1, True), ("!=", 1, 1, False),
                                             (">", None, 1, None)])
def test_corpus_operator_oracle(op, count, n, want):
    """ASVS V5.1.3 · CWE-1023 · CWE-697: every comparison operator, boundaries and the unknown count, as ZIA evaluates D<id>.S terms."""
    import corpus_engines as ce

    assert ce.evaluate_expression(f"D1.S {op} {n}", {1: count})[0] is want


@pytest.mark.parametrize("a,b,op,want", [(True, None, "AND", None), (False, None, "AND", False), (True, None, "OR", True),
                                         (False, None, "OR", None)])
def test_corpus_three_valued_logic(a, b, op, want):
    """ASVS V5.1.3 · CWE-1023: an unknown term decides nothing it cannot decide (Kleene AND / OR)."""
    import corpus_engines as ce
    counts = {1: 1 if a else 0, 2: None}

    assert ce.evaluate_expression(f"D1.S > 0 {op} D2.S > 0", counts)[0] is want


# ── native_zscaler: a pack never keeps another tenant's dictionary id ──

@pytest.mark.parametrize("expr,bad", [("D7.U > 1 AND D8.S > 0", "D7.U"), ("D(7) > 0", "D(7)"), ("(D(7).S > 1)", "D(7).S")])
def test_native_engine_with_a_term_a_pack_cannot_name_is_left_out(expr, bad):
    """ASVS V5.1.3 · A08:2021 · CWE-1023 · CWE-706: an engine term other than D<id>.S is not carried with the source tenant's id; the engine is named as left out."""
    import native_zscaler as nz
    warnings: List[str] = []

    out = nz.convert_engine({"name": "E", "customDlpEngine": True, "engineExpression": expr}, {"7": "A", "8": "B"}, warnings)

    assert out is None and bad in warnings[0]


def test_native_engine_with_s_terms_converts_by_name():
    """ASVS V5.1.3 · CWE-20: D<id>.S terms become D:<name>; nothing is left out."""
    import native_zscaler as nz
    warnings: List[str] = []

    out = nz.convert_engine({"name": "E", "customDlpEngine": True, "engineExpression": "((D7.S > 1) AND (D8.S > 0))"}, {"7": "A", "8": "B"}, warnings)

    assert out == {"name": "E", "expression": "((D:A > 1) AND (D:B > 0))"} and warnings == []


# ── guidance: only a web address becomes a proposal ──────────────────

@pytest.fixture
def gd(monkeypatch, tmp_path):
    import guidance
    monkeypatch.setenv("DLP_CHECK_GUIDANCE_STATE", str(tmp_path / "guidance_state.json"))
    monkeypatch.setenv("DLP_CHECK_CHECKS_CONFIG", str(tmp_path / "checks_config.json"))
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    guidance.save_state({"seen": {}, "sources": {}, "baselined_at": "2026-01-01T00:00:00+00:00"})
    return guidance


@pytest.mark.parametrize("url", ["javascript:alert(1)//ssl inspection", "data:text/html,ssl inspection", "//evil.example/ssl-inspection",
                                 "https://user@evil.example/ssl inspection", "https:\\\\evil.example/ssl-inspection"])
def test_guidance_non_web_article_url_never_becomes_a_proposal(gd, url):
    """ASVS V5.1.5 · A03:2021 · CWE-79 · CWE-601 · WSTG-CLNT-04: an article whose URL is not an http(s) web address is recorded as no action, never a linked proposal."""
    res = gd.evaluate([{"url": url, "title": "SSL inspection now supports TLS 1.3", "first_seen": 1_000}], now=2_000)

    assert res["raised"] == [] and res["no_action"] == 1


def test_guidance_web_article_still_becomes_a_proposal(gd):
    """ASVS V5.1.5 · CWE-20: an https article on a mapped topic still becomes a proposal."""
    res = gd.evaluate([{"url": "https://help.zscaler.com/zia/ssl-inspection", "title": "SSL inspection best practice", "first_seen": 1_000}], now=2_000)

    assert [r["url"] for r in res["raised"]] == ["https://help.zscaler.com/zia/ssl-inspection"]


def test_guidance_malformed_entry_fields_do_not_stop_the_run(gd):
    """ASVS V7.4.1 · CWE-755 · CWE-20: an entry with a non-numeric first_seen, a non-string URL or no object at all is skipped or read, never a crash."""
    entries = ["junk", {"url": 7}, {"url": "https://help.zscaler.com/zia/dlp-engine", "title": "DLP engine tips", "first_seen": "yesterday"}]

    res = gd.evaluate(entries, now=2_000)

    assert [r["url"] for r in res["raised"]] == ["https://help.zscaler.com/zia/dlp-engine"]


# ── vertical: industry words, not substrings ─────────────────────────

@pytest.mark.parametrize("given,industry", [
    ("Healthcare", "Healthcare"), ("hospital network", "Healthcare"), ("Real estate", "Other"), ("FedEx logistics", "Other"),
    ("Federal agency", "Federal"), ("US DoD contractor", "Federal"), ("Defence", "Federal"), ("Community bank", "Financial services"),
    ("Statewide agency", "State & local government"), ("Local government", "State & local government"), ("fintech", "Technology"),
    ("Software", "Technology"), ("University", "Education"), ("Auto manufacturing", "Manufacturing"), ("", ""), ("Farming", "Other"),
    ("law enforcement (cjis)", "Law enforcement (CJIS)"),
])
def test_vertical_industry_oracle(given, industry):
    """ASVS V5.1.3 · CWE-20 · CWE-185: a free-text industry maps by words ('real estate' is not a state, 'FedEx' not federal)."""
    import vertical

    assert vertical.normalize_industry(given) == industry


def test_vertical_other_shows_everything_and_a_chosen_pack_wins():
    """ASVS V5.1.3 · CWE-20: no or Other industry narrows nothing; packs chosen on the profile win over the industry's."""
    import vertical

    other = vertical.scope_for({"industry": "Farming"}, all_frameworks=["HIPAA", "CIS"], all_packs=["a", "b"])
    chosen = vertical.scope_for({"industry": "Healthcare", "baseline_packs": ["b"]}, all_packs=["a", "b"])

    assert (other["frameworks"], other["packs"], other["scoped"]) == (["HIPAA", "CIS"], ["a", "b"], False)
    assert (chosen["packs"], chosen["packs_from"]) == (["b"], "profile")


# ── corpus_engines: the validators against published reference values ──

@pytest.mark.parametrize("fn,value,ok", [
    ("luhn_ok", "4111 1111 1111 1111", True), ("luhn_ok", "4111 1111 1111 1112", False), ("luhn_ok", "046454286", False),
    ("npi_ok", "1234567893", True), ("npi_ok", "1234567890", False),                           # CMS NPI check-digit example
    ("aba_ok", "011000015", True), ("aba_ok", "011000016", False), ("aba_ok", "001000015", False),
    ("iban_ok", "GB82 WEST 1234 5698 7654 32", True), ("iban_ok", "GB82 WEST 1234 5698 7654 33", False), ("iban_ok", "GB82", False),
    ("mbi_ok", "1EG4-TE5-MK73", True), ("mbi_ok", "1EG4-TE5-MK7S", False),                    # CMS specimen MBI
    ("_mod11", "943 476 5919", True), ("_mod11", "943 476 5918", False),                       # NHS example number
    ("_tfn", "123 456 782", True), ("_tfn", "123 456 783", False),
    ("_sin_ok", "046 454 286", True), ("_sin_ok", "046 454 287", False), ("_sin_ok", "4111111111111111", False),
    ("ssn_ok", "078-05-1120", False), ("ssn_ok", "666-12-1234", False), ("ssn_ok", "987-65-4321", False),
])
def test_corpus_validator_oracle(fn, value, ok):
    """ASVS V5.1.3 · CWE-1023 · CWE-697: each local detector's check digit agrees with the published reference value."""
    import corpus_engines as ce

    assert getattr(ce, fn)(value) is ok


def test_corpus_canadian_sin_detector_finds_a_valid_sin():
    """ASVS V5.1.3 · CWE-1023 · CWE-697: the Canadian SIN detector counts a nine-digit Luhn-valid SIN (it never could: the card minimum applied)."""
    import corpus_engines as ce
    det = next(d for d in ce.DETECTORS if d["key"] == "canada_sin")

    n, samples = ce.run_detector(det, "SIN 046 454 286 on file; 046 454 287 is a typo.")

    assert (n, samples) == (1, ["••• ••• 286"])


@pytest.mark.parametrize("group,ok", [(49, False), (50, True), (65, True), (66, False), (69, False), (70, True), (88, True), (89, False),
                                      (90, True), (92, True), (93, False), (94, True), (99, True)])
def test_corpus_itin_group_boundaries(group, ok):
    """ASVS V5.1.3 · CWE-1023 · CWE-697: an ITIN's group digits are 50-65, 70-88, 90-92 or 94-99 (IRS), boundaries included."""
    import corpus_engines as ce

    assert ce.itin_ok(f"900-{group:02d}-0000") is ok


@pytest.mark.parametrize("key", ["credit_card", "mbi", "iban", "aba"])
def test_corpus_synthetic_samples_are_detected(key):
    """ASVS V5.1.3 · CWE-1023: every published test value the POV kit ships is counted by its own detector."""
    import corpus_engines as ce

    assert all(ce.sample_detected(key, ce.sample(key, i)) for i in range(len(ce.SAMPLES[key])))


def test_corpus_reserved_ssns_are_not_counted_and_generated_samples_are_injected():
    """ASVS V5.1.3 · CWE-330: the reserved 987-65-432x SSNs are not counted by the strict detector; generated samples use the injected RNG."""
    import random
    import corpus_engines as ce

    assert not any(ce.sample_detected("ssn", ce.sample("ssn", i)) for i in range(10))
    assert ce.sample("phone", rng=random.Random(1)) == ce.sample("phone", rng=random.Random(1)) and ce.sample("phone", rng=random.Random(1)).startswith("(555) 555-01")
    with pytest.raises(KeyError):
        ce.sample("nope")
