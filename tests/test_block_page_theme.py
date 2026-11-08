"""Block page theme builder (block_page_theme.py, ops_zia_eun.py, /api/block-page/*): a local, read-only preview and
generator; applying to ZIA only through Bulk changes with write mode, an assessor and the typed phrase APPLY EUN.
Fakes only: no tenant, no network; state in tmp_path."""
from __future__ import annotations

import base64
import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import block_page_theme as bpt  # noqa: E402
import ops_zia_eun as oe  # noqa: E402
import pack_channels as pc  # noqa: E402
from test_admin_ops import FULL_SCOPE, Tenant  # noqa: E402

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\0" * 40).decode()
ASSESSOR = "Jane Doe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_BLOCK_PAGE_THEME", str(tmp_path / "bpt.json"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    ao.load_plugins()
    return tmp_path


# ── the theme ────────────────────────────────────────────────────────────
def test_html_escapes_every_value_and_has_no_script_or_external_resource():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: hostile text in a theme is escaped in the generated page, which holds no script, no external URL and a CSP."""
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    s = bpt.clean_theme({"org_name": evil, "title": evil, "message": evil, "support_email": "a@b.co"})
    page = bpt.render_html(s, {"mime": "image/png", "b64": PNG})
    assert "<script" not in page.lower() and "<img src=x" not in page and "&lt;img src=x" in page
    assert "&lt;script&gt;" in page and "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "http://" not in page and "src=\"data:image/png;base64," in page


@pytest.mark.parametrize("raw", [{"accent": "red"}, {"accent": "#12345"}, {"policy_link": "javascript:alert(1)"}, {"policy_link": "http://x.example"},
                                 {"support_email": "not an email"}, {"support_phone": "<b>"}, {"show_logo": "yes"}, {"surprise": 1},
                                 {"title": ""}, {"title": "x" * 81}])
def test_bad_settings_are_refused(raw):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: colours, links, contacts, switches and unknown keys are validated; a bad value is refused, not cut or ignored."""
    with pytest.raises(bpt.ThemeError):
        bpt.clean_theme(raw)


@pytest.mark.parametrize("data", ["", "not base64!!", base64.b64encode(b"<svg onload=alert(1)/>").decode(),
                                  base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * (bpt.MAX_LOGO_BYTES + 1)).decode()])
def test_logo_must_be_a_small_png_jpeg_or_gif_by_its_bytes(data):
    """ASVS V12.2.1 · CWE-434 · WSTG-BUSL-08: a logo that is not base64, is SVG, or is too large is refused; the declared type is not trusted."""
    with pytest.raises(bpt.ThemeError):
        bpt.clean_logo(data)
    with pytest.raises(bpt.ThemeError):
        bpt.clean_logo("data:image/png;base64," + data)   # claiming PNG does not make it one


def test_logo_is_stored_locally_and_never_returned_as_bytes(isolated):
    """ASVS V6.1.1 · CWE-312: the logo lives in the local store; the page-facing theme carries its facts only, and an export holds it as a data URI."""
    out = bpt.save("acme", {"org_name": "Acme"}, logo="data:image/png;base64," + PNG, by="alice")
    assert out["logo"]["mime"] == "image/png" and "b64" not in str(out)
    assert PNG not in str(bpt.get("acme"))
    assert PNG in bpt.generate("acme")["html"]
    assert os.stat(isolated / "bpt.json").st_mode & 0o077 == 0
    bpt.remove_logo("acme")
    assert bpt.get("acme")["logo"] is None and PNG not in bpt.generate("acme")["html"]


def test_theme_count_and_names_are_bounded():
    """ASVS V5.1.4 · CWE-770: at most MAX_THEMES themes; a name that is not a short slug is refused."""
    for i in range(bpt.MAX_THEMES):
        bpt.save(f"t{i}", {})
    with pytest.raises(bpt.ThemeError):
        bpt.save("one-more", {})
    for bad in ("../x", "A b", "x" * 41):
        with pytest.raises(bpt.ThemeError):
            bpt.clean_name(bad)


def test_review_warns_about_low_contrast_and_missing_contact():
    """WCAG 2.2 SC 1.4.3 · ASVS V1.1.2: pale text on a white card is flagged below 4.5:1, and a missing contact is named."""
    w = bpt.review(dict(bpt.DEFAULTS, text="#cccccc"))
    assert any("contrast" in x and "4.5" in x for x in w) and any("support contact" in x for x in w)
    assert bpt.contrast("#000000", "#ffffff") == 21.0


def test_generate_sends_nothing_and_omits_blank_text_from_the_settings():
    """ASVS V4.1.3 · CWE-862: generating is read-only; blank text is not sent (it would erase ZIA's value) and the logo is never in the settings."""
    bpt.save("a", {"message": "Hello", "support_email": "", "show_logo": True}, logo=PNG)
    g = bpt.generate("a")
    assert g["eun_settings"]["customText"] == "Hello" and "supportEmail" not in g["eun_settings"] and g["eun_settings"]["displayCompLogo"] is True
    assert PNG not in str(g["eun_settings"])


# ── applying, through the engine ─────────────────────────────────────────
class Eun:
    def __init__(self, t, current=None):
        self.t = t
        self.cur = copy.deepcopy(current if current is not None else {"notificationType": "DEFAULT", "displayReason": False, "displayCompName": True,
                                                                        "displayCompLogo": False, "supportEmail": "old@x.co", "aupFrequency": "NEVER"})
        self.sent = []

    def __call__(self, zia, method, path, body=None):
        assert path == "/eun"
        if method == "GET":
            return copy.deepcopy(self.cur), None
        assert not self.t.frozen, "a write was sent during a preview"
        self.sent.append(copy.deepcopy(body))
        self.cur = copy.deepcopy(body)
        return body, None


def tenant(monkeypatch, **kw):
    t = Tenant()
    e = Eun(t, **kw)
    monkeypatch.setattr(pc, "raw_request", e)
    return t, e


SPEC = {"type": oe.TYPE, "theme": "acme"}


def preview(t, spec=SPEC, scope=FULL_SCOPE):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=scope, tenant_label="acme")
    finally:
        t.frozen = False


def apply(t, spec=SPEC, *, phrase=None, prepared=None, writes=True, assessor=ASSESSOR):
    p = prepared or preview(t, spec)
    return p, ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=writes, assessor=assessor, tenant_label="acme",
                         confirm_text=p["confirm_phrase"] if phrase is None else phrase)


def test_registered_under_build_new_and_unchanged_defaults_are_listed():
    """ASVS V1.14.1 · CWE-1059: the theme change is one plugin type of the one engine, with its form script present."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert cat[oe.TYPE]["group"] == "Build new" and cat[oe.TYPE]["script"] == "ops_zia_eun.js"
    assert os.path.isfile(os.path.join(ROOT, "static", "ops_zia_eun.js"))


def test_plan_lists_each_changed_field_before_and_after_and_sends_nothing(monkeypatch):
    """ASVS V4.1.3 · V11.1.1 · CWE-841 · WSTG-BUSL-01: the preview lists only the fields that differ, asks APPLY EUN, warns that users see it and that the logo is not sent; nothing is written."""
    bpt.save("acme", {"message": "Blocked by policy", "show_reason": True, "support_email": "help@acme.example"})
    t, e = tenant(monkeypatch)
    p = preview(t)
    fields = {u["field"]: (u["before"], u["after"]) for u in p["items"]}
    assert fields["displayReason"] == (False, True) and fields["supportEmail"] == ("old@x.co", "help@acme.example")
    assert "displayCompName" not in fields           # already True: no change listed
    assert p["confirm_phrase"] == oe.PHRASE and oe.LOGO_NOTE in p["warnings"] and e.sent == []


def test_apply_needs_write_mode_the_assessor_and_the_typed_phrase(monkeypatch):
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: disabled by default: without write mode, a named assessor or the typed phrase nothing is sent."""
    bpt.save("acme", {"message": "Hi"})
    t, e = tenant(monkeypatch)
    p = preview(t)
    with pytest.raises(PermissionError):
        apply(t, prepared=p, writes=False)
    with pytest.raises(ao.OperationError, match="assessor"):
        apply(t, prepared=p, assessor=" ")
    _p, r = apply(t, prepared=p, phrase="apply")
    assert r["status"] == "refused" and e.sent == []


def test_apply_puts_the_object_as_read_with_only_the_planned_fields_then_undo_restores(monkeypatch, isolated):
    """ASVS V11.1.1 · V7.1.3 · CWE-754 · WSTG-BUSL-01: one PUT carries the object as read plus the changed fields, it reads back, is audited, and Undo restores the old values."""
    bpt.save("acme", {"message": "Hi", "show_reason": True})
    t, e = tenant(monkeypatch)
    before = copy.deepcopy(e.cur)
    import pack_ops as ops
    with ops.audit_scope(actor="alice"):
        p, r = apply(t)
    assert ao.record(r, by=ASSESSOR, actor="alice")
    assert r["status"] == "applied" and len(e.sent) == 1
    assert e.sent[0]["aupFrequency"] == "NEVER" and e.sent[0]["customText"] == "Hi" and e.sent[0]["displayReason"] is True
    assert r["verification"]["mismatched"] == [] and r["verification"]["confirmed"] == r["verification"]["checked"] >= 1
    inv = r["inverse"]
    assert inv["type"] == oe.TYPE and inv["settings"]["displayReason"] is False and "customText" not in inv["settings"]
    undo = ao.plan(t, inv, scope=FULL_SCOPE, tenant_label="acme")
    ao.execute(t, inv, plan_hash=undo["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
               confirm_text=undo["confirm_phrase"])
    assert e.cur["displayReason"] == before["displayReason"] and e.cur["supportEmail"] == before["supportEmail"]
    import audit
    assert any(x.get("event") == "admin_operation" and x.get("type") == oe.TYPE for x in audit.tail(50))


def test_a_field_changed_after_the_preview_is_a_conflict_and_nothing_is_sent(monkeypatch):
    """ASVS V11.1.1 · CWE-367 · WSTG-BUSL-01: someone edits the settings in the portal after the preview: the re-plan differs and nothing is sent."""
    bpt.save("acme", {"message": "Hi", "show_reason": True})
    t, e = tenant(monkeypatch)
    p = preview(t)
    e.cur["displayReason"] = True          # a planned field, changed in the portal after the preview
    _p, r = apply(t, prepared=p)
    assert r["status"] in ("plan_changed", "conflict") and e.sent == []


def test_already_matching_settings_are_blocked(monkeypatch):
    """ASVS V11.1.1 · CWE-841: nothing to change is a blocked plan, not an empty write."""
    bpt.save("acme", {"message": "Hi"})
    t, e = tenant(monkeypatch)
    want = bpt.settings_for(bpt.get("acme")["settings"], None)
    e.cur.update(want)
    p = preview(t)
    assert p["status"] == "blocked" and e.sent == []


def test_unreadable_settings_plan_nothing_and_unknown_theme_is_refused(monkeypatch):
    """ASVS V7.4.1 · CWE-754: an unreadable /eun and a theme that does not exist both plan nothing."""
    bpt.save("acme", {})
    t = Tenant()
    monkeypatch.setattr(pc, "raw_request", lambda zia, m, p, b=None: (None, "HTTP 500"))
    with pytest.raises(ao.OperationError, match="could not be read"):
        preview(t)
    t2, _e = tenant(monkeypatch)
    with pytest.raises(ao.OperationError, match="no saved theme"):
        preview(t2, {"type": oe.TYPE, "theme": "ghost"})


def test_out_of_scope_and_bad_specs_are_refused(monkeypatch):
    """ASVS V4.1.3 · V5.1.3 · CWE-863: no ZIA area in scope, an unknown field or a javascript: link in an Undo spec is refused before anything is read."""
    t, e = tenant(monkeypatch)
    with pytest.raises(ao.OperationError):
        ao.plan(t, SPEC, scope=ao.scope_for(["zpa"], {}))
    for bad in ({"type": oe.TYPE, "settings": {"aupMessage": "x"}}, {"type": oe.TYPE, "settings": {"orgPolicyLink": "javascript:x"}},
                {"type": oe.TYPE}, {"type": oe.TYPE, "theme": "a", "settings": {"displayReason": True}}):
        with pytest.raises(ao.OperationError):
            oe.normalize(bad)


# ── routes ───────────────────────────────────────────────────────────────
@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    return TestClient(srv.app)


def test_routes_save_preview_export_and_delete_without_a_tenant(client):
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: the theme routes work on a fresh install with no tenant, the export is a no-store nosniff attachment with a CSP, and a bad body is a 4xx."""
    r = client.put("/api/block-page/theme", json={"name": "acme", "settings": {"org_name": "Acme"}, "logo": PNG})
    assert r.status_code == 200 and r.json()["logo"]["mime"] == "image/png" and PNG not in r.text
    assert client.get("/api/block-page/themes").json()["themes"][0]["name"] == "acme"
    p = client.post("/api/block-page/preview", json={"name": "acme", "settings": {"title": "Nope"}}).json()
    assert "<title>Nope</title>" in p["html"] and p["eun_settings"]["displayCompLogo"] is True
    x = client.get("/api/block-page/export", params={"name": "acme"})
    assert x.status_code == 200 and x.headers["cache-control"] == "no-store" and x.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in x.headers["content-disposition"] and "default-src 'none'" in x.headers["content-security-policy"]
    assert client.put("/api/block-page/theme", json={"name": "acme", "settings": {"accent": "red"}}).status_code == 400
    assert client.put("/api/block-page/theme", json={"name": "../x", "settings": {}}).status_code == 400
    assert client.delete("/api/block-page/theme", params={"name": "acme", "logo_only": True}).json()["logo"] is None
    assert client.delete("/api/block-page/theme", params={"name": "acme"}).status_code == 200
    assert client.delete("/api/block-page/theme", params={"name": "acme"}).status_code == 404


def test_ui_script_shows_the_page_only_in_a_sandboxed_frame_and_escapes():
    """WCAG 2.2 SC 4.1.2 · ASVS V5.3.3 · CWE-79: the form registers the type, names its inputs, escapes values through H.E and frames the generated page with sandbox=""."""
    js = open(os.path.join(ROOT, "static", "ops_zia_eun.js"), encoding="utf-8").read()
    assert "register({ type: 'zia_eun_theme'" in js and 'sandbox=""' in js and "srcdoc" in js and "H.E" in js
    assert js.count("aria-label") >= 5


# ── "Use my hosted block page": notificationType CUSTOM + redirectUrl ───────
HOSTED = "https://blocked.acme.example/page.html"
HOSTED_SPEC = {"type": oe.TYPE, "theme": "acme", "hosted_url": HOSTED}


def test_every_field_the_app_writes_is_a_field_of_the_sdk_model():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-20: reads the installed SDK's EndUserNotification model at test time and asserts every field this app writes is one of its fields, so the field names are evidence, not an assumption."""
    import re
    import upstream_check as uc
    from zscaler.zia.models.endusernotification import EndUserNotification
    sdk = uc.installed_sdk_dir()
    assert sdk, "the Zscaler SDK is not installed"
    model = set(EndUserNotification({}).request_format()) | uc.model_wire_fields("endusernotification", sdk)   # the model's own wire names
    assert {"notificationType", "redirectUrl", "displayCompLogo"} <= model
    theme_fields = set(bpt.settings_for(bpt.clean_theme({"message": "x", "support_email": "a@b.co", "support_phone": "123", "policy_link": "https://x.example"}), {"mime": "image/png"}))
    assert set(oe.WRITTEN_FIELDS) <= model and set(bpt.EUN_FIELDS) <= model and theme_fields <= model
    src = open(os.path.join(sdk, "zia", "end_user_notification.py"), encoding="utf-8").read()
    assert re.search(r"notification_type \(str\): EUN type\. Values: DEFAULT, CUSTOM", src)
    assert set(oe.NOTIFICATION_TYPES) == {"DEFAULT", "CUSTOM"} and oe.HOSTED_TYPE == "CUSTOM"


def test_hosted_page_plan_sets_custom_type_and_redirect_with_the_same_gates(monkeypatch):
    """ASVS V4.1.3 · V11.1.1 · CWE-841 · WSTG-BUSL-01: choosing a hosted page adds notificationType CUSTOM and redirectUrl to the preview, still asks APPLY EUN and warns users are sent to that address; nothing is written."""
    bpt.save("acme", {"message": "Hi"})
    t, e = tenant(monkeypatch)
    p = preview(t, HOSTED_SPEC)
    f = {u["field"]: (u["before"], u["after"]) for u in p["items"]}
    assert f["notificationType"] == ("DEFAULT", "CUSTOM") and f["redirectUrl"] == (None, HOSTED)
    assert p["confirm_phrase"] == oe.PHRASE and oe.HOSTED_NOTE in p["warnings"] and e.sent == []
    plain = {u["field"] for u in preview(t, SPEC)["items"]}
    assert "notificationType" not in plain and "redirectUrl" not in plain
    with pytest.raises(PermissionError):
        apply(t, HOSTED_SPEC, writes=False)
    _p, r = apply(t, HOSTED_SPEC, phrase="apply")
    assert r["status"] == "refused" and e.sent == []


@pytest.mark.parametrize("url", ["http://blocked.acme.example/p.html", "https://user:pw@blocked.acme.example/p.html", "https://user@blocked.acme.example/",
                                 "javascript:alert(1)", "ftp://x.example/p", "https:///nohost", "//blocked.acme.example/p", "https://blocked.acme.example/a b",
                                 "https://blocked.acme.example\\@evil.example/", "https://blocked.acme.example/\"onload=x", "https://x.example/" + "a" * 1100, "", "   "])
def test_redirect_url_must_be_https_without_credentials(monkeypatch, url):
    """ASVS V5.1.5 · CWE-601 · WSTG-CLNT-04: a hosted block page address that is not https, carries credentials or odd characters is refused before anything is read or sent."""
    bpt.save("acme", {"message": "Hi"})
    t, e = tenant(monkeypatch)
    with pytest.raises(ao.OperationError):
        oe.check_redirect_url(url)
    spec = {"type": oe.TYPE, "theme": "acme", "hosted_url": url}
    if url.strip():
        with pytest.raises(ao.OperationError):
            ao.plan(t, spec, scope=FULL_SCOPE, tenant_label="acme")
    with pytest.raises(ao.OperationError):
        ao.plan(t, {"type": oe.TYPE, "settings": {"redirectUrl": url or "http://x"}}, scope=FULL_SCOPE, tenant_label="acme")
    assert e.sent == []


def test_hosted_page_apply_reads_back_and_undo_restores_type_and_redirect(monkeypatch, isolated):
    """ASVS V11.1.1 · V7.1.3 · CWE-754 · WSTG-BUSL-01: applying a hosted page sends one PUT with CUSTOM and the address, reads it back, audits, and Undo puts the old notification type back."""
    bpt.save("acme", {"message": "Hi"})
    t, e = tenant(monkeypatch, current={"notificationType": "DEFAULT", "redirectUrl": "https://old.example/p", "displayReason": False, "displayCompName": True,
                                        "displayCompLogo": False, "aupFrequency": "NEVER"})
    import pack_ops as ops
    with ops.audit_scope(actor="alice"):
        _p, r = apply(t, HOSTED_SPEC)
    assert ao.record(r, by=ASSESSOR, actor="alice")
    assert r["status"] == "applied" and len(e.sent) == 1
    assert e.sent[0]["notificationType"] == "CUSTOM" and e.sent[0]["redirectUrl"] == HOSTED and e.sent[0]["aupFrequency"] == "NEVER"
    assert r["verification"]["mismatched"] == [] and r["verification"]["confirmed"] == r["verification"]["checked"] >= 2
    inv = r["inverse"]
    assert inv["settings"]["notificationType"] == "DEFAULT" and inv["settings"]["redirectUrl"] == "https://old.example/p"
    undo = ao.plan(t, inv, scope=FULL_SCOPE, tenant_label="acme")
    ao.execute(t, inv, plan_hash=undo["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme", confirm_text=undo["confirm_phrase"])
    assert e.cur["notificationType"] == "DEFAULT" and e.cur["redirectUrl"] == "https://old.example/p"
    import audit
    assert any(x.get("event") == "admin_operation" and x.get("type") == oe.TYPE for x in audit.tail(50))


def test_hosted_url_needs_a_theme_and_a_known_type(monkeypatch):
    """ASVS V5.1.3 · CWE-20: a hosted address without a theme, or an Undo spec with an unknown notification type, is refused."""
    t, _e = tenant(monkeypatch)
    with pytest.raises(ao.OperationError):
        oe.normalize({"type": oe.TYPE, "settings": {"displayReason": True}, "hosted_url": HOSTED})
    with pytest.raises(ao.OperationError, match="notificationType"):
        oe.normalize({"type": oe.TYPE, "settings": {"notificationType": "FANCY"}})


def test_ui_offers_the_hosted_option_and_sends_it_in_the_spec():
    """ASVS V5.3.3 · CWE-79: the form has the 'Use my hosted block page' option and puts the address in the operation spec; values are escaped."""
    js = open(os.path.join(ROOT, "static", "ops_zia_eun.js"), encoding="utf-8").read()
    assert "Use my hosted block page" in js and "hosted_url" in js and "E(z.hostedUrl)" in js
