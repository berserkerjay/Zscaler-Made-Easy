"""The loop, round 2: it reads only the in-scope part with the real
readers, a run whose reads failed is not reported as measured, one run at
a time across processes, an honest audit line, and the Digest page's run
feedback."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

import audit
import continuous_eval as ce
import dlp_api_server as srv
import proposals
import tenant_profiles as tp
from test_continuous_eval import _Recorder, _client, _env, _http, _profile, _state


class _Reads:
    """A client that answers every SDK call with an empty list and records
    the call's path (zia.dlp_web_rules.list_rules, zwa.dlp_incidents...)."""

    def __init__(self, log, path=""):
        self._log, self._p = log, path

    def __getattr__(self, name):
        return _Reads(self._log, f"{self._p}.{name}" if self._p else name)

    def __call__(self, *a, **k):
        self._log.append(self._p)
        return ([], None, None)


class _RateLimited:
    """Every ZIA / ZWA call is refused with HTTP 429."""

    def __init__(self, log):
        self._log = log

    def __getattr__(self, name):
        return self

    def __call__(self, *a, **k):
        self._log.append("call")
        raise RuntimeError("HTTP 429 Too Many Requests: rate limit exceeded")


def _quiet(monkeypatch):
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])


# ── Only the in-scope part is read (FP/TP Detection Ratio included) ──

def test_fp_tp_reads_only_the_dlp_channels_on_zscaler(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    # Workflow Automation's incidents are read only when it is marked Zscaler too.
    _profile(scopes=["dlp"], channels={"web_dlp": "zscaler", "endpoint_dlp": "alternative", "email_dlp": "alternative",
                                       "saas_casb": "alternative", "workflow_automation": "zscaler"}, baseline_packs=[])
    log = []
    d = ce.run_once(build_client=lambda creds: _Reads(log), notify=False)
    t = d["tenants"][0]
    reads = sorted(set(log))
    assert t["errors"] == [] and t["detection_health"] is not None, t
    assert "zia.dlp_web_rules.list_rules" in reads and any(r.startswith("zwa.dlp_incidents") for r in reads), reads
    for off in ("casb_dlp_rules", "endpoint_dlp_rules", "outbound_email_dlp_rules", "saas_security_api", "endpoint_application"):
        assert not any(off in r for r in reads), (off, reads)
    md = ce.to_markdown(d)
    assert "Not read (not in scope): SaaS tenants" in md and "Not read (not in scope): DLP rules on Endpoint, SaaS Security, Email" in md


def test_endpoint_only_never_reads_the_web_rules_or_the_receivers(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    _profile(scopes=["dlp"], channels={"endpoint_dlp": "zscaler", "web_dlp": "alternative"}, baseline_packs=[])
    log = []
    d = ce.run_once(build_client=lambda creds: _Reads(log), notify=False)
    reads = sorted(set(log))
    assert d["tenants"][0]["errors"] == [], d["tenants"][0]
    assert "zia.endpoint_dlp_rules.list_rules" in reads, reads
    assert not any("dlp_web_rules" in r or "dlp_resources" in r or "casb" in r or "email" in r for r in reads), reads
    # No "forward Web DLP matches" proposal from a channel that was not read.
    assert not any(p["kind"] == "enable_incident_forwarding" for p in proposals.list_queue("acme"))


def test_workflow_automation_on_another_product_reads_no_incidents(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    _profile(scopes=["dlp"], channels={"web_dlp": "zscaler", "workflow_automation": "alternative"}, baseline_packs=[])
    log = []
    d = ce.run_once(build_client=lambda creds: _Reads(log), notify=False)
    t = d["tenants"][0]
    assert not any(r.startswith("zwa") for r in log), log
    assert t["detection_health"] is None and any("Workflow Automation is covered by another product" in x for x in t["skipped"])


def test_dlp_with_the_scope_page_default_reads_nothing(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    _profile(scopes=["dlp"], channels={}, baseline_packs=["healthcare_phi_baseline"])
    built = []
    d = ce.run_once(build_client=lambda creds: built.append(1) or _Reads([]), notify=False)
    t = d["tenants"][0]
    assert built == [] and t["note"].startswith("nothing in scope for the loop"), t
    assert "drift not measured" in t["drift"]["note"] and d["summary"]["tenants"] == 0


_ALL_OFF = {"web_dlp": "alternative", "endpoint_dlp": "alternative", "saas_casb": "alternative", "email_dlp": "alternative",
            "workflow_automation": "alternative"}
_RULES_OF = {"web_dlp": "dlp_web_rules", "endpoint_dlp": "endpoint_dlp_rules", "saas_casb": "casb_dlp_rules",
             "email_dlp": "outbound_email_dlp_rules"}


@pytest.mark.parametrize("on", ["endpoint_dlp", "email_dlp", "saas_casb", "web_dlp"])
def test_drift_reads_only_the_in_scope_channel_with_a_ticked_pack(tmp_path, monkeypatch, on):
    """Drift with a ticked pack (Workflow Automation elsewhere, so only drift
    and the SaaS step can read): no other channel's rules, no Web DLP rules
    unless Inline Web is on Zscaler, no SaaS tenants unless SaaS Security is."""
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    _profile(scopes=["dlp"], channels=dict(_ALL_OFF, **{on: "zscaler"}), baseline_packs=["healthcare_phi_baseline"])
    log = []
    d = ce.run_once(build_client=lambda creds: _Reads(log), notify=False)
    t = d["tenants"][0]
    reads = sorted(set(log))
    assert t["errors"] == [], t
    assert any(_RULES_OF[on] in r for r in reads), reads
    for ch, api in _RULES_OF.items():
        if ch != on:
            assert not any(api in r for r in reads), (ch, reads)
    if on != "saas_casb":
        assert not any("saas_security_api" in r or "casb_tenant" in r for r in reads), reads
        assert "Not read (not in scope): SaaS tenants" in ce.to_markdown(d)


def test_drift_with_web_out_of_scope_and_every_read_refused_is_unreachable(tmp_path, monkeypatch):
    """With the Web DLP rules left out, the two reads that remain both
    failing make the tenant unreachable (not 'reachable with 2 of 3')."""
    import pack_deploy

    class _Refuse:
        def __getattr__(self, name):
            return self

        def __call__(self, *a, **k):
            raise RuntimeError("HTTP 429 Too Many Requests")

    snap = pack_deploy.fetch_tenant(_Refuse(), dict(pack_deploy.pc.needs([]), web_rules=False))
    assert snap["reachable"] is False, snap
    assert pack_deploy.fetch_tenant(_Refuse(), pack_deploy.pc.needs([]))["reachable"] is False


# ── A run whose reads failed is not a measurement ────────────────────

def test_every_read_refused_is_partial_and_raises_nothing(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    calls = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: _RateLimited(calls))
    pid = _profile(scopes=["dlp"], channels={"web_dlp": "zscaler"}, baseline_packs=["healthcare_phi_baseline"])
    st, _ = _state(monkeypatch)
    r = _http().post("/api/digests/run", json={"notify": False})
    assert r.status_code == 200 and r.json()["status"] == "partial" and r.json()["errors"] > 0
    t = r.json()["digest"]["tenants"][0]
    assert calls, "the reads were attempted"
    assert st["last_status"] == "partial" and st["profiles"][pid]["status"] == "error", st
    assert any("429" in e for e in t["errors"]) and any(e.startswith("drift:") for e in t["errors"]), t["errors"]
    assert t["detection_health"] is None and t["drift"]["packs"] == [] and "drift not measured" in t["drift"]["note"]
    assert proposals.list_queue("acme") == [], "no proposal from a read that failed"
    hist = tp.get(pid).get("history") or []
    assert not any(h.get("journey") or h.get("detection_health") for h in hist), hist
    assert ce.main(["--once", "--no-notify"]) == 1


# ── Drift measures the pack as packed, never adds a rule ─────────────

def test_drift_never_adds_rules_the_pack_does_not_ship(tmp_path, monkeypatch):
    import pack_deploy as pd
    from test_channel_targets_undo import _pack
    from test_pack_channels import make_client
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    pack = _pack(tmp_path / "packs")          # one Web DLP rule only
    client = make_client()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)["status"] == "applied"
    as_packed = pd.journey(pd.preflight(client, [pack], writes_enabled=False, apply_tweaks=False))["baselines"][0]
    monkeypatch.setattr("dlp_importer.discover_packs", lambda root: [pack])
    monkeypatch.setattr("detection_health.generate", lambda client, **kw: {"errors": [], "summary": {}, "findings": []})
    pid = _profile(scopes=["dlp"], channels={"web_dlp": "zscaler", "endpoint_dlp": "zscaler"}, baseline_packs=["alpha"])
    seen = []
    real = pd.preflight
    monkeypatch.setattr("pack_deploy.preflight", lambda c, p, **kw: seen.append(kw.get("channel_targets")) or real(c, p, **kw))
    d = ce.run_once(build_client=lambda creds: client, notify=False)
    row = d["tenants"][0]["drift"]["packs"][0]
    assert seen == [{"alpha": ["web"]}], seen
    assert (row["stage"], row["score"], row["missing"]) == (as_packed["stage"], as_packed["score"], 0), (row, as_packed)
    assert d["tenants"][0]["errors"] == []
    # A pack with no rule on an in-scope channel is not measured at all.
    tp.upsert({"id": pid, "name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789",
               "scopes": ["dlp"], "channels": {"endpoint_dlp": "zscaler"}, "baseline_packs": ["alpha"]},
              client_secret="secret-secret-secret", remember_secret=True)
    seen.clear()
    d = ce.run_once(build_client=lambda creds: client, notify=False)
    assert seen == [] and len(d["tenants"][0]["drift"]["not_measured"]) == 1, d["tenants"][0]["drift"]


# ── Proposals: "new" means raised by this run, whichever section ran ─

def test_a_saas_only_profile_does_not_count_open_proposals_as_new(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    _profile(scopes=["zia_extras"], channels={"saas_casb": "zscaler"})
    tenants = [{"tenant_id": 2, "tenant_name": "Acme Box", "saas_application": "BOX", "status": "AUTH_EXPIRED", "saas_type": "OFLCASB_DLP_FILE"}]
    first = ce.run_once(build_client=lambda creds: _client(tenants), notify=False)
    assert first["tenants"][0]["proposals"]["new"] == 1
    second = ce.run_once(build_client=lambda creds: _client(tenants), notify=False)
    assert second["tenants"][0]["proposals"]["new"] == 0 and second["summary"]["proposals_new"] == 0
    assert second["tenants"][0]["proposals"]["open"] == 1


# ── The audit line says what was read ────────────────────────────────

def test_the_audit_line_counts_profiles_read_and_every_error(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _quiet(monkeypatch)
    _profile(name="None1", scopes=[], channels={})
    _profile(name="None2", scopes=["zia_extras"], channels={})
    _profile(name="Read", scopes=["dlp"], channels={"web_dlp": "zscaler"})

    def _refused(creds):
        raise RuntimeError("429 Too Many Requests")
    d = ce.run_once(build_client=_refused, notify=False)
    lines = [json.loads(x) for x in open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8") if x.strip()]
    rec = [x for x in lines if x.get("event") == "continuous_evaluation"][-1]
    assert rec["tenants"] == d["summary"]["tenants"] == 1 and rec["tenants_not_in_scope"] == 2, rec
    assert rec["errors"] == ce.run_errors(d) >= 1, rec


# ── One run at a time, across processes ──────────────────────────────

def test_the_cli_does_not_run_while_another_run_holds_the_lock(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    monkeypatch.setattr(srv, "_build_sdk_client", rec.build)
    _profile(scopes=["dlp"], channels={"web_dlp": "zscaler"})
    with ce.run_lock():                       # a run in progress (the server's, say)
        assert ce.main(["--once", "--no-notify"]) == 2
        r = _http().post("/api/digests/run", json={"notify": False})
        assert r.status_code == 409 and "already in progress" in r.text
    assert rec.calls == [] and ce.list_digests() == []
    assert ce.main(["--once", "--no-notify"]) == 0 and "detection_health" in rec.kinds()


def test_the_lock_is_seen_by_another_process(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    monkeypatch.setattr(srv, "_build_sdk_client", rec.build)
    _profile(scopes=["dlp"], channels={"web_dlp": "zscaler"})
    holder = ("import sys, continuous_eval as ce\n"
              "with ce.run_lock():\n"
              "    print('locked', flush=True)\n"
              "    sys.stdin.readline()\n")
    p = subprocess.Popen([sys.executable, "-c", holder], cwd=ce.ROOT, env=dict(os.environ), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "locked"
        assert ce.main(["--once", "--no-notify"]) == 2 and rec.calls == []
    finally:
        p.communicate("\n", timeout=30)
    assert ce.main(["--once", "--no-notify"]) == 0 and "detection_health" in rec.kinds()


def test_two_runs_in_the_same_second_keep_both_digests(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    d1 = {"id": "20261001-161036", "at": "x", "tenants": [], "errors": []}
    d2 = dict(d1)
    ce.write_digest(d1)
    ce.write_digest(d2)
    assert d2["id"] == "20261001-161037" and len([x for x in os.listdir(ce.digest_dir()) if x.endswith(".json")]) == 2


# ── The timer uses the configured interval ───────────────────────────

def test_the_timer_waits_the_configured_interval(monkeypatch):
    import asyncio
    st, _ = _state(monkeypatch)
    st.update({"enabled": True, "interval_seconds": 7 * 3600})
    runs, sleeps = [], []
    monkeypatch.setattr(srv, "_continuous_eval_once", lambda notify=True: runs.append(1))

    async def _sleep(s):
        sleeps.append(s)
        if len(sleeps) > 2:
            st["enabled"] = False
    monkeypatch.setattr(srv.asyncio, "sleep", _sleep)
    asyncio.run(srv._dh_auto_refresh_loop())
    assert sleeps == [30, 7 * 3600, 7 * 3600] and len(runs) == 2


# ── The Digest page ──────────────────────────────────────────────────

PAGE = os.path.join(ce.ROOT, "static", "report_digest.html")
HARNESS = os.path.join(os.path.dirname(__file__), "digest_page_harness.js")
_DIGESTS = {"digests": [{"id": "20261001-120000", "at": "2026-10-01T12:00:00+00:00", "noteworthy": False, "summary": {"tenants": 1}}],
            "notifications": {"interval_hours": 0, "email": {}, "webhook": {}}, "schedule": {"enabled": False}}


def _page(responses, click=False):
    out = subprocess.run(["node", HARNESS, PAGE, json.dumps({"responses": responses, "click": click})],
                         capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


@needs_node
def test_page_says_timer_off_unless_the_server_runs_one():
    off = _page({"GET /api/digests": {"status": 200, "body": _DIGESTS}})
    assert "Timer" in off["sched"] and "off" in off["sched"] and "Every" not in off["sched"], off
    on = dict(_DIGESTS, notifications=dict(_DIGESTS["notifications"], interval_hours=6), schedule={"enabled": True, "next_run_at": 1790000000})
    on_page = _page({"GET /api/digests": {"status": 200, "body": on}})
    assert "Every" in on_page["sched"] and "6 h" in on_page["sched"], on_page
    # Hours set but the server did not start the timer: still off.
    half = dict(on, schedule={"enabled": False})
    assert "Every" not in _page({"GET /api/digests": {"status": 200, "body": half}})["sched"]


@needs_node
def test_page_says_a_partial_run_finished_with_errors():
    res = _page({"GET /api/digests": {"status": 200, "body": _DIGESTS},
                 "POST /api/digests/run": {"status": 200, "body": {"ok": True, "status": "partial", "errors": 2, "digest": {}}}}, click=True)
    assert res["status"].startswith("Finished with errors") and res["warn"] and not res["bad"], res
    assert res["live"] == "The loop finished with errors"
    ok = _page({"GET /api/digests": {"status": 200, "body": _DIGESTS},
                "POST /api/digests/run": {"status": 200, "body": {"ok": True, "status": "ok", "errors": 0, "digest": {}}}}, click=True)
    assert ok["status"].startswith("Done") and not ok["warn"] and ok["live"] == "The loop finished"


@needs_node
def test_page_says_a_run_in_progress_is_not_a_failure():
    res = _page({"GET /api/digests": {"status": 200, "body": _DIGESTS},
                 "POST /api/digests/run": {"status": 409, "body": {"detail": "a run of the loop is already in progress; wait for it to finish"}}},
                click=True)
    assert res["status"].startswith("A run of the loop is already in progress") and "nothing failed" in res["status"], res
    assert not res["bad"] and res["warn"] and res["live"] == "A run is already in progress" and not res["disabled"]


def test_a_client_that_answers_every_attribute_has_no_rate_key_or_label():
    """zia_rate reads only the strings attach_client stamped: a proxy or
    test double that answers every attribute is not mistaken for a label."""
    import zia_rate
    c = _Reads([])
    assert zia_rate.key_of(c) == "" and zia_rate.label_of(c) is None and zia_rate.labels_of(c) is None
    zia_rate.attach_client(c, "k1", ("classic API (production)", "? (production)"))
    assert zia_rate.labels_of(c) == ("classic API (production)", "? (production)")
    assert zia_rate.key_of(c) == "k1" and zia_rate.label_of(c) == "classic API (production)"
