"""Cloud QA wave 6, area "posture": shadowed rules, the posture score and
its alerts, device posture, browser security and the audit timeline.

Every test is pure or runs against tmp files and fakes: no tenant, no
network (a socket guard fails any connection), no real clock."""
from __future__ import annotations

import json
import random
import socket
from datetime import datetime, timedelta, timezone

import pytest

import audit_timeline as at
import browser_security as bs
import continuous_eval as ce
import device_posture as dp
import posture_plus as pp
import shadow_rules as sr
import tenant_profiles as tp
import zpa_reader as zr


# ── isolation: tmp files, no notification, no network ─────────────────
@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for k, v in {"DLP_CHECK_SECRET_STORE": "file", "DLP_CHECK_POSTURE_SETTINGS": tmp_path / "posture_settings.json",
                 "DLP_CHECK_PROFILES": tmp_path / "tenant_profiles.json", "DLP_CHECK_DIGESTS": tmp_path / "digests",
                 "DLP_CHECK_AUDIT": tmp_path / "audit.log", "DLPCHECK_PROPOSALS_FILE": tmp_path / "proposals.json",
                 "DLPCHECK_CHANGE_QUEUE_FILE": tmp_path / "change_requests.json",
                 "DLP_CHECK_GUIDANCE_STATE": tmp_path / "guidance_state.json", "DLP_CHECK_CHECKS_CONFIG": tmp_path / "checks_config.json",
                 "DLP_CHECK_SAAS_MATRIX": tmp_path / "saas_apps.local.json", "DLP_CHECK_SAAS_MATRIX_REFRESH": "0"}.items():
        monkeypatch.setenv(k, str(v))
    for k in ("DLP_CHECK_SMTP_HOST", "DLP_CHECK_DIGEST_TO", "DLP_CHECK_DIGEST_WEBHOOK", "DLP_CHECK_NOTIFY", "DLP_CHECK_SMTP_USER"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("bp_crawler.last_summary", lambda: {})
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])


@pytest.fixture
def no_network(monkeypatch):
    """Any socket connection fails the test; returns the attempts."""
    tried = []

    def refuse(*a, **k):
        tried.append(a)
        raise AssertionError("a network connection was attempted")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    return tried


def _no_tenant(creds):
    raise AssertionError("tenant read")


# ══ 1. Shadowed rules ═════════════════════════════════════════════════
def _r(i, order, action="ALLOW", state="ENABLED", **kw):
    d = {"id": i, "name": f"r{i}", "order": order, "state": state, "action": action}
    d.update(kw)
    return d


def _kind_of(res, rule_name):
    return sorted(f["kind"] for f in res["findings"] if f["rule"] == rule_name and f["kind"] != "disabled")


# (policy, rule A (above), rule B (below), web DLP mode, the finding on B)
SHADOW_ORACLE = [
    # URL filtering: first match; group criteria are supersets.
    ("url_filtering", {"urlCategories": ["GAMBLING", "ADULT"]}, {"urlCategories": ["GAMBLING"]}, "", ["shadowed"]),
    ("url_filtering", {"urlCategories": ["GAMBLING"]}, {"urlCategories": ["GAMBLING", "ADULT"]}, "", []),
    ("url_filtering", {"urlCategories": ["GAMBLING"], "users": [{"id": 1}]}, {"urlCategories": ["GAMBLING"]}, "", []),
    ("url_filtering", {"urlCategories": ["GAMBLING"]}, {"urlCategories": ["GAMBLING"], "users": [{"id": 1}]}, "", ["shadowed"]),
    ("url_filtering", {"urlCategories": ["GAMBLING"], "excludedUsers": [{"id": 9}]}, {"urlCategories": ["GAMBLING"]}, "", []),
    ("url_filtering", {"urlCategories": ["GAMBLING"], "timeWindows": [{"id": 1}]}, {"urlCategories": ["GAMBLING"]}, "", []),
    ("url_filtering", {"urlCategories": ["GAMBLING"], "sizeQuota": 100}, {"urlCategories": ["GAMBLING"]}, "", []),
    ("url_filtering", {"urlCategories": ["ANY"]}, {"urlCategories": ["GAMBLING"]}, "", ["after_catch_all"]),
    ("url_filtering", {"urlCategories": ["GAMBLING"], "protocols": ["HTTP_RULE"]}, {"urlCategories": ["GAMBLING"], "protocols": ["HTTP_RULE"]}, "", ["duplicate"]),
    # A non-terminal action never shadows (Cloud Firewall hands over on EVAL_NWAPP).
    ("firewall", {"action": "EVAL_NWAPP", "destAddresses": ["10.0.0.0/8"]}, {"destAddresses": ["10.0.0.0/8"]}, "", []),
    ("firewall", {"action": "BLOCK_DROP", "destAddresses": ["10.0.0.1", "10.0.0.2"]}, {"destAddresses": ["10.0.0.1"]}, "", ["shadowed"]),
    ("firewall", {"srcIps": ["10.1.1.1"]}, {"srcIpGroups": [{"id": 3}]}, "", []),
    # Inline Web DLP by rule order: engines must be the same set.
    ("web_dlp", {"dlpEngines": [{"id": 1}]}, {"dlpEngines": [{"id": 1}], "users": [{"id": 2}]}, "rule_order", ["shadowed"]),
    ("web_dlp", {"dlpEngines": [{"id": 1}, {"id": 2}]}, {"dlpEngines": [{"id": 1}]}, "rule_order", []),
    ("web_dlp", {"withoutContentInspection": True}, {"dlpEngines": [{"id": 1}]}, "rule_order", ["after_catch_all"]),
    ("web_dlp", {"dlpEngines": [{"id": 1}], "ocrEnabled": False}, {"dlpEngines": [{"id": 1}], "ocrEnabled": True}, "rule_order", []),
    ("web_dlp", {"dlpEngines": [{"id": 1}], "minSize": 10}, {"dlpEngines": [{"id": 1}], "minSize": 20}, "rule_order", ["shadowed"]),
    ("web_dlp", {"dlpEngines": [{"id": 1}], "minSize": 20}, {"dlpEngines": [{"id": 1}], "minSize": 10}, "rule_order", []),
    # Inline Web DLP evaluate all, Endpoint DLP: superseded (stricter action wins), never shadowed.
    ("web_dlp", {"action": "BLOCK", "dlpEngines": [{"id": 1}]}, {"action": "ALLOW", "dlpEngines": [{"id": 1}], "users": [{"id": 2}]}, "evaluate_all", ["superseded"]),
    ("web_dlp", {"action": "ALLOW", "dlpEngines": [{"id": 1}]}, {"action": "BLOCK", "dlpEngines": [{"id": 1}], "users": [{"id": 2}]}, "evaluate_all", []),
    ("endpoint_dlp", {"action": "BLOCK", "dlpEngines": [{"id": 1}]}, {"action": "ALLOW", "dlpEngines": [{"id": 1}]}, "", ["superseded"]),
    # Outbound email: ties are not claimed, a stricter rule is.
    ("email_dlp", {"action": "BLOCK", "dlpEngines": [{"id": 1}]}, {"action": "BLOCK", "dlpEngines": [{"id": 1}], "users": [{"id": 2}]}, "", []),
    ("email_dlp", {"action": "BLOCK", "dlpEngines": [{"id": 1}]}, {"action": "QUARANTINE", "dlpEngines": [{"id": 1}]}, "", ["superseded"]),
    # SaaS: duplicates only.
    ("saas_dlp", {"dlpEngines": [{"id": 1}]}, {"dlpEngines": [{"id": 1}]}, "", ["duplicate"]),
    ("saas_dlp", {"withoutContentInspection": True}, {"dlpEngines": [{"id": 1}]}, "", []),
    # Cloud App Control: per type, only the activities named.
    ("cloud_app_control", {"type": "WEBMAIL", "applications": ["GMAIL"], "actions": ["BLOCK_WEBMAIL_VIEW", "BLOCK_WEBMAIL_SEND"]},
     {"type": "WEBMAIL", "applications": ["GMAIL"], "actions": ["ALLOW_WEBMAIL_SEND"]}, "", ["shadowed"]),
    ("cloud_app_control", {"type": "WEBMAIL", "applications": ["GMAIL"], "actions": ["BLOCK_WEBMAIL_VIEW"]},
     {"type": "WEBMAIL", "applications": ["GMAIL"], "actions": ["ALLOW_WEBMAIL_SEND"]}, "", []),
    ("cloud_app_control", {"type": "WEBMAIL", "applications": ["GMAIL"], "actions": ["BLOCK_WEBMAIL_VIEW"]},
     {"type": "FILE_SHARE", "applications": ["GMAIL"], "actions": ["ALLOW_WEBMAIL_VIEW"]}, "", []),
    ("cloud_app_control", {"type": "WEBMAIL", "applications": [], "actions": ["BLOCK_WEBMAIL_VIEW"]},
     {"type": "WEBMAIL", "applications": ["GMAIL"], "actions": ["ALLOW_WEBMAIL_VIEW"]}, "", []),
    # SSL inspection: a rule targeting Zscaler-maintained lists is never compared.
    ("ssl_inspection", {"action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["FINANCE", "HEALTH"]},
     {"action": {"type": "DECRYPT"}, "urlCategories": ["FINANCE"]}, "", ["shadowed"]),
]


@pytest.mark.parametrize("policy, a, b, mode, expected", SHADOW_ORACLE)
def test_shadowed_rule_detection_matches_the_oracle_for_every_rule_type(policy, a, b, mode, expected):
    """ASVS V1.14.1 · CWE-697 · WSTG-BUSL-01: shadowed, catch-all, duplicate and superseded rules match the oracle per rule type."""
    rules = [_r(1, 1, **dict({"action": a.get("action", "ALLOW")}, **a)), _r(2, 2, **dict({"action": b.get("action", "ALLOW")}, **b))]
    res = sr.analyse({policy: rules}, web_dlp_mode=mode or sr.MODE_UNKNOWN)
    assert _kind_of(res, "r2") == expected


def test_the_shadowing_rule_wins_over_a_later_one_and_is_named():
    """ASVS V1.14.1 · CWE-697 · WSTG-BUSL-01: a rule is reported once, against the first covering rule above it."""
    rules = [_r(1, 1, "BLOCK", urlCategories=["A", "B"]), _r(2, 2, "ALLOW", urlCategories=["A", "B", "C"]), _r(3, 3, "ALLOW", urlCategories=["A"])]
    res = sr.analyse({"url_filtering": rules})
    f = [x for x in res["findings"] if x["rule"] == "r3"]
    assert len(f) == 1 and f[0]["shadowed_by"]["name"] == "r1" and f[0]["severity"] == "medium"


def _brute_first_match(rules):
    """The reference: every rule above, in order (the n² model the index must equal)."""
    out, above = [], []
    for b in rules:
        if not b["enabled"]:
            continue
        if b.get("default_rule"):
            above.append(b)
            continue
        for a in above:
            if not sr._terminal(a):
                continue
            if b["policy"] == "cloud_app_control" and not sr._cac_covers_actions(a, b):
                continue
            if sr.is_catch_all(a, b):
                out.append((b["name"], "after_catch_all", a["name"]))
                break
            if sr.covers(a, b)[0]:
                same = (a.get("action") == b.get("action")) if b["policy"] != "cloud_app_control" else (sr._activities(a) == sr._activities(b))
                out.append((b["name"], "duplicate" if a["sig"] == b["sig"] and same else "shadowed", a["name"]))
                break
        above.append(b)
    return out


def _random_rules(rng, policy, n):
    pick = lambda pool: rng.sample(pool, rng.randint(0, 2))  # noqa: E731
    rules = []
    for i in range(n):
        r = {"id": i, "name": f"r{i}", "order": i + 1, "state": rng.choice(["ENABLED"] * 5 + ["DISABLED"])}
        if policy == "cloud_app_control":
            r.update(type=rng.choice(["WEBMAIL", "AI_ML"]), applications=pick(["A", "B", "C"]),
                     actions=rng.sample(["BLOCK_WEBMAIL_VIEW", "ALLOW_WEBMAIL_SEND", "CAUTION_WEBMAIL_UPLOAD"], rng.randint(1, 2)))
        else:
            r["action"] = rng.choice(["ALLOW", "BLOCK", "EVAL_NWAPP" if policy == "firewall" else "CAUTION"])
            r["users"] = [{"id": u} for u in pick([1, 2, 3])]
            r["groups"] = [{"id": g} for g in pick([7, 8])]
            if policy == "url_filtering":
                r["urlCategories"] = pick(["ANY", "GAMBLING", "ADULT", "NEWS"])
                r["protocols"] = pick(["HTTP_RULE", "HTTPS_RULE"])
            elif policy == "firewall":
                r["destAddresses"] = pick(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
                r["nwServices"] = [{"id": s} for s in pick([20, 21])]
            elif policy == "web_dlp":
                r["dlpEngines"] = [{"id": e} for e in pick([61, 62])]
                r["withoutContentInspection"] = rng.random() < 0.15
                r["urlCategories"] = pick(["GAMBLING", "NEWS"])
        rules.append(r)
    return rules


@pytest.mark.parametrize("policy", ["url_filtering", "firewall", "web_dlp", "cloud_app_control"])
def test_the_candidate_index_finds_exactly_what_comparing_every_pair_finds(policy):
    """ASVS V1.14.1 · CWE-697 · WSTG-BUSL-01: the pair index never misses or invents a shadow (seeded oracle against all pairs)."""
    rng = random.Random(20261029)
    for _ in range(25):
        raw = _random_rules(rng, policy, 40)
        sr._MEMO.tokens = {}
        try:
            rules = sorted((sr.normalize(policy, r) for r in raw), key=sr._sort_key)
            groups = {}
            for r in rules:
                groups.setdefault(r.get("type") or "" if policy == "cloud_app_control" else "", []).append(r)
            want = sorted(x for g in groups.values() for x in _brute_first_match(g))
            got = sorted((f["rule"], f["kind"], f["shadowed_by"]["name"]) for g in groups.values() for f in sr._first_match(g))
        finally:
            sr._MEMO.tokens = None
        assert got == want


@pytest.mark.parametrize("policy", ["firewall", "url_filtering", "web_dlp"])
def test_a_large_tenant_compares_only_the_pairs_that_matter(policy, monkeypatch):
    """ASVS V11.1.4 · CWE-407 · CWE-400 · WSTG-BUSL-07: 600 distinct rules cost about one comparison each, not 180,000."""
    n, calls = 600, {"n": 0}
    real = sr.covers

    def counting(a, b):
        calls["n"] += 1
        return real(a, b)
    monkeypatch.setattr(sr, "covers", counting)
    key = {"firewall": "destAddresses", "url_filtering": "urlCategories", "web_dlp": "dlpEngines"}[policy]
    rules = [_r(i, i + 1, "BLOCK", **{key: [{"id": i}] if policy == "web_dlp" else [f"V{i}"]}) for i in range(n)]
    res = sr.analyse({policy: rules}, web_dlp_mode=sr.MODE_RULE_ORDER)
    assert [f for f in res["findings"] if f["kind"] != "disabled"] == []
    assert calls["n"] <= 2 * n


def test_rules_with_the_same_criteria_are_still_candidates_when_a_criterion_cannot_be_compared():
    """ASVS V1.14.1 · CWE-697 · WSTG-BUSL-01: identical rules with an unmodelled field are still reported as duplicates."""
    rules = [_r(1, 1, "BLOCK", urlCategories=["A"], someNewField="x"), _r(2, 2, "BLOCK", urlCategories=["A"], someNewField="x")]
    assert _kind_of(sr.analyse({"url_filtering": rules}), "r2") == ["duplicate"]


# ══ 2. Posture score, projections and alerts ═════════════════════════
def _c(cid, status, sec="S"):
    return {"id": cid, "sec": sec, "label": cid, "status": status}


SCORE_ORACLE = [
    # (statuses, score)  score = round(PASS / (PASS + FAIL + REVIEW) * 100); INFO and ERROR do not count
    (["PASS"], 100), (["FAIL"], 0), (["PASS", "FAIL"], 50), (["PASS", "REVIEW", "FAIL"], 33),
    (["PASS", "PASS", "FAIL"], 67), (["PASS", "INFO", "ERROR"], 100), (["INFO", "ERROR"], None), ([], None),
]


@pytest.mark.parametrize("statuses, score", SCORE_ORACLE)
def test_the_score_is_the_engines_formula(statuses, score):
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: the overall score matches the documented formula, with no score when nothing is scoreable."""
    assert pp.score_of([_c(f"c{i}", s) for i, s in enumerate(statuses)]) == score


def test_points_and_the_projection_are_the_formula_run_twice():
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: fixing 2 of 4 failing checks out of 8 lifts 50 to 75, and INFO is never 'fixed'."""
    checks = [_c(f"p{i}", "PASS") for i in range(4)] + [_c(f"f{i}", "FAIL") for i in range(3)] + [_c("r0", "REVIEW"), _c("i0", "INFO")]
    p = pp.project(checks, selected=["f0", "r0", "i0", "nope"])
    assert (p["score"], p["projected"], p["points"]) == (50, 75, 25)
    assert p["fixed"] == ["f0", "r0"] and p["ignored"] == ["i0", "nope"]
    assert pp.points_for(checks, ["f0"])["exact_points"] == 12.5


def test_a_staged_fix_recipe_counts_and_a_pack_deploy_does_not():
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: only pending or approved fix recipes for failing checks move the projection."""
    checks = [_c("p0", "PASS"), _c("f0", "FAIL"), _c("f1", "FAIL"), _c("f2", "FAIL")]
    reqs = [{"id": 1, "status": "pending", "kind": "fix_recipe", "payload": {"check_id": "f0"}},
            {"id": 2, "status": "rejected", "kind": "fix_recipe", "payload": {"check_id": "f1"}},
            {"id": 3, "status": "approved", "kind": "deploy", "payload": {}},
            {"id": 4, "status": "approved", "kind": "fix_recipe", "payload": {"check_id": "p0"}}]
    p = pp.project(checks, requests=reqs)
    assert p["fixed"] == ["f0"] and p["projected"] == 50
    assert [x["request"] for x in p["queue"]["not_counted"]] == [3, 4]


@pytest.mark.parametrize("prev, cur, threshold, lost", [
    (80, 75, 5, 5), (80, 76, 5, None), (80, 90, 5, None), (80.0, 70.4, 5, 9), (None, 10, 5, None), ("80", 10, 5, None),
    (True, 0, 1, None), (float("inf"), 3, 5, None), (float("nan"), 3, 5, None), (80, float("-inf"), 5, None),
])
def test_score_drop_boundaries_and_values_that_are_no_score(prev, cur, threshold, lost):
    """ASVS V5.1.4 · CWE-20 · CWE-681 · WSTG-INPV-01: a drop is reported from the threshold up; true, NaN and Infinity are no score and never raise."""
    assert pp.score_drop(prev, cur, threshold) == lost


def _entry(at_, score, states):
    return {"at": at_, "score": score, "maturity": "x", "checks": len(states), "states": states}


def _profile_with_drop():
    p = tp.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "scopes": []},
                  client_secret="secret-secret-secret", remember_secret=True)
    tp.add_history(p["id"], _entry("2026-01-01T00:00:00+00:00", 80, {"4.1": "P"}))
    tp.add_history(p["id"], _entry("2026-02-01T00:00:00+00:00", 70, {"4.1": "F"}))
    return p["id"]


def _later(monkeypatch, step=[0]):
    """Each digest a second apart, from an injected clock (no wait, no real time)."""
    base = datetime(2026, 3, 1, tzinfo=timezone.utc)

    class _Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            step[0] += 1
            return base + timedelta(seconds=step[0])
    monkeypatch.setattr(ce, "datetime", _Clock)


def test_an_assessment_drop_is_reported_once_not_again_every_other_run(monkeypatch, no_network):
    """ASVS V7.1.1 · CWE-799 · WSTG-BUSL-05: the third run after a drop still knows the first one reported it."""
    _profile_with_drop()
    _later(monkeypatch)
    runs = [ce.run_once(build_client=_no_tenant, notify=False) for _ in range(3)]
    assert [len(d["tenants"][0]["score_alerts"]) for d in runs] == [1, 0, 0]
    assert no_network == []


def test_a_drop_is_not_sent_when_score_drop_alerts_are_off(monkeypatch, no_network):
    """ASVS V8.3.4 · CWE-359 · WSTG-BUSL-01: a digest sent for another reason does not carry a score drop the operator kept local."""
    _profile_with_drop()
    sent = []
    monkeypatch.setenv("DLP_CHECK_DIGEST_WEBHOOK", "https://example.webhook.office.com/webhookb2/abc")
    monkeypatch.setenv("DLP_CHECK_NOTIFY", "always")
    monkeypatch.setattr(ce, "_send_webhook", lambda subject, body, url: sent.append(body) or {"channel": "webhook", "sent": True})
    d = ce.run_once(build_client=_no_tenant, notify=True)
    assert d["tenants"][0]["score_alerts"] and "Score drop" in ce.to_markdown(d)   # kept in the digest itself
    assert len(sent) == 1 and "Score drop" not in sent[0] and "0 score drop(s)" in sent[0]
    assert no_network == []


def test_a_drop_is_sent_when_score_drop_alerts_are_on(monkeypatch, no_network):
    """ASVS V7.1.1 · CWE-778 · WSTG-BUSL-01: turned on, the drop alone makes the digest noteworthy and it is in what is sent."""
    _profile_with_drop()
    pp.save_settings({"score_drop_points": 5, "notify_score_drop": True})
    sent = []
    monkeypatch.setenv("DLP_CHECK_DIGEST_WEBHOOK", "https://example.webhook.office.com/webhookb2/abc")
    monkeypatch.setattr(ce, "_send_webhook", lambda subject, body, url: sent.append(body) or {"channel": "webhook", "sent": True})
    d = ce.run_once(build_client=_no_tenant, notify=True)
    assert d["noteworthy"] and len(sent) == 1 and "Score drop:" in sent[0] and "80% → 70%" in sent[0]
    assert no_network == []


def test_no_channel_configured_sends_nothing_and_opens_no_connection(no_network):
    """ASVS V14.2.1 · CWE-918 · WSTG-INPV-19: with alerts on but no e-mail or webhook set up, nothing is sent and no socket opens."""
    _profile_with_drop()
    pp.save_settings({"score_drop_points": 5, "notify_score_drop": True})
    d = ce.run_once(build_client=_no_tenant, notify=True)
    assert d["notified"][0]["sent"] is False and no_network == []


def test_the_carried_forward_list_is_bounded(monkeypatch):
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-07: what a digest remembers as reported stays small, however many drops there were."""
    pid = _profile_with_drop()
    _later(monkeypatch)
    many = [f"2025-{m:02d}-{d:02d}T00:00:00+00:00" for m in range(1, 4) for d in range(1, 15)]
    ce.write_digest({"id": "20260101-000000", "at": "x", "tenants": [{"profile_id": pid, "score_alerts_reported": many}]})
    d = ce.run_once(build_client=_no_tenant, notify=False)
    assert len(d["tenants"][0]["score_alerts_reported"]) == ce.ALERTS_KEPT and d["tenants"][0]["score_alerts"]


# ══ 3. Device posture ════════════════════════════════════════════════
@pytest.mark.parametrize("posture_type, family", [
    ("CROWDSTRIKE_ZTA_SCORE", "edr"), ("CROWD_STRIKE", "edr"), ("DETECT_CROWD_STRIKE", "edr"), ("DETECT_MS_DEFENDER", "edr"),
    ("DETECT_SENTINELONE", "edr"), ("DETECT_CARBON_BLACK", "edr"), ("MS_EDR", "edr"), ("XDR_SCORE", "edr"),
    ("DOMAIN_JOINED", "domain_join"), ("AZURE_AD_DOMAIN_JOINED", "domain_join"), ("ENTRA_JOINED", "domain_join"),
    ("CERTIFICATE_TRUST", "certificate"), ("SERVER_VALIDATED_CLIENT_CERTIFICATE", "certificate"),
    ("FULL_DISK_ENCRYPTION", "disk_hygiene"), ("ZCC_VERSION", "disk_hygiene"), ("OS_VERSION", "os_version"),
    ("UNAUTHORIZED_MODIFICATION", "mobile_integrity"), ("JAMF_DETECTION", "mdm"), ("FIREWALL", "firewall"),
    ("PROCESS_CHECK", "process"), ("FILE_PATH", "marker"), ("REGISTRY_KEY", "marker"), ("OWNERSHIP_VARIABLE", "marker"),
    ("crowd-strike", "edr"), ("", None), ("SOMETHING_NEW", None), ("CENTRAL_POLICY", None), ("SHREDDER", None),
])
def test_posture_families_are_inferred_from_the_type(posture_type, family):
    """ASVS V1.14.1 · CWE-697 · WSTG-BUSL-01: posture types land in the right family; a keyword inside another word is no match."""
    assert dp.family_from_type(posture_type) == family


@pytest.mark.parametrize("name, posture_type, family, source", [
    ("CrowdStrike installed", "FILE_PATH", "marker", "type"), ("Falcon override", "", "marker", "name"),
    ("SentinelOne check", "", "edr", "name"), ("Corp AD joined", "", "domain_join", "name"),
    ("Legacy check 7", "SOMETHING_NEW", "unknown", "none"), ("Central policy", "CENTRAL_POLICY", "unknown", "none"),
])
def test_a_marker_is_never_enforcement_and_the_source_is_said(name, posture_type, family, source):
    """ASVS V1.14.1 · CWE-697 · WSTG-BUSL-01: the classification says whether it came from the type or the name, and markers never enforce."""
    c = dp.classify(name, posture_type)
    assert (c["family"], c["source"]) == (family, source) and c["enforces"] == (family not in ("marker", "unknown"))


def _cond_rule(operator, negated, rhs, with_other=True, rule_op="AND"):
    ops = [{"type": "POSTURE", "lhs": "u", "rhs": rhs}] + ([{"type": "PLATFORM", "lhs": "mac", "rhs": "true"}] if with_other else [])
    return {"operator": rule_op, "conditions": [{"operator": operator, "negated": negated, "operands": ops}]}


@pytest.mark.parametrize("operator, negated, rhs, sense, optional", [
    ("OR", False, "true", "must_pass", True),     # posture OR platform: posture optional
    ("AND", False, "true", "must_pass", False),
    ("OR", False, "false", "must_fail", True),
    ("AND", False, "false", "must_fail", False),
    ("OR", True, "true", "must_fail", False),     # NOT (posture OR platform) = NOT posture AND NOT platform
    ("OR", True, "false", "must_pass", False),    # NOT (fails OR platform) = passes AND NOT platform: required
    ("AND", True, "true", "must_fail", True),     # NOT (posture AND platform) = NOT posture OR NOT platform
    ("AND", True, "false", "must_pass", True),
])
def test_negated_posture_conditions_follow_de_morgan(operator, negated, rhs, sense, optional):
    """ASVS V1.14.1 · CWE-697 · CWE-863 · WSTG-ATHZ-02: a negated condition flips both the sense and whether the posture is optional."""
    u = dp._uses(_cond_rule(operator, negated, rhs), "POSTURE")[0]
    assert (u["sense"], u["optional"]) == (sense, optional)


def test_a_posture_check_alone_is_never_optional_and_or_rules_make_it_so():
    """ASVS V1.14.1 · CWE-863 · WSTG-ATHZ-02: a lone posture operand is required unless the rule joins its conditions with OR."""
    assert dp._uses(_cond_rule("OR", True, "false", with_other=False), "POSTURE")[0]["optional"] is False
    r = _cond_rule("AND", False, "true", with_other=False, rule_op="OR")
    r["conditions"].append({"operator": "OR", "negated": False, "operands": [{"type": "PLATFORM", "lhs": "mac", "rhs": "true"}]})
    assert dp._uses(r, "POSTURE")[0]["optional"] is True


def test_a_negated_or_with_a_must_fail_posture_is_enforced_and_not_flagged_optional():
    """ASVS V1.14.1 · CWE-863 · WSTG-ATHZ-02: NOT (fails EDR OR on macOS) requires EDR, so it counts as enforced and is not DP-04."""
    rule = zr.normalize_rule({"id": "r1", "ruleOrder": "1", "name": "Rule", "action": "ALLOW", "operator": "AND", "conditions": [
        {"operator": "OR", "negated": True, "operands": [{"objectType": "POSTURE", "lhs": "u", "rhs": "false"},
                                                         {"objectType": "PLATFORM", "lhs": "mac", "rhs": "true"}]}]}, 0, "access")
    snap = {"collections": {"posture_profiles": {"read": True, "complete": True}, "trusted_networks": {"read": True, "complete": True}},
            "posture_profiles": [], "trusted_networks": [], "policies": {"access": [rule]}}
    rep = dp.analyze(snap, raw_profiles=[{"id": "p1", "name": "Corp EDR", "postureUdid": "u", "postureType": "CROWDSTRIKE_ZTA_SCORE"}], raw_trusted=[])
    assert rep["rules"][0]["flags"] == [] and rep["counts"]["allow_rules_enforced"] == 1
    assert "must pass" in rep["rules"][0]["posture"][0]["via"]


def test_condition_html_escapes_tenant_names():
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-01: a profile name with markup is shown as text."""
    names = dp.Names({}, [dict(dp.normalize_profile({"id": "p", "name": "<img src=x onerror=alert(1)>", "postureUdid": "u"}))])
    rule = {"operator": "AND", "conditions": [{"operator": "OR", "negated": True, "operands": [{"type": "POSTURE", "lhs": "u", "rhs": "true"}]}]}
    html = dp.condition_html(dp.condition_tree(rule, names))
    assert "<img" not in html and "&lt;img" in html and "NOT" in html


# ══ 4. Browser security ══════════════════════════════════════════════
def test_browser_versions_with_words_and_numbers_sort_without_an_error():
    """ASVS V5.1.4 · CWE-755 · CWE-20 · WSTG-ERRH-01: tenant version strings such as 'beta' next to '90' never crash the report."""
    out = bs.outdated_not_blocked({"blocked": {"CHROME": ["100"]}}, [{"browser": "CHROME", "older": ["90", "beta", "9", "100", "10.0.1"]}])
    assert out[0]["not_blocked"] == ["9", "10.0.1", "90", "beta"] and out[0]["count"] == 4
    assert bs._version_key(None) == () and bs._version_key("Beta") == bs._version_key("beta")


def _entry_with(cbi, risky=False, used=True, zpa_rules=()):
    return {"name": "P", "cbi": dict({"name": "P", "controls_read": True, "watermark": {}}, **cbi), "zia": None, "zpa": [],
            "zia_rules": [], "zpa_rules": list(zpa_rules), "risky": risky, "risky_why": ["GenAI apps"] if risky else [],
            "used": used, "smart": False}


@pytest.mark.parametrize("cbi, zpa_rules, fid, sev", [
    ({"copy_paste": "all"}, (), "BS-C1", "medium"), ({"copy_paste": "none"}, (), None, None),
    ({"upload_download": "upstream"}, (), "BS-C2", "medium"), ({"upload_download": "none"}, (), None, None),
    ({"allow_printing": True}, (), "BS-C3", "low"), ({"allow_printing": False}, (), None, None),
    ({"watermark": {"enabled": False}}, (), "BS-C4", "low"), ({"watermark": {"enabled": True, "show_user_id": False}}, (), "BS-C4", "info"),
    ({"watermark": {"enabled": True, "show_user_id": True}}, (), None, None), ({"watermark": {"enabled": None}}, (), None, None),
    ({"session_persistence": True}, (), "BS-C5", "low"), ({"debug_mode_allowed": True}, (), "BS-C6", "medium"),
    ({"local_render": True}, (), "BS-C7", "low"), ({"browser_in_browser": True}, (), "BS-C8", "info"),
    ({"forward_to_zia": False}, ({"name": "z"},), "BS-C9", "low"), ({"forward_to_zia": False}, (), None, None),
])
def test_every_isolation_control_check(cbi, zpa_rules, fid, sev):
    """ASVS V1.14.1 · CWE-693 · WSTG-CONF-02: each isolation control raises exactly its own finding at its severity, and only when weak."""
    out = bs._control_findings(_entry_with(cbi, zpa_rules=zpa_rules))
    assert [(f["id"], f["severity"]) for f in out] == ([(fid, sev)] if fid else [])


@pytest.mark.parametrize("risky, used, want", [(True, True, "high"), (False, True, "medium"), (False, False, "low"), (False, None, "medium")])
def test_severity_follows_what_the_profile_isolates(risky, used, want):
    """ASVS V1.14.1 · CWE-693 · WSTG-CONF-02: copy and paste is high for GenAI or sensitive use, medium when used, low when unused."""
    out = bs._control_findings(_entry_with({"copy_paste": "all"}, risky=risky, used=used))
    assert out[0]["severity"] == want


def test_controls_not_read_raise_no_finding():
    """ASVS V1.14.1 · CWE-693 · WSTG-CONF-02: a profile whose controls were not read is never called permissive."""
    e = _entry_with({"copy_paste": "all"})
    e["cbi"]["controls_read"] = False
    assert bs._control_findings(e) == []


@pytest.mark.parametrize("bc, supported, ids", [
    ({"smart_isolation": False}, [], ["BS-B1"]), ({"smart_isolation": True, "smart_isolation_profile": None}, [], ["BS-B2"]),
    ({"smart_isolation": True, "smart_isolation_profile": {"id": "1", "name": "x"}}, [], []),
    ({"allow_all_browsers": True}, [{"browser": "CHROME", "older": ["90"]}], ["BS-B3"]),
    ({"bypass_all_browsers": True}, [], ["BS-B4"]), ({"blocked": {"CHROME": []}}, [{"browser": "CHROME", "older": ["90"]}], ["BS-B5"]),
    ({"blocked": {"CHROME": ["90"]}}, [{"browser": "CHROME", "older": ["90"]}], []), ({"enable_warnings": False}, [], ["BS-B6"]),
    ({"enable_warnings": None}, [], []),
])
def test_every_browser_control_check(bc, supported, ids):
    """ASVS V1.14.1 · CWE-1104 · WSTG-CONF-02: each Browser Control setting raises its own finding only when weak."""
    snap = {"scope": {"zia": True}, "zia": {"sections": {}, "profiles": [], "browser_control": bc, "supported": supported,
                                            "rules": {"url_filtering": [], "cloud_app_control": []}}}
    assert sorted(f["id"] for f in bs._zia_findings(snap, [], [])) == ids


def test_an_isolate_rule_without_or_with_a_missing_profile():
    """ASVS V1.14.1 · CWE-693 · WSTG-CONF-02: isolate with no profile is high, with an unknown profile medium, with a known one nothing."""
    rule = lambda p: bs.normalize_zia_rule({"id": "1", "name": "GenAI", "action": "ISOLATE", "cbiProfile": p}, "url_filtering")  # noqa: E731
    snap = {"scope": {"zia": True}, "zia": {"sections": {}, "profiles": [{"id": "7", "name": "Strict", "url": "", "default": False}],
                                            "browser_control": None, "supported": None,
                                            "rules": {"url_filtering": [rule(None), rule({"id": "8", "name": "Gone"}), rule({"id": "7", "name": "Strict"})],
                                                      "cloud_app_control": []}}}
    assert sorted(f["id"] for f in bs._zia_findings(snap, [], [])) == ["BS-R1", "BS-R2"]


def test_error_text_never_carries_a_token_or_a_certificate():
    """ASVS V7.1.1 · CWE-532 · CWE-209 · WSTG-ERRH-01: an SDK error is shown without its bearer token or PEM body."""
    s = bs._err_text("401 Bearer eyJabc.def token=SECRETVALUE -----BEGIN CERTIFICATE-----MIIBroot-----END CERTIFICATE-----")
    assert "eyJabc" not in s and "SECRETVALUE" not in s and "MIIB" not in s and len(s) <= 200


# ══ 5. Audit timeline ════════════════════════════════════════════════
@pytest.mark.parametrize("text, utc", [
    ("2026-10-20 10:15:30 PDT", "2026-10-20T17:15:30+00:00"), ("2026-10-20 10:15:30 PST", "2026-10-20T18:15:30+00:00"),
    ("Tue Oct 20 10:15:30 PDT 2026", "2026-10-20T17:15:30+00:00"), ("10/20/2026 10:15:30 PM EST", "2026-10-21T03:15:30+00:00"),
    ("2026-10-20 10:15:30 CEST", "2026-10-20T08:15:30+00:00"), ("2026-10-20 10:15:30 ACST", "2026-10-20T00:45:30+00:00"),
    ("2026-10-20 10:15:30 UTC", "2026-10-20T10:15:30+00:00"), ("2026-10-20T10:15:30+05:30", "2026-10-20T04:45:30+00:00"),
    ("Oct 20, 2026 10:15:30 AM", "2026-10-20T10:15:30+00:00"), ("2026-10-20 10:15:30", "2026-10-20T10:15:30+00:00"),
])
def test_a_named_time_zone_is_applied_not_dropped(text, utc):
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: a ZIA time in PDT or CEST lands at the right UTC instant on the timeline."""
    assert at._iso(at.parse_time(text)) == utc


@pytest.mark.parametrize("text", ["2026-10-20 10:15:30 IST", "2026-10-20 10:15:30 XYZT", "Tue Oct 20 10:15:30 IST 2026"])
def test_an_ambiguous_or_unknown_zone_is_never_guessed(text):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: IST (India, Ireland or Israel) or an unknown zone leaves the time unreadable, never read as UTC."""
    assert at.parse_time(text) is None


def test_an_unreadable_zone_is_kept_last_with_its_time_as_written():
    """ASVS V7.1.1 · CWE-778 · WSTG-BUSL-01: a row whose zone is unknown is still on the timeline, listed last and said in the notes."""
    rows = at.parse_csv("Time,Admin,Action\n2026-10-20 10:00:00 IST,a@x.example,Update\n2026-10-20 11:00:00 UTC,b@x.example,Update\n")["rows"]
    out = at.build(window_=at.window(30, now=datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp()), zia={"status": "read", "csv": {"rows": rows}},
                   deployments=[], audit_entries=[])
    assert [e["time_raw"] for e in out["events"]] == ["2026-10-20 11:00:00 UTC", "2026-10-20 10:00:00 IST"]
    assert any("could not read" in n for n in out["notes"])


def test_the_window_uses_the_injected_clock_and_utc_day_ends():
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: a dates-only window runs from the start day's midnight to the end day's last millisecond, UTC."""
    now = datetime(2026, 10, 29, 12, tzinfo=timezone.utc).timestamp()
    w = at.window(start="2026-10-01", end="2026-10-02", now=now)
    assert (w["start"], w["end"], w["days"]) == ("2026-10-01T00:00:00+00:00", "2026-10-02T23:59:59+00:00", 2.0)
    assert at.window(start="2026-10-28", end="2026-12-31", now=now)["end"] == "2026-10-29T12:00:00+00:00"   # never in the future
    with pytest.raises(ValueError):
        at.window(start="2026-10-01 10:00:00 IST", now=now)


def _ev(i, ts):
    return at._ev("app", datetime.fromtimestamp(ts, tz=timezone.utc) if ts is not None else None, action=f"a{i}")


def test_the_timeline_is_paged_newest_first_with_a_cut_count():
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-07: past the limit the newest events are kept, the cut is counted and every id is unique."""
    evs = [_ev(i, 1_700_000_000 + i) for i in range(10)] + [_ev(99, None)]
    # The window's end has one second of slack (an end rounded down to the second).
    out, outside, cut = at.merge(evs, start_ts=1_700_000_002, end_ts=1_700_000_007, limit=4)
    assert [e["action"] for e in out] == ["a8", "a7", "a6", "a5"] and outside == 3 and cut == 4
    assert len({e["id"] for e in out}) == 4


def test_untimed_events_come_after_timed_ones_and_survive_the_window():
    """ASVS V7.1.1 · CWE-778 · WSTG-BUSL-01: an event with no readable time is never dropped by the window, only listed last."""
    out, outside, cut = at.merge([_ev(1, None), _ev(2, 1_700_000_005)], start_ts=1_700_000_000, end_ts=1_700_000_010)
    assert [e["action"] for e in out] == ["a2", "a1"] and (outside, cut) == (0, 0)


def test_admin_names_appear_only_where_the_timeline_needs_them():
    """ASVS V8.3.4 · CWE-359 · WSTG-INFO-05: the admin is in the event's admin, its raw row and its foreign-change reason, never in notes or the summary."""
    csv_text = ("Time,Admin ID,Action,Resource Name,Pre-Action,Post-Action\n"
                '2026-10-20 10:00:00 UTC,alice@corp.example,Update,PCI block,"{""description"": ""x [Jane pack pci v2]""}",'
                '"{""description"": ""y""}"\n')
    rows = at.parse_csv(csv_text)["rows"]
    out = at.build(window_=at.window(30, now=datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp()), zia={"status": "read", "csv": {"rows": rows}},
                   deployments=[], audit_entries=[], labels=["acme"])
    e = out["events"][0]
    assert e["admin"] == "alice@corp.example" and e["foreign_change"] and "alice@corp.example" in e["foreign_reason"]
    for where in (out["notes"], out["summary"], out["window"], out["zia"]):
        assert "alice" not in json.dumps(where)
    row = at.export_rows(out["events"])[0]
    assert row["admin"] == "alice@corp.example"


def test_the_csv_export_neutralises_formulas_from_the_tenant():
    """ASVS V5.3.7 · CWE-1236 · WSTG-INPV-01: an admin or object name starting with = is written as text."""
    rows = at.parse_csv("Time,Admin,Action,Resource\n2026-10-20 10:00:00,=HYPERLINK(\"x\"),Update,+cmd\n")["rows"]
    text = at.to_csv(at.zia_events(rows, [], []))
    assert "\n=HYPERLINK" not in text and ",=HYPERLINK" not in text and ",+cmd" not in text


# ══ 6. Error paths and the rest of each module's branches ════════════
@pytest.mark.parametrize("raw, port", [("", 587), (None, 587), ("2525", 2525), ("smtp", 587), ("0", 587), ("70000", 587), (" 465 ", 465)])
def test_a_bad_smtp_port_never_ends_the_run(raw, port, monkeypatch):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-ERRH-01: DLP_CHECK_SMTP_PORT that is not a port falls back to 587 instead of raising."""
    if raw is None:
        monkeypatch.delenv("DLP_CHECK_SMTP_PORT", raising=False)
    else:
        monkeypatch.setenv("DLP_CHECK_SMTP_PORT", raw)
    assert ce.notification_settings()["email"]["port"] == port


def test_a_run_with_a_bad_smtp_port_still_writes_its_digest(monkeypatch, no_network):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: the loop finishes and records its digest when the mail port is a typo."""
    monkeypatch.setenv("DLP_CHECK_SMTP_PORT", "smtp")
    monkeypatch.setenv("DLP_CHECK_NOTIFY", "always")
    d = ce.run_once(build_client=None, notify=True)
    assert ce.get_digest(d["id"]) is not None and d["notified"][0]["channel"] == "none" and no_network == []


class _Resp:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


@pytest.mark.parametrize("status, text, sent, why", [
    (200, "ok", True, None), (302, "", False, "redirect"), (500, "boom at /webhookb2/SECRETPATH123", False, "[redacted]"),
])
def test_a_webhook_answer_is_recorded_without_its_url_secret(status, text, sent, why, monkeypatch):
    """ASVS V8.3.4 · CWE-532 · CWE-918 · WSTG-INPV-19: a redirect is not followed and a failure never records the webhook's path."""
    posted = []
    monkeypatch.setattr("requests.post", lambda url, json=None, timeout=0, allow_redirects=True: posted.append(allow_redirects) or _Resp(status, text))
    r = ce._send_webhook("s", "b", "https://example.webhook.office.com/webhookb2/SECRETPATH123")
    assert r["sent"] is sent and posted == [False] and "SECRETPATH123" not in json.dumps(r)
    if why:
        assert why in r["why"]


def test_a_webhook_that_raises_is_recorded_without_its_url(monkeypatch):
    """ASVS V7.4.1 · CWE-209 · CWE-532 · WSTG-ERRH-01: the connection error names no part of the webhook URL."""
    def boom(url, **k):
        raise OSError(f"Max retries exceeded with url: {url}")
    monkeypatch.setattr("requests.post", boom)
    r = ce._send_webhook("s", "b", "https://hooks.slack.com/services/T000/B000/XXXXSECRET")
    assert r["sent"] is False and "XXXXSECRET" not in r["why"] and "T000" not in r["why"]
    assert ce._send_webhook("s", "b", "http://hooks.slack.com/x")["why"].startswith("the webhook must be")


def test_the_mode_never_sends_even_a_noteworthy_digest(monkeypatch):
    """ASVS V14.2.1 · CWE-1188 · WSTG-CONF-02: DLP_CHECK_NOTIFY=never sends nothing whatever the digest holds."""
    monkeypatch.setenv("DLP_CHECK_NOTIFY", "never")
    monkeypatch.setenv("DLP_CHECK_DIGEST_WEBHOOK", "https://example.webhook.office.com/webhookb2/abc")
    monkeypatch.setattr(ce, "_send_webhook", lambda *a: (_ for _ in ()).throw(AssertionError("sent")))
    out = ce.send_notifications({"noteworthy": True, "tenants": [], "summary": {}})
    assert out[0]["sent"] is False and "never" in out[0]["why"]


def test_the_command_line_runs_once_and_says_what_it_did(monkeypatch, capsys):
    """ASVS V7.1.1 · CWE-755 · WSTG-ERRH-01: --once --no-notify runs without sending and exits 0; a run already in progress exits 2."""
    calls = []
    monkeypatch.setattr(ce, "run_once", lambda **k: calls.append(k) or {"id": "x", "noteworthy": False, "path": "p", "notified": [], "errors": [], "tenants": []})
    assert ce.main(["--once", "--no-notify"]) == 0 and calls[0]["notify"] is False
    assert "digest x: quiet" in capsys.readouterr().out

    def busy(**k):
        raise ce.LoopRunInProgress("busy")
    monkeypatch.setattr(ce, "run_once", busy)
    assert ce.main([]) == 2


def test_a_second_run_while_one_holds_the_lock_reads_nothing():
    """ASVS V11.1.6 · CWE-367 · CWE-362 · WSTG-BUSL-07: the loop lock refuses a concurrent run before anything is read."""
    with ce.run_lock():
        with pytest.raises(ce.LoopRunInProgress):
            ce.run_once(build_client=_no_tenant, notify=False)


def test_digest_ids_are_validated_before_they_name_a_file():
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: a digest id that is not a timestamp never reaches the file system."""
    for bad in ("../../etc/passwd", "20260101-000000.json", "", "2026010-000000", None):
        assert ce.get_digest(bad) is None


class _AuditClient:
    """ZIA's audit log report: one POST to create it, GETs for status and the CSV."""

    def __init__(self, create=200, states=("COMPLETE",), status_code=200, download=(200, "Time,Admin,Action\n2026-10-20 10:00:00,a,Update\n")):
        self.create, self.states, self.status_code, self.download = create, list(states), status_code, download
        self.sent = []

    def post(self, ep, body):
        self.sent.append(("POST", ep, body))
        return ({"message": "busy"} if self.create != 200 else {}), self.create

    def get(self, ep):
        self.sent.append(("GET", ep))
        if ep == at.DOWNLOAD_EP:
            return self.download[1], self.download[0]
        st = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {"status": st, "progressItemsComplete": 3}, self.status_code


class _NoWait:
    def __init__(self, stop_after=None):
        self.n, self.stop_after = 0, stop_after

    def is_set(self):
        return self.stop_after is not None and self.n >= self.stop_after

    def wait(self, s):
        self.n += 1
        return self.is_set()


def test_the_audit_report_is_created_polled_and_downloaded_with_one_post():
    """ASVS V1.14.1 · CWE-841 · WSTG-BUSL-01: one POST that creates the report, status GETs, one download; nothing else is sent."""
    c = _AuditClient(states=("EXECUTING", "COMPLETE"))
    out = at.read_zia_audit(c, 1, 2, cancel=_NoWait())
    assert out["status"] == "read" and len(out["csv"]["rows"]) == 1
    assert [x[0] for x in c.sent] == ["POST", "GET", "GET", "GET"] and c.sent[0][2] == {"startTime": 1, "endTime": 2}


@pytest.mark.parametrize("client, words", [
    (_AuditClient(create=403), "View Activity Log"), (_AuditClient(create=409), "already preparing"),
    (_AuditClient(status_code=500), "did not answer the report's status"), (_AuditClient(states=("FAILED",)), "ended the audit log report as FAILED"),
    (_AuditClient(download=(404, "gone")), "did not hand over"),
])
def test_every_audit_report_failure_is_said_in_words(client, words):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a refused, failed or missing report is a plain sentence, never an exception."""
    out = at.read_zia_audit(client, 1, 2, cancel=_NoWait())
    assert out["status"] == "failed" and words in out["error"]


def test_a_report_that_never_finishes_times_out_and_stop_ends_the_wait():
    """ASVS V11.1.7 · CWE-400 · WSTG-BUSL-07: a report stuck in progress ends at the timeout, and Stop raises before more is asked."""
    out = at.read_zia_audit(_AuditClient(states=("EXECUTING",)), 1, 2, cancel=_NoWait(), timeout=-1)
    assert out["status"] == "failed" and "had not finished" in out["error"]
    c = _AuditClient(states=("EXECUTING",))
    with pytest.raises(at.Stopped):
        at.read_zia_audit(c, 1, 2, cancel=_NoWait(stop_after=2))
    assert [x[0] for x in c.sent].count("POST") == 1


def test_secret_values_in_audit_rows_are_redacted_in_json_and_text():
    """ASVS V8.3.4 · CWE-532 · CWE-200 · WSTG-INFO-05: a password in a pre or post value, or a secret-named column, never reaches the timeline."""
    v = at.parse_value('{"name": "x", "nested": {"apiKey": "AKIA-SECRET"}, "list": [{"password": "hunter2"}]}')
    assert "AKIA-SECRET" not in json.dumps(v) and "hunter2" not in json.dumps(v)
    assert "hunter2" not in at.parse_value('{"password": "hunter2", broken')
    row = at.parse_csv("Time,Action,Admin,Client Secret\n2026-10-20 10:00:00,Update,a,s3cr3t\n")["rows"][0]
    assert row["raw"]["Client Secret"] == "[redacted]"


def test_huge_and_deep_audit_values_are_capped():
    """ASVS V5.1.4 · CWE-400 · CWE-674 · WSTG-INPV-01: a deep or huge value is cut, never recursed without bound."""
    deep = {}
    cur = deep
    for _ in range(50):
        cur["a"] = {}
        cur = cur["a"]
    assert "…" in json.dumps(at.redact(deep), ensure_ascii=False)
    assert len(at.flatten(deep)) <= 1
    assert len(at.parse_value("x" * (at.MAX_VALUE + 10))) == at.MAX_VALUE + 1
    assert at.parse_time("1" * 200) is None


def test_redaction_of_quoted_pairs_runs_in_linear_time():
    """ASVS V5.1.5 · CWE-1333 · WSTG-INPV-01: a long cell of quotes and keyword fragments is redacted quickly (no catastrophic backtracking)."""
    import time as _t
    text = ('"secret' * 20000) + '": "v"'
    t0 = _t.perf_counter()
    at.redact_text(text)
    assert _t.perf_counter() - t0 < 1.0


def test_browser_reads_say_what_could_not_be_read():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a failed ZIA list is 'not read' with a reason; a partial Cloud App Control read is incomplete."""
    from test_browser_security import FakeTenant
    fail = {"zia.cloud_browser_isolation.list_isolation_profiles": "HTTP 500 boom", "zia.secure_browsing.get_browser_control_settings": "HTTP 500",
            "zia.secure_browsing.get_supported_browser_versions": "HTTP 500", "zia.url_filtering.list_rules": "HTTP 500",
            "zia.cloudappcontrol.list_rules": None}
    t = FakeTenant(fail={k: v for k, v in fail.items() if v})
    snap = bs.read_zia(t, lambda m: None, None, read_cac=True)
    secs = snap["sections"]
    assert not secs["zia_profiles"]["read"] and not secs["browser_control"]["read"] and not secs["url_filtering"]["read"]
    assert snap["profiles"] is None and snap["browser_control"] is None and snap["supported"] is None


def test_no_zia_or_zpa_api_reads_nothing_and_says_so():
    """ASVS V1.14.1 · CWE-754 · WSTG-ERRH-01: a sign-in without the ZIA or ZPA API marks every section unread with the reason."""
    class Bare:
        zia = None
        zpa = None
    z = bs.read_zia(Bare(), lambda m: None, None, read_cac=True)
    p = bs.read_zpa(Bare(), lambda m: None, None)
    assert all(not s["read"] and "no ZIA API" in s["error"] for s in z["sections"].values())
    assert all(not s["read"] and "no ZPA API" in s["error"] for s in p["sections"].values())


@pytest.mark.parametrize("scopes, zia, zpa, cac", [
    (["zia_extras", "zpa"], True, True, False), (["zpa"], False, True, False), ([], False, False, False), ("zia_extras", False, False, False),
])
def test_browser_scope_reads_only_what_is_ticked(scopes, zia, zpa, cac):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: only the ticked products are read; without a channel declaration no Cloud App Control rule is."""
    s = bs.scope_for(scopes, None)
    assert (s["zia"], s["zpa"], s["cac"], s["read"]) == (zia, zpa, cac, zia or zpa)


def test_shadow_scope_and_the_web_dlp_mode_read():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: Cloud Firewall is read only with ZIA platform, and an unreadable DLP mode is 'unknown'."""
    assert "firewall" in sr.scope_for(["zia_extras"], {})["read"] and "firewall" not in sr.scope_for(["dlp"], {})["read"]

    class C:
        def __init__(self, ans):
            self.ans = ans

        def get(self, ep):
            if isinstance(self.ans, Exception):
                raise self.ans
            return self.ans
    assert sr.read_web_dlp_mode(C(({"enableEvaluateAllDlpRules": True}, 200)))[0] == sr.MODE_EVAL_ALL
    assert sr.read_web_dlp_mode(C(({"enable_evaluate_all_dlp_rules": "false"}, 200)))[0] == sr.MODE_RULE_ORDER
    assert sr.read_web_dlp_mode(C(({}, 200)))[0] == sr.MODE_UNKNOWN
    assert sr.read_web_dlp_mode(C(({}, 403)))[0] == sr.MODE_UNKNOWN
    assert sr.read_web_dlp_mode(C(RuntimeError("x")))[0] == sr.MODE_UNKNOWN


def test_the_shadow_csv_neutralises_tenant_formulas():
    """ASVS V5.3.7 · CWE-1236 · WSTG-INPV-01: a rule named =cmd is written as text in the CSV export."""
    rules = [_r(1, 1, urlCategories=["A"]), dict(_r(2, 2, urlCategories=["A"]), name="=cmd|' /C calc'!A0")]
    text = sr.to_csv(sr.analyse({"url_filtering": rules}))
    assert ",=cmd" not in text and "'=cmd" in text


def test_odd_rule_shapes_are_read_defensively():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: non-dict rules, None lists, unknown policies and odd orders never raise."""
    res = sr.analyse({"url_filtering": [None, "x", _r(1, "not a number", urlCategories=None), _r(2, None, users=[{"name": "u"}, {}])],
                      "no_such_policy": [_r(3, 1)], "firewall": None})
    assert set(res["counts_by_policy"]) == {"url_filtering"} and res["counts_by_policy"]["url_filtering"]["rules"] == 2


def test_a_sign_in_error_that_echoes_the_secret_never_reaches_the_digest(no_network):
    """ASVS V7.1.1 · ASVS V8.3.4 · CWE-532 · CWE-209 · WSTG-ERRH-01: the profile's client secret, raw or URL-encoded, is redacted from tenant errors."""
    secret = "S3cr3t+Value/42"
    tp.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "baseline_packs": [],
               "scopes": ["dlp"], "channels": {"saas_casb": "zscaler"}}, client_secret=secret, remember_secret=True)

    def echoing(creds):
        raise RuntimeError(f"401 for body client_secret={creds['client_secret']}&x=S3cr3t%2BValue%2F42")
    d = ce.run_once(build_client=echoing, notify=False)
    errs = d["tenants"][0]["errors"]
    on_disk = json.dumps(ce.get_digest(d["id"])) + ce.to_markdown(d)
    assert errs and errs[0].startswith("connect: 401") and "[redacted]" in errs[0]
    assert secret not in on_disk and "S3cr3t%2BValue" not in on_disk and no_network == []


def test_a_record_that_names_no_tenant_is_not_shown_on_a_tenants_timeline():
    """ASVS V4.2.1 · CWE-639 · CWE-200 · WSTG-ATHZ-04: with a tenant chosen, an unlabeled deployment or write is left out and counted, not shown."""
    deps = [{"id": "d1", "at": "2026-10-20T09:00:00+00:00", "tenant_label": "acme", "by": "Jane", "packs": ["pci"], "created": []},
            {"id": "d2", "at": "2026-10-20T09:05:00+00:00", "tenant_label": "", "by": "Sam", "packs": ["hipaa"], "created": [{"name": "Other's rule"}]}]
    entries = [{"event": "object_write", "at": "2026-10-20T09:10:00+00:00", "tenant": None, "name": "Other's rule", "action": "create"},
               {"event": "sso_login", "at": "2026-10-20T09:11:00+00:00", "actor": "me"}]
    out = at.build(window_=at.window(30, now=datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp()), zia=None, deployments=deps,
                   audit_entries=entries, labels=["acme"], zia_requested=False)
    assert [e.get("object_id") or e["action"] for e in out["events"]] == ["sso login", "d1"]
    assert "Other's rule" not in json.dumps(out["events"]) and any("2 of Zscaler Made Easy's record(s) name no tenant" in n for n in out["notes"])
    every = at.build(window_=at.window(30, now=datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp()), zia=None, deployments=deps,
                     audit_entries=entries, zia_requested=False)
    assert every["summary"]["events"] == 4   # no tenant chosen: everything


@pytest.mark.parametrize("cc", [
    {"gaps": [{"name": "Email", "checks_not_in_scope": "lots"}]}, {"gaps": "x"}, {"alternative": [None, 5, {"checks_not_in_scope": "1e400"}]},
    {"gaps": [{"name": "Email", "checks_not_in_scope": -4}], "hidden": "many"},
])
def test_odd_channel_coverage_from_the_page_is_a_200_not_a_500(cc):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-INPV-01: counts in the request that are not numbers are read as none, never a server error."""
    from test_posture_plus import _client
    r = _client().post("/api/posture/summary", json={"checks": [{"id": "a", "status": "PASS"}], "channel_coverage": cc})
    assert r.status_code == 200 and r.json()["coverage"]["total"] == 1


@pytest.mark.parametrize("content", ['{"score_drop_points": Infinity}', '["x"]', '{"score_drop_points": "7", "notify_score_drop": "true"}', "not json"])
def test_a_damaged_settings_file_reads_as_the_defaults(content, tmp_path, monkeypatch):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-ERRH-01: a hand-edited posture_settings.json never breaks the alerts or the settings page."""
    p = tmp_path / "s.json"
    p.write_text(content, encoding="utf-8")
    monkeypatch.setenv("DLP_CHECK_POSTURE_SETTINGS", str(p))
    s = pp.settings()
    assert s["notify_score_drop"] is False and s["score_drop_points"] in (5, 7)


def test_a_damaged_history_state_reads_as_not_run():
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-ERRH-01: a state that is not a code (a list, a number) never breaks the trend."""
    d = pp.diff({"score": 80, "states": {"a": ["x"], "b": "P"}}, {"score": 70, "states": {"a": "F", "b": 3}})
    assert [x["id"] for x in d["newly_failing"]] == ["a"] and d["newly_failing"][0]["from"] == "not run"
    assert pp.trend([{"score": 80, "states": {"a": ["x"]}}, {"score": 70, "states": {"a": "F"}}])["runs"] == 2


def test_odd_queue_and_drift_shapes_are_ignored():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a change request whose payload is not an object, or a drift that is not one, is skipped."""
    q = pp.queued_fixes([{"status": "pending", "kind": "fix_recipe", "payload": "x"}], ["a"])
    assert q["counted"] == [] and q["not_counted"][0]["check_id"] == ""
    assert pp.tenant_alerts({"drift": "x"}, [], cfg={"score_drop_points": 5, "notify_score_drop": False}) == []
