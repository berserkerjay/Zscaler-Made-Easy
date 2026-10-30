"""Write tests/fixtures/pre_wave5_stores.json: the app's saved files as the
last release before Wave 5 wrote them, made by that release's own code.

    git worktree add /tmp/pre-wave5 9b28a1c        # the merge of #94 on main
    python tools/pre_wave5_fixtures.py /tmp/pre-wave5 tests/fixtures/pre_wave5_stores.json

The old checkout is this repository's own code at an earlier commit. It is
run in a child process with every store pointed at a temporary folder, the
network blocked and no credential store, through its HTTP API and module
APIs as a person would use it: tenant profiles (a ZIdentity client with a
remembered secret, a classic sign-in, a bare one, assessment history with
and without per-check states), proposals (one snoozed), the change queue (a
pending request with a comment, a rejected one), workspace notes (a tag, a
comment, a to-do), posture settings, a deployment, a bulk change and a
self-heal run. Every value is a fixture: no real tenant, no real secret.
tests/test_regression_migration.py loads the bundle with the current code.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

STORES = ("tenant_profiles.json", "proposals.json", "change_requests.json", "workspace_notes.json", "posture_settings.json",
          "deployments.json", "self_heal_state.json")

_CHILD = r'''
import json, os, socket, sys
root, data = sys.argv[1], sys.argv[2]
for k in [k for k in os.environ if k.startswith(("ZSCALER_", "DLP_CHECK_", "DLPCHECK_"))]:
    del os.environ[k]
os.environ.update({
    "ZSCALER_UI_AUTH": "0", "DLP_CHECK_SECRET_STORE": "file", "DLP_CHECK_SELF_HEAL_MINUTES": "0",
    "DLP_CHECK_PROFILES": f"{data}/tenant_profiles.json", "DLPCHECK_PROPOSALS_FILE": f"{data}/proposals.json",
    "DLPCHECK_CHANGE_QUEUE_FILE": f"{data}/change_requests.json", "DLP_CHECK_WORKSPACE_NOTES": f"{data}/workspace_notes.json",
    "DLP_CHECK_POSTURE_SETTINGS": f"{data}/posture_settings.json", "DLP_CHECK_DEPLOYMENTS": f"{data}/deployments.json",
    "DLP_CHECK_AUDIT": f"{data}/audit.log", "DLP_CHECK_SELF_HEAL_STATE": f"{data}/self_heal_state.json",
    "DLP_CHECK_SSL_COVERAGE_STATE": f"{data}/ssl.json", "DLP_CHECK_GUIDANCE_STATE": f"{data}/guidance.json",
    "DLP_CHECK_ZIA_RATE_STATE": f"{data}/zia_rate.json", "DLP_CHECK_BEACON_STATE": f"{data}/beacon.json",
    "DLP_CHECK_DIGESTS": f"{data}/digests", "DLP_CHECK_UI_TOKEN_DIR": data, "XDG_CACHE_HOME": f"{data}/cache",
})
def _no_network(*a, **k):
    raise OSError("fixture generation is offline")
socket.create_connection = _no_network
sys.modules["keyring"] = None
os.chdir(root)
sys.path.insert(0, root)
from fastapi.testclient import TestClient
import dlp_api_server as srv
import tenant_profiles as tp
c = TestClient(srv.app, base_url="http://127.0.0.1")
def ok(r):
    assert r.status_code < 300, (str(r.request.url), r.status_code, r.text[:300])
    return r.json()
ok(c.post("/api/tenant-profiles", json={"name": "Acme Corp", "vanity_domain": "acme", "cloud": "zscalertwo", "client_id": "cid-acme",
                                          "client_secret": "fixture-secret-not-real", "remember_secret": True, "assessor": "Dana Analyst",
                                          "scopes": ["dlp", "zia_extras"], "channels": {"web": "zscaler", "endpoint": "gap"}}))
ok(c.post("/api/tenant-profiles", json={"name": "Classic Tenant", "auth_method": "legacy", "cloud": "zscloud", "username": "admin@example.com",
                                          "password": "fixture-password-not-real", "api_key": "fixturekey00", "remember_secret": True}))
ok(c.post("/api/tenant-profiles", json={"name": "Bare"}))
rep = {"score": 71, "maturity": "Developing", "metadata": {"assessor": "Dana Analyst"},
       "checks": [{"id": "DLP.1", "status": "PASS"}, {"id": "DLP.2", "status": "FAIL"}, {"id": "DLP.3", "status": "FAIL", "out_of_scope": True}],
       "critical": [{"id": "DLP.2"}],
       "journey": {"status": "ok", "stage": 2, "score": 60, "baselines": [{"id": "b1", "name": "B1", "stage": 2, "score": 60, "state": "x", "next_steps": ["a", "b"]}]}}
tp.add_history("acme-corp", tp.snapshot(rep))
tp.add_history("acme-corp", tp.snapshot(dict(rep, score=64, checks=[{"id": "DLP.1", "status": "FAIL"}, {"id": "DLP.2", "status": "FAIL"}])))
tp.add_history("acme-corp", {"at": "2025-01-01T00:00:00+00:00", "score": 50, "checks": 3})
tp.mark_proposal_queue_migrated("acme-corp")
import proposals
T = "acme (zscalertwo)"
proposals.refresh_from_report({"settings": {"promote_window_days": 30},
                               "rules": [{"name": "R1", "channel": "web", "id": 11, "action": "ALLOW", "promote_rate_pct": 1.0}],
                               "findings": [{"kind": "promotable_rule", "name": "R1"}, {"kind": "dead_rule", "name": "R1"}]}, T)
proposals.decide(T, proposals.list_queue(T)[0]["id"], "snooze", by="dana", note="later", days=7)
import change_queue
kind = sorted(change_queue.KINDS)[0]
r1 = change_queue.file_request(kind=kind, tenant=T, tenant_label=T, title="Enable rule", summary={"n": 1}, items=[{"what": "x"}],
                               plan_hash="h" * 16, requested_by="dana", payload={"k": "v"}, note="please")
change_queue.comment(r1["id"], by="sam", text="looks fine")
r2 = change_queue.file_request(kind=kind, tenant=T, tenant_label=T, title="Second", summary={}, items=[], plan_hash="g" * 16,
                               requested_by="dana", payload={})
change_queue.decide(r2["id"], "reject", by="sam", comment="no")
import workspace_notes as wn
wn.apply(T, "check", "DLP.2", "add_tag", by="dana", tag="urgent", label="DLP.2 check")
wn.apply(T, "check", "DLP.2", "add_comment", by="dana", text="Customer asked about endpoints")
wn.apply(T, "check", "DLP.2", "add_todo", by="dana", text="Call back")
ok(c.put("/api/posture/settings", json={"score_drop_points": 7, "notify_score_drop": True}))
import deployments
deployments.add({"id": "dep-fixture1", "tenant_label": T, "packs": ["hipaa"], "created": [{"kind": "rule", "id": 5, "name": "x"}],
                 "at": "2025-02-01T00:00:00+00:00", "status": "applied"})
deployments.add_operation({"id": "op-fixture1", "tenant_label": T, "operation": {"kind": "noop"}, "items": [],
                           "at": "2025-02-01T00:00:00+00:00"})
ok(c.post("/api/self-heal/run"))
'''


def main(old_root: str, out: str) -> int:
    with tempfile.TemporaryDirectory(prefix="pre-wave5-") as data:
        subprocess.run([sys.executable, "-I", "-c", _CHILD, os.path.abspath(old_root), data], check=True)
        bundle = {}
        for name in STORES:
            with open(os.path.join(data, name), "r", encoding="utf-8") as f:
                bundle[name] = json.load(f)
    commit = subprocess.run(["git", "-C", old_root, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"made_by": f"tools/pre_wave5_fixtures.py from commit {commit or 'unknown'}", "stores": bundle}, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"Wrote {out}: {', '.join(STORES)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
