"""Wave 9 security gates, the pages: the delete-all and pack-removal flows
send the typed phrase the dry run or plan shows (confirm_phrase), and the
Evaluate All enable and remediation flows send the previewed plan_hash.

The shipped functions are cut out of static/index.html and
static/deploy_studio.js and run in node with the page's helpers and fetch
replaced by recorders, so no server, tenant or browser is involved; they
skip without node. The fake server answers with the phrase the real server
code makes (rule_migrator.delete_phrase, pack_removal.confirm_phrase)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

import pack_removal
import rule_migrator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

H_DELETE, H_ENABLE, H_FIX, H_REMOVE = ("a" * 64), ("b" * 64), ("c" * 64), ("d" * 64)
RULES_PHRASE = rule_migrator.delete_phrase(3)          # what the delete-all dry run shows
OBJECTS_PHRASE = pack_removal.confirm_phrase(2)        # what the removal plan shows


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _fn(src, name):
    """One top-level (async) function of a shipped file, as written."""
    m = re.search(r"^(?:async )?function " + re.escape(name) + r"\(.*?^\}$", src, re.S | re.M)
    assert m, name
    return m.group(0)


# The page's helpers, replaced by recorders. `dialog` is what the typed
# phrase dialog answers: "shown" types the phrase it was given, "padded"
# types it with spaces round it, null cancels; "none" removes the dialog
# (window.prompt answers instead).
PRELUDE = r"""
const __calls = [], __asked = [], __alerts = [];
const __dialog = %(dialog)s;
const window = {};
if (__dialog !== 'none') window.dlpDialog = { phrase: async (o) => { __asked.push(o.phrase); return __dialog === 'shown' ? o.phrase : __dialog === 'padded' ? `  ${o.phrase} ` : null; } };
window.prompt = (msg) => { __asked.push((msg.match(/Type (.*) to /) || [])[1]); return (msg.match(/Type (.*) to /) || [])[1]; };
const alert = (m) => __alerts.push(String(m));
const confirm = () => true;
const announce = () => {};
const escapeHtml = (s) => String(s ?? '');
const el = () => ({ style: {}, innerHTML: '', textContent: '' });
const __els = {};
const document = { getElementById: (id) => (__els[id] = __els[id] || el()) };
const migrateValidateCreds = () => ({ vanity_domain: 'acme' });
const migrateCredBody = () => ({ vanity_domain: 'acme' });
const tenantWriteBody = (b) => { b.confirm = true; b.assessor = 'Jane Doe'; return b; };
const scopePageSelection = () => ({});
const clearPendingAction = () => {}, registerPendingAction = () => {}, updateActivationBanner = () => '';
let _step4Plan = null;
let _remediationPlanHash = '';
let _currentRemediationCheckId = 'FW-01';
const _findRecipeForCheck = () => ({ label: 'QA fix', destructive: true, writes: 1 });
const _collectRemediationCriteria = () => ({}), _collectWizardCriteria = () => ({});
const _wizardPlanReady = () => {};
const _remediationResults = [], _remediationQueue = ['FW-01'];
let _remediationIndex = 0;
const __answers = %(answers)s;
async function fetch(url, opts) {
  const body = JSON.parse(opts.body);
  __calls.push({ url, body });
  const a = __answers[url + (body.dry_run === true ? '#dry' : '')] || __answers[url] || {};
  return { ok: true, status: 200, json: async () => a };
}
// deploy_studio.js
const _dzDlg = () => window.dlpDialog || null;
const DZ = { removal: %(removal)s, busy: false, job: null };
const _dzRemovalRender = () => {}, _dzRateText = () => '', _dzCreds = () => ({ vanity_domain: 'acme' });
const _dzRemovalScope = () => ({ pack_ids: ['qa-pack'] });
async function _dzRunJob(url, body) { __calls.push({ url, body }); return { status: 'done', result: { status: 'done', logs: ['ok'] } }; }
"""

ANSWERS = {
    "/api/migrate/delete-all#dry": {"status": "dry_run", "plan_hash": H_DELETE, "confirm_phrase": RULES_PHRASE, "would_delete": [],
                                    "would_delete_count": 3},
    "/api/migrate/delete-all": {"status": "completed", "deleted_count": 3, "failed_count": 0},
    "/api/migrate/enable#dry": {"status": "dry_run", "plan_hash": H_ENABLE, "endpoint": "/webDlpGlobalOptions",
                                "field": "enableEvaluateAllDlpRules", "value": True},
    "/api/migrate/enable": {"status": "activated"},
    "/api/remediation/plan": {"ok": True, "plan_hash": H_FIX, "method": "PUT", "endpoint": "/zia/qa", "body": {}},
    "/api/remediation/execute": {"status": "completed", "http_status": 200},
}
REMOVAL = {"plan": {"items": [{"status": "remove", "kind": "policy", "name": "QA rule"}, {"status": "remove", "kind": "engine", "name": "QA engine"},
                              {"status": "keep", "kind": "dictionary", "name": "Shared"}],
                    "plan_hash": H_REMOVE, "confirm_phrase": OBJECTS_PHRASE, "tenant_label": "acme"}, "pack": {"name": "QA pack"}}


def _run(functions, scenario, dialog="shown", answers=None, removal=None):
    """Run `scenario` (JS, awaited) with the named shipped functions; answers
    {calls: [{url, body}], asked: [phrases shown], alerts: [...]}."""
    index, studio = _read("static", "index.html"), _read("static", "deploy_studio.js")
    src = "\n".join(_fn(studio if name.startswith("_dz") else index, name) for name in functions)
    prelude = PRELUDE % {"dialog": json.dumps(dialog), "answers": json.dumps(ANSWERS if answers is None else answers),
                         "removal": json.dumps(REMOVAL if removal is None else removal)}
    script = f"{prelude}\n{src}\n{scenario}\nconsole.log(JSON.stringify({{ calls: __calls, asked: __asked, alerts: __alerts }}));"
    r = subprocess.run([NODE, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def _live(calls, url):
    return [c["body"] for c in calls if c["url"] == url and c["body"].get("dry_run") is not True]


# ── delete every Inline Web DLP rule ────────────────────────────────────
@pytest.mark.parametrize("dialog", ["shown", "padded", "none"])
def test_delete_all_sends_the_phrase_the_dry_run_showed_and_its_plan_hash(dialog):
    """ASVS V11.1.1 · V4.3.2 · CWE-841 · CWE-352 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: after the dry run, the live delete-all asks for the phrase the dry run returned (DELETE <n> RULES) and sends it, trimmed, with the dry run's plan_hash."""
    # Act
    got = _run(["step3bDeleteAll"], "await step3bDeleteAll(true); await step3bDeleteAll(false);", dialog=dialog)
    # Assert
    assert rule_migrator.DELETE_PHRASE_SHAPE.match(RULES_PHRASE)
    assert got["asked"] == [RULES_PHRASE]
    live = _live(got["calls"], "/api/migrate/delete-all")
    assert len(live) == 1 and live[0]["confirm_phrase"] == RULES_PHRASE and live[0]["plan_hash"] == H_DELETE
    assert live[0]["dry_run"] is False and live[0]["confirm"] is True


def test_delete_all_sends_nothing_when_the_phrase_dialog_is_cancelled():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: cancelling the typed phrase dialog sends no live delete-all."""
    # Act
    got = _run(["step3bDeleteAll"], "await step3bDeleteAll(true); await step3bDeleteAll(false);", dialog=None)
    # Assert
    assert got["asked"] == [RULES_PHRASE] and _live(got["calls"], "/api/migrate/delete-all") == []


def test_delete_all_without_a_dry_run_first_sends_nothing():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: a live delete-all before any dry run (no phrase to show) asks for nothing, sends nothing and says to run the preview."""
    # Act
    got = _run(["step3bDeleteAll"], "await step3bDeleteAll(false);")
    # Assert
    assert got["calls"] == [] and got["asked"] == [] and "dry run" in got["alerts"][0]


# ── pack removal ────────────────────────────────────────────────────────
@pytest.mark.parametrize("dialog", ["shown", "padded", "none"])
def test_pack_removal_sends_the_phrase_the_plan_showed_and_its_plan_hash(dialog):
    """ASVS V11.1.1 · V4.3.2 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: the final removal step asks for the plan's phrase (DELETE <n> OBJECTS) and starts the removal with it, trimmed, and the plan's plan_hash."""
    # Act
    got = _run(["_dzRemovalApply"], "await _dzRemovalApply();", dialog=dialog)
    # Assert
    assert got["asked"] == [OBJECTS_PHRASE] == ["DELETE 2 OBJECTS"]
    assert [c["url"] for c in got["calls"]] == ["/api/dlp-packs/removal/apply/start"]
    body = got["calls"][0]["body"]
    assert body["confirm_phrase"] == OBJECTS_PHRASE and body["plan_hash"] == H_REMOVE and body["confirm"] is True


def test_pack_removal_sends_nothing_when_the_phrase_dialog_is_cancelled():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: cancelling the removal phrase dialog starts no removal."""
    # Act
    got = _run(["_dzRemovalApply"], "await _dzRemovalApply();", dialog=None)
    # Assert
    assert got["asked"] == [OBJECTS_PHRASE] and got["calls"] == []


# ── Evaluate All enable and remediation: the plan hash ──────────────────
def test_the_evaluate_all_enable_sends_the_dry_runs_plan_hash():
    """ASVS V11.1.1 · CWE-367 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: Activate after the enable dry run sends the dry run's plan_hash with the live write."""
    # Act
    got = _run(["step4EnablePlan", "step4Activate"], "await step4EnablePlan(); await step4Activate();")
    # Assert
    live = _live(got["calls"], "/api/migrate/enable")
    assert len(live) == 1 and live[0]["plan_hash"] == H_ENABLE and live[0]["dry_run"] is False and live[0]["confirm"] is True


def test_the_evaluate_all_enable_sends_nothing_when_the_dry_run_found_no_setting():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: a dry run with no plan_hash (no setting found) stages nothing, so Activate sends no live write."""
    answers = dict(ANSWERS, **{"/api/migrate/enable#dry": {"status": "not_found", "message": "No setting found."}})
    # Act
    got = _run(["step4EnablePlan", "step4Activate"], "await step4EnablePlan(); await step4Activate();", answers=answers)
    # Assert
    assert _live(got["calls"], "/api/migrate/enable") == [] and "dry run" in got["alerts"][0]


@pytest.mark.parametrize("preview,apply", [("remediationPreview", "remediationActivate"), ("wizardPreview", "wizardApply")])
def test_a_remediation_sends_the_previewed_plan_hash(preview, apply):
    """ASVS V11.1.1 · CWE-367 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.4: the remediation panel and the wizard send the plan_hash of the preview they showed with the live apply."""
    # Act
    got = _run([preview, apply], f"await {preview}(); await {apply}();")
    # Assert
    assert [c["url"] for c in got["calls"]] == ["/api/remediation/plan", "/api/remediation/execute"]
    live = got["calls"][1]["body"]
    assert live["plan_hash"] == H_FIX and live["dry_run"] is False and live["confirm"] is True
