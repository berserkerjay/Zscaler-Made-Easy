"""A classic-API (legacy) user can start an assessment: runAssessment's
credential gate asks for the chosen sign-in's fields only, never the hidden
OneAPI vanity domain, client id or secret, and no vanity domain is sent."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _fn(src, start, end):
    i = src.index(start)
    return src[i:src.index(end, i)]


def _run(tmp_path, method, values):
    html = _read("static/index.html")
    code = (_fn(html, "function currentAuthMethod()", "function applyAuthMethod()")
            + _fn(html, "function migrateCredBody()", "function popMissingCredsAlert(")
            + _fn(html, "async function runAssessment()", "function buildPartialReport()")
            + _fn(html, "// The server's reason for refusing a run", "function resetForm()"))
    harness = """
const vm = require('vm');
const VALUES = __VALUES__;
const els = {};
const el = id => els[id] || (els[id] = {id, value: VALUES[id] || '', textContent: '', disabled: false, style: {}, className: '',
  classList: {add(){}, remove(){}}});
const popped = [], sent = [];
const ctx = {
  document: {getElementById: el}, window: {__dbRunStarted(){}, __dbRunRefused(){}},
  popMissingCredsAlert: m => popped.push(m), getSelectedScopes: () => ['dlp'],
  setStatus(){}, setStep(){}, alert(){}, confirm: () => true,
  AbortController, console, TextDecoder, setInterval, clearInterval,
  fetch: async (url, opts) => { sent.push([url, JSON.parse(opts.body)]); return {ok: false, status: 400, json: async () => ({detail: 'stop here'})}; },
  buildPartialReport(){}, handleEvent(){},
};
vm.createContext(ctx);
vm.runInContext(CODE + ';this.__run = runAssessment;', ctx);
ctx.__run().then(() => { process.stdout.write(JSON.stringify({popped, sent})); });
""".replace("__VALUES__", json.dumps(dict(values, authMethod=method))).replace("CODE", json.dumps(code))
    f = tmp_path / "h.js"
    f.write_text(harness, encoding="utf-8")
    return json.loads(subprocess.run(["node", str(f)], capture_output=True, text=True, check=True).stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_a_classic_api_run_passes_the_gate_without_any_oneapi_field(tmp_path):
    out = _run(tmp_path, "legacy", {"org": "Acme", "assessor": "Pat", "zuser": "admin@acme.com",
                                    "zpass": "pw-pw-pw-pw", "zkey": "abcdefghijkl"})
    assert out["popped"] == [], out["popped"]
    assert [u for u, _b in out["sent"]] == ["/api/assess"], out["sent"]
    body = out["sent"][0][1]
    assert body["auth_method"] == "legacy" and body["username"] == "admin@acme.com"
    assert not body.get("vanity_domain") and not body.get("client_id") and not body.get("client_secret")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_a_classic_api_run_asks_for_the_classic_fields_only(tmp_path):
    out = _run(tmp_path, "legacy", {"org": "Acme", "assessor": "Pat", "vd": "acme", "cid": "x", "csec": "y"})
    assert out["sent"] == []
    assert [i for i, _l in out["popped"][0]] == ["zuser", "zpass", "zkey"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_a_oneapi_run_still_needs_the_vanity_domain_client_id_and_secret(tmp_path):
    out = _run(tmp_path, "oneapi", {"org": "Acme", "assessor": "", "zuser": "u", "zpass": "p", "zkey": "k"})
    assert out["sent"] == []
    assert [i for i, _l in out["popped"][0]] == ["assessor", "vd", "cid", "csec"]


def test_the_guide_focuses_the_chosen_sign_ins_first_blank_field():
    block = _fn(_read("static/guide.js"), "function _gdGoConfig()", "function _gdGoResults()")
    assert "currentAuthMethod() === 'legacy'" in block and "['zuser', 'zpass', 'zkey']" in block
