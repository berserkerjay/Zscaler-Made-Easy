"""Deployment planning clarity (UI/UX stage 5): one count vocabulary
across the Studio's hero, tiles and gates; conflicts told apart from
skips; write-mode copy that says what it is (server-wide, until restart);
the approve step's two activation statements agree; the select footer
names the channels; the stale button name is gone."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _js():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c.get("/static/deploy_studio.js").text


def test_one_count_vocabulary_for_hero_tiles_gates_and_announcement():
    js = _js()
    assert "function _dzCounts(R)" in js and "c.writes = c.create + c.modify + c.restore;" in js and "c.blocked = c.conflict + c.dependency + c.empty;" in js
    review = js.split("function _dzRenderReview()")[1].split("function _dzGatesHtml")[0]
    assert "const c = _dzCounts(R);" in review and "${_dzN(c.create, 'object')} to create" in review
    assert '<div class="k">Will create</div><div class="v">${c.create}</div>' in review and '<div class="k">Kept as-is</div><div class="v">${c.differs}</div>' in review
    gates = js.split("function _dzGatesHtml")[1].split("function _dzUntickedChannels")[0]
    assert "const c = _dzCounts(R);" in gates and "There is something to write (${writesText})." in gates
    assert "Nothing to write: every object is skipped or in conflict" in gates and "conflict')}: those objects and what depends on them are left out" in gates
    assert "data.will_create} changes" not in js and "${c.create} to create, ${c.modify + c.restore} to change" in js


def test_conflicts_and_skips_are_separate_and_named():
    js = _js()
    assert "'Conflicts — resolve before deploying (deselect a pack or rename)'" in js
    assert "'Skipped — a prerequisite is missing, or the dictionary is empty'" in js and "'Skipped — dependency or conflict'" not in js
    assert "label: 'Skipped: needs a prerequisite'" in js and "label: 'Skipped: empty'" in js
    assert "<strong>Skipped vs conflict.</strong>" in js
    assert "its content matched where the tenant let it be compared" in js   # "reuse" no longer promises "same content"


def test_write_mode_copy_says_server_wide_until_restart_and_what_can_change():
    js = _js()
    assert "Enable write mode on this server?" in js and "applies to every browser and tab using this server, and stays on until the server restarts" in js
    assert "Write mode enabled on this server until it restarts." in js and "Write mode enabled for this session." not in js
    assert "Write mode is on for this server (every browser using it) until the server restarts." in js and "this server session" not in js
    assert "Enabled from this window" not in js and "Enabled from this app: it applies to every browser using this server" in js
    assert "existing objects are never overwritten" not in js and "Existing objects are never overwritten" not in js
    assert "listed as <em>Will modify</em> for approval" in js and "<strong>Existing objects are not overwritten.</strong>" in js
    guide = TestClient(srv.app).get("/static/guide.js").text
    assert "stays on for this server (every browser using it) until the server restarts" in guide


def test_approve_step_activation_statements_agree_and_footer_names_channels():
    js = _js()
    assert "an admin must activate changes in the ZIA portal afterwards" not in js
    assert "the deploy activates the changes in ZIA when it completes (if activation cannot run, the result says so" in js
    assert "The deploy activates the changes in ZIA when it completes.<br>" in js and "Existing objects are never overwritten;'" not in js
    assert "Channels — ${_dzTargetsSummary(sel.map(p => p.id))}. Preflight reads the tenant and writes nothing." in js
    assert "<strong>Export Terraform</strong>" not in js and "<strong>Hand off as Terraform</strong> on the review step" in js
    assert "creates what this list creates and imports what already exists" in js and "is exactly this list" not in js
    # The safeguards stay: consent, plan hash, write mode, blocked status all gate the button.
    assert "${DZ.consent && R.status !== 'blocked' && !writeOff ? '' : 'disabled'} onclick=\"_dzApply()\"" in js
