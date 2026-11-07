"""Leftover-rule cleanup with Keep boxes: the rule picker marks rules this app made whose pack is gone from the
library (or has no live deployment for the tenant) as leftovers with Keep ticked by default; only unticked leftovers
become a removal selection, which still goes through the removal preview, typed phrase, write mode and Undo."""
from __future__ import annotations

import os

import pack_deploy as pd
import pack_removal as pr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = {"reachable": True, "dictionaries": {}, "engines": {}, "channels": {},
        "rules": [{"id": 7, "name": "Customer rule", "description": "Customer finance rule [Q3 pack review]"},
                  {"id": 9, "name": "Live", "description": "Monitor. [Jane Doe pack alpha v2] Deployed DISABLED."},
                  {"id": 10, "name": "Gone", "description": "Monitor. [DLP-Check pack gone v1]"},
                  {"id": 11, "name": "Undeployed", "description": "Monitor. [Jane Doe pack beta v1]"}]}


def _inv(monkeypatch, live=None):
    monkeypatch.setattr(pd, "library_ids", lambda: {"alpha", "beta"})
    monkeypatch.setattr(pd, "fetch_tenant", lambda client, need=None, **kw: SNAP)
    inv = pr.inventory(object(), None)
    if live is not None:
        pr.mark_leftovers(inv, live)
    return {r["name"]: r for r in inv["rules"]}


def test_a_rule_whose_pack_left_the_library_is_a_leftover_kept_by_default(monkeypatch):
    """ASVS V4.1.3 · CWE-1188 · WSTG-BUSL-01: read-only by default: a rule from a pack no longer in the library is a leftover with Keep ticked; customer rules and live packs are not leftovers."""
    rows = _inv(monkeypatch)
    assert rows["Gone"]["leftover"] and "no longer in the library" in rows["Gone"]["leftover"] and rows["Gone"]["keep"] is True
    assert not rows["Customer rule"]["leftover"] and not rows["Live"]["leftover"] and not rows["Undeployed"]["leftover"]


def test_with_deployment_records_a_pack_nothing_holds_is_a_leftover_too(monkeypatch):
    """ASVS V11.1.1 · CWE-841: given the packs a live deployment holds, a rule of any other pack of ours is a leftover; a name is never provenance, only the app's own tag."""
    rows = _inv(monkeypatch, live=["alpha"])
    assert not rows["Live"]["leftover"] and "no live deployment" in rows["Undeployed"]["leftover"] and rows["Gone"]["leftover"]
    assert not rows["Customer rule"]["leftover"]


def test_only_unticked_leftovers_become_the_removal_selection(monkeypatch):
    """ASVS V4.1.3 · CWE-285: ticked Keep boxes are never selected, a non-leftover is never selected whatever keep says, and the result is the {channel, id} list the removal preview takes."""
    rows = list(_inv(monkeypatch, live=["alpha"]).values())
    ids = {r["name"]: f"{r['channel']}:{r['id']}" for r in rows}
    sel = pr.selection_without_kept(rows, [ids["Gone"]])
    assert [s["id"] for s in sel] == [11]                                   # Gone is kept; Undeployed is not
    assert pr.selection_without_kept(rows, ids.values()) == []              # every box ticked: nothing to remove
    assert all(s["id"] not in (7, 9) for s in pr.selection_without_kept(rows, []))   # customer and live rules are never offered


def test_the_picker_shows_a_keep_box_for_leftovers_only():
    """WCAG 2.2 SC 4.1.2 · ASVS V5.3.3 · CWE-79: a leftover row's checkbox is a named Keep box (ticked unless selected) and the reason is escaped."""
    js = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert "aria-label=\"Keep ${_dzE(r.name)} (leftover: ${_dzE(r.leftover)})\"" in js and "_dzPickToggle('${_dzE(key(r))}', !this.checked)" in js
