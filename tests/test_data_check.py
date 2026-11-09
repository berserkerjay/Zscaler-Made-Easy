"""The data folder self-check and its safe repair (data_check, GET
/api/data-check, POST /api/data-check/repair, --check-data/--repair-data).

Real temporary folders, no tenant, no network. The repair removes only
stale lock files and stale temporary copies; every store, key and backup
survives it."""
from __future__ import annotations

import json
import os
import time

import pytest
from fastapi.testclient import TestClient

import data_check as dc
import store_crypto


@pytest.fixture
def folder(monkeypatch, tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(d / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(d / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_STORE_KEY_FILE", str(d / "store_keys.json"))
    return d


def by_id(rep):
    return {c["id"]: c for c in rep["checks"]}


def old(path, seconds=7200):
    t = time.time() - seconds
    os.utime(path, (t, t))


def test_missing_folder_fails_with_steps(monkeypatch, tmp_path):
    """ASVS V12.1.1 · CWE-754 · WSTG-CONF-04: a data folder that does not exist is a failure with a plain next step."""
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "nope" / "p.json"))
    rep = dc.check()
    assert rep["status"] == "fail" and by_id(rep)["folder_exists"]["status"] == "fail" and rep["steps"]


def test_healthy_fresh_folder(folder):
    """ASVS V12.1.1 · CWE-754: an empty writable folder passes: exists, writable, no stores, no leftovers; the probe file is gone."""
    rep = dc.check()
    c = by_id(rep)
    assert c["folder_exists"]["status"] == "ok" and c["folder_writable"]["status"] == "ok"
    assert c["stores_readable"]["status"] == "ok" and c["stale_locks"]["status"] == "ok" and c["stale_temp"]["status"] == "ok"
    assert not [f for f in os.listdir(folder) if f.startswith(".datacheck-probe")]


def test_read_only_folder_is_reported(folder, monkeypatch):
    """ASVS V12.1.1 · CWE-754: a folder that cannot be written fails the writable check and says how to fix it."""
    def boom(**kw):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(dc.tempfile, "mkstemp", boom)
    c = by_id(dc.check())["folder_writable"]
    assert c["status"] == "fail" and any("writable data folder" in s for s in c["fix"])


def test_encryption_state_is_reported(folder, monkeypatch):
    """ASVS V6.1.1 · CWE-311: the check says whether store encryption is on, off, or leaves plain stores."""
    monkeypatch.setenv(store_crypto.SETTING, "0")
    assert by_id(dc.check())["encryption"]["status"] == "warn"
    monkeypatch.delenv(store_crypto.SETTING, raising=False)
    (folder / "tenant_profiles.json").write_text(json.dumps({"version": 1, "profiles": {}}), encoding="utf-8")
    e = by_id(dc.check())["encryption"]
    assert e["status"] == "warn" and e["plain_files"] >= 1 and any("seal-all" in s for s in e["fix"])
    store_crypto.seal_all()
    assert by_id(dc.check())["encryption"]["status"] == "ok"


def test_unreadable_and_unknown_schema_stores(folder):
    """ASVS V12.1.1 · CWE-502: a damaged store fails the read check; a store from a newer schema warns; a sealed store with no key here fails."""
    (folder / "tenant_profiles.json").write_text("{not json", encoding="utf-8")
    rep = dc.check()
    assert by_id(rep)["stores_readable"]["status"] == "fail" and "tenant_profiles.json" in by_id(rep)["stores_readable"]["detail"]
    (folder / "tenant_profiles.json").write_text(json.dumps({"version": 99, "profiles": {}}), encoding="utf-8")
    rep = dc.check()
    assert by_id(rep)["stores_readable"]["status"] == "ok" and by_id(rep)["stores_schema"]["status"] == "warn"
    (folder / "tenant_profiles.json").write_text("ZMEENC1:deadbeef:AAAA", encoding="utf-8")
    assert by_id(dc.check())["stores_readable"]["status"] == "fail"


def test_stale_leftovers_are_found_and_only_those(folder):
    """ASVS V12.1.1 · CWE-459: only an old, unheld, empty lock beside a store, and an old temp copy, are stale; a fresh one, a held one, requirements.lock and the key lock are not."""
    (folder / "tenant_profiles.json").write_text(json.dumps({"version": 1, "profiles": {}}), encoding="utf-8")
    (folder / "proposals.json").write_text("{}", encoding="utf-8")
    stale = folder / "proposals.json.lock"; stale.write_text("")
    fresh = folder / "tenant_profiles.json.lock"; fresh.write_text("")
    orphan = folder / "ghost.json.lock"; orphan.write_text("")          # no sibling store: not ours to remove
    req = folder / "requirements.lock"; req.write_text("pkg==1 --hash=sha256:x\n")
    keylock = folder / store_crypto.LOCK_NAME; keylock.write_text("")
    tmp = folder / ".profiles-abc123"; tmp.write_text("{}")
    fresh_tmp = folder / ".deployments-new"; fresh_tmp.write_text("{}")
    for p in (stale, orphan, req, keylock, tmp):
        old(p)
    rep = dc.check()
    assert by_id(rep)["stale_locks"]["status"] == "warn" and by_id(rep)["stale_locks"]["count"] == 1
    assert by_id(rep)["stale_temp"]["status"] == "warn" and by_id(rep)["stale_temp"]["count"] == 1
    assert rep["repairable"] == {"stale_locks": 1, "stale_temp_files": 1}
    out = dc.repair()
    assert out["removed_locks"] == ["proposals.json.lock"] and out["removed_temp_files"] == [".profiles-abc123"]
    for survivor in (fresh, orphan, req, keylock, fresh_tmp, folder / "tenant_profiles.json", folder / "proposals.json"):
        assert survivor.exists(), survivor.name
    assert not stale.exists() and not tmp.exists()
    assert by_id(dc.check())["stale_locks"]["status"] == "ok"


def test_a_held_lock_is_never_removed(folder):
    """ASVS V12.1.1 · CWE-667: a lock file another holder has locked is in use, not stale, and the repair leaves it."""
    (folder / "sync_jobs.json").write_text("{}", encoding="utf-8")
    lk = folder / "sync_jobs.json.lock"; lk.write_text("")
    old(lk)
    f = open(lk, "a+")
    try:
        assert store_crypto._try_lock(f)
        rep = dc.check()
        assert by_id(rep)["stale_locks"]["status"] == "ok" and "in use" in by_id(rep)["stale_locks"]["detail"]
        assert dc.repair()["removed_locks"] == [] and lk.exists()
    finally:
        store_crypto._unlock(f)


def test_repair_is_audited_by_name_only(folder):
    """ASVS V7.1.1 · CWE-532: the repair writes an audit entry naming the removed files and no contents."""
    (folder / "proposals.json").write_text("{}", encoding="utf-8")
    t = folder / ".deployments-zzz"; t.write_text("SECRETCONTENT-9f3")
    old(t)
    dc.repair()
    text = store_crypto.open_text((folder / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    assert "data_check_repair" in text and ".deployments-zzz" in text and "SECRETCONTENT-9f3" not in text


def test_routes_check_and_repair(folder, monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: GET /api/data-check answers no-store; the repair needs the typed phrase and removes only stale files."""
    import dlp_api_server as srv
    c = TestClient(srv.app)
    r = c.get("/api/data-check")
    assert r.status_code == 200 and "no-store" in r.headers["cache-control"] and r.json()["checks"]
    t = folder / ".profiles-old"; t.write_text("{}"); old(t)
    assert c.post("/api/data-check/repair", json={"confirm_text": "nope"}).status_code == 400 and t.exists()
    r = c.post("/api/data-check/repair", json={"confirm_text": "REPAIR DATA FOLDER"})
    assert r.status_code == 200 and r.json()["removed_temp_files"] == [".profiles-old"] and not t.exists()
    assert r.json()["check"]["checks"]


def test_team_rules_are_admin_only():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-03: both routes are administrator-only on a team server."""
    import team_routes
    assert team_routes.ROUTE_RULES["GET /api/data-check"] == team_routes.ADMIN
    assert team_routes.ROUTE_RULES["POST /api/data-check/repair"] == team_routes.ADMIN


def test_cli_flag_exit_codes(folder, capsys):
    """ASVS V12.1.1 · CWE-754: --check-data prints the check and exits 0 healthy, 1 on a warning; --repair-data removes leftovers first."""
    import dlp_assessment_full_auto as fa
    with pytest.raises(SystemExit) as ex:
        fa.main(["--check-data"])
    assert ex.value.code == 0 and "Data folder:" in capsys.readouterr().out
    t = folder / ".profiles-old"; t.write_text("{}"); old(t)
    with pytest.raises(SystemExit) as ex:
        fa.main(["--check-data"])
    assert ex.value.code == 1 and t.exists()
    with pytest.raises(SystemExit) as ex:
        fa.main(["--repair-data"])
    assert ex.value.code == 0 and not t.exists() and "Removed 0 stale lock" in capsys.readouterr().out
