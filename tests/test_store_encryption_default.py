"""Encrypted stores ON by default (store_crypto.py): a fresh install seals
every store; an upgrade seals the plain stores an earlier version wrote,
once, with a verified backup first, atomically and resumably (an interrupted
run carries on, a file that does not read back is put back); the opt-out
(DLP_CHECK_STORE_ENCRYPTION=0) and unseal-all; the key in the credential
store where there is one and in the owner-only key file where there is not
(the container's /data, a headless Linux); a key ring that cannot be read is
never replaced; no plain copy is left behind; rotation still works.

tests/conftest.py runs the suite with the shipped default (on); every test
here also removes the setting (default_on) unless it tests the opt-out. No network,
no real credential store (a fake keyring module where one is needed)."""
from __future__ import annotations

import json
import os
import stat
import sys
import types

import pytest

import audit
import change_queue
import deployments
import store_crypto
import tenant_profiles
import workspace_notes

SETTING = "DLP_CHECK_STORE_ENCRYPTION"


@pytest.fixture
def default_on(monkeypatch):
    """The shipped default: the setting is not set at all."""
    monkeypatch.delenv(SETTING, raising=False)
    monkeypatch.setitem(store_crypto._KEY_PROBLEM, "problem", None)


def _data_dir():
    return os.path.dirname(os.path.abspath(tenant_profiles.store_path()))


def _profile(name="Plainco"):
    return tenant_profiles.upsert({"name": name, "cloud": "zscalerten", "vanity_domain": f"{name.lower()}.example",
                                   "client_id": f"cid-{name}"})["id"]


def _fill_stores_plain(monkeypatch):
    """Stores as a version with encryption off wrote them: plain JSON with a PLAIN marker in each."""
    monkeypatch.setenv(SETTING, "0")
    pid = _profile("Secretco")
    tenant_profiles.save_snapshot(json.dumps({"responses": {"marker": "SNAPSHOT-PLAIN"}}), {"label": "secretco"}, pid)
    change_queue.file_request(kind="pack_deploy", tenant="secretco.example", tenant_label="CQ-PLAIN", title="CQ-PLAIN", summary={},
                              items=[], plan_hash="p" * 64, requested_by="enc-user", payload={})
    deployments.add({"id": "dep-enc", "tenant_label": "DEP-PLAIN", "created": []})
    workspace_notes.apply("NOTES-PLAIN", "rule", "1", "add_tag", by="enc-user", tag="t")
    audit.record("enc_test", marker="AUDIT-PLAIN")
    audit.record("enc_test", marker="AUDIT-PLAIN-2")
    import config_backup as cb
    import sync_jobs
    doc = cb.build_doc({"zia.rule_labels": [{"id": 1, "name": "BK-PLAIN label"}]}, {"tenant_label": "BK-PLAIN", "profile_id": pid})
    cb.save_backup(doc)
    cb.save_template(cb.make_template(doc, [{"type": "zia.rule_labels", "name": "BK-PLAIN label"}], name="TPL-PLAIN"), profile_id=pid)
    cb.refresh_cache(pid, {"zia.rule_labels": [{"id": 1, "name": "CACHE-PLAIN label"}]}, {"tenant_label": "CACHE-PLAIN"})
    with sync_jobs._locked():
        sync_jobs._write({"version": 1, "jobs": {"job-enc": {"id": "job-enc", "name": "SYNC-PLAIN"}}})
    files = [e["path"] for e in store_crypto._store_paths()]
    assert len(files) >= 10 and all("PLAIN" in open(p, encoding="utf-8").read() or "Secretco" in open(p, encoding="utf-8").read()
                                    for p in files if "workspace" not in p), files
    monkeypatch.delenv(SETTING)
    return pid


def _read_everything(pid):
    import config_backup as cb
    import sync_jobs
    assert tenant_profiles.get(pid)["name"] == "Secretco"
    snap = tenant_profiles.list_snapshots(pid)[0]["id"]
    assert b"SNAPSHOT-PLAIN" in tenant_profiles.read_snapshot(snap, 1_000_000)
    assert change_queue.list_requests("secretco.example")[0]["title"] == "CQ-PLAIN"
    assert deployments.get("dep-enc")["tenant_label"] == "DEP-PLAIN"
    assert workspace_notes.list_notes("NOTES-PLAIN")
    marks = [e.get("marker") for e in audit.tail(100)]
    assert "AUDIT-PLAIN" in marks and "AUDIT-PLAIN-2" in marks
    (bk,) = cb.list_backups(pid)
    assert cb.load_backup(bk["id"])["types"]["zia.rule_labels"][0]["name"] == "BK-PLAIN label"
    (tpl,) = cb.list_templates()
    assert cb.load_template(tpl["id"])["meta"]["name"] == "TPL-PLAIN"
    assert cb.read_cache(pid)["meta"]["tenant_label"] == "CACHE-PLAIN"
    assert sync_jobs._read()["jobs"]["job-enc"]["name"] == "SYNC-PLAIN"


def _no_plain_anywhere():
    """No file under the data folder (stores, journal, leftovers) holds a PLAIN marker or the tenant's name."""
    hits = []
    for root, _dirs, names in os.walk(_data_dir()):
        for n in names:
            p = os.path.join(root, n)
            try:
                raw = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if "PLAIN" in raw or "Secretco" in raw:
                hits.append(p)
    return hits


def _every_store_sealed(kid=None):
    for e in store_crypto._store_paths():
        raw = open(e["path"], encoding="utf-8").read()
        lines = [ln for ln in raw.splitlines() if ln.strip()] if e["lines"] else [raw]
        assert lines and all(ln.startswith(f"ZMEENC1:{kid}:" if kid else "ZMEENC1:") for ln in lines), e["path"]


class _Crash(BaseException):
    """A process killed in the middle of the migration (not an error the code may catch)."""


# ── default on for a fresh install ──────────────────────────────────────
def test_a_fresh_install_seals_every_store_by_default(default_on):
    """ASVS V6.1.1 · V14.1.1 · CWE-311 · CWE-1188 · WSTG-CRYP-04: with no setting at all a new store is written AES-256-GCM sealed, reads back, and the key file is owner-only."""
    assert store_crypto.enabled() and not store_crypto.explicitly_on()
    pid = _profile("Freshco")
    raw = open(tenant_profiles.store_path(), encoding="utf-8").read()
    assert raw.startswith("ZMEENC1:") and "Freshco" not in raw
    assert tenant_profiles.get(pid)["name"] == "Freshco"
    assert stat.S_IMODE(os.stat(store_crypto.key_file()).st_mode) == 0o600
    st = store_crypto.status()
    assert st["enabled"] and st["default"] and st["sealing"] and st["algorithm"] == "AES-256-GCM" and st["kept_in"] == "key file"
    assert store_crypto.migrate()["status"] == "nothing"          # nothing plain on a fresh install


def test_unknown_values_count_as_on_and_only_the_opt_out_words_turn_it_off(monkeypatch):
    """ASVS V14.1.1 · CWE-1188: secure by default: a typo is not an opt-out; 0/off/false/no are."""
    for v in ("", "1", "yes", "ON", "maybe"):
        monkeypatch.setenv(SETTING, v)
        assert store_crypto.enabled(), v
    for v in ("0", "off", "False", " no "):
        monkeypatch.setenv(SETTING, v)
        assert not store_crypto.enabled(), v


# ── the opt-out ─────────────────────────────────────────────────────────
def test_the_opt_out_writes_plain_owner_only_json(monkeypatch):
    """ASVS V14.1.1 · CWE-1188: DLP_CHECK_STORE_ENCRYPTION=0 keeps every store the plain JSON it always was, and the start-up says so."""
    monkeypatch.setenv(SETTING, "0")
    _profile("Optco")
    assert json.load(open(tenant_profiles.store_path(), encoding="utf-8"))["profiles"]["optco"]["name"] == "Optco"
    assert store_crypto.seal_text("x") == "x" and not store_crypto.status()["enabled"]
    said = []
    assert store_crypto.startup(said.append)["status"] == "off"
    assert "DLP_CHECK_STORE_ENCRYPTION=0" in said[0]
    assert not os.path.exists(store_crypto.key_file())


def test_unseal_all_turns_sealed_stores_back_into_plain_files_only_after_the_opt_out(default_on, monkeypatch):
    """ASVS V6.2.1 · CWE-311 · CWE-459: unseal-all refuses while encryption is on; after the opt-out every sealed store becomes plain JSON again and still reads."""
    pid = _fill_stores_plain(monkeypatch)
    assert store_crypto.migrate()["status"] == "done"
    with pytest.raises(RuntimeError, match="DLP_CHECK_STORE_ENCRYPTION=0"):
        store_crypto.unseal_all()
    monkeypatch.setenv(SETTING, "0")
    out = store_crypto.unseal_all()
    assert len(out["files"]) >= 10
    for e in store_crypto._store_paths():
        assert "ZMEENC1:" not in open(e["path"], encoding="utf-8").read(), e["path"]
    _read_everything(pid)


# ── the one-time migration of plain stores ──────────────────────────────
def test_an_upgrade_seals_every_plain_store_once_and_leaves_no_plain_copy(default_on, monkeypatch):
    """ASVS V6.1.1 · V8.3.4 · CWE-311 · CWE-312 · CWE-459 · WSTG-CRYP-04: the first start after the upgrade seals every plain store (backups, caches, templates, sync jobs, audit log...), everything reads back, the backup and the per-file journal are gone, and no plain copy stays."""
    pid = _fill_stores_plain(monkeypatch)
    said = []
    out = store_crypto.startup(said.append)
    assert out["status"] == "done" and out["files"] >= 10
    assert "encrypted" in said[0] and "verified backup" in said[0] and "DLP_CHECK_STORE_ENCRYPTION=0" in said[0]
    _every_store_sealed(out["key"])
    _read_everything(pid)
    assert not os.path.exists(store_crypto.backup_dir())
    assert _no_plain_anywhere() == []
    journal = json.load(open(store_crypto.migration_path(), encoding="utf-8"))
    assert journal["state"] == "done" and "files" in journal and not isinstance(journal["files"], dict)   # counts only, no paths or hashes
    assert any(e.get("event") == "store_encryption_migrated" for e in audit.tail(50))
    assert store_crypto.migrate()["status"] == "nothing"          # one time: a second start has nothing to do


def test_an_interrupted_migration_resumes_from_its_journal_without_losing_data(default_on, monkeypatch):
    """ASVS V8.3.4 · CWE-404 · CWE-664: a process killed after some files are sealed leaves every store readable (sealed or still plain), the backup and journal kept; the next start carries on and finishes."""
    pid = _fill_stores_plain(monkeypatch)
    real, calls = store_crypto._seal_one, []

    def die_on_third(path, rec, kid, key):
        calls.append(path)
        if len(calls) == 3:
            raise _Crash()
        return real(path, rec, kid, key)
    monkeypatch.setattr(store_crypto, "_seal_one", die_on_third)
    with pytest.raises(_Crash):
        store_crypto.migrate()
    journal = json.load(open(store_crypto.migration_path(), encoding="utf-8"))
    assert journal["state"] == "in_progress" and sum(1 for r in journal["files"].values() if r["sealed"]) == 2
    assert os.path.isdir(store_crypto.backup_dir()) and len(os.listdir(store_crypto.backup_dir())) == len(journal["files"])
    assert stat.S_IMODE(os.stat(store_crypto.backup_dir()).st_mode) == 0o700
    _read_everything(pid)                                            # half-way: nothing lost
    assert store_crypto.migration_status()["state"] == "in_progress"
    monkeypatch.setattr(store_crypto, "_seal_one", real)
    out = store_crypto.migrate()
    assert out["status"] == "done"
    _every_store_sealed(out["key"])
    _read_everything(pid)
    assert _no_plain_anywhere() == []


def test_a_crash_between_sealing_a_file_and_journaling_it_is_recognised_on_the_rerun(default_on, monkeypatch):
    """ASVS V8.3.4 · CWE-664: a file sealed but not yet recorded in the journal opens on the rerun and is counted as done, never sealed twice or lost."""
    pid = _fill_stores_plain(monkeypatch)
    real, n = store_crypto._save_journal, []

    def die_on_third(j):
        n.append(1)
        if len(n) == 3:                    # 1: the backup is recorded; 2: first file; 3: second file sealed, not journaled
            raise _Crash()
        return real(j)
    monkeypatch.setattr(store_crypto, "_save_journal", die_on_third)
    with pytest.raises(_Crash):
        store_crypto.migrate()
    monkeypatch.setattr(store_crypto, "_save_journal", real)
    out = store_crypto.migrate()
    assert out["status"] == "done"
    _every_store_sealed(out["key"])
    _read_everything(pid)


def test_a_file_that_does_not_read_back_is_put_back_from_the_backup_and_the_rerun_finishes(default_on, monkeypatch):
    """ASVS V8.3.4 · V6.2.1 · CWE-354 · CWE-664: a sealed file that does not open to what the backup holds is restored from the backup (plain, readable), the migration stops with a plain message and keeps the backup; the next start finishes."""
    pid = _fill_stores_plain(monkeypatch)
    before = open(tenant_profiles.store_path(), encoding="utf-8").read()
    real = store_crypto._seal_with

    def corrupt_profiles(text, kid, key):
        return real(text.replace("Secretco", "Wrongco"), kid, key)
    monkeypatch.setattr(store_crypto, "_seal_with", corrupt_profiles)
    out = store_crypto.migrate()
    assert out["status"] == "stopped" and "put back from the backup" in out["error"] and "Nothing was lost" in out["message"]
    assert open(tenant_profiles.store_path(), encoding="utf-8").read() == before     # put back exactly as it was
    assert os.path.isdir(store_crypto.backup_dir())
    _read_everything(pid)
    monkeypatch.setattr(store_crypto, "_seal_with", real)
    assert store_crypto.migrate()["status"] == "done"
    _read_everything(pid)
    assert _no_plain_anywhere() == []


def test_the_migration_removes_an_old_plain_temporary_copy_but_not_a_write_in_progress(default_on, monkeypatch):
    """ASVS V8.3.4 · CWE-459: a stale ".<store>.<x>.tmp" an older version's crash left beside a store goes; a fresh one (a write in progress) stays."""
    _fill_stores_plain(monkeypatch)
    folder, base = os.path.split(tenant_profiles.store_path())
    stale, fresh = os.path.join(folder, f".{base}.abc.tmp"), os.path.join(folder, f".{base}.def.tmp")
    for p in (stale, fresh):
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"profiles": {"x": {"name": "Secretco"}}}')
    os.utime(stale, (1_000_000, 1_000_000))
    os.utime(fresh, (1_007_000, 1_007_000))
    assert store_crypto.migrate(now=lambda: 1_008_000.0)["status"] == "done"
    assert not os.path.exists(stale) and os.path.exists(fresh)


def _old(path, when=1_000_000):
    os.utime(path, (when, when))
    return path


def test_every_kind_of_plain_temporary_copy_goes_at_every_start(default_on):
    """ASVS V8.3.4 · CWE-459 · CWE-312: the stores' real temporary names (".profiles-*", ".deployments-*", ".<store>.*.tmp", ".selfheal-*.tmp") are removed when stale, at every start and not only by the migration; a fresh one stays."""
    _profile("Tempco")
    folder = _data_dir()
    stale = [os.path.join(folder, n) for n in (".profiles-abc123", ".deployments-abc123", ".change_requests.ab12.tmp", ".selfheal-ab12.tmp")]
    fresh = os.path.join(folder, ".profiles-def456")
    for p in stale + [fresh]:
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"name": "Secretco"}')
        _old(p)
    _old(fresh, 1_007_000)
    assert store_crypto.migrate(now=lambda: 1_008_000.0)["status"] == "nothing"     # nothing plain to seal, yet the leftovers go
    assert [p for p in stale if os.path.exists(p)] == [] and os.path.exists(fresh)


def test_a_damaged_copy_self_healing_kept_is_sealed_like_its_store(default_on, monkeypatch):
    """ASVS V6.1.1 · V8.3.4 · CWE-312 · WSTG-CRYP-04: a plain "<store>.corrupt-<time>" copy is sealed by the upgrade (it opens to what it held), so no plain copy stays."""
    pid = _fill_stores_plain(monkeypatch)
    copy = tenant_profiles.store_path() + ".corrupt-20261101-000000"
    with open(copy, "w", encoding="utf-8") as f:
        f.write('{"profiles": {"x": {"name": "Secretco"')     # damaged: not even JSON
    out = store_crypto.migrate()
    assert out["status"] == "done"
    raw = open(copy, encoding="utf-8").read()
    assert raw.startswith("ZMEENC1:") and store_crypto.open_text(raw).endswith('"Secretco"')
    assert _no_plain_anywhere() == []
    _read_everything(pid)


def test_rotation_keeps_an_old_key_a_file_still_names(default_on, monkeypatch):
    """ASVS V6.4.2 · CWE-320 · CWE-404: a sealed damaged copy that cannot be re-sealed (it does not open) keeps its key through a rotation instead of becoming unreadable for good; with nothing left on the old key it is forgotten (test_rotation_still_works_...)."""
    _profile("Rotco")
    old = store_crypto._load_ring()["current"]
    copy = tenant_profiles.store_path() + ".corrupt-20261101-000000"
    with open(copy, "w", encoding="utf-8") as f:
        f.write(f"ZMEENC1:{old}:AAAA")                       # sealed with the current key, but damaged
    out = store_crypto.rotate()
    assert out["old_keys_kept"] == [old]
    ring = store_crypto._load_ring()
    assert ring["current"] == out["new_key"] and set(ring["keys"]) == {old, out["new_key"]}
    assert open(copy, encoding="utf-8").read() == f"ZMEENC1:{old}:AAAA"     # left exactly as self-healing kept it
    assert tenant_profiles.get("rotco")["name"] == "Rotco"


def test_a_backup_folder_that_cannot_be_removed_is_reported_not_called_removed(default_on, monkeypatch):
    """ASVS V8.3.4 · CWE-459 · CWE-312 · CWE-390: when the backup folder survives its removal the migration says "stopped", names the unencrypted copies, and the status says so; the next start removes it and finishes."""
    pid = _fill_stores_plain(monkeypatch)
    real = store_crypto.shutil.rmtree
    monkeypatch.setattr(store_crypto.shutil, "rmtree", lambda *a, **k: None)
    out = store_crypto.migrate()
    assert out["status"] == "stopped" and "UNENCRYPTED" in out["message"] and "removed" not in out["message"].split(":")[0]
    assert out["plaintext_backup_files"] > 0 and store_crypto.migration_status()["plaintext_backup_files"] == out["plaintext_backup_files"]
    _read_everything(pid)
    monkeypatch.setattr(store_crypto.shutil, "rmtree", real)
    assert store_crypto.migrate()["status"] == "done"
    assert not os.path.exists(store_crypto.backup_dir()) and "plaintext_backup" not in store_crypto.migration_status()


def test_a_stopped_migration_keeps_a_plain_backup_only_of_what_is_not_sealed_and_says_so(default_on, monkeypatch):
    """ASVS V8.3.4 · CWE-312 · CWE-459: an audit line sealed with a key that is not here stops the migration at every start; the backups of the files already sealed are dropped, and the message, the status and the Team page say an unencrypted backup is kept."""
    pid = _fill_stores_plain(monkeypatch)
    with open(audit.path(), "a", encoding="utf-8") as f:
        f.write("ZMEENC1:deadbeef:AAAA\n")
    out = store_crypto.migrate()
    assert out["status"] == "stopped" and "UNENCRYPTED backup" in out["message"]
    left = os.listdir(store_crypto.backup_dir())
    assert 0 < len(left) < out["files"] + len(left) and not any(n.endswith("tenant_profiles.json") for n in left)
    st = store_crypto.status()["migration"]
    assert st["plaintext_backup_files"] == len(left) and "UNENCRYPTED" in st["plaintext_backup"]
    assert tenant_profiles.get(pid)["name"] == "Secretco"
    team = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "report_team.html"), encoding="utf-8").read()
    assert "plaintext_backup" in team and "E(data.stores.migration.plaintext_backup)" in team


# ── the key: credential store, key file fallback, never replaced blind ──
def _fake_keyring(monkeypatch, *, fail_backend=False, locked=False):
    store = {}
    mod = types.ModuleType("keyring")
    backends = types.ModuleType("keyring.backends")
    failmod = types.ModuleType("keyring.backends.fail")

    class FailKeyring:
        pass
    failmod.Keyring = FailKeyring

    class Backend:
        pass
    mod.get_keyring = lambda: FailKeyring() if fail_backend else Backend()

    def get_password(svc, name):
        if locked:
            raise RuntimeError("locked")
        return store.get((svc, name))

    def set_password(svc, name, value):
        store[(svc, name)] = value
    mod.get_password, mod.set_password = get_password, set_password
    backends.fail = failmod
    mod.backends = backends
    monkeypatch.setitem(sys.modules, "keyring", mod)
    monkeypatch.setitem(sys.modules, "keyring.backends", backends)
    monkeypatch.setitem(sys.modules, "keyring.backends.fail", failmod)
    return store


def test_the_key_goes_to_the_credential_store_where_there_is_one(default_on, monkeypatch):
    """ASVS V6.4.1 · CWE-321 · CWE-522: with a working credential store the key ring is kept there and read back; no key file is written."""
    store = _fake_keyring(monkeypatch)
    _profile("Kcco")
    assert ("dlp-check", "store-keys") in store and not os.path.exists(store_crypto.key_file())
    assert store_crypto.status()["kept_in"] == "credential store"
    assert tenant_profiles.get("kcco")["name"] == "Kcco"


def test_without_a_usable_credential_store_the_key_goes_to_the_protected_key_file(default_on, monkeypatch, tmp_path):
    """ASVS V6.4.1 · CWE-321 · CWE-732: keyring installed with no backend (a headless Linux, the container) falls back to the owner-only key file; DLP_CHECK_STORE_KEY_FILE moves it off the data volume."""
    _fake_keyring(monkeypatch, fail_backend=True)
    where = tmp_path / "keys" / "store_keys.json"
    monkeypatch.setenv("DLP_CHECK_STORE_KEY_FILE", str(where))
    _profile("Fileco")
    assert where.is_file() and stat.S_IMODE(os.stat(where).st_mode) == 0o600
    ring = json.loads(where.read_text(encoding="utf-8"))
    assert ring["current"] in ring["keys"]
    st = store_crypto.status()
    assert st["kept_in"] == "key file" and st["key_file"] == str(where)
    for e in store_crypto._store_paths():
        assert ring["keys"][ring["current"]] not in open(e["path"], encoding="utf-8").read()


def test_the_default_key_file_lives_with_the_data_in_the_container_and_the_no_install_edition(default_on, monkeypatch, tmp_path):
    """ASVS V6.4.1 · CWE-732: the key file sits beside the stores: /data in the container (Dockerfile's DLP_CHECK_PROFILES), the per-user data folder in the no-install edition."""
    df = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Dockerfile"), encoding="utf-8").read()
    assert "DLP_CHECK_PROFILES=/data/tenant_profiles.json" in df
    monkeypatch.setenv("DLP_CHECK_PROFILES", "/data/tenant_profiles.json")
    assert store_crypto.key_file() == os.path.join("/data", "store_keys.json")
    import standalone_main
    env = {}
    standalone_main.configure(env, str(tmp_path / "userdata"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", env["DLP_CHECK_PROFILES"])
    assert os.path.dirname(store_crypto.key_file()) == os.path.dirname(env["DLP_CHECK_PROFILES"])


def test_the_status_says_where_the_key_is_not_where_it_would_go(default_on, monkeypatch):
    """ASVS V6.4.1 · CWE-1059 · CWE-451: a ring kept in the key file is reported as in the key file even after a credential store appears."""
    _profile("Whereco")
    assert os.path.isfile(store_crypto.key_file())
    _fake_keyring(monkeypatch)
    st = store_crypto.status()
    assert st["kept_in"] == "key file" and st["key_file"] == store_crypto.key_file()


def test_a_key_file_the_operator_named_is_never_moved_or_deleted(default_on, monkeypatch, tmp_path):
    """ASVS V6.4.1 · CWE-321 · CWE-404: with DLP_CHECK_STORE_KEY_FILE set, a credential store that appears later does not take the key, and a rotation keeps the ring in that file."""
    where = tmp_path / "keys" / "store_keys.json"
    monkeypatch.setenv("DLP_CHECK_STORE_KEY_FILE", str(where))
    _profile("Namedco")
    store = _fake_keyring(monkeypatch)
    out = store_crypto.rotate()
    assert where.is_file() and json.loads(where.read_text(encoding="utf-8"))["current"] == out["new_key"]
    assert out["kept_in"] == "key file" and store == {} and store_crypto.status()["kept_in"] == "key file"
    assert tenant_profiles.get("namedco")["name"] == "Namedco"


def test_a_locked_credential_store_is_never_replaced_by_a_new_key(default_on, monkeypatch):
    """ASVS V6.4.1 · CWE-320 · CWE-664: when the credential store cannot be read, no new key is made (that would orphan every sealed store); the store stays plain and status says why; an explicit =1 refuses instead."""
    store = _fake_keyring(monkeypatch, locked=True)
    _profile("Lockco")
    assert store == {}                                             # nothing written over the old entry
    assert json.load(open(tenant_profiles.store_path(), encoding="utf-8"))["profiles"]["lockco"]["name"] == "Lockco"
    st = store_crypto.status()
    assert not st["sealing"] and "credential store could not be read" in st["problem"]
    monkeypatch.setenv(SETTING, "1")
    with pytest.raises(store_crypto.KeyUnavailable):
        store_crypto.seal_text("x")


def test_a_damaged_key_file_is_never_overwritten(default_on):
    """ASVS V6.4.1 · CWE-320 · CWE-664: a key file that exists but does not parse is left as it is (it may be recovered), no new key replaces it, and the migration says why."""
    with open(store_crypto.key_file(), "w", encoding="utf-8") as f:
        f.write("{not json")
    _profile("Dmgco")
    assert open(store_crypto.key_file(), encoding="utf-8").read() == "{not json"
    out = store_crypto.migrate()
    assert out["status"] == "no_key" and "could not be read" in out["message"]


def test_no_place_to_keep_a_key_leaves_stores_plain_by_default_but_refuses_when_asked_for(default_on, monkeypatch, tmp_path):
    """ASVS V6.4.1 · CWE-1188 · CWE-755: when no key can be kept anywhere, the default keeps stores plain and readable (nothing sealed with a key that would be lost) and says so at start-up; an explicit =1 is an error."""
    blocker = tmp_path / "a-file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("DLP_CHECK_STORE_KEY_FILE", str(blocker / "store_keys.json"))   # its folder is a file: nothing can be written
    _profile("Nokeyco")
    assert '"Nokeyco"' in open(tenant_profiles.store_path(), encoding="utf-8").read()
    said = []
    assert store_crypto.startup(said.append)["status"] == "no_key" and "stay unencrypted" in said[0]
    monkeypatch.setenv(SETTING, "1")
    with pytest.raises(store_crypto.KeyUnavailable):
        store_crypto.seal_text("x")


def test_rotation_still_works_after_the_migration_and_forgets_the_old_key(default_on, monkeypatch):
    """ASVS V6.4.2 · CWE-320 · WSTG-CRYP-04: after the upgrade a rotation re-seals every store with a new key, forgets the old one, and everything still reads."""
    pid = _fill_stores_plain(monkeypatch)
    first = store_crypto.migrate()["key"]
    out = store_crypto.rotate()
    assert out["old_key"] == first and out["new_key"] != first
    assert set(store_crypto._load_ring()["keys"]) == {out["new_key"]}
    _every_store_sealed(out["new_key"])
    _read_everything(pid)


def test_fips_mode_is_unchanged_by_the_default(default_on, monkeypatch):
    """ASVS V6.2.2 · CWE-327: FIPS mode keeps the same approved store algorithm (AES-256-GCM) and the default seals with it."""
    monkeypatch.setenv("DLP_CHECK_FIPS_MODE", "1")
    assert any("AES-256-GCM" in r for r in store_crypto.fips_status()["restricted"])
    sealed = store_crypto.seal_text("fips")
    assert sealed.startswith("ZMEENC1:") and store_crypto.open_text(sealed) == "fips"


# ── where it runs, and what the docs say ────────────────────────────────
def test_the_server_runs_the_migration_before_it_serves():
    """ASVS V14.1.1 · CWE-1188: dlp_api_server.main (the launchers, the container and the no-install edition all start it) runs store_crypto.startup before uvicorn."""
    import inspect
    import dlp_api_server
    src = inspect.getsource(dlp_api_server.main)
    assert "store_crypto.startup(print)" in src and src.index("store_crypto.startup(print)") < src.index("uvicorn.run(")


def test_install_security_and_help_document_the_default_the_opt_out_and_the_key():
    """ASVS V14.1.1 · CWE-1059: INSTALL.md, SECURITY.md and the in-app help say encryption is on by default, how to opt out, and where the key is kept."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    install = open(os.path.join(root, "INSTALL.md"), encoding="utf-8").read()
    security = open(os.path.join(root, "SECURITY.md"), encoding="utf-8").read()
    help_js = open(os.path.join(root, "static", "help_catalog.js"), encoding="utf-8").read()
    for text in (install, security):
        assert "DLP_CHECK_STORE_ENCRYPTION=0" in text and "on by default" in text and "DLP_CHECK_STORE_KEY_FILE" in text
        assert "unseal-all" in text
    assert "Encrypted stores" in install
    assert "on by default" in help_js and "DLP_CHECK_STORE_ENCRYPTION=0" in help_js


def test_the_docs_say_where_the_key_and_any_plain_backup_really_are():
    """ASVS V14.1.1 · CWE-1059 · CWE-312: SECURITY.md says the default Linux and container key sits beside the data (a copy of the folder carries it) and that a stopped migration keeps an unencrypted backup; INSTALL.md notes the macOS Keychain prompt after an update."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sec = " ".join(open(os.path.join(root, "SECURITY.md"), encoding="utf-8").read().split())
    assert "In the default Linux and container setup the key file sits in that same folder or volume" in sec
    assert "A migration that stops keeps an unencrypted backup" in sec and "store-encryption-backup/" in sec
    inst = " ".join(open(os.path.join(root, "INSTALL.md"), encoding="utf-8").read().split())
    assert "Always Allow" in inst and "unencrypted" in inst and "never moved or deleted" in inst
