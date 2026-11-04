"""One store-key change at a time across processes (store_crypto.py): a
rotation, the one-time migration and making the first key hold an OS file
lock in the data folder, so two app processes on one data folder (a second
server, the CLI beside a running server) never change the key at once. The
other process is a real one (a child Python that holds the lock in the
middle of its own rotation); the waiting side's clock and sleep are
injected, so nothing here depends on timing. No network, no credential
store (the key ring is the owner-only key file)."""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

import store_crypto as sc
import tenant_profiles
from test_team_server import team_on, world  # noqa: F401  (team-mode fixtures)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The other process: it starts a rotation (or makes the first key) and stops
# inside it, holding the lock, until it is told to go on.
CHILD = r"""
import sys
sys.modules["keyring"] = None              # the key file, never this machine's credential store
sys.path.insert(0, sys.argv[1])
import store_crypto as sc
mode = sys.argv[2]
if mode == "rotate":
    real = sc._reseal_file
    state = {"paused": False}
    def paused(path, lines, seal):
        if not state["paused"]:
            state["paused"] = True
            print("HOLDING", flush=True)
            sys.stdin.readline()
        return real(path, lines, seal)
    sc._reseal_file = paused
    print("DONE " + sc.rotate()["new_key"], flush=True)
else:
    with sc._exclusive("test"):
        print("HOLDING", flush=True)
        sys.stdin.readline()
        print("DONE " + sc._current(create=True)["current"], flush=True)
"""


@pytest.fixture
def default_on(monkeypatch):
    monkeypatch.delenv("DLP_CHECK_STORE_ENCRYPTION", raising=False)
    monkeypatch.setitem(sc._KEY_PROBLEM, "problem", None)
    monkeypatch.setitem(sys.modules, "keyring", None)


def _child(mode):
    p = subprocess.Popen([sys.executable, "-c", CHILD, ROOT, mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=dict(os.environ), cwd=ROOT)
    line = p.stdout.readline().strip()
    assert line == "HOLDING", (line, p.stderr.read() if p.poll() is not None else "")
    return p


def _finish(p):
    """Let the child go on; its result line."""
    out, err = p.communicate("\n", timeout=60)
    assert p.returncode == 0, err
    return out.strip().split()[-1]


def _sealed_with(path):
    with open(path, encoding="utf-8") as f:
        return sc._key_ids_in(f.read(), False)


@pytest.fixture
def store(default_on):
    """A profile store sealed with the first key: (profile id, store path, first key)."""
    pid = tenant_profiles.upsert({"name": "Lockco", "cloud": "zscalerten", "vanity_domain": "lockco.example", "client_id": "cid-lock"})["id"]
    path = tenant_profiles.store_path()
    first = sc._load_ring()["current"]
    assert _sealed_with(path) == {first}
    return pid, path, first


def test_a_rotation_while_another_process_rotates_is_refused_and_changes_nothing(store, monkeypatch):
    """ASVS V6.4.2 · CWE-362 · CWE-667: while another process is in the middle of a rotation, a second rotation that may not wait stops with StoreBusy before touching the key ring or a store; the first finishes and every store still opens."""
    # Arrange
    pid, path, first = store
    other = _child("rotate")
    try:
        ring_during = sc._load_ring()
        monkeypatch.setattr(sc, "LOCK_WAIT_SECONDS", 0)
        # Act
        with pytest.raises(sc.StoreBusy, match="nothing was changed"):
            sc.rotate()
        # Assert: this process changed nothing while the other held the lock
        assert sc._load_ring() == ring_during and _sealed_with(path) == {first}
    finally:
        theirs = _finish(other)
    assert sc._load_ring() == {"current": theirs, "keys": {theirs: ring_during["keys"][theirs]}}
    assert _sealed_with(path) == {theirs} and tenant_profiles.get(pid)["name"] == "Lockco"


def test_a_second_rotation_waits_for_the_first_then_rotates_from_its_key(store, monkeypatch):
    """ASVS V6.4.2 · CWE-362 · CWE-667: a rotation started while another process rotates waits for it, then rotates from the key that one made: one key in the ring at the end, every store sealed with it and readable."""
    # Arrange
    pid, path, first = store
    other = _child("rotate")
    done = {}

    def wait_once(_seconds):          # the waiting side's sleep: the other process finishes meanwhile
        if "theirs" not in done:
            done["theirs"] = _finish(other)

    monkeypatch.setattr(sc, "_clock", lambda: 0.0)
    monkeypatch.setattr(sc, "_sleep", wait_once)
    try:
        # Act
        out = sc.rotate()
    finally:
        if other.poll() is None:
            _finish(other)
    # Assert
    assert done["theirs"] != first and out["old_key"] == done["theirs"] and out["new_key"] not in (first, done["theirs"])
    assert set(sc._load_ring()["keys"]) == {out["new_key"]} and sc._load_ring()["current"] == out["new_key"]
    assert _sealed_with(path) == {out["new_key"]} and tenant_profiles.get(pid)["name"] == "Lockco"


def test_two_processes_making_the_first_key_end_with_one_key(default_on, monkeypatch):
    """ASVS V6.4.1 · CWE-362 · CWE-321: when two processes start on a data folder with no key, the one that waits uses the key the other made instead of making a second one that would replace it."""
    # Arrange
    assert sc._load_ring()["keys"] == {}
    other = _child("first-key")
    made = {}

    def wait_once(_seconds):
        if "theirs" not in made:
            made["theirs"] = _finish(other)

    monkeypatch.setattr(sc, "_clock", lambda: 0.0)
    monkeypatch.setattr(sc, "_sleep", wait_once)
    try:
        # Act
        ring = sc._current(create=True)
    finally:
        if other.poll() is None:
            _finish(other)
    # Assert
    assert ring["current"] == made["theirs"] and set(sc._load_ring()["keys"]) == {made["theirs"]}
    assert sc.open_text(sc.seal_text("kept")) == "kept"


def test_the_lock_is_free_again_after_a_refusal_and_after_each_change(store, monkeypatch):
    """ASVS V6.4.2 · CWE-667 · CWE-404: the lock is let go after a rotation, a migration run and a refusal, so the next change goes ahead at once."""
    # Arrange
    monkeypatch.setattr(sc, "LOCK_WAIT_SECONDS", 0)
    # Act / Assert
    sc.rotate()
    sc.migrate()
    other = _child("first-key")
    with pytest.raises(sc.StoreBusy):
        sc.rotate()
    _finish(other)
    assert sc.rotate()["new_key"] == sc._load_ring()["current"] and sc._HELD == {"depth": 0, "file": None}


def test_the_rotate_route_answers_409_at_once_while_another_process_rotates(store, world):
    """ASVS V6.4.2 · CWE-362 · WSTG-BUSL-07: on a team server, Rotate the store key while another process rotates is a 409 at once (the server never waits on the lock) and changes nothing."""
    # Arrange
    from test_team_server import _login, _refill
    root = _login("root")
    root.headers["Origin"] = "http://testserver"
    _refill()
    pid, path, first = store
    other = _child("rotate")
    try:
        ring_during = sc._load_ring()
        # Act
        r = root.post("/api/team/store-key/rotate")
        # Assert
        assert r.status_code == 409 and "nothing was changed" in r.json()["detail"], r.text
        assert sc._load_ring() == ring_during and _sealed_with(path) == {first}
    finally:
        theirs = _finish(other)
    assert _sealed_with(path) == {theirs} and tenant_profiles.get(pid)["name"] == "Lockco"
