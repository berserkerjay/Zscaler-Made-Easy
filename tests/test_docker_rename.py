"""The Docker names follow the app's name (container and service
zscaler-made-easy, image zscaler-made-easy:local, volume
zscaler-made-easy-data), and an install from before the rename loses
nothing: the update scripts COPY the old data volume into the new one,
keep the old one as a backup, and never start the new container on an
empty volume while old data is uncopied.

Three layers: the script text (both scripts), the shell script run against
a fake `docker` that keeps volumes as folders (no daemon needed, runs
everywhere), and, with ZME_DOCKER_TESTS=1 and a reachable Docker daemon,
the real copy with the real image.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW = "zscaler-made-easy-data"
IMAGE = "zscaler-made-easy:local"
MARKER = ".zscaler-made-easy-moved-from"


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read().replace("\r\n", "\n")


SH, PS = _read("update_container.sh"), _read("update_container.ps1")


# ── The names ─────────────────────────────────────────────────────────

def test_compose_names_the_volume_zscaler_made_easy_data_whatever_the_folder():
    """SSDF PW.9.1 · CWE-1188: compose gives the data volume a fixed name, so it no longer depends on the folder name."""
    yaml = pytest.importorskip("yaml")
    # Arrange
    compose = yaml.safe_load(_read("docker-compose.yml"))
    # Act
    service = compose["services"]["zscaler-made-easy"]
    # Assert
    assert compose["name"] == "zscaler-made-easy"
    assert list(compose["services"]) == ["zscaler-made-easy"]
    assert service["container_name"] == "zscaler-made-easy" and service["image"] == IMAGE
    assert service["volumes"] == [f"{NEW}:/data"]
    assert compose["volumes"] == {NEW: {"name": NEW}}
    assert not compose["volumes"][NEW].get("external"), "compose still manages it (docker compose down -v stays documented)"


def test_compose_keeps_every_hardening_setting_after_the_rename():
    """ASVS V14.1.3 · CWE-250: the rename changes names only; read-only root, cap-drop ALL and no-new-privileges stay."""
    yaml = pytest.importorskip("yaml")
    service = yaml.safe_load(_read("docker-compose.yml"))["services"]["zscaler-made-easy"]
    assert service["read_only"] is True and service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"] and "user" not in service


@pytest.mark.parametrize("rel", ["update_container.sh", "update_container.ps1"])
def test_the_update_scripts_check_and_name_the_new_container(rel):
    """SSDF PW.9.1: "is it running" and the closing hint use the new container name."""
    src = _read(rel)
    assert re.search(r"""(CONTAINER="zscaler-made-easy"|\$Container = 'zscaler-made-easy')""", src)
    assert "docker logs $CONTAINER" in src or "docker logs $Container" in src
    assert "grep -qx dlp-check" not in src and "-contains 'dlp-check'" not in src


# ── The copy, from the script text ────────────────────────────────────

def _commands(src: str):
    """Lines of the script that run something (comments and messages left out)."""
    out = []
    for line in src.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or re.match(r"""^(say|Say)\b""", s):
            continue
        out.append(s)
    return out


@pytest.mark.parametrize("src", [SH, PS], ids=["sh", "ps1"])
def test_the_update_scripts_migrate_by_copy_and_never_delete_or_move_the_old_volume(src):
    """CWE-212 · SSDF PW.9.1 · CISA Secure by Design (fail safe): old data is copied read-only, never moved or deleted."""
    # Arrange
    cmds = "\n".join(_commands(src))
    # Act: every docker volume rm, mv or rm -v in a command line
    removals = re.findall(r"docker volume rm \S+", cmds)
    # Assert
    assert "cp -a /from/. /to/" in src, "the copy keeps owner, modes and timestamps"
    assert re.search(r"OLD_VOLUME\"?:/from:ro|\{old\}:/from:ro", src), "the old volume is mounted read-only for the copy"
    assert removals and all("NEW_VOLUME" in r or "NewVolume" in r for r in removals), removals
    assert not re.search(r"(^|\s)mv\s", cmds) and not re.search(r"Move-Item|Rename-Item", cmds)
    assert not re.search(r"docker (rm|container rm)\s[^\n]*(-v\b|--volumes|-fv\b)", cmds), "removing the old container keeps its volume"
    assert "docker volume prune" not in cmds and "compose down" not in cmds
    assert "kept as a backup" in src and "docker volume rm $c" in src, "one line names the backup and the exact command"


@pytest.mark.parametrize("src", [SH, PS], ids=["sh", "ps1"])
def test_the_copy_runs_as_root_only_in_its_own_locked_down_throwaway_container(src):
    """ASVS V14.1.3 · CWE-250 · CISA Secure by Design (least privilege): root only for the one copy, no network, minimal caps."""
    runs = [c for c in re.split(r"\n(?=\s*(?:if |&& |\$copy = |docker run))", src) if "--user" in c]
    assert runs, "the copy and the check name their user"
    for run in runs:
        for flag in ("--rm", "--network", "none", "--read-only", "ALL", "no-new-privileges:true"):
            assert flag in run, (flag, run[:200])
    assert "--user" not in _read("docker-compose.yml"), "the app's own container is unchanged"
    assert "--privileged" not in src and "SYS_ADMIN" not in src


@pytest.mark.parametrize("src", [SH, PS], ids=["sh", "ps1"])
def test_the_scripts_ask_instead_of_guessing_between_several_old_volumes(src):
    """CWE-20 · CISA Secure by Design (deny by default): with more than one old volume nothing happens until one is named."""
    assert "ZME_OLD_VOLUME" in src and ("--old-volume" in src or "-OldVolume" in src)
    assert "will not guess" in src and ("return 2" in src)


def test_the_copy_happens_after_the_build_and_before_the_new_container_starts():
    """CWE-665 · CISA Secure by Design (fail closed): no start on an empty volume while old data is uncopied."""
    for src, call in ((SH, "migrate_old_data || exit $?"), (PS, "$moved = Move-OldData")):
        build = src.index("docker compose build")
        migrate = src.index(call, build)
        assert src.index("docker compose up -d", migrate) > migrate
        assert "docker compose up -d --build" not in src, "a start that also builds could run before the copy"


# ── The shell script against a fake docker ────────────────────────────

FAKE_DOCKER = r'''
import json, os, shutil, sys
MARKER = ".zscaler-made-easy-moved-from"
state = os.environ["FAKE_DOCKER_STATE"]
vols = os.path.join(state, "volumes")
os.makedirs(vols, exist_ok=True)
cpath = os.path.join(state, "containers.json")
containers = json.load(open(cpath)) if os.path.exists(cpath) else {}
args = sys.argv[1:]
with open(os.path.join(state, "calls"), "a") as f:
    f.write(" ".join(args) + "\n")
def save():
    json.dump(containers, open(cpath, "w"))
def same(a, b):
    def walk(r):
        out = {}
        for d, ds, fs in os.walk(r):
            for n in ds + fs:
                p = os.path.join(d, n)
                out[os.path.relpath(p, r)] = None if os.path.isdir(p) else open(p, "rb").read()
        return out
    return walk(a) == walk(b)
if args[:1] == ["ps"]:
    print("\n".join(n for n, up in containers.items() if up or "-a" in args)); sys.exit(0)
if args[:2] == ["volume", "ls"]:
    print("\n".join(sorted(os.listdir(vols)))); sys.exit(0)
if args[:2] == ["volume", "inspect"]:
    sys.exit(0 if os.path.isdir(os.path.join(vols, args[2])) else 1)
if args[:2] == ["volume", "create"]:
    os.makedirs(os.path.join(vols, args[-1]), exist_ok=True); sys.exit(0)
if args[:2] == ["volume", "rm"]:
    shutil.rmtree(os.path.join(vols, args[2])); sys.exit(0)
if args[:2] == ["image", "inspect"]:
    sys.exit(1 if os.environ.get("FAKE_NO_IMAGE") else 0)
if args[0] in ("stop", "start"):
    containers[args[1]] = args[0] == "start"; save(); sys.exit(0)
if args[0] == "rm":
    containers.pop(args[-1], None); save(); sys.exit(0)
if args[0] == "run":
    mounts, env = {}, {}
    for i, a in enumerate(args):
        if a == "-v":
            name, path = args[i + 1].split(":")[:2]
            mounts[path] = os.path.join(vols, name)
        if a == "-e":
            k, v = args[i + 1].split("=", 1)
            env[k] = v
    code = args[-1]
    if code == "cp -a /from/. /to/":
        if os.environ.get("FAKE_COPY_FAIL"):
            print("cp: cannot create regular file '/to/x': No space left on device", file=sys.stderr); sys.exit(1)
        shutil.copytree(mounts["/from"], mounts["/to"], dirs_exist_ok=True, copy_function=shutil.copy2); sys.exit(0)
    if "os.path.exists('/to/" in code:
        sys.exit(0 if os.path.exists(os.path.join(mounts["/to"], MARKER)) else 1)
    if "os.listdir('/to')" in code:
        sys.exit(0 if not os.listdir(mounts["/to"]) else 1)
    if "open('/to/" in code:
        open(os.path.join(mounts["/to"], MARKER), "w").write(env["ZME_FROM"] + "\n"); sys.exit(0)
    if "st('/from')==st('/to')" in code:
        sys.exit(0 if same(mounts["/from"], mounts["/to"]) else 1)
    sys.exit(3)
sys.exit(0)
'''


@pytest.fixture
def fake(tmp_path):
    """A copy of update_container.sh beside a fake docker whose volumes are folders."""
    bash = shutil.which("bash")
    if not bash or sys.platform.startswith("win"):
        pytest.skip("bash is needed to run the script")
    app, bin_, state = tmp_path / "app", tmp_path / "bin", tmp_path / "state"
    for d in (app, bin_, state / "volumes"):
        d.mkdir(parents=True)
    shutil.copy(os.path.join(ROOT, "update_container.sh"), app / "update_container.sh")
    (bin_ / "docker").write_text(f"#!{sys.executable}\n" + FAKE_DOCKER)
    os.chmod(bin_ / "docker", 0o755)

    class Fake:
        def volume(self, name, files=None):
            root = state / "volumes" / name
            root.mkdir()
            for rel, body in (files or {}).items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(body)
            return root

        def container(self, name, running=True):
            path = state / "containers.json"
            c = json.loads(path.read_text()) if path.exists() else {}
            c[name] = running
            path.write_text(json.dumps(c))

        def containers(self):
            path = state / "containers.json"
            return json.loads(path.read_text()) if path.exists() else {}

        def volumes(self):
            return sorted(os.listdir(state / "volumes"))

        def calls(self):
            p = state / "calls"
            return p.read_text() if p.exists() else ""

        def run(self, *args, **env):
            e = {k: v for k, v in os.environ.items() if k != "ZME_OLD_VOLUME"}
            e.update(PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}", FAKE_DOCKER_STATE=str(state), **env)
            r = subprocess.run([bash, str(app / "update_container.sh"), "--migrate-only", *args],
                               env=e, capture_output=True, text=True, timeout=60)
            return r.returncode, r.stdout + r.stderr

        def tree(self, name):
            """The volume's files, the move's marker left out."""
            root = state / "volumes" / name
            return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*")) if p.is_file() and p.name != MARKER}

        def marker(self, name=NEW):
            p = state / "volumes" / name / MARKER
            return p.read_text() if p.exists() else None

    return Fake()


OLD_FILES = {"tenant_profiles.json": '{"profiles": [{"id": "acme"}]}', "audit.log": "line 1\n",
             "user_packs/custom.json": '{"id": "custom"}'}


def test_the_first_run_copies_the_old_volume_and_keeps_it(fake):
    """CWE-212 · SSDF PW.9.1: every file arrives in the new volume; the old volume and its files stay as they were."""
    # Arrange
    fake.volume("dlp-check_dlpcheck-data", OLD_FILES)
    fake.container("dlp-check")
    # Act
    code, out = fake.run()
    # Assert
    assert code == 0, out
    assert fake.tree(NEW) == fake.tree("dlp-check_dlpcheck-data") == OLD_FILES
    assert fake.marker() == "dlp-check_dlpcheck-data\n", "the new volume records where it was copied from"
    assert fake.marker("dlp-check_dlpcheck-data") is None, "nothing is written to the old volume"
    assert "dlp-check_dlpcheck-data" in fake.volumes(), "the old volume is kept"
    assert "dlp-check" not in fake.containers(), "the old container is removed so port 8001 is free"
    assert "The old volume dlp-check_dlpcheck-data is kept as a backup" in out
    assert "docker volume rm dlp-check_dlpcheck-data" in out
    assert "volume rm dlp-check_dlpcheck-data" not in fake.calls()


def test_a_second_run_copies_nothing(fake):
    """CWE-664 · SSDF PW.9.1: with both volumes present the script is idempotent: no second copy, no new volume."""
    # Arrange
    fake.volume("dlp-check_dlpcheck-data", OLD_FILES)
    assert fake.run()[0] == 0
    first_calls = fake.calls()
    # Act
    code, out = fake.run()
    # Assert
    later = fake.calls()[len(first_calls):]
    assert code == 0 and "Copied" not in out and "copying" not in out
    assert "volume create" not in later and "cp -a" not in later
    assert fake.tree(NEW) == OLD_FILES


def test_the_old_container_alone_is_removed_and_nothing_is_copied_without_old_data(fake):
    """CWE-664: an old compose container (<project>-dlp-check-1) is removed to free the port; no volume is made up."""
    fake.container("dlp-check-dlp-check-1", running=False)
    fake.container("unrelated", running=True)
    code, out = fake.run()
    assert code == 0, out
    assert set(fake.containers()) == {"unrelated"}
    assert fake.volumes() == [] and "volume create" not in fake.calls()


def test_several_old_volumes_stop_the_script_until_one_is_named(fake):
    """CWE-20 · CISA Secure by Design (deny by default): two candidates are listed, nothing is stopped, created or copied."""
    # Arrange
    fake.volume("dlp-check_dlpcheck-data", {"a": "1"})
    fake.volume("zscaler-made-easy_dlpcheck-data", {"b": "2"})
    fake.container("dlp-check")
    # Act
    code, out = fake.run()
    # Assert
    assert code == 2
    assert "dlp-check_dlpcheck-data" in out and "zscaler-made-easy_dlpcheck-data" in out and "--old-volume" in out
    assert NEW not in fake.volumes() and fake.containers() == {"dlp-check": True}
    assert "stop" not in fake.calls() and "rm" not in fake.calls().split()


@pytest.mark.parametrize("how", ["flag", "env"])
def test_the_chosen_old_volume_is_copied(fake, how):
    """CWE-20: --old-volume NAME or ZME_OLD_VOLUME=NAME picks the volume to copy; the other is left alone."""
    fake.volume("dlp-check_dlpcheck-data", {"a": "1"})
    fake.volume("zscaler-made-easy_dlpcheck-data", {"b": "2"})
    pick = "zscaler-made-easy_dlpcheck-data"
    code, out = fake.run("--old-volume", pick) if how == "flag" else fake.run(ZME_OLD_VOLUME=pick)
    assert code == 0, out
    assert fake.tree(NEW) == {"b": "2"} and fake.tree("dlp-check_dlpcheck-data") == {"a": "1"}


def test_a_named_volume_that_does_not_exist_changes_nothing(fake):
    """CWE-20: a mistyped name is refused before anything is touched."""
    fake.volume("dlpcheck-data", {"a": "1"})
    code, out = fake.run("--old-volume", "dlpcheck-dta")
    assert code == 2 and "no volume called dlpcheck-dta" in out and NEW not in fake.volumes()


def test_a_failed_copy_stops_without_an_empty_new_volume_and_restarts_the_old_app(fake):
    """CWE-755 · CISA Secure by Design (fail closed): the copy fails, the script says so, the half volume goes, the old app runs."""
    # Arrange
    fake.volume("dlpcheck-data", OLD_FILES)
    fake.container("dlp-check", running=True)
    # Act
    code, out = fake.run(FAKE_COPY_FAIL="1")
    # Assert
    assert code == 1 and "failed" in out and "NOT started" in out
    assert NEW not in fake.volumes(), "the next run copies afresh instead of finding an empty volume"
    assert fake.tree("dlpcheck-data") == OLD_FILES
    assert fake.containers() == {"dlp-check": True}, "the old container runs as before"


def test_no_image_means_no_copy_and_a_clear_message(fake):
    """CWE-755: without the new image nothing is stopped or created, and the message says how to build it."""
    fake.volume("dlpcheck-data", OLD_FILES)
    fake.container("dlp-check")
    code, out = fake.run(FAKE_NO_IMAGE="1")
    assert code == 1 and "not built yet" in out
    assert NEW not in fake.volumes() and fake.containers() == {"dlp-check": True}


def test_an_empty_new_volume_left_by_an_older_update_script_is_filled(fake):
    """CWE-665 · CISA Secure by Design (fail closed): the old script's compose run made the new volume empty; the copy still happens."""
    # Arrange: what the update before this one leaves (new names, no data in them).
    fake.volume("dlp-check_dlpcheck-data", OLD_FILES)
    fake.volume(NEW)
    fake.container("dlp-check", running=True)
    fake.container("zscaler-made-easy", running=False)
    # Act
    code, out = fake.run()
    # Assert
    assert code == 0, out
    assert fake.tree(NEW) == OLD_FILES and fake.marker() == "dlp-check_dlpcheck-data\n"
    assert fake.tree("dlp-check_dlpcheck-data") == OLD_FILES
    assert "zscaler-made-easy" not in fake.containers(), "the never-started container on the empty volume goes; compose makes it again"


def test_a_new_volume_with_files_it_did_not_copy_is_never_overwritten(fake):
    """CWE-212 · CWE-367 · CISA Secure by Design (fail closed): both volumes hold files and the script did not fill the new one: it stops."""
    # Arrange
    fake.volume("dlp-check_dlpcheck-data", OLD_FILES)
    fake.volume(NEW, {"tenant_profiles.json": '{"profiles": [{"id": "typed-in-later"}]}'})
    fake.container("dlp-check", running=True)
    # Act
    code, out = fake.run()
    # Assert
    assert code == 1 and "copies nothing rather than overwrite anything" in out
    assert fake.tree(NEW) == {"tenant_profiles.json": '{"profiles": [{"id": "typed-in-later"}]}'}
    assert fake.tree("dlp-check_dlpcheck-data") == OLD_FILES and fake.containers() == {"dlp-check": True}
    assert "docker volume rm zscaler-made-easy-data" in out, "the message says how to start the copy over"


def test_a_finished_move_never_asks_which_old_volume(fake):
    """CWE-664: once the new volume carries the marker, extra old volumes do not stop later updates."""
    fake.volume("dlp-check_dlpcheck-data", OLD_FILES)
    assert fake.run()[0] == 0
    fake.volume("zscaler-made-easy_dlpcheck-data", {"b": "2"})
    code, out = fake.run()
    assert code == 0 and "will not guess" not in out and fake.tree(NEW) == OLD_FILES


def test_up_to_date_is_only_up_to_date_when_no_old_data_waits():
    """CWE-665: a running new container on the old script's empty volume does not end the update before the copy."""
    assert '&& ! migration_pending; then' in SH and "-and -not (Test-MigrationPending)" in PS


@pytest.mark.parametrize("name, matched", [
    ("dlpcheck-data", True), ("dlp-check_dlpcheck-data", True), ("zscaler-made-easy_dlpcheck-data", True),
    ("dlpcheck-data-backup", False), ("my-dlpcheck-data", False), (NEW, False), ("_dlpcheck-data", False),
])
def test_old_volume_names_are_recognised_exactly(name, matched):
    """CWE-185: only dlpcheck-data and <project>_dlpcheck-data count as old data volumes."""
    sh_re = re.search(r"OLD_VOLUME_RE='([^']+)'", SH).group(1)
    ps_re = re.search(r"\$OldVolumeRe = '([^']+)'", PS).group(1)
    assert sh_re == ps_re
    assert bool(re.match(sh_re, name)) is matched


@pytest.mark.parametrize("name, matched", [
    ("dlp-check", True), ("dlp-check-dlp-check-1", True), ("zscaler-made-easy-dlp-check-1", True),
    ("zscaler-made-easy", False), ("dlp-check-old", False), ("my-dlp-check", False),
])
def test_old_container_names_are_recognised_exactly(name, matched):
    """CWE-185: only dlp-check and compose's <project>-dlp-check-<n> count as old containers."""
    sh_re = re.search(r"OLD_CONTAINER_RE='([^']+)'", SH).group(1)
    ps_re = re.search(r"\$OldContainerRe = '([^']+)'", PS).group(1)
    assert sh_re == ps_re
    assert bool(re.match(sh_re, name)) is matched


# ── The real thing, with Docker ───────────────────────────────────────

OLD_REAL = "dlp-check_dlpcheck-data"
OLD_CONTAINER_REAL = "zmetest-dlp-check-1"
LIST_PY = ("import hashlib,json,os;r='/v';print(json.dumps({os.path.relpath(os.path.join(d,n),r):"
           "[s.st_mode,s.st_uid,s.st_gid,int(s.st_mtime),None if os.path.isdir(os.path.join(d,n)) else "
           "hashlib.sha256(open(os.path.join(d,n),'rb').read()).hexdigest()] for d,ds,fs in os.walk(r) "
           "for n in ds+fs for s in [os.lstat(os.path.join(d,n))]},sort_keys=True))")


def _docker(*args, check=True):
    r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=1800)
    if check and r.returncode:
        raise AssertionError(f"docker {' '.join(args)}: {r.stderr[-800:]}")
    return r


def _docker_ready() -> str:
    if os.environ.get("ZME_DOCKER_TESTS") != "1":
        return "set ZME_DOCKER_TESTS=1 to run the real migration with Docker"
    if not shutil.which("docker") or not shutil.which("bash"):
        return "docker and bash are needed"
    if subprocess.run(["docker", "info"], capture_output=True).returncode:
        return "the Docker daemon is not reachable"
    vols = _docker("volume", "ls", "-q").stdout.split()
    taken = [v for v in vols if v == NEW or re.match(r"^(dlpcheck-data|.+_dlpcheck-data)$", v)]
    names = _docker("ps", "-a", "--format", "{{.Names}}").stdout.split()
    taken += [n for n in names if re.match(r"^(dlp-check|.+-dlp-check-.+)$", n)]
    if taken:
        return f"this Docker already holds real data or containers the test would touch: {taken}"
    return ""


def _listing(volume: str) -> dict:
    out = _docker("run", "--rm", "--network", "none", "--read-only", "--user", "0", "--cap-drop", "ALL",
                  "--cap-add", "DAC_OVERRIDE", "-v", f"{volume}:/v:ro", "--entrypoint", "python", IMAGE, "-c", LIST_PY).stdout
    return json.loads(out)


_NO_DOCKER = _docker_ready()


@pytest.mark.skipif(bool(_NO_DOCKER), reason=_NO_DOCKER or "Docker is ready")
def test_real_docker_migration_copies_once_and_keeps_the_old_volume(tmp_path):
    """CWE-212 · SSDF PW.8.2 · CISA Secure by Design (fail safe): with real Docker, data arrives intact and the old volume is untouched."""
    created_volumes, created_containers = [], []
    try:
        # Arrange: the image, and an install from before the rename.
        if os.environ.get("ZME_DOCKER_BUILD", "1") == "1":   # 0: use an image built beforehand (behind TLS inspection)
            _docker("build", "-t", IMAGE, ROOT)
        _docker("volume", "create", OLD_REAL); created_volumes.append(OLD_REAL)
        created_volumes.append(NEW)   # the script creates it; the test removes it
        _docker("run", "--rm", "--network", "none", "-v", f"{OLD_REAL}:/data", "--entrypoint", "sh", IMAGE, "-c", textwrap.dedent("""\
            set -e
            echo '{"profiles": [{"id": "acme", "name": "Acme"}]}' > /data/tenant_profiles.json && chmod 600 /data/tenant_profiles.json
            printf 'one\\ntwo\\n' > /data/audit.log && chmod 640 /data/audit.log
            mkdir -p /data/user_packs && echo '{"id": "custom"}' > /data/user_packs/custom.json
            touch -d '2025-01-02 03:04:05' /data/audit.log
            """))
        _docker("create", "--name", OLD_CONTAINER_REAL, "-v", f"{OLD_REAL}:/data", IMAGE); created_containers.append(OLD_CONTAINER_REAL)
        before = _listing(OLD_REAL)
        app = tmp_path / "app"
        app.mkdir()
        shutil.copy(os.path.join(ROOT, "update_container.sh"), app / "update_container.sh")
        env = {k: v for k, v in os.environ.items() if k != "ZME_OLD_VOLUME"}
        # Act
        first = subprocess.run(["bash", str(app / "update_container.sh"), "--migrate-only"], env=env,
                               capture_output=True, text=True, timeout=600)
        after_first = _listing(NEW)
        moved_from = after_first.pop(MARKER, None)
        second = subprocess.run(["bash", str(app / "update_container.sh"), "--migrate-only"], env=env,
                                capture_output=True, text=True, timeout=600)
        # Assert
        assert first.returncode == 0, first.stdout + first.stderr
        assert f"Copied {OLD_REAL} into {NEW}" in first.stdout
        assert f"docker volume rm {OLD_REAL}" in first.stdout
        assert after_first == before, "same files, content, modes, owners and timestamps"
        assert moved_from is not None, "the new volume records the move"
        assert stat.S_IMODE(before["tenant_profiles.json"][0]) == 0o600 and stat.S_IMODE(before["audit.log"][0]) == 0o640
        assert _listing(OLD_REAL) == before, "the old volume is untouched"
        assert OLD_CONTAINER_REAL not in _docker("ps", "-a", "--format", "{{.Names}}").stdout.split()
        assert second.returncode == 0 and "Copied" not in second.stdout and "copying" not in second.stdout
        after_second = _listing(NEW)
        assert after_second.pop(MARKER, None) == moved_from and after_second == before, "the second run changed nothing"
    finally:
        for c in created_containers:
            _docker("rm", "-f", c, check=False)
        for v in created_volumes:
            _docker("volume", "rm", v, check=False)
