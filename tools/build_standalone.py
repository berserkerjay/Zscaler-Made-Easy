#!/usr/bin/env python3
"""Build the standalone (no-install) edition with PyInstaller.

    python tools/build_standalone.py [--version v3.1.0] [--out dist/standalone]

Run it from a checkout, in a Python 3.11 environment installed from the
hash-pinned locks only:

    python -m pip install --require-hashes --no-deps -r requirements-pip.lock
    pip install --require-hashes --no-deps -r requirements.lock
    pip install --require-hashes --no-deps -r requirements-ci.lock   # PyInstaller

It freezes standalone_main.py into one folder for the operating system and
processor it runs on (PyInstaller does not cross-compile; the release
workflow, .github/workflows/release-standalone.yml, runs it once per
platform) and packs that folder into one archive:

    ZscalerMadeEasy-<version>-<windows-x64|macos-arm64|macos-x64|linux-x64>.<zip|tar.gz>

with <archive>.sha256 beside it. What goes in the bundle is fixed by one
rule: the files git tracks at this commit (bundle_files), never anything
else in the folder. Local state that git ignores (tenant profiles with
remembered secrets, the UI token, audit log, local_settings.env, ...) can
then never be shipped, and a tracked file with one of those names stops the
build (fail closed). The bundle also carries the licence texts of what it
redistributes: LICENSE, THIRD_PARTY_NOTICES.md, third_party_licenses/ and
the CPython licence of the interpreter it embeds.

Code signing is optional and only happens when the release workflow has the
signing secrets (macOS: STANDALONE_CODESIGN_IDENTITY names a Developer ID
identity already in the keychain; Windows signs the .exe after this script).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from typing import Dict, Iterable, List, Optional, Sequence

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAME = "ZscalerMadeEasy"
ENTRY = "standalone_main.py"
BUILD_INFO_FILE = "standalone_build.json"

# Files that hold secrets, customer data or machine state when they exist
# in an app folder. git ignores them (.gitignore); if one is ever tracked,
# the build stops instead of shipping it to every download.
FORBIDDEN_NAMES = re.compile(
    r"(^|/)(tenant_config\.json|tenant_profiles\.json|ui_token\.txt|local_settings\.(env|bat)|audit\.log(\..*)?"
    r"|deployments\.json|proposals\.json|change_requests\.json|workspace_notes\.json|posture_settings\.json"
    r"|guidance_state\.json|self_heal\.json|zia_rate_state\.json.*|tenant_fingerprint\.key|server\.(log|pid)"
    r"|launcher\.log|saas_apps\.local\.json|\.env|.*\.(pem|key|p12|pfx|crt|cer))$")
# Folders git tracks that the running app never reads and that hold no
# runtime resource (agent instructions for contributors).
SKIP_PREFIXES = (".agents/",)
# The install, start, update and stop scripts of the other editions: they
# need Python or Docker and would only mislead inside this bundle.
SKIP_LAUNCHERS = re.compile(r"^[^/]+\.(bat|vbs|sh|ps1)$")
# Modules that are never needed at run time and are large.
EXCLUDE_MODULES = ("tkinter", "pytest", "_pytest", "pyflakes", "IPython", "matplotlib", "PyInstaller")


def tracked_files(root: str = ROOT) -> List[str]:
    """The files git tracks in root (forward slashes), from the index."""
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True, capture_output=True).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


def forbidden(paths: Iterable[str]) -> List[str]:
    return [p for p in paths if FORBIDDEN_NAMES.search(p.replace("\\", "/"))]


def bundle_files(tracked: Sequence[str]) -> List[str]:
    """The tracked files that go into the bundle, at the same relative
    paths (the app finds them beside its modules, as in a checkout).
    Raises ValueError when a tracked file must never ship."""
    bad = forbidden(tracked)
    if bad:
        raise ValueError("refusing to bundle files that hold secrets or local state: " + ", ".join(bad))
    return [p for p in tracked if not p.startswith(SKIP_PREFIXES) and not SKIP_LAUNCHERS.match(p)]


def py_modules(root: str = ROOT) -> List[str]:
    """pyproject.toml's py-modules: the app's own top-level modules. Several
    are loaded by file path or imported inside functions, which
    PyInstaller's import scan cannot see, so all of them are named."""
    import tomllib
    with open(os.path.join(root, "pyproject.toml"), "rb") as f:
        return list(tomllib.load(f)["tool"]["setuptools"]["py-modules"])


def platform_label(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    os_name = {"windows": "windows", "darwin": "macos", "linux": "linux"}.get(system)
    arch = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if not os_name or not arch:
        raise ValueError(f"unsupported build platform {system}/{machine}")
    return f"{os_name}-{arch}"


def safe_version(raw: str) -> str:
    """A version string that is safe in a file name (tags like v3.1.0)."""
    v = re.sub(r"[^A-Za-z0-9._-]+", "-", (raw or "").strip()).strip("-.")
    if not v:
        raise ValueError("empty version")
    return v[:64]


def python_licence() -> Optional[str]:
    """The licence file of the CPython this build embeds."""
    for p in (os.path.join(sys.base_prefix, "LICENSE.txt"),
              os.path.join(sys.base_prefix, "lib", f"python{sys.version_info[0]}.{sys.version_info[1]}", "LICENSE.txt"),
              os.path.join(sys.base_prefix, "Resources", "LICENSE.txt")):
        if os.path.isfile(p):
            return p
    return None


README = """Zscaler Made Easy, standalone edition ({version}, {label})
=============================================================

Nothing to install: no Python, no virtual environment, no administrator rights.

Before the first start, check the download (INSTALL.md, "Download and run"):
  1. Its SHA-256 matches the .sha256 file and the release's SHA256SUMS.txt.
  2. GitHub vouches that it was built from this repository by its release
     workflow:  gh attestation verify <archive> --repo <owner>/<repository>
{signing}
Start it: open this folder and double-click {exe}. A console window shows
the address and the UI token, and your browser opens the app. Keep the
window open while you use it; close it (or press Ctrl+C) to stop.

Secure defaults that cannot be switched off in this edition: the app listens
on 127.0.0.1 only (this computer), asks every browser for the UI token, and
starts read-only (writing to a tenant needs write mode and its confirmations).

Your data (tenant profiles, audit log, settings) is kept in your per-user
data folder, not here, so a new version can replace this folder:
  Windows  %LOCALAPPDATA%\\ZscalerMadeEasy
  macOS    ~/Library/Caches/ZscalerMadeEasy
  Linux    ~/.cache/zscaler_made_easy
Proxy and corporate root certificate settings go in local_settings.env in
that folder (KEY=VALUE lines, e.g. REQUESTS_CA_BUNDLE=/path/to/root-ca.pem).

Built from commit {commit}. Licences: _internal/LICENSE, _internal/THIRD_PARTY_NOTICES.md,
_internal/third_party_licenses/ and _internal/PYTHON_LICENSE.txt.
"""
SIGNED_NOTE = "  The program is code-signed{notarized}; your system checks the signature itself.\n"
UNSIGNED_NOTE = ("  This build is NOT code-signed. Windows SmartScreen or macOS Gatekeeper will\n"
                 "  warn on the first start; allow it only after steps 1 and 2 succeed\n"
                 "  (INSTALL.md says how, without turning those protections off).\n")


def pyinstaller_args(files: Sequence[str], modules: Sequence[str], staging: str, dist: str, work: str,
                     codesign_identity: str = "", entitlements: str = "") -> List[str]:
    """The PyInstaller command line (without the program name)."""
    sep = os.pathsep
    args = [os.path.join(ROOT, ENTRY), "--name", NAME, "--onedir", "--console", "--noconfirm", "--clean",
            "--distpath", dist, "--workpath", work, "--specpath", work,
            "--paths", ROOT, "--collect-submodules", "zscaler", "--collect-data", "zscaler"]
    for m in modules:
        args += ["--hidden-import", m]
    for m in EXCLUDE_MODULES:
        args += ["--exclude-module", m]
    for rel in files:
        dest = os.path.dirname(rel) or "."
        args += ["--add-data", f"{os.path.join(ROOT, *rel.split('/'))}{sep}{dest}"]
    for name in os.listdir(staging):
        args += ["--add-data", f"{os.path.join(staging, name)}{sep}."]
    if codesign_identity:
        args += ["--codesign-identity", codesign_identity]
        if entitlements:
            args += ["--osx-entitlements-file", entitlements]
    return args


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_archive(folder: str, archive_base: str, label: str) -> str:
    """Pack folder as <archive_base>.zip (Windows) or .tar.gz (keeps the
    executable bit and symbolic links on macOS and Linux), with the
    folder's name as the single top-level entry."""
    parent, top = os.path.split(folder.rstrip(os.sep))
    if label.startswith("windows"):
        path = archive_base + ".zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for dirpath, dirnames, filenames in os.walk(folder):
                dirnames.sort()
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    z.write(full, os.path.relpath(full, parent))
        return path
    path = archive_base + ".tar.gz"
    with tarfile.open(path, "w:gz", compresslevel=9) as t:
        t.add(folder, arcname=top, filter=_tar_owner)
    return path


def _tar_owner(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def build(version: str, out: str, commit: str, ref: str, signed: bool, notarized: bool,
          codesign_identity: str = "", entitlements: str = "") -> Dict[str, str]:
    import PyInstaller.__main__  # from requirements-ci.lock (hash-pinned)

    label = platform_label()
    version = safe_version(version)
    files = bundle_files(tracked_files())
    work = os.path.join(out, "work")
    dist = os.path.join(out, "dist")
    for d in (work, dist):
        shutil.rmtree(d, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="standalone-staging-") as staging:
        with open(os.path.join(staging, BUILD_INFO_FILE), "w", encoding="utf-8") as f:
            json.dump({"version": version, "commit": commit, "ref": ref, "platform": label, "signed": signed}, f)
        lic = python_licence()
        if lic:
            shutil.copyfile(lic, os.path.join(staging, "PYTHON_LICENSE.txt"))
        else:
            print("warning: the CPython licence file was not found; the bundle will not carry it", file=sys.stderr)
        PyInstaller.__main__.run(pyinstaller_args(files, py_modules(), staging, dist, work, codesign_identity, entitlements))
    folder = os.path.join(dist, NAME)
    exe = NAME + (".exe" if label.startswith("windows") else "")
    if not os.path.isfile(os.path.join(folder, exe)):
        raise SystemExit(f"PyInstaller did not produce {exe}")
    signing = SIGNED_NOTE.format(notarized=" and notarized by Apple" if notarized else "") if signed else UNSIGNED_NOTE
    with open(os.path.join(folder, "README-standalone.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(README.format(version=version, label=label, signing=signing, exe=exe, commit=commit or "unknown"))
    top = f"{NAME}-{version}-{label}"
    final = os.path.join(dist, top)
    shutil.rmtree(final, ignore_errors=True)
    os.rename(folder, final)
    return {"folder": final, "exe": os.path.join(final, exe), "label": label, "top": top}


def package(folder: str, out: str, label: str, top: str) -> Dict[str, str]:
    os.makedirs(out, exist_ok=True)
    archive = make_archive(folder, os.path.join(out, top), label)
    digest = sha256_file(archive)
    with open(archive + ".sha256", "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{digest}  {os.path.basename(archive)}\n")
    return {"archive": archive, "sha256": digest}


def _git_out(*args: str) -> str:
    try:
        return subprocess.run(["git", "-C", ROOT, *args], check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", default=os.environ.get("STANDALONE_VERSION") or "")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist", "standalone"))
    ap.add_argument("--build-only", action="store_true", help="build the folder, do not archive it (signing runs between the two)")
    ap.add_argument("--package-only", metavar="FOLDER", help="archive an already built (and signed) folder")
    ap.add_argument("--signed", action="store_true", help="say in the README that the build is code-signed")
    ap.add_argument("--notarized", action="store_true")
    a = ap.parse_args(argv)
    out = os.path.abspath(a.out)
    if a.package_only:
        folder = os.path.abspath(a.package_only)
        top = os.path.basename(folder.rstrip(os.sep))
        res = package(folder, out, platform_label(), top)
        print(json.dumps(res))
        return 0
    commit = _git_out("rev-parse", "--short=12", "HEAD")
    ref = os.environ.get("GITHUB_REF_NAME") or _git_out("rev-parse", "--abbrev-ref", "HEAD")
    version = a.version or f"dev-{commit or 'unknown'}"
    res = build(version, out, commit, ref, a.signed, a.notarized,
                os.environ.get("STANDALONE_CODESIGN_IDENTITY", ""), os.environ.get("STANDALONE_ENTITLEMENTS", ""))
    if not a.build_only:
        res.update(package(res["folder"], out, res["label"], res["top"]))
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
