"""Both delivery modes are built from this one source tree: the local
installer (install.sh / the Windows .bat files) and the container
(Dockerfile, docker-compose.yml). These tests keep them in step: the
same pinned dependency file, the same entry point, every module listed
for the package, and shell scripts that parse."""
from __future__ import annotations

import glob
import os
import re
import subprocess
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def test_pyproject_lists_every_top_level_module_and_the_entry_points():
    meta = tomllib.loads(_read("pyproject.toml"))
    modules = set(meta["tool"]["setuptools"]["py-modules"])
    on_disk = {os.path.basename(p)[:-3] for p in glob.glob(os.path.join(ROOT, "*.py"))}
    assert modules == on_disk, {"missing from pyproject": sorted(on_disk - modules), "not on disk": sorted(modules - on_disk)}
    scripts = meta["project"]["scripts"]
    assert scripts["dlp-check"] == "dlp_api_server:main" and scripts["dlp-check-assess"] == "dlp_assessment_full_auto:main"
    import dlp_api_server, dlp_assessment_full_auto, continuous_eval
    assert callable(dlp_api_server.main) and callable(dlp_assessment_full_auto.main) and callable(continuous_eval.main)
    assert meta["project"]["requires-python"] == ">=3.11"


def test_pyproject_dependencies_match_requirements_txt():
    meta = tomllib.loads(_read("pyproject.toml"))
    wanted = {re.split(r"[<>=!~]", d)[0].strip().lower() for d in meta["project"]["dependencies"]}
    listed = {re.split(r"[<>=!~]", l)[0].strip().lower() for l in _read("requirements.txt").splitlines() if l.strip() and not l.startswith("#")}
    assert wanted == listed, {"only in pyproject": sorted(wanted - listed), "only in requirements.txt": sorted(listed - wanted)}


def test_installer_and_container_install_the_same_pinned_file_and_run_the_same_entry_point():
    dockerfile = _read("Dockerfile")
    assert "requirements.lock" in dockerfile and "--require-hashes" in dockerfile
    assert 'CMD ["python", "dlp_api_server.py"]' in dockerfile
    assert "requirements.lock" in _read("install.sh") and "--require-hashes" in _read("install.sh")
    assert "requirements.lock" in _read("INSTALL_Zscaler_Assessment.bat") and "--require-hashes" in _read("INSTALL_Zscaler_Assessment.bat")
    assert "dlp_api_server.py" in _read("start.sh") and "dlp_api_server.py" in _read("START_Zscaler_Assessment.bat")
    compose = _read("docker-compose.yml")
    assert "build: ." in compose and "127.0.0.1:8000:8000" in compose and "read_only: true" in compose


def test_shell_scripts_parse_and_are_executable():
    for name in ("install.sh", "start.sh", "stop.sh"):
        path = os.path.join(ROOT, name)
        r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        assert r.returncode == 0, (name, r.stderr)
        assert os.access(path, os.X_OK) or sys.platform.startswith("win"), f"{name} is not executable (chmod +x)"


def test_secret_and_state_files_never_reach_the_image_or_the_repository():
    dockerignore = _read(".dockerignore").split()
    gitignore = _read(".gitignore")
    for name in ("tenant_config.json", "tenant_profiles.json", "deployments.json", "ui_token.txt", ".env"):
        assert name in dockerignore, f"{name} would be copied into the image"
    for name in ("tenant_config.json", "tenant_profiles.json", "local_settings.env", "*.log", ".venv/"):
        assert name in gitignore, f"{name} is not git-ignored"
    assert os.path.exists(os.path.join(ROOT, "local_settings.env.example"))
