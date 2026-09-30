"""Whatever works on the local install works in the container, without
fault. The container runs from a read-only app folder with /data as its
only writable place, listens on 0.0.0.0 inside its own network (published
on the host's loopback), and ships without pip. A check of the running
container found features that silently failed or were refused there; these
tests pin each fix."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dockerfile_env() -> dict:
    text = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
    return dict(re.findall(r"^\s+(DLP_CHECK_[A-Z_]+|DLPCHECK_[A-Z_]+|XDG_CACHE_HOME)=(\S+?)\s*\\?$", text, re.M))


def test_every_store_the_app_writes_is_on_the_volume_in_the_container():
    env = _dockerfile_env()
    for var in ("DLP_CHECK_PROFILES", "DLP_CHECK_DEPLOYMENTS", "DLP_CHECK_AUDIT", "DLP_CHECK_UI_TOKEN_DIR", "DLP_CHECK_DIGESTS",
                "DLPCHECK_PROPOSALS_FILE", "DLP_CHECK_GUIDANCE_STATE", "DLP_CHECK_SAAS_MATRIX", "DLP_CHECK_BEACON_STATE",
                "DLP_CHECK_CHECKS_CONFIG", "XDG_CACHE_HOME"):
        assert env.get(var, "").startswith("/data"), (var, env.get(var))


@pytest.mark.parametrize("module, fn, name", [("zscaler_update_check", "_cache_path", "update_cache.json"),
                                              ("bp_crawler", "_cache_path", "bp_crawl_cache.json"),
                                              ("zscaler_best_practices", "_discovered_store_path", "bp_discovered.json")])
def test_the_caches_follow_xdg_cache_home_on_linux(monkeypatch, tmp_path, module, fn, name):
    # In the container HOME is the read-only app folder, so ~/.cache is not
    # writable; XDG_CACHE_HOME (set to /data/cache by the Dockerfile) is.
    import importlib
    mod = importlib.import_module(module)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    path = getattr(mod, fn)()
    assert path.startswith(str(tmp_path)) and path.endswith(name)


def test_approved_references_add_to_the_shipped_config(monkeypatch, tmp_path):
    import guidance
    shipped = tmp_path / "app" / "checks_config.json"
    shipped.parent.mkdir()
    shipped.write_text(json.dumps({"version": 1, "checks": {"A.1": {"references": [{"url": "https://shipped/1"}]}}}))
    monkeypatch.setattr(guidance, "shipped_config_path", lambda: str(shipped))
    local = tmp_path / "data" / "checks_config.json"
    local.parent.mkdir()
    monkeypatch.setenv("DLP_CHECK_CHECKS_CONFIG", str(local))
    before = shipped.read_text()
    guidance.record_approval({"change": {"article": "https://new/2", "checks": ["A.1", "B.2"]}, "evidence": {"article_title": "New"}})
    assert shipped.read_text() == before, "the shipped file is never written where it is read-only"
    urls = [r["url"] for r in guidance.references_for("A.1")]
    assert urls == ["https://shipped/1", "https://new/2"] and [r["url"] for r in guidance.references_for("B.2")] == ["https://new/2"]
    assert guidance.config_summary()["references"] == 3


def test_a_local_install_reads_and_writes_the_one_shipped_file(monkeypatch, tmp_path):
    import guidance
    shipped = tmp_path / "checks_config.json"
    shipped.write_text(json.dumps({"version": 1, "checks": {}}))
    monkeypatch.setattr(guidance, "shipped_config_path", lambda: str(shipped))
    monkeypatch.delenv("DLP_CHECK_CHECKS_CONFIG", raising=False)
    guidance.record_approval({"change": {"article": "https://new/2", "checks": ["A.1"]}, "evidence": {}})
    assert "https://new/2" in shipped.read_text() and [r["url"] for r in guidance.references_for("A.1")] == ["https://new/2"]


def _pack(base, pid, dict_name):
    cfg = base / pid / "configs"
    cfg.mkdir(parents=True)
    (cfg / "dlp_dictionaries.json").write_text(json.dumps([{"name": dict_name}]))
    return base / pid


def test_a_built_in_pack_rebuilt_in_the_library_replaces_the_shipped_one(monkeypatch, tmp_path):
    import dlp_importer
    _pack(tmp_path, "src_pack", "Shipped")
    _pack(tmp_path, "other", "Other")
    rebuilt = _pack(tmp_path / "user_packs", "src_pack", "Rebuilt")   # the library under an explicit root
    packs = {p["id"]: p for p in dlp_importer.discover_packs(str(tmp_path))}
    assert packs["src_pack"]["dir"] == str(rebuilt) and packs["src_pack"]["source"] == "rebuilt"
    assert packs["other"]["source"] == "built-in" and len(packs) == 2, "one entry per id"


def test_a_rebuild_writes_a_library_copy_when_the_pack_folder_is_read_only(monkeypatch, tmp_path):
    import dlp_api_server as srv
    shipped = _pack(tmp_path / "app", "src_pack", "Shipped")
    (shipped / "terraform").mkdir()
    lib = tmp_path / "data_packs"
    monkeypatch.setenv("DLP_CHECK_USER_PACKS", str(lib))
    real_access = os.access
    monkeypatch.setattr(srv.os, "access", lambda p, m: False if str(p).startswith(str(tmp_path / "app")) else real_access(p, m))
    target = srv._writable_pack_dir("src_pack", str(shipped))
    assert target == str(lib / "src_pack") and os.path.isfile(os.path.join(target, "configs", "dlp_dictionaries.json"))
    assert not os.path.exists(os.path.join(target, "terraform")), "its Terraform is regenerated beside it, not copied"
    monkeypatch.setattr(srv.os, "access", real_access)
    assert srv._writable_pack_dir("src_pack", str(shipped)) == str(shipped), "a writable pack folder is used as it is"


def test_rewriting_a_pack_follows_the_same_rule_as_write_mode(monkeypatch):
    import security
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "127.0.0.1")
    assert security.only_this_computer_can_reach() is True
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "0.0.0.0")
    assert security.only_this_computer_can_reach() is False
    src = open(os.path.join(ROOT, "dlp_api_server.py"), encoding="utf-8").read()
    i = src.index("async def dlp_pack_from_tenant")
    assert "_security.only_this_computer_can_reach()" in src[i:i + 2500]


def test_secure_by_design_counts_a_loopback_published_container_as_this_machine_only(monkeypatch):
    import secure_by_design
    import security
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "127.0.0.1")
    checks = secure_by_design.evaluate(None).get("controls") or secure_by_design.evaluate(None).get("checks")
    loop = next(c for c in checks if c.get("id") == "loopback")
    assert loop["status"] == "pass" and "loopback" in loop["evidence"]
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "0.0.0.0")
    checks = secure_by_design.evaluate(None).get("controls") or secure_by_design.evaluate(None).get("checks")
    assert next(c for c in checks if c.get("id") == "loopback")["status"] == "fail"


def _wheel(version):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("zscaler/__init__.py", f'__version__ = "{version}"\n')
    return buf.getvalue()


def test_the_sdk_release_is_fetched_without_pip_and_checked(tmp_path):
    import upstream_check
    whl = _wheel("9.9.9")
    good = hashlib.sha256(whl).hexdigest()

    def getter(sha):
        def get(url):
            if url == "https://pypi.org/pypi/zscaler-sdk-python/9.9.9/json":
                return json.dumps({"urls": [{"packagetype": "bdist_wheel", "filename": "zscaler_sdk_python-9.9.9-py3-none-any.whl",
                                             "url": "https://files.pythonhosted.org/x.whl", "digests": {"sha256": sha}}]}).encode(), 200, ""
            if url == "https://files.pythonhosted.org/x.whl":
                return whl, 200, ""
            return None, 404, ""
        return get
    out, err = upstream_check.download_sdk("9.9.9", str(tmp_path / "ok"), get=getter(good))
    assert not err and open(os.path.join(out, "zscaler", "__init__.py")).read().strip() == '__version__ = "9.9.9"'
    out, err = upstream_check.download_sdk("9.9.9", str(tmp_path / "bad"), get=getter("0" * 64))
    assert out is None and "SHA-256" in err and not os.path.exists(tmp_path / "bad" / "9.9.9")
    src = open(os.path.join(ROOT, "upstream_check.py"), encoding="utf-8").read()
    assert '"pip", "download"' not in src, "the container image has no pip"
    import zscaler_update_check
    assert "files.pythonhosted.org" in zscaler_update_check.ALLOWED_HOSTS


def test_uploaded_packs_use_the_volume_when_the_app_root_is_passed(monkeypatch, tmp_path):
    # The server saves uploads with root=PACKS_ROOT and discovery passes it
    # too; in the container /app is read-only, so the setting must apply.
    import pack_library
    from dlp_importer import PACKS_ROOT
    monkeypatch.setenv("DLP_CHECK_USER_PACKS", str(tmp_path / "vol"))
    assert pack_library.user_packs_dir(PACKS_ROOT) == str(tmp_path / "vol")
    assert pack_library.user_packs_dir() == str(tmp_path / "vol")
    assert pack_library.user_packs_dir(str(tmp_path / "other")) == os.path.join(str(tmp_path / "other"), "user_packs")
