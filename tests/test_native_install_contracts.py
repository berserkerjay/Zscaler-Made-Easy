"""Cross-platform delivery contracts, plus actual local Terraform discovery.

Real installers/lifecycles are executed by tools/verify_native_install.py.
These tests protect edge conditions without launching tenant-connected services.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def text(name):
    return (ROOT / name).read_text(encoding='utf-8')


def test_unix_loads_proxy_and_ca_before_the_first_download():
    script = text('install.sh')
    first_pip = script.index('"$VPY" -m pip install')
    assert script.index('. ./local_settings.env') < first_pip
    assert script.index('export PIP_CERT="$REQUESTS_CA_BUNDLE"') < first_pip
    assert '--upgrade pip' not in script, 'No unpinned network bootstrap before corporate settings'


def test_windows_installs_both_dependencies_and_commands_into_private_environment():
    script = text('INSTALL_Zscaler_Made_Easy.bat')
    private = script.index('set "PYTHON_EXE=%INSTALL_DIR%\\.venv\\Scripts\\python.exe"')
    assert script.index('-m venv') < private < script.index('--require-hashes')
    assert '--no-deps --no-build-isolation -e "%INSTALL_DIR%"' in script
    assert '-m pip --version' in script and 'goto :makevenv' in script


@pytest.mark.parametrize('script', ['START_Zscaler_Made_Easy.bat', 'START_Zscaler_Made_Easy_WRITES_ENABLED.bat', 'UPDATE_Zscaler_Made_Easy.bat'])
def test_all_windows_server_paths_prefer_the_apps_interpreter(script):
    source = text(script)
    assert source.index('.venv\\Scripts\\python.exe') < source.index('where python')
    assert 'if not defined PYTHON_EXE set "PYTHON_EXE=%%i"' in source


def test_silent_shortcut_loads_settings_before_selecting_port():
    script = text('START_Zscaler_Made_Easy.vbs')
    assert script.index('call """ & dir & "\\local_settings.bat') < script.index('port = sh.ExpandEnvironmentStrings')
    assert 'DLPCHECK_SETTINGS_LOADED' in script
    assert 'sh.Environment("PROCESS")("DLPCHECK_SETTINGS_LOADED") = ""' in script
    assert 'extra = " /restart"' in script
    assert 'ZSCALER_OPEN_BROWSER' in script


@pytest.mark.parametrize('name', ['INSTALL_Zscaler_Made_Easy.bat', 'UPDATE_Zscaler_Made_Easy.bat'])
def test_shortcuts_do_not_embed_the_install_path_as_powershell_source(name):
    script = text(name)
    shortcut_lines = [line for line in script.splitlines() if 'CreateShortcut' in line]
    assert len(shortcut_lines) == 2
    for line in shortcut_lines:
        assert '$env:INSTALL_DIR' in line
        assert '%INSTALL_DIR%' not in line, 'An apostrophe in the user folder must not break PowerShell quoting'


@pytest.mark.parametrize('name', ['START_Zscaler_Made_Easy.bat', 'START_Zscaler_Made_Easy_WRITES_ENABLED.bat'])
def test_console_launchers_use_the_servers_authenticated_browser_url(name):
    script = text(name)
    assert 'ZSCALER_OPEN_BROWSER' in script
    assert '&& start http://localhost:' not in script


def test_python_override_exists_on_both_installer_platforms():
    for name in ('install.sh', 'INSTALL_Zscaler_Made_Easy.bat'):
        assert 'DLP_CHECK_PYTHON' in text(name)
        assert 'sys.version_info >= (3, 11)' in text(name)


def test_workflow_requires_native_platforms_and_installer_results():
    workflow = text('.github/workflows/native-install.yml')
    for target in ('ubuntu-24.04', 'macos-15', 'macos-15-intel', 'windows-2025'):
        assert target in workflow
    assert 'fail-fast: false' in workflow
    assert 'python tools/verify_native_install.py' in workflow
    assert '--working-tree' not in workflow
    assert 'if: always()' in workflow and 'if-no-files-found: error' in workflow


def test_terraform_absent_is_reported_without_installing_or_contacting_anyone(monkeypatch):
    import upstream_check
    monkeypatch.setenv('PATH', '')
    def forbidden(*args, **kwargs):
        pytest.fail('Missing Terraform must not execute or install anything')
    monkeypatch.setattr(upstream_check.subprocess, 'run', forbidden)
    assert upstream_check.provider_schema() == (None, 'terraform is not installed')


def test_real_native_terraform_can_read_and_format_the_committed_workspaces(tmp_path):
    terraform = shutil.which('terraform')
    if not terraform:
        if os.environ.get('NATIVE_REQUIRE_TERRAFORM') == '1':
            pytest.fail('Native CI requires the pinned Terraform binary')
        pytest.skip('Terraform is not installed on this optional local test machine')
    version = subprocess.run([terraform, 'version', '-json'], capture_output=True, text=True, check=True)
    assert json.loads(version.stdout)['terraform_version']
    result = subprocess.run([terraform, 'fmt', '-check', '-recursive', '-diff', str(ROOT / 'terraform')], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_native_subprocess_guard_rejects_remote_dns_before_resolution(tmp_path):
    marker, log = tmp_path / 'guard', tmp_path / 'blocked.jsonl'
    env = os.environ.copy()
    env.update(PYTHONPATH=str(ROOT / 'tests/native_support'), NATIVE_GUARD_MARKER=str(marker), NATIVE_EGRESS_LOG=str(log))
    result = subprocess.run([sys.executable, '-c', "import socket; socket.getaddrinfo('unreachable.invalid', 443)"], env=env, capture_output=True, text=True)
    assert result.returncode != 0 and 'permits loopback only' in result.stderr
    assert marker.read_text().strip() == 'loopback-only'
    assert json.loads(log.read_text())['blocked_host'] == 'unreachable.invalid'


def test_browser_discovery_supports_standard_windows_and_mac_installations(monkeypatch):
    spec = importlib.util.spec_from_file_location('native_browser_driver', ROOT / 'tests/test_flow_browser_acceptance.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.delenv('CHROME_BIN', raising=False)
    monkeypatch.setattr(module.shutil, 'which', lambda name: None)
    for expected in ('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', 'C:/Program Files/Google/Chrome/Application/chrome.exe'):
        monkeypatch.setenv('PROGRAMFILES', 'C:/Program Files')
        monkeypatch.setattr(module.Path, 'is_file', lambda self: str(self).replace('\\', '/') == expected)
        assert module._chrome().replace('\\', '/') == expected


def test_windows_batch_driver_preserves_cmd_quoting(monkeypatch):
    spec = importlib.util.spec_from_file_location('native_install_driver', ROOT / 'tools/verify_native_install.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv('COMSPEC', r'C:\Windows\System32\cmd.exe')
    command = module.batch(r'C:\test folder\START.bat', '--console')
    assert command == '\"C:\\Windows\\System32\\cmd.exe\" /d /s /c \"\"C:\\test folder\\START.bat\" --console\"'


def test_native_driver_preserves_healthy_environment_and_checks_default_discovery():
    driver = text('tools/verify_native_install.py')
    assert "env.pop('DLP_CHECK_PYTHON', None)" in driver
    assert "sentinel.read_text(encoding='utf-8') == 'preserve healthy environment'" in driver
    assert "os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'" in driver
    assert driver.index('parser.error(') < driver.index("artifacts = Path(args.artifacts)")


def test_native_driver_preserves_timeout_diagnostics(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('native_install_timeout_driver', ROOT / 'tools/verify_native_install.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('synthetic command', 2, output=b'progress', stderr=b'error detail')
    monkeypatch.setattr(module.subprocess, 'run', timeout)
    log = tmp_path / 'timeout.log'
    with pytest.raises(subprocess.TimeoutExpired):
        module.run(['synthetic command'], tmp_path, {}, log, timeout=2)
    assert log.read_text() == 'progress\nerror detail\nTimed out after 2 seconds\n'


def test_native_lifecycle_fails_if_runtime_attempts_remote_networking():
    driver = text('tools/verify_native_install.py')
    assert "assert not egress.exists() or not egress.read_text().strip()" in driver


def test_windows_stop_reports_kill_result_not_headless_cosmetic_timeout():
    script = text('STOP_Zscaler_Made_Easy.bat')
    assert 'set "STOP_FAILED=0"' in script
    assert 'set "STOP_FAILED=1"' in script
    assert 'if not defined DLPCHECK_STOPPED_%%a' in script
    assert script.rstrip().endswith('exit /b %STOP_FAILED%')
    assert 'timeout /t 2 >nul 2>&1' in script
    assert text('UPDATE_Zscaler_Made_Easy.bat').rstrip().endswith('exit /b 0')


@pytest.mark.parametrize('name', ['STOP_Zscaler_Made_Easy.bat', 'UPDATE_Zscaler_Made_Easy.bat', 'UNINSTALL_Zscaler_Made_Easy.bat'])
def test_windows_lifecycle_matches_the_exact_port_not_a_prefix(name):
    script = text(name)
    assert 'findstr /C:":%ZSCALER_PORT% "' in script
    assert 'findstr ":%ZSCALER_PORT%"' not in script


def test_incomplete_active_environment_is_not_deleted_by_its_own_interpreter():
    unix, windows = text('install.sh'), text('INSTALL_Zscaler_Made_Easy.bat')
    assert unix.index('Run deactivate') < unix.index('rm -rf .venv')
    assert windows.index('goto :activebrokenvenv') < windows.index('rmdir /s /q')
    assert 'The environment has not been deleted.' in windows
    assert 'is_relative_to' in unix and 'is_relative_to' in windows


@pytest.mark.skipif(os.name != 'nt', reason='Requires the actual native Windows findstr executable')
def test_real_windows_findstr_distinguishes_port_808_from_8080():
    lines = '  TCP    127.0.0.1:8080    0.0.0.0:0    LISTENING    111\n  TCP    127.0.0.1:808    0.0.0.0:0    LISTENING    222\n'
    result = subprocess.run(['findstr', '/C::808 '], input=lines, capture_output=True, text=True)
    assert result.returncode == 0
    assert ':808 ' in result.stdout and ':8080 ' not in result.stdout


def test_native_auth_smoke_uses_a_local_protected_route_not_online_update_status():
    driver = text('tools/verify_native_install.py')
    assert "request(base, '/api/health'" not in driver
    assert "request(base, '/api/dlp-packs')[0] == 401" in driver
    assert "request(base, '/api/dlp-packs', 'invalid-token')[0] == 401" in driver
    assert "request(base, '/api/dlp-packs', token)[0] == 200" in driver


def test_installed_source_probe_uses_filesystem_identity_for_windows_short_paths():
    driver = text('tools/verify_native_install.py')
    assert 'pathlib.Path(dlp_api_server.__file__).resolve().parent.samefile(pathlib.Path.cwd())' in driver
    assert "app = (work / f'{mode} install with spaces').resolve()" in driver


@pytest.mark.parametrize('name', ['INSTALL_Zscaler_Made_Easy.bat', 'UPDATE_Zscaler_Made_Easy.bat'])
def test_shortcuts_are_made_as_zscaler_made_easy_and_replace_the_old_name(name):
    lines = [line for line in text(name).splitlines() if 'CreateShortcut' in line]
    assert [("'Desktop'" in l, "'Programs'" in l) for l in lines] == [(True, False), (False, True)]
    for line in lines:
        assert line.count('"') == 2 and line.startswith('powershell -NoProfile -Command "') and line.split('"')[2] in ('', ' >nul 2>&1'), \
            'one cmd-quoted PowerShell command: no inner double quote for cmd to pair up'
        assert '%' not in line, 'cmd would expand it'
        assert "$new = Join-Path " in line and "'Zscaler Made Easy.lnk'" in line and '$ws.CreateShortcut($new)' in line
        assert "(Join-Path $app 'START_Zscaler_Made_Easy.vbs')" in line
        removal = "if (Test-Path -LiteralPath $new) { Remove-Item -LiteralPath (Join-Path "
        assert line.index('$lnk.Save()') < line.index(removal) and "'Zscaler Assessment.lnk') -ErrorAction SilentlyContinue }" in line, \
            'the old shortcut goes only once the new one exists'


def test_installer_reports_the_new_shortcut_name():
    script = text('INSTALL_Zscaler_Made_Easy.bat')
    assert 'set "SHORTCUT_NOTE=Desktop shortcut: "Zscaler Made Easy""' in script
    assert "GetFolderPath('Desktop')) 'Zscaler Made Easy.lnk')) { exit 0 }" in script


def test_uninstall_removes_the_shortcut_under_both_names_in_both_folders():
    script = text('UNINSTALL_Zscaler_Made_Easy.bat')
    both = "foreach ($name in 'Zscaler Made Easy.lnk', 'Zscaler Assessment.lnk') { Remove-Item -LiteralPath (Join-Path $%s $name) -ErrorAction SilentlyContinue };"
    for var, folder in (('desktop', 'Desktop'), ('start', 'Programs')):
        assert f"\"${var} = [Environment]::GetFolderPath('{folder}');\" ^" in script
        assert both % var in script


def test_launchers_point_at_each_other_by_their_new_names():
    assert 'start "" wscript.exe "%~dp0START_Zscaler_Made_Easy.vbs"' in text('START_Zscaler_Made_Easy.bat')
    assert 'dir & "\\START_Zscaler_Made_Easy.bat""' in text('START_Zscaler_Made_Easy.vbs')
    assert text('UPDATE_Zscaler_Made_Easy.bat').count('wscript.exe "%INSTALL_DIR%\\START_Zscaler_Made_Easy.vbs"') == 1
