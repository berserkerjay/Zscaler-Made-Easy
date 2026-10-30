#!/usr/bin/env python3
"""Run the documented native installers in disposable Git and ZIP copies.

This is deliberately an integration driver, not a mocked installer test. All
runtime requests stay on loopback; installation fetches only the hash-locked
public dependencies. No credentials, live tenant, or user's installation is used.
CI records the exact source commit, platform, interpreter, and individual cases.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = os.name == 'nt'


def clean_env():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('ZSCALER_', 'ZIA_', 'ZPA_', 'ZCC_', 'ZDX_', 'DLP_CHECK_', 'DLPCHECK_', 'ENABLE_WRITE_'))}
    env.update(PYTHONUTF8='1', PYTHONUNBUFFERED='1', PYTHONDONTWRITEBYTECODE='1',
               DLP_CHECK_PYTHON=sys.executable, PIP_DISABLE_PIP_VERSION_CHECK='1')
    return env


def run(command, cwd, env, log, timeout=600, success=True):
    args = command if isinstance(command, str) else [str(x) for x in command]
    try:
        cp = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        def decoded(value):
            return value.decode('utf-8', 'replace') if isinstance(value, bytes) else (value or '')
        log.write_text(decoded(error.stdout) + '\n' + decoded(error.stderr) + f'\nTimed out after {timeout} seconds\n', encoding='utf-8')
        raise
    log.write_text(cp.stdout + '\n' + cp.stderr, encoding='utf-8')
    if success and cp.returncode:
        raise AssertionError(f'{command[0]} returned {cp.returncode}; see {log}\n{cp.stdout[-3000:]}\n{cp.stderr[-3000:]}')
    return cp


def batch(path, *args):
    # cmd.exe does not use the CRT argv quoting that Python applies to a
    # list. Pass its complete command line unchanged, with /s /c's outer
    # pair enclosing the quoted batch path. Inputs are our fixture paths.
    comspec = os.environ.get('COMSPEC', 'cmd.exe')
    inner = subprocess.list2cmdline([str(path), *args])
    return f'"{comspec}" /d /s /c "{inner}"'


def available_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def request(base, route, token='', data=None):
    headers = {'X-DLP-Check-Token': token} if token else {}
    if data is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(data).encode()
    req = urllib.request.Request(base + route, headers=headers, data=data)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=3) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def wait_server(base, up=True):
    until = time.monotonic() + 45
    while time.monotonic() < until:
        try:
            responding = request(base, '/api/ping')[0] == 200
        except (OSError, TimeoutError):
            responding = False
        if responding == up:
            return
        time.sleep(.2)
    raise AssertionError(f'Server failed to become {"ready" if up else "stopped"}: {base}')


# What the shortcuts were called before the rename to Zscaler Made Easy.
LEGACY_SHORTCUT = 'Zscaler Assessment.lnk'
PLANT_LEGACY_SHORTCUTS = ("$w=New-Object -ComObject WScript.Shell; foreach($folder in @('Desktop','Programs')) { "
                          "$s=$w.CreateShortcut((Join-Path ([Environment]::GetFolderPath($folder)) '" + LEGACY_SHORTCUT + "')); "
                          "$s.TargetPath='wscript.exe'; $s.WorkingDirectory=$env:NATIVE_INSTALL_DIR; $s.Save() }")


def source_files(source):
    return subprocess.check_output(['git', 'ls-files', '-z'], cwd=source).decode().split('\0')[:-1]


def checkout(source, destination, mode, working_tree=False):
    if mode == 'git':
        subprocess.run(['git', '-c', 'core.autocrlf=false', 'clone', '--quiet', '--no-hardlinks', str(source), str(destination)], check=True)
    else:
        destination.mkdir(parents=True)
        archive = destination.parent / 'source.zip'
        subprocess.run(['git', 'archive', '--format=zip', '-o', str(archive), 'HEAD'], cwd=source, check=True)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(destination)
            for member in bundle.infolist():
                mode_bits = member.external_attr >> 16
                if mode_bits and not WINDOWS:
                    (destination / member.filename).chmod(mode_bits)
        archive.unlink()
    if working_tree:
        # Explicit local-development mode only; never used by CI.
        names = source_files(source)
        names += subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z'], cwd=source).decode().split('\0')[:-1]
        for name in names:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, target)
    assert (destination / '.git').exists() == (mode == 'git')


def verify_mode(source, work, artifacts, mode, record, working_tree=False):
    # Resolve the existing parent too: Windows TEMP can use an 8.3 alias
    # while Python/COM report the long path (RUNNER~1 versus runneradmin).
    app = (work / f'{mode} install with spaces').resolve()
    checkout(source, app, mode, working_tree)
    env = clean_env()
    if mode == 'zip':
        env.pop('DLP_CHECK_PYTHON', None)  # Ordinary PATH discovery; Git covers the explicit override.
    port = available_port()
    base = f'http://127.0.0.1:{port}'
    settings = app / ('local_settings.bat' if WINDOWS else 'local_settings.env')
    values = dict(ZSCALER_PORT=str(port), ZSCALER_OPEN_BROWSER='0', ENABLE_WRITE_ACTIONS='',
                  DLP_CHECK_BEACON_HOURS='0', DLP_CHECK_CONTINUOUS_EVAL_HOURS='0', NO_PROXY='127.0.0.1,localhost,::1')
    if WINDOWS:
        settings.write_text('@echo off\n' + ''.join(f'set "{k}={v}"\n' for k, v in values.items()), encoding='ascii')
    else:
        settings.write_text(''.join(f'{k}={shlex.quote(v)}\n' for k, v in values.items()), encoding='utf-8')
        settings.chmod(0o600)
    original_settings = settings.read_bytes()
    installer = batch(app / 'INSTALL_Zscaler_Made_Easy.bat') if WINDOWS else ['bash', str(app / 'install.sh')]
    python = app / '.venv' / ('Scripts/python.exe' if WINDOWS else 'bin/python')
    logs = artifacts / mode
    logs.mkdir()
    if WINDOWS:
        # Shortcuts left by an install from before the rename: the installer replaces them.
        env['NATIVE_INSTALL_DIR'] = str(app)
        run(['powershell', '-NoProfile', '-Command', PLANT_LEGACY_SHORTCUTS], app, env, logs / 'legacy-shortcuts.log')
    sentinel = app / '.venv' / 'native-reinstall-sentinel'
    for phase in ('fresh', 'reinstall'):
        run(installer, app.parent, env, logs / f'install-{phase}.log')
        assert python.is_file(), 'Installer did not create its private Python environment'
        assert settings.read_bytes() == original_settings, 'Installer overwrote local settings'
        if phase == 'fresh':
            sentinel.write_text('preserve healthy environment', encoding='utf-8')
        else:
            assert sentinel.read_text(encoding='utf-8') == 'preserve healthy environment', 'Reinstall deleted a healthy environment'
        record(f'{mode}-{phase}-installer-keeps-settings')
    run([python, '-m', 'pip', 'check'], app, env, logs / 'pip-check.log')
    record(f'{mode}-locked-dependencies-consistent')
    probe = '''import importlib.metadata as m, importlib.util, json, os, pathlib, sys
import dlp_api_server, dlp_mcp_server, scenario_flow, tenant_profiles
assert sys.prefix != sys.base_prefix
assert pathlib.Path(dlp_api_server.__file__).resolve().parent.samefile(pathlib.Path.cwd())
assert sys.version_info[:2] == tuple(map(int, os.environ['NATIVE_EXPECTED_PYTHON'].split('.')))
commands = set()
for dist_name in ('zscaler-made-easy', 'dlp-check'):   # the distribution under either name
    try:
        commands |= {e.name for e in m.distribution(dist_name).entry_points}
    except m.PackageNotFoundError:
        pass
assert {'zscaler-made-easy','zscaler-made-easy-assess','zscaler-made-easy-evaluate'} <= commands
assert {'dlp-check','dlp-check-assess','dlp-check-evaluate'} <= commands   # the names from before the rename still work
if sys.platform == 'win32':
    import win32api, win32cred, colorama, keyring
    from keyring.backends.Windows import WinVaultKeyring
    assert WinVaultKeyring.priority > 0
elif sys.platform == 'darwin':
    import keyring
    from keyring.backends.macOS import Keyring
    assert Keyring.priority > 0
else:
    assert importlib.util.find_spec('keyring') is None
print(json.dumps({'python': sys.version, 'executable': sys.executable, 'prefix': sys.prefix, 'platform': sys.platform, 'commands': sorted(commands)}))
'''
    env['NATIVE_EXPECTED_PYTHON'] = f'{sys.version_info.major}.{sys.version_info.minor}'
    run([python, '-c', probe], app, env, logs / 'installed-environment.json')
    record(f'{mode}-private-python-editable-commands-native-dependencies')
    if WINDOWS:
        command = ('''$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; foreach($folder in @('Desktop','Programs')) { $p=Join-Path ([Environment]::GetFolderPath($folder)) 'Zscaler Made Easy.lnk'; if (!(Test-Path $p)) {throw "Missing shortcut: $p"}; if (Test-Path (Join-Path ([Environment]::GetFolderPath($folder)) ''' + repr(LEGACY_SHORTCUT) + ''')) {throw "Old shortcut left in $folder"}; $s=$w.CreateShortcut($p); if ($s.WorkingDirectory -ne $env:NATIVE_INSTALL_DIR) {throw 'Wrong shortcut working directory'}; if ($s.Arguments -ne ('"' + (Join-Path $env:NATIVE_INSTALL_DIR 'START_Zscaler_Made_Easy.vbs') + '"')) {throw 'Wrong shortcut arguments'}; Write-Output $p }''')
        env['NATIVE_INSTALL_DIR'] = str(app)
        run(['powershell', '-NoProfile', '-Command', command], app, env, logs / 'shortcuts.log')
        record(f'{mode}-desktop-and-start-menu-shortcuts-replace-pre-rename-ones')
    # The actual launchers run the real server; sitecustomize only blocks
    # non-loopback DNS/TCP so a regression cannot reach a real tenant.
    runtime = env.copy()
    runtime['PYTHONPATH'] = str(app / 'tests' / 'native_support')
    runtime['NATIVE_EGRESS_LOG'] = str(logs / 'blocked-egress.jsonl')
    runtime['NATIVE_GUARD_MARKER'] = str(logs / 'guard-active')
    starter = (['cscript.exe', '//nologo', str(app / 'START_Zscaler_Made_Easy.vbs')]
               if WINDOWS else ['bash', str(app / 'start.sh'), '--background'])
    stopper = batch(app / 'STOP_Zscaler_Made_Easy.bat') if WINDOWS else ['bash', str(app / 'stop.sh')]
    proc = None
    try:
        run(starter, app.parent, runtime, logs / 'start.log', timeout=90)
        wait_server(base)
        assert (logs / 'guard-active').is_file(), 'Runtime egress guard did not load'
        record(f'{mode}-documented-launcher-custom-port')
        token_path = app / 'ui_token.txt'
        token = token_path.read_text().strip()
        assert token
        # /api/health intentionally checks GitHub for updates, so use a
        # protected local endpoint to verify auth without asking for online work.
        assert request(base, '/api/dlp-packs')[0] == 401
        assert request(base, '/api/dlp-packs', 'invalid-token')[0] == 401
        assert request(base, '/api/dlp-packs', token)[0] == 200
        record(f'{mode}-token-required-and-accepted')
        status, payload, _ = request(base, '/api/dlp-packs', token)
        assert status == 200
        packs = [p['id'] for p in json.loads(payload)['packs']]
        assert 'fed_policy_pack' in packs and 'cjis_policy_pack' in packs
        assert request(base, '/api/dlp-packs/apply', token,
                       {'pack_ids': packs, 'assessor': 'Synthetic Native Assessor', 'plan_hash': 'unused', 'confirm': True})[0] == 403
        record(f'{mode}-pack-files-present-and-writes-disabled')
        pages = ('/', '/report/motion', '/reference/data-security-portfolio-framework', '/reference/data-security-architect', '/reference/embed/portfolio-map', '/reference/embed/copilot-readiness')
        for page in pages:
            status, content, headers = request(base, page, token)
            assert status == 200 and len(content) > 1000, (page, status)
            assert any(k.lower() == 'content-type' and 'text/html' in v for k, v in headers.items()), page
            assert 'content-security-policy' in {k.lower() for k in headers}, page
        record(f'{mode}-new-pages-and-embedded-assets-served-with-csp')
        if not WINDOWS:
            pid = (app / 'server.pid').read_text()
            run(starter, app, runtime, logs / 'repeat-start.log')
            assert (app / 'server.pid').read_text() == pid
            assert token_path.stat().st_mode & 0o077 == 0
            assert (app / 'server.log').stat().st_mode & 0o077 == 0
            record(f'{mode}-repeated-start-keeps-process-and-private-token')
        else:
            run(starter, app, runtime, logs / 'repeat-start.log', timeout=90)
            assert token_path.read_text().strip() == token
            record(f'{mode}-repeated-silent-start-keeps-server')
        run(stopper, app.parent, runtime, logs / 'stop.log')
        wait_server(base, up=False)
        record(f'{mode}-documented-stop-releases-port')
        if WINDOWS:
            # The names from before the rename still start the app: the silent
            # launcher as an old build's Update app restart runs it, then the
            # batch file as an old build's restart fallback runs it.
            legacy_starts = (('legacy-vbs-restart', ['wscript.exe', '//B', '//Nologo', str(app / 'START_Zscaler_Assessment.vbs'), '/restart']),
                             ('legacy-bat', batch(app / 'START_Zscaler_Assessment.bat')))
            for name, legacy in legacy_starts:
                run(legacy, app, runtime, logs / f'{name}.log', timeout=90)
                wait_server(base)
                run(stopper, app.parent, runtime, logs / f'{name}-stop.log')
                wait_server(base, up=False)
                record(f'{mode}-{name}-starts-the-app')
        # Exercise the foreground debugging/CLI route too, after a real stop.
        foreground = batch(app / 'START_Zscaler_Made_Easy.bat', '--console') if WINDOWS else ['bash', str(app / 'start.sh')]
        with (logs / 'foreground.log').open('w', encoding='utf-8') as output:
            proc = subprocess.Popen(foreground, cwd=app.parent, env=runtime, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            wait_server(base)
            assert token_path.read_text().strip() != token, 'A restart reused the old UI token'
            record(f'{mode}-foreground-restart-rotates-token')
            if WINDOWS:
                run(stopper, app.parent, runtime, logs / 'foreground-stop.log')
            else:
                proc.terminate()
            proc.wait(timeout=20)
            wait_server(base, up=False)
    finally:
        # Cleanup is restricted to this isolated server and this selected port.
        if proc is not None and proc.poll() is None:
            if WINDOWS:
                subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True)
            else:
                proc.kill()
            proc.wait(timeout=10)
        run(stopper, app.parent, runtime, logs / 'cleanup.log', success=False)
        for name in ('server.log', 'launcher.log'):
            if (app / name).is_file():
                shutil.copy2(app / name, logs / name)
    egress = logs / 'blocked-egress.jsonl'
    assert not egress.exists() or not egress.read_text().strip(), f'Runtime attempted external networking; see {egress}'
    record(f'{mode}-runtime-made-no-external-network-attempts')
    # Browser tests use the private environment the installer just created.
    run([python, '-m', 'pip', 'install', '--require-hashes', '--no-deps', '-r', str(app / 'requirements-dev.lock')], app, env, logs / 'test-tools.log')
    if mode == 'git':
        test_env = env.copy()
        test_env.update(DLP_RUN_BROWSER_ACCEPTANCE='1', BROWSER_ACCEPTANCE_ARTIFACTS=str(logs / 'browser'))
        run([python, '-m', 'pytest', '-q', 'tests/test_flow_browser_acceptance.py', 'tests/test_native_install_contracts.py',
             'tests/test_native_tls_proxy.py', '--junitxml=' + str(logs / 'native-tests.xml')], app, test_env, logs / 'native-tests.log', timeout=360)
        record(f'{mode}-real-browser-and-native-contract-tests')
    if WINDOWS:
        run(['powershell', '-NoProfile', '-Command', PLANT_LEGACY_SHORTCUTS], app, env, logs / 'legacy-shortcuts-before-uninstall.log')
        run(batch(app / 'UNINSTALL_Zscaler_Made_Easy.bat'), app.parent, env, logs / 'uninstall.log')
        verify_removed = ("foreach($folder in @('Desktop','Programs')) { foreach($name in @('Zscaler Made Easy.lnk', '" + LEGACY_SHORTCUT + "')) { "
                          "if (Test-Path (Join-Path ([Environment]::GetFolderPath($folder)) $name)) { exit 1 } } }; exit 0")
        run(['powershell', '-NoProfile', '-Command', verify_removed], app, env, logs / 'uninstall-shortcuts.log')
        assert (app / 'dlp_api_server.py').is_file() and python.is_file(), 'Uninstaller deleted application files'
        record(f'{mode}-uninstall-removes-shortcuts-under-both-names-and-keeps-application-files')
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--working-tree', action='store_true', help='Local development only; CI always verifies the committed tree')
    args = parser.parse_args()
    if WINDOWS and (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        parser.error('Windows integration installs create desktop/Start menu shortcuts and may run only on disposable GitHub-hosted CI runners.')
    artifacts = Path(args.artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()
    report = {'commit': commit, 'working_tree': args.working_tree, 'platform': platform.platform(),
              'machine': platform.machine(), 'python': sys.version, 'cases': [],
              'enterprise_zscaler_ca': 'UNVERIFIED: synthetic loopback CA/proxy tests only'}
    def record(case):
        report['cases'].append({'id': case, 'passed': True})
        print('PASS', case, flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix='dlp native install ') as tmp:
            for mode in ('zip', 'git'):
                verify_mode(ROOT, Path(tmp), artifacts, mode, record, args.working_tree)
        report['passed'] = True
    except Exception as error:
        report['passed'] = False
        report['error'] = str(error)
        raise
    finally:
        (artifacts / 'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
