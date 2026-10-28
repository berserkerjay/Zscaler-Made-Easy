#!/usr/bin/env python3
"""Smoke-test a built standalone edition: start it, ask it, stop it.

    python tools/smoke_standalone.py dist/standalone/ZscalerMadeEasy-<version>-<platform>.tar.gz [--commit <sha>]
    python tools/smoke_standalone.py <unpacked folder>/ZscalerMadeEasy[.exe]

Given the archive, it first checks it against its .sha256 file and unpacks
it the way a person would, so what is tested is exactly what ships.

Runs the real binary in a throw-away home folder (its per-user data folder
lands there), with the browser switched off and with the settings that
would loosen it deliberately set (ZSCALER_UI_AUTH=0, ZSCALER_BIND_HOST=0.0.0.0)
to prove the standalone edition ignores them. It then checks, over HTTP on
127.0.0.1 with nothing but the standard library:

  - /api/ping answers; /api/health answers 401 without the UI token and 200
    with it (the token is read from the console line the launcher prints);
  - the token file is written owner-only into the per-user data folder,
    not into the app folder;
  - the server is not reachable on this machine's network address;
  - write mode is off;
  - the regex worker dlp_efficacy runs through sys.executable works, and
    any other `-I -c` code is refused, not run;
  - the process stops on an interrupt and frees its port.

Exit code 0 when every check passed. The release workflow runs it on each
platform's runner right after the build.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPEN_LINE = re.compile(r"Open (http://localhost:(\d+)/)\?token=([A-Za-z0-9_-]+)")
TOKEN_HEADER = "X-DLP-Check-Token"
START_TIMEOUT = 180   # a first start unpacks and scans ~100 MB (Windows Defender, Gatekeeper)


def isolated_env(home: str, port_start: int = 8000) -> Tuple[Dict[str, str], str]:
    """The environment to start the binary with, and the data folder it
    should use: every per-user location points into `home`."""
    keep = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    local = os.path.join(home, "AppData", "Local")
    cache = os.path.join(home, ".cache")
    env.update({"HOME": home, "USERPROFILE": home, "LOCALAPPDATA": local, "XDG_CACHE_HOME": cache,
                "ZSCALER_OPEN_BROWSER": "0", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8",
                # Settings that would loosen a normal install; the standalone edition must ignore both.
                "ZSCALER_UI_AUTH": "0", "ZSCALER_BIND_HOST": "0.0.0.0"})
    if port_start != 8000:
        env["ZSCALER_PORT"] = str(port_start)
    if sys.platform == "win32":
        data = os.path.join(local, "ZscalerMadeEasy")
    elif sys.platform == "darwin":
        data = os.path.join(home, "Library", "Caches", "ZscalerMadeEasy")
    else:
        data = os.path.join(cache, "zscaler_made_easy")
    return env, data


def _reader(stream, q: "queue.Queue[Optional[str]]", log: List[str]) -> None:
    for raw in iter(stream.readline, b""):
        line = raw.decode("utf-8", "replace").rstrip()
        log.append(line)
        q.put(line)
    q.put(None)


def _get(url: str, token: Optional[str] = None, timeout: float = 30) -> Tuple[int, str]:
    req = urllib.request.Request(url, headers={TOKEN_HEADER: token} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - http://127.0.0.1 only
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _non_loopback_address() -> Optional[str]:
    """This machine's address on its network (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))   # TEST-NET-1: routing lookup only
            ip = s.getsockname()[0]
        return None if ip.startswith("127.") or ip == "0.0.0.0" else ip
    except OSError:
        return None


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _stop(proc: subprocess.Popen) -> int:
    """Interrupt (Ctrl+C / Ctrl+Break), then force the whole tree down."""
    try:
        if sys.platform == "win32":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGINT)
        return proc.wait(timeout=30)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.kill()
        return proc.wait(timeout=30)


def run_worker_checks(exe: str, env: Dict[str, str]) -> List[str]:
    sys.path.insert(0, ROOT)
    import dlp_efficacy
    problems = []
    cp = subprocess.run([exe, "-I", "-c", dlp_efficacy._REGEX_WORKER], input=json.dumps(["a+", "aa b aaa"]),
                        capture_output=True, text=True, env=env, timeout=120)
    if cp.returncode != 0 or cp.stdout.strip() != "2":
        problems.append(f"the regex worker did not answer 2 (rc {cp.returncode}, out {cp.stdout.strip()!r}, err {cp.stderr.strip()[-300:]!r})")
    canary = os.path.join(tempfile.gettempdir(), f"standalone-smoke-canary-{os.getpid()}")
    cp = subprocess.run([exe, "-I", "-c", f"open({canary!r}, 'w').write('ran')"], capture_output=True, text=True, env=env, timeout=120)
    if cp.returncode == 0 or os.path.exists(canary):
        problems.append("other -I -c code was run instead of refused")
    if os.path.exists(canary):
        os.remove(canary)
    return problems


def smoke(exe: str, commit: str = "", port_start: int = 8000) -> List[str]:
    exe = os.path.abspath(exe)
    problems: List[str] = []
    home = tempfile.mkdtemp(prefix="zme-smoke-home-")
    env, data = isolated_env(home, port_start)
    log: List[str] = []
    try:
        problems += run_worker_checks(exe, env)
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        proc = subprocess.Popen([exe], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=env, cwd=home, creationflags=flags)
        q: "queue.Queue[Optional[str]]" = queue.Queue()
        threading.Thread(target=_reader, args=(proc.stdout, q, log), daemon=True).start()
        url = port = token = None
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            try:
                line = q.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                break
            m = OPEN_LINE.search(line)
            if m:
                url, port, token = m.group(1), int(m.group(2)), m.group(3)
                break
        if not url:
            problems.append("the app did not print its address and token")
            _stop(proc)
            return problems
        base = f"http://127.0.0.1:{port}"
        ok = False
        while time.monotonic() < deadline:
            try:
                ok = _get(base + "/api/ping", timeout=5)[0] == 200
            except OSError:
                ok = False
            if ok:
                break
            time.sleep(0.5)
        if not ok:
            problems.append("/api/ping never answered 200")
        else:
            status, _ = _get(base + "/api/health")
            if status != 401:
                problems.append(f"/api/health without the token answered {status}, not 401 (ZSCALER_UI_AUTH=0 must be ignored)")
            status, body = _get(base + "/api/health", token)
            health = json.loads(body) if status == 200 else {}
            if status != 200 or health.get("status") != "ok" or not health.get("total_checks"):
                problems.append(f"/api/health with the token answered {status}: {body[:300]}")
            elif commit and not str(health.get("git_commit", "")).startswith(commit[:7]):
                problems.append(f"/api/health reports commit {health.get('git_commit')!r}, built from {commit!r}")
            for path, needle in (("/", "Zscaler Made Easy"), ("/static/explain.js", "DLP_EXPLAIN_ORDER"), ("/report/path", "rp-hero")):
                status, body = _get(base + path, token)
                if status != 200 or needle not in body:
                    problems.append(f"{path} answered {status} without its content: a bundled page or script is missing")
            status, body = _get(base + "/api/write-mode", token)
            wm = json.loads(body) if status == 200 else {}
            if status != 200 or wm.get("enabled") is not False:
                problems.append(f"write mode is not off by default: {status} {body[:300]}")
            if not port_start <= port < port_start + 100:
                problems.append(f"port {port} is not the first free one from {port_start}")
            ip = _non_loopback_address()
            if ip and _reachable(ip, port):
                problems.append(f"the server answers on {ip}:{port}; it must listen on 127.0.0.1 only")
            print(f"checked: port {port}, " + (f"not reachable on {ip}" if ip else "no network address to probe"))
            token_file = os.path.join(data, "ui_token.txt")
            if not os.path.isfile(token_file) or open(token_file, encoding="utf-8").read().strip() != token:
                problems.append(f"the UI token file is not in the per-user data folder ({token_file})")
            elif sys.platform != "win32" and stat.S_IMODE(os.stat(token_file).st_mode) & 0o077:
                problems.append("the UI token file is readable by other users")
            app_dir = os.path.dirname(exe)
            for d, _dirs, files in os.walk(app_dir):
                if "ui_token.txt" in files or "audit.log" in files or "tenant_profiles.json" in files:
                    problems.append(f"the app wrote local state into its own folder: {d}")
                    break
        code = _stop(proc)
        if _reachable("127.0.0.1", port):
            problems.append(f"port {port} still answers after the app was stopped (exit code {code})")
    finally:
        if problems:
            out = "\n".join(log[-60:])
            print("---- app output ----\n" + re.sub(r"(token[=: ]+)[A-Za-z0-9_-]{16,}", r"\1<token>", out))
        shutil.rmtree(home, ignore_errors=True)
    return problems


def unpack(archive: str, dest: str) -> str:
    """Check archive against <archive>.sha256 and unpack it into dest
    (tar: the "data" filter refuses links out of dest, absolute paths and
    special files); returns the program inside."""
    import hashlib
    import tarfile
    import zipfile
    side = archive + ".sha256"
    if os.path.isfile(side):
        want = open(side, encoding="utf-8").read().split()[0].lower()
        h = hashlib.sha256()
        with open(archive, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != want:
            raise SystemExit(f"{archive}: SHA-256 does not match {side}")
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest)
    else:
        with tarfile.open(archive) as t:
            t.extractall(dest, filter="data")
    tops = os.listdir(dest)
    if len(tops) != 1:
        raise SystemExit(f"{archive}: expected one top-level folder, found {tops}")
    exe = os.path.join(dest, tops[0], "ZscalerMadeEasy" + (".exe" if sys.platform == "win32" else ""))
    if not os.path.isfile(exe):
        raise SystemExit(f"{archive}: no program at {exe}")
    return exe


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("target", help="the archive (.zip / .tar.gz) or the program itself")
    ap.add_argument("--commit", default="")
    ap.add_argument("--port-start", type=int, default=8000, help="where the free-port search starts (ZSCALER_PORT); 8000 as shipped")
    a = ap.parse_args(argv)
    if a.target.endswith((".zip", ".tar.gz")):
        dest = tempfile.mkdtemp(prefix="zme-smoke-unpacked-")
        try:
            problems = smoke(unpack(os.path.abspath(a.target), dest), a.commit, a.port_start)
        finally:
            shutil.rmtree(dest, ignore_errors=True)
    else:
        problems = smoke(a.target, a.commit, a.port_start)
    for p in problems:
        print(f"FAIL: {p}")
    print("standalone smoke test: " + ("passed" if not problems else f"{len(problems)} problem(s)"))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
