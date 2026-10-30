"""Entry point of the standalone (no-install) edition of Zscaler Made Easy.

tools/build_standalone.py freezes this file with PyInstaller into one
folder per operating system (Windows x64, macOS arm64 and x64, Linux x64)
that runs without Python, a virtual environment or an installer: unpack,
double-click ZscalerMadeEasy, and the browser opens the app. It starts the
same server the launchers start (dlp_api_server.main) with the same
secure defaults, and three of them cannot be switched off here:

  - loopback only: the server listens on 127.0.0.1, whatever
    ZSCALER_BIND_HOST or local_settings.env say (a copy that should be
    reachable from the network is the container's job, behind SSO);
  - the UI token gate stays on (ZSCALER_UI_AUTH=0 is ignored), with a
    fresh random token every start (a fixed ZSCALER_UI_TOKEN is ignored);
    the browser is opened with the token the way the launchers open it,
    and the token file is written to the per-user data folder, owner-only;
  - read-only at every start: ENABLE_WRITE_ACTIONS (from the environment or
    local_settings.env) is ignored. Writing to a tenant needs the in-app
    write-mode switch, with its typed confirmation, and every other gate.

The bundled app folder is replaced by every new download and may be
read-only, so everything the app writes (tenant profiles, audit log,
deployments, the UI token, digests, ...) goes to the per-user data folder
zscaler_update_check.data_dir() already uses for its cache (owner-only,
0700): %LOCALAPPDATA%\\ZscalerMadeEasy on Windows,
~/Library/Caches/ZscalerMadeEasy on macOS, ~/.cache/zscaler_made_easy on
Linux. Machine settings (proxy, the corporate root CA for TLS inspection)
go in local_settings.env in that folder.

The port is the first free one from 8000 on 127.0.0.1 (ZSCALER_PORT moves
the starting point), so a second copy, or another program on 8000, does
not stop it from starting.

The standalone edition cannot update itself: a new version is a new
download, verified with its checksum and build attestation (INSTALL.md,
"Download and run").
"""
from __future__ import annotations

import json
import os
import socket
import sys
from typing import Callable, Dict, List, MutableMapping, Optional, Sequence

LOOPBACK = "127.0.0.1"
FIRST_PORT = 8000
PORT_TRIES = 100
SETTINGS_FILE = "local_settings.env"
MAX_SETTINGS_BYTES = 256 * 1024
BUILD_INFO_FILE = "standalone_build.json"
# Set for the lifetime of a standalone server. A process that starts with
# it already set was spawned by the app itself (a subprocess that reached
# sys.executable, which here is this program and not a Python
# interpreter): it must never become a second server.
SERVER_MARK = "DLP_CHECK_STANDALONE_SERVER"
_OFF = ("0", "false", "no", "off")

# Where each store goes inside the data folder: the same settings the
# container sets to /data (Dockerfile), plus the uploaded-packs folder.
# Stores not listed derive their folder from one of these (change queue,
# workspace notes, self-heal state, posture settings and fingerprint key
# sit beside proposals.json, tenant_profiles.json or deployments.json).
STORE_SETTINGS = {
    "DLP_CHECK_PROFILES": "tenant_profiles.json",
    "DLP_CHECK_DEPLOYMENTS": "deployments.json",
    "DLP_CHECK_ZIA_RATE_STATE": "zia_rate.json",
    "DLP_CHECK_AUDIT": "audit.log",
    "DLP_CHECK_DIGESTS": "digests",
    "DLPCHECK_PROPOSALS_FILE": "proposals.json",
    "DLP_CHECK_GUIDANCE_STATE": "guidance_state.json",
    "DLP_CHECK_SAAS_MATRIX": "saas_apps.local.json",
    "DLP_CHECK_BEACON_STATE": "beacon_state.json",
    "DLP_CHECK_CHECKS_CONFIG": "checks_config.json",
    "DLP_CHECK_USER_PACKS": "user_packs",
}


def bundle_dir() -> str:
    """The folder the app's files were unpacked from: PyInstaller's
    sys._MEIPASS when frozen, this file's folder when run from source."""
    return getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))


def load_settings_file(path: str, env: MutableMapping[str, str]) -> List[str]:
    """KEY=VALUE lines of local_settings.env into env, the way the server
    reads the one next to a local install: blank lines and # comments are
    skipped, quotes around a value are dropped, a value already in the
    environment wins. Returns the keys it set."""
    added: List[str] = []
    try:
        # utf-8-sig: Notepad's "UTF-8 with BOM" must not glue the BOM to the
        # first key. A file that is not text, or far larger than any settings
        # file, is not read: the app starts with its defaults instead.
        with open(path, encoding="utf-8-sig") as f:
            text = f.read(MAX_SETTINGS_BYTES + 1)
    except (OSError, ValueError):
        return added
    if len(text) > MAX_SETTINGS_BYTES:
        return added
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in env:
            env[k] = v
            added.append(k)
    return added


def configure(env: MutableMapping[str, str], data: str) -> List[str]:
    """Put the standalone defaults into env (the process environment, or a
    dict in tests) and return the notices to print. Order matters: the
    settings file is read first, then the security settings are forced, so
    neither the environment nor the file can loosen them."""
    notes: List[str] = []
    load_settings_file(os.path.join(data, SETTINGS_FILE), env)
    host = (env.get("ZSCALER_BIND_HOST") or "").strip()
    if host and host != LOOPBACK:
        notes.append(f"ZSCALER_BIND_HOST={host} is ignored: the standalone edition listens on {LOOPBACK} only.")
    env["ZSCALER_BIND_HOST"] = LOOPBACK
    if (env.get("ZSCALER_UI_AUTH") or "").strip().lower() in _OFF:
        notes.append("ZSCALER_UI_AUTH=0 is ignored: the standalone edition always asks for the UI token.")
    env["ZSCALER_UI_AUTH"] = "1"
    # A fixed token would never rotate and may be short; a settings file in
    # the data folder (which any program run as this user can write) must
    # not pin it, nor switch writes on before anyone has typed the phrase.
    if (env.pop("ZSCALER_UI_TOKEN", None) or "").strip():
        notes.append("ZSCALER_UI_TOKEN is ignored: the standalone edition makes a new random UI token every start.")
    if env.pop("ENABLE_WRITE_ACTIONS", None) is not None:
        notes.append("ENABLE_WRITE_ACTIONS is ignored: the standalone edition starts read-only; turn on write mode with the switch in the app.")
    # Not a container: the container's exposure rules (DLP_CHECK_HOST_BIND)
    # must not apply to a process on this machine's own network stack.
    env.pop("DLP_CHECK_IN_CONTAINER", None)
    env.setdefault("ZSCALER_OPEN_BROWSER", "1")
    env.setdefault("DLP_CHECK_UI_TOKEN_DIR", data)
    for key, name in STORE_SETTINGS.items():
        env.setdefault(key, os.path.join(data, name))
    # PyInstaller points LD_LIBRARY_PATH at the bundle on Linux; programs
    # the app starts (git, the browser through xdg-open) get the person's own.
    if "LD_LIBRARY_PATH_ORIG" in env:
        env["LD_LIBRARY_PATH"] = env.pop("LD_LIBRARY_PATH_ORIG")
    elif getattr(sys, "frozen", False) and env.get("LD_LIBRARY_PATH") == bundle_dir():
        env.pop("LD_LIBRARY_PATH", None)
    return notes


def apply_build_info(env: MutableMapping[str, str], folder: str) -> Dict[str, str]:
    """The commit and ref the build was made from (written by
    tools/build_standalone.py into the bundle), for /api/health and the
    Update app card. Missing or malformed: nothing is set."""
    try:
        with open(os.path.join(folder, BUILD_INFO_FILE), encoding="utf-8") as f:
            info = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(info, dict):
        return {}
    out = {k: str(info.get(k) or "") for k in ("commit", "ref", "version")}
    if out["commit"]:
        env.setdefault("DLP_CHECK_BUILD_COMMIT", out["commit"])
    if out["ref"]:
        env.setdefault("DLP_CHECK_BUILD_BRANCH", out["ref"])
    return out


def port_is_free(host: str, port: int) -> bool:
    """Can a listening socket be bound to host:port right now? On Windows
    SO_EXCLUSIVEADDRUSE, because SO_REUSEADDR there would let this bind
    succeed on a port another program is already listening on."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if sys.platform == "win32":
                s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
            else:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
    except OSError:
        return False
    return True


def first_free_port(start: int = FIRST_PORT, tries: int = PORT_TRIES, host: str = LOOPBACK,
                    is_free: Callable[[str, int], bool] = port_is_free) -> Optional[int]:
    """The first port from `start` that can be bound on host, trying at
    most `tries` ports and never past 65535; None when all are taken."""
    for port in range(max(1, start), min(65535, start + tries - 1) + 1):
        if is_free(host, port):
            return port
    return None


def starting_port(env: MutableMapping[str, str]) -> int:
    raw = (env.get("ZSCALER_PORT") or "").strip()
    return int(raw) if raw.isdigit() and 1 <= int(raw) <= 65535 else FIRST_PORT


def is_regex_worker(argv: Sequence[str]) -> bool:
    """dlp_efficacy runs tenant regexes in `sys.executable -I -c <its
    worker>` so a runaway pattern cannot hang the server. Frozen,
    sys.executable is this program: that exact call runs the same worker
    (run_regex_worker), and any other -c text is refused, never executed."""
    if len(argv) != 3 or list(argv[:2]) != ["-I", "-c"]:
        return False
    import dlp_efficacy
    return argv[2] == dlp_efficacy._REGEX_WORKER


# The worker's limits, as in dlp_efficacy._REGEX_WORKER (tests/test_standalone.py
# holds the two to the same numbers and the same answers).
WORKER_MEMORY_BYTES = 256 * 1024 * 1024
WORKER_CPU_SECONDS = 1


def run_regex_worker() -> int:
    """dlp_efficacy's regex worker as code of this program (nothing is
    compiled from text): bounded memory and CPU time where the system
    offers limits, then the number of case-insensitive matches of the
    pattern read from stdin. A bad pattern or a limit hit ends the process
    with an error, which dlp_efficacy reports as unknown."""
    import re
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (WORKER_MEMORY_BYTES, WORKER_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (WORKER_CPU_SECONDS, WORKER_CPU_SECONDS))
    except (ImportError, AttributeError, ValueError, OSError):
        pass
    pattern, content = json.load(sys.stdin)
    print(sum(1 for _ in re.finditer(pattern, content, re.IGNORECASE)))
    return 0


def _pause_if_double_clicked() -> None:
    """Keep the window open on a failed start when the person double-clicked
    the program (a console that closes at once shows them nothing)."""
    try:
        if getattr(sys, "frozen", False) and sys.stdin is not None and sys.stdin.isatty():
            input("  Press Enter to close this window.")
    except (EOFError, OSError, RuntimeError):
        pass


def main(argv: Optional[Sequence[str]] = None, env: Optional[MutableMapping[str, str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    if argv[:2] == ["-I", "-c"]:
        if is_regex_worker(argv):
            return run_regex_worker()
        print("  Refused: this program runs Zscaler Made Easy; it does not run Python code.", file=sys.stderr)
        return 2
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv and argv[0] == "--version":
        info = apply_build_info({}, bundle_dir())
        print(f"Zscaler Made Easy standalone {info.get('version') or 'dev'} ({info.get('commit') or 'unknown commit'})")
        return 0
    if argv:
        print(f"  Unknown option {argv[0]!r}. Start it without options; --help says what it does.", file=sys.stderr)
        return 2
    if env.get(SERVER_MARK):
        print("  Refused: started from inside a running copy of the app; a second server is never started this way.", file=sys.stderr)
        return 2

    for stream in (sys.stdout, sys.stderr):
        try:
            # The address and token must show at once, also when the
            # output goes to a pipe or a log file rather than a console.
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    import zscaler_update_check
    data = zscaler_update_check.data_dir()
    notes = configure(env, data)
    apply_build_info(env, bundle_dir())
    port = first_free_port(starting_port(env))
    if port is None:
        print(f"\n  Could not start: no free port on {LOOPBACK} from {starting_port(env)} on. "
              f"Close another copy of the app, or set ZSCALER_PORT to a free port.\n", file=sys.stderr)
        _pause_if_double_clicked()
        return 2
    env["ZSCALER_PORT"] = str(port)
    env[SERVER_MARK] = "1"
    for n in notes:
        print(f"  Note: {n}")
    print(f"  Your data and settings: {data}")
    print("  Keep this window open while you use the app; close it (or press Ctrl+C) to stop.")

    import dlp_api_server
    code = dlp_api_server.main([])
    if code:
        _pause_if_double_clicked()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
