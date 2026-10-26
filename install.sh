#!/usr/bin/env bash
# Local installer for Linux and macOS (Windows: INSTALL_Zscaler_Made_Easy.bat).
#
# Creates a private Python environment in .venv next to this file, installs
# the dependencies pinned by hash in requirements.lock (the same file the
# container installs from), installs the app into that environment so the
# `dlp-check` command exists, and writes nothing outside this folder.
#
#   ./install.sh            install (or reinstall after an update)
#   ./start.sh              start the web app and print the address to open
#   ./stop.sh               stop it
#   .venv/bin/dlp-check     the same server, as a command
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

say()  { printf '  %s\n' "$*"; }
fail() { printf '\n  ERROR: %s\n\n' "$*" >&2; exit 1; }

# 1. A Python 3.11+ interpreter.
PY="${DLP_CHECK_PYTHON:-}"
if [ -n "$PY" ]; then
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null || fail "DLP_CHECK_PYTHON must name a working Python 3.11 or newer interpreter."
fi
for cand in python3 python python3.14 python3.13 python3.12 python3.11; do
  [ -n "$PY" ] && break
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then PY="$cand"; break; fi
  fi
done
[ -n "$PY" ] || fail "Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/ (or your package manager) and run this again."
say "Using $("$PY" --version 2>&1) at $(command -v "$PY")"

# 2. A private environment, so nothing touches the system Python.
if [ -x .venv/bin/python ] && ! .venv/bin/python -m pip --version >/dev/null 2>&1; then
  # Never delete the interpreter selected from an activated, broken .venv.
  if "$PY" -c 'import pathlib, sys; sys.exit(0 if pathlib.Path(sys.executable).absolute().is_relative_to(pathlib.Path(".venv").absolute()) else 1)'; then
    fail "The active .venv is incomplete. Run deactivate, then run ./install.sh again; the environment has not been deleted."
  fi
  say "The private environment in .venv is incomplete (no pip); making it again…"
  rm -rf .venv
fi
if [ ! -x .venv/bin/python ]; then
  say "Creating the private environment in .venv…"
  "$PY" -m venv .venv || { rm -rf .venv; fail "Could not create the virtual environment (is the python3-venv package installed? On Debian/Ubuntu: sudo apt install -y python3-venv)."; }
fi
VPY=".venv/bin/python"

# 3. Dependencies, pinned by hash. Missing lock files fail closed.
# A work laptop behind TLS inspection or a proxy keeps the CA bundle and the
# proxy in local_settings.env (copy the example before installing); pip
# reads the same variables, so the install works from the first run.
if [ -f local_settings.env ]; then set -a; . ./local_settings.env; set +a; fi
if [ -n "${REQUESTS_CA_BUNDLE:-}" ] && [ -z "${PIP_CERT:-}" ]; then export PIP_CERT="$REQUESTS_CA_BUNDLE"; fi
if [ -f requirements.lock ]; then
  say "Installing the dependencies pinned in requirements.lock…"
  "$VPY" -m pip install --quiet --disable-pip-version-check --require-hashes --no-deps -r requirements.lock \
    || fail "Dependency install failed. If you are behind a corporate proxy, set HTTPS_PROXY (and REQUESTS_CA_BUNDLE for TLS inspection) and run this again."
else
  # Never an unhashed install: without the lock nothing pins what pip downloads.
  fail "requirements.lock is missing from this folder, so the dependencies cannot be installed hash-verified. Get a complete copy of the app (git clone, or a fresh ZIP) and run this again."
fi

# 4. The app itself, editable, so the dlp-check command runs this folder's code.
say "Installing the dlp-check command…"
"$VPY" -m pip install --quiet --disable-pip-version-check --no-deps --no-build-isolation -e . \
  || fail "Could not install the app into the environment."

# 5. Machine-specific settings file (proxy, CA bundle, credentials), never overwritten.
if [ ! -f local_settings.env ] && [ -f local_settings.env.example ]; then
  cp local_settings.env.example local_settings.env
  chmod 600 local_settings.env   # it may hold ZSCALER_CLIENT_SECRET and the like: owner-only
  say "Created local_settings.env from the example (git-ignored; edit it for a proxy or credentials)."
fi
chmod +x start.sh stop.sh 2>/dev/null || true

printf '\n  ════════════════════════════════════════════════════════════\n'
printf '   Installed. Start with:  ./start.sh   (Ctrl-C stops it)\n'
printf '   The address and the UI token are printed when it starts.\n'
printf '   ./start.sh --background runs it detached; ./stop.sh stops that.\n'
printf '  ════════════════════════════════════════════════════════════\n\n'
