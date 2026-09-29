#!/usr/bin/env bash
# Start the web app on this machine (Linux / macOS). Windows: START_Zscaler_Assessment.bat.
#
#   ./start.sh              foreground: the address and UI token are printed; Ctrl-C stops it
#   ./start.sh --background start detached, output in server.log, stop with ./stop.sh
#
# Secure-by-design defaults, identical to the Windows launcher and the
# container: bound to localhost, writes to the tenant refused until
# ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND (or the switch in the app), no
# tracebacks unless ZSCALER_DEBUG=1. Machine-specific settings (proxy, CA
# bundle, credentials) come from local_settings.env, which is git-ignored.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

[ -x .venv/bin/python ] || { printf '\n  Run ./install.sh first (no .venv found).\n\n' >&2; exit 1; }
if [ -f local_settings.env ]; then set -a; . ./local_settings.env; set +a; fi
export ZSCALER_BIND_HOST="${ZSCALER_BIND_HOST:-127.0.0.1}"
export ZSCALER_PORT="${ZSCALER_PORT:-8000}"
export ZSCALER_OPEN_BROWSER="${ZSCALER_OPEN_BROWSER:-1}"

if [ "${1:-}" = "--background" ]; then
  if [ -f server.pid ] && kill -0 "$(cat server.pid)" 2>/dev/null; then
    printf '  Already running (pid %s). Stop it with ./stop.sh first.\n' "$(cat server.pid)"; exit 0
  fi
  nohup .venv/bin/python dlp_api_server.py > server.log 2>&1 &
  echo $! > server.pid
  sleep 2
  if kill -0 "$(cat server.pid)" 2>/dev/null; then
    printf '  Started (pid %s). Address and UI token: see server.log. Stop with ./stop.sh\n' "$(cat server.pid)"
    grep -m1 "Open http" server.log || true
  else
    printf '  The server stopped straight away; the reason is in server.log:\n' >&2; tail -5 server.log >&2; rm -f server.pid; exit 2
  fi
else
  exec .venv/bin/python dlp_api_server.py
fi
