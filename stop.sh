#!/usr/bin/env bash
# Stop a server started with ./start.sh --background (Windows: STOP_Zscaler_Made_Easy.bat).
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"
if [ -f server.pid ] && kill -0 "$(cat server.pid)" 2>/dev/null; then
  kill "$(cat server.pid)" && printf '  Stopped (pid %s).\n' "$(cat server.pid)"
  rm -f server.pid
else
  rm -f server.pid
  printf '  Nothing to stop: no server started by ./start.sh --background is running.\n'
fi
