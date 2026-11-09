#!/usr/bin/env bash
# Install the systemd service on RHEL (run as root, once, by the operator).
#
#   1. ./install.sh already ran in this folder (it made .venv).
#   2. sudo deploy/rhel/install_service.sh [--now]
#
# Creates the unprivileged user zscaler-made-easy, installs the unit with this
# folder's path, reloads systemd and enables the service (starts it with --now).
# The app never runs this script. The service listens on 127.0.0.1 only.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_SRC="$APP_DIR/deploy/rhel/zscaler-made-easy.service"
UNIT_DST="/etc/systemd/system/zscaler-made-easy.service"
SVC_USER="zscaler-made-easy"

fail() { printf '\n  ERROR: %s\n\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail "Run this as root (sudo)."
[ -x "$APP_DIR/.venv/bin/zscaler-made-easy" ] || fail "Run ./install.sh in $APP_DIR first (no .venv/bin/zscaler-made-easy)."
command -v systemctl >/dev/null 2>&1 || fail "systemd was not found."

if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /sbin/nologin "$SVC_USER"
fi
# The service user reads the app folder; it must not be able to change it.
chmod -R go-w "$APP_DIR"
install -m 0644 /dev/null "$UNIT_DST"
sed "s|@APP_DIR@|$APP_DIR|g" "$UNIT_SRC" > "$UNIT_DST"
systemctl daemon-reload
systemctl enable zscaler-made-easy.service
if [ "${1:-}" = "--now" ]; then systemctl start zscaler-made-easy.service; fi
printf '  Installed %s (user %s, 127.0.0.1:8000).\n  Start: systemctl start zscaler-made-easy   Logs: journalctl -u zscaler-made-easy\n' "$UNIT_DST" "$SVC_USER"
