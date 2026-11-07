#!/usr/bin/env bash
# Build an offline install bundle (run by the operator on a machine WITH internet).
#
#   deploy/rhel/build_wheelhouse.sh [OUTPUT_DIR]      default: ./wheelhouse
#
# Downloads every dependency pinned by hash in requirements.lock into
# OUTPUT_DIR/wheels (hash-verified), and copies the lock. Move the whole folder
# with the app to the air-gapped host and run:
#
#   (the pip --no-index command is in docs/RHEL_AIRGAPPED.md)
#
# Optional extras for delivery (paramiko, smbprotocol) are added with --with-delivery.
# The app never runs this script.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$APP_DIR/wheelhouse}"
EXTRAS=0
for a in "$@"; do [ "$a" = "--with-delivery" ] && EXTRAS=1; done
[ "$OUT" = "--with-delivery" ] && OUT="$APP_DIR/wheelhouse"
PY="${DLP_CHECK_PYTHON:-python3}"
[ -f "$APP_DIR/requirements.lock" ] || { echo "requirements.lock is missing." >&2; exit 1; }
mkdir -p "$OUT/wheels"
"$PY" -m pip download --require-hashes --no-deps -r "$APP_DIR/requirements.lock" -d "$OUT/wheels"
if [ "$EXTRAS" = 1 ]; then
  "$PY" -m pip download --no-deps paramiko smbprotocol -d "$OUT/wheels"
fi
cp "$APP_DIR/requirements.lock" "$OUT/requirements.lock"
( cd "$OUT" && sha256sum wheels/* > SHA256SUMS )
echo "Wheelhouse in $OUT ($(ls "$OUT/wheels" | wc -l) files). Copy it with the app to the offline host."
