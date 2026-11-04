#!/usr/bin/env bash
# Copy this computer's Zscaler Root CA into certs/ so the container build
# (pip) and the running app trust Zscaler's TLS inspection.
# Usage: ./get_zscaler_cert.sh   (then ./update_container.sh)
set -eu
cd "$(dirname "$0")"
OUT=certs/zscaler-root.crt
NAME="${ZSCALER_CA_NAME:-Zscaler Root CA}"
mkdir -p certs
pem=""
if [ "$(uname -s)" = "Darwin" ]; then
  for kc in "" /Library/Keychains/System.keychain; do
    pem="$(security find-certificate -c "$NAME" -p $kc 2>/dev/null || true)"
    [ -n "$pem" ] && break
  done
else
  for f in /usr/local/share/ca-certificates/* /etc/pki/ca-trust/source/anchors/* /etc/ssl/certs/*.pem /etc/ssl/certs/*.crt; do
    [ -f "$f" ] || continue
    if command -v openssl >/dev/null 2>&1; then
      openssl x509 -noout -subject -in "$f" 2>/dev/null | grep -qi "$NAME" || continue
    else
      grep -qi "zscaler" "$f" 2>/dev/null || continue
    fi
    pem="$(cat "$f")"; break
  done
fi
case "$pem" in
  *"BEGIN CERTIFICATE"*) printf '%s\n' "$pem" > "$OUT"; echo "Saved $OUT. Now run ./update_container.sh" ;;
  *) echo "$NAME not found on this computer. Ask IT for the root certificate as a Base-64 .crt file and save it as $OUT."; exit 1 ;;
esac
