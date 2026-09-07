#!/usr/bin/env bash
# Reassemble the patch bundle, verify every hash, apply the commits onto
# claude/review-repo-xRk8y, verify the resulting file blobs, push, and
# remove this carrier branch. Exits non-zero (with a clear message) at the
# first check that fails; nothing is pushed unless every check passes.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
T=transfer
export GIT_TERMINAL_PROMPT=0
TARGET=claude/review-repo-xRk8y

echo '== 1/5 verifying chunks'
while read -r name size sha; do
  [ -f "$T/$name" ] || { echo "MISSING $name"; exit 2; }
  actual=$(tr -d '\n\r ' < "$T/$name" | sha256sum | cut -d' ' -f1)
  [ "$actual" = "$sha" ] || { echo "CORRUPT $name expected=$sha actual=$actual"; exit 3; }
  echo "  ok $name"
done < "$T/CHUNKS"

echo '== 2/5 reassembling'
: > /tmp/deploy.b64
while read -r name size sha; do tr -d '\n\r ' < "$T/$name" >> /tmp/deploy.b64; done < "$T/CHUNKS"
[ "$(sha256sum /tmp/deploy.b64 | cut -d' ' -f1)" = "$(tr -d '\n\r ' < $T/B64_SHA256)" ] || { echo 'B64 sha mismatch'; exit 4; }
base64 -d /tmp/deploy.b64 | gunzip -c > /tmp/deploy.mbox
[ "$(sha256sum /tmp/deploy.mbox | cut -d' ' -f1)" = "$(tr -d '\n\r ' < $T/MBOX_SHA256)" ] || { echo 'MBOX sha mismatch'; exit 5; }
echo "  mbox ok ($(wc -c < /tmp/deploy.mbox) bytes)"

echo '== 3/5 applying onto' "$TARGET"
git fetch origin "$TARGET"
git checkout -B "$TARGET" "origin/$TARGET"
[ "$(git rev-parse HEAD)" = "$(tr -d '\n\r ' < $T/BASE)" ] || { echo "base moved: $(git rev-parse HEAD) (expected $(cat $T/BASE))"; exit 6; }
git -c user.name=Claude -c user.email=noreply@anthropic.com am --committer-date-is-author-date /tmp/deploy.mbox

echo '== 4/5 verifying result'
fail=0
while read -r sha path; do
  actual=$(git rev-parse "HEAD:$path")
  if [ "$actual" = "$sha" ]; then echo "  blob ok $path"; else echo "  BLOB MISMATCH $path expected=$sha actual=$actual"; fail=1; fi
done < "$T/BLOBS"
[ "$fail" -eq 0 ] || exit 7
git log --oneline "origin/$TARGET..HEAD"

echo '== 5/5 pushing'
git push origin "$TARGET"
git push origin --delete claude/transfer-deploy || echo '  (carrier branch not deleted — remove manually)'
echo "DONE head=$(git rev-parse HEAD)"
