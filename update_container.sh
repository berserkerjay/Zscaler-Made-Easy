#!/usr/bin/env bash
# Update the Zscaler Made Easy container: pull the latest code for this checkout's
# branch from GitHub and rebuild the container, only when GitHub has
# something new. Run it on the computer that runs Docker, from the folder
# that holds docker-compose.yml (a git clone, not a ZIP).
#
#   ./update_container.sh              update now if GitHub is ahead
#   ./update_container.sh --branch qa  switch to a branch (main, qa or dev) and update from it
#   ./update_container.sh --force      rebuild even when already up to date
#   ./update_container.sh --schedule   also update automatically every day at 03:17
#   ./update_container.sh --unschedule stop the automatic update
#   ./update_container.sh --old-volume NAME   which old data volume to copy, when there are several
#   ./update_container.sh --migrate-only      only copy the old data across (the image must be built)
#
# main is what customers run; qa and dev carry changes before they are
# promoted (dev -> qa -> main). The branch chosen stays checked out, so
# later runs and the daily schedule keep updating from it.
#
# Saved data (profiles, deployment records, audit log, uploaded packs) is in
# the zscaler-made-easy-data volume and survives the rebuild. The rebuild
# restarts the app, which prints a new UI token (docker logs zscaler-made-easy).
#
# Moving to the new name: before the rename the container was dlp-check and
# the data was on a volume called dlpcheck-data or <folder>_dlpcheck-data.
# The first run after the rename COPIES that volume into
# zscaler-made-easy-data (it never moves or deletes it), then removes the old
# container so port 8001 is free. Later runs copy nothing. With more than one
# old volume it asks which one: --old-volume NAME or ZME_OLD_VOLUME=NAME.
set -euo pipefail
cd "$(dirname "$0")"
DIR="$(pwd)"
LOG="$DIR/update_container.log"
say() { echo "$(date '+%Y-%m-%d %H:%M:%S')  $*" | tee -a "$LOG"; }
MARK="# Zscaler Made Easy container auto-update"

FORCE=""; SCHEDULE=""; WANT=""; MIGRATE_ONLY=""; OLD_VOLUME="${ZME_OLD_VOLUME:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --schedule) SCHEDULE=1 ;;
    --unschedule)
      ( crontab -l 2>/dev/null | grep -v "$MARK" ) | crontab - || true
      say "Automatic update removed."
      exit 0
      ;;
    --branch) shift; WANT="${1:-}" ;;
    --branch=*) WANT="${1#--branch=}" ;;
    --old-volume) shift; OLD_VOLUME="${1:-}" ;;
    --old-volume=*) OLD_VOLUME="${1#--old-volume=}" ;;
    --migrate-only) MIGRATE_ONLY=1 ;;
    *) echo "Unknown option $1. Use --branch main|qa|dev, --force, --schedule, --unschedule, --old-volume NAME or --migrate-only."; exit 2 ;;
  esac
  shift
done
case "$WANT" in
  ""|main|qa|dev) ;;
  DLP-CHECK-QA) WANT=qa ;;   # the QA branch's old name
  *) echo "Unknown branch '$WANT': choose main, qa or dev."; exit 2 ;;
esac

# ── Moving to the new name ────────────────────────────────────────────────
NEW_VOLUME="zscaler-made-easy-data"
IMAGE="zscaler-made-easy:local"
CONTAINER="zscaler-made-easy"
OLD_VOLUME_RE='^(dlpcheck-data|.+_dlpcheck-data)$'       # docker run -v dlpcheck-data, or compose's <project>_dlpcheck-data
OLD_CONTAINER_RE='^(dlp-check|.+-dlp-check-.+)$'         # container_name dlp-check, or compose's <project>-dlp-check-1
# The image's own Python checks the copy: every file and folder arrived with
# the same size, mode and owner. Single quotes only, so the line passes
# through any shell unchanged.
VERIFY_PY="import os,sys;st=lambda r:{(os.path.relpath(os.path.join(d,n),r),s.st_mode,s.st_uid,s.st_gid,0 if os.path.isdir(os.path.join(d,n)) else s.st_size) for d,ds,fs in os.walk(r) for n in ds+fs for s in [os.lstat(os.path.join(d,n))]};sys.exit(0 if st('/from')==st('/to') else 1)"
# Written into the new volume once the copy is verified: what tells a later
# run the move is done (a new volume without it may be one an older update
# script created empty). The checks below are Python in the image, with
# single quotes only, like VERIFY_PY.
MARKER=".zscaler-made-easy-moved-from"
HAS_MARKER_PY="import os,sys;sys.exit(0 if os.path.exists('/to/$MARKER') else 1)"
IS_EMPTY_PY="import os,sys;sys.exit(0 if not os.listdir('/to') else 1)"
MARK_PY="import os;open('/to/$MARKER','w').write(os.environ['ZME_FROM']+chr(10))"

# Run one check on the new volume, read-only, as the image's own user:
# 0 yes, 1 no, 125 or more: Docker could not run it.
new_volume_check() {
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$NEW_VOLUME":/to:ro --entrypoint python "$IMAGE" -c "$1" >/dev/null 2>&1
}

old_volumes() { docker volume ls -q | grep -E "$OLD_VOLUME_RE" || true; }

# True while data from before the rename is still to be copied.
migration_pending() {
  [ -n "$(old_volumes)" ] || return 1
  docker volume inspect "$NEW_VOLUME" >/dev/null 2>&1 || return 0
  ! new_volume_check "$HAS_MARKER_PY"
}

migrate_old_data() {
  local olds cands n c rc copy="" refill=""
  olds="$(docker ps -a --format '{{.Names}}' | grep -E "$OLD_CONTAINER_RE" || true)"
  cands="$(old_volumes)"
  if [ -n "$OLD_VOLUME" ] && ! docker volume inspect "$OLD_VOLUME" >/dev/null 2>&1; then
    say "Stopped: there is no volume called $OLD_VOLUME; nothing was changed."; return 2
  fi
  if [ -n "$cands" ] || [ -n "$OLD_VOLUME" ]; then
    docker image inspect "$IMAGE" >/dev/null 2>&1 || { say "Stopped: the image $IMAGE is not built yet, so the old data cannot be copied. Run ./update_container.sh --force first."; return 1; }
    if ! docker volume inspect "$NEW_VOLUME" >/dev/null 2>&1; then
      copy=1
    else
      new_volume_check "$HAS_MARKER_PY"; rc=$?
      if [ "$rc" -ge 125 ]; then say "Stopped: could not read the volume $NEW_VOLUME; nothing was changed."; return 1; fi
      if [ "$rc" -ne 0 ]; then
        # No marker: an older update script may have created it empty.
        new_volume_check "$IS_EMPTY_PY"; rc=$?
        if [ "$rc" -ge 125 ]; then say "Stopped: could not read the volume $NEW_VOLUME; nothing was changed."; return 1; fi
        if [ "$rc" -ne 0 ]; then
          say "Stopped: both the old data ($(printf '%s\n' $cands $OLD_VOLUME | sort -u | tr '\n' ' ' | sed 's/ $//')) and $NEW_VOLUME hold files, and this script did not fill $NEW_VOLUME, so it copies nothing rather than overwrite anything. Nothing was changed."
          say "  If the app on the new volume shows your data (you copied it yourself), keep it and remove the old volume:  docker volume rm <old volume>"
          say "  If it holds only what a first start wrote (no profiles), remove it and run this again:  docker rm -f $CONTAINER; docker volume rm $NEW_VOLUME"
          return 1
        fi
        copy=1; refill=1
      fi
    fi
    if [ -n "$copy" ] && [ -z "$OLD_VOLUME" ]; then
      n="$(printf '%s\n' "$cands" | grep -c .)"
      if [ "$n" -gt 1 ]; then
        say "Stopped: more than one volume holds data from before the rename, and this script will not guess which one is yours:"
        printf '%s\n' "$cands" | sed 's/^/    /' | tee -a "$LOG"
        say "Run it again naming the one to copy:  ./update_container.sh --old-volume <name>   (or ZME_OLD_VOLUME=<name>). Nothing was changed."
        return 2
      fi
      OLD_VOLUME="$cands"
    fi
  fi
  if [ -n "$copy" ]; then
    say "Moving to the new name: copying volume $OLD_VOLUME into $NEW_VOLUME (the old volume is kept)…"
    if [ -n "$refill" ]; then
      # The empty volume an older script made, and the never-used container
      # on it, go first (the container holds no data; the volume is empty).
      docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
      docker volume rm "$NEW_VOLUME" >/dev/null 2>&1 || { say "Stopped: could not replace the empty volume $NEW_VOLUME; nothing was copied."; return 1; }
    fi
    # Stop the old app first, so nothing writes to the old volume during the copy.
    for c in $olds; do docker stop "$c" >/dev/null 2>&1 || true; done
    docker volume create \
      --label com.docker.compose.project=zscaler-made-easy \
      --label com.docker.compose.volume=zscaler-made-easy-data "$NEW_VOLUME" >/dev/null || {
      for c in $olds; do docker start "$c" >/dev/null 2>&1 || true; done
      say "Stopped: could not create the volume $NEW_VOLUME; nothing was copied and the old container runs as before."
      return 1
    }
    # One short-lived container from the image just built (nothing is
    # pulled). It runs as root only because the image's user cannot write
    # into a new, empty volume or keep other owners; it keeps only the
    # capabilities cp -a needs, has no network, a read-only root, and the
    # old volume mounted read-only. The app's own container is unchanged.
    if docker run --rm --network none --read-only --user 0 \
         --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
         --security-opt no-new-privileges:true \
         -v "$OLD_VOLUME":/from:ro -v "$NEW_VOLUME":/to \
         --entrypoint sh "$IMAGE" -c 'cp -a /from/. /to/' 2>&1 | tee -a "$LOG" \
       && docker run --rm --network none --read-only --user 0 --cap-drop ALL --cap-add DAC_OVERRIDE \
         --security-opt no-new-privileges:true \
         -v "$OLD_VOLUME":/from:ro -v "$NEW_VOLUME":/to:ro \
         --entrypoint python "$IMAGE" -c "$VERIFY_PY" 2>&1 | tee -a "$LOG" \
       && docker run --rm --network none --read-only --user 0 --cap-drop ALL --cap-add DAC_OVERRIDE \
         --security-opt no-new-privileges:true -e ZME_FROM="$OLD_VOLUME" \
         -v "$NEW_VOLUME":/to \
         --entrypoint python "$IMAGE" -c "$MARK_PY" 2>&1 | tee -a "$LOG"; then
      say "Copied $OLD_VOLUME into $NEW_VOLUME; every file arrived with the same size, mode and owner."
    else
      # Remove only the half-filled volume this run created, so the next run
      # copies afresh; start the old app again so nothing is lost or down.
      docker volume rm "$NEW_VOLUME" >/dev/null 2>&1 || true
      for c in $olds; do docker start "$c" >/dev/null 2>&1 || true; done
      say "Stopped: copying $OLD_VOLUME into $NEW_VOLUME failed (see the lines above). The new container was NOT started; the old data is untouched and the old container runs as before."
      return 1
    fi
  fi
  # The old container would hold port 8001: remove it (its volume stays).
  for c in $olds; do
    docker rm -f "$c" >/dev/null 2>&1 && say "Removed the old container $c (its data volume is kept)." || true
  done
  for c in $(old_volumes); do
    say "The old volume $c is kept as a backup; once the app works with your data, remove it with:  docker volume rm $c"
  done
  return 0
}

if [ -n "$MIGRATE_ONLY" ]; then
  command -v docker >/dev/null || { say "docker is not installed or not on PATH."; exit 1; }
  migrate_old_data || exit $?
  exit 0
fi
if [ -n "$SCHEDULE" ]; then
  command -v crontab >/dev/null || { echo "crontab is not available; schedule '$DIR/update_container.sh' with your system's scheduler instead."; exit 1; }
  ( crontab -l 2>/dev/null | grep -v "$MARK" ; echo "17 3 * * * '$DIR/update_container.sh' >/dev/null 2>&1 $MARK" ) | crontab -
  say "Scheduled: every day at 03:17 this computer runs $DIR/update_container.sh, updating from the branch checked out then (log: $LOG)."
fi

command -v git >/dev/null || { say "git is not installed; install it and run this again."; exit 1; }
command -v docker >/dev/null || { say "docker is not installed or not on PATH."; exit 1; }
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  say "This folder is not a git clone (a ZIP download), so it cannot pull updates. Clone it once:"
  say "  git clone https://github.com/berserkerjay/Zscaler-Made-Easy.git && cd Zscaler-Made-Easy && ./update_container.sh --force"
  exit 1
fi
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  say "Stopped: files in this folder were edited by hand and an update would overwrite them:"
  git status --porcelain --untracked-files=no | tee -a "$LOG"
  say "Put settings in .env instead (see INSTALL.md), then run: git checkout -- <file> and this script again."
  exit 1
fi
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
LOCAL="$(git rev-parse --short HEAD)"
if [ -n "$WANT" ] && [ "$WANT" != "$BRANCH" ]; then
  git fetch --quiet origin "$WANT" || { say "Could not fetch $WANT from GitHub; nothing was changed."; exit 1; }
  if git show-ref --verify --quiet "refs/heads/$WANT"; then git checkout --quiet "$WANT"; else git checkout --quiet -b "$WANT" --track "origin/$WANT"; fi
  say "Switched from $BRANCH to $WANT; later runs and the schedule update from $WANT."
  BRANCH="$WANT"; FORCE=1   # a different branch is always rebuilt
fi
git fetch --quiet origin "$BRANCH"
REMOTE="$(git rev-parse --short "origin/$BRANCH")"
if [ "$(git rev-parse --short HEAD)" = "$REMOTE" ] && [ -z "$FORCE" ] && docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" && ! migration_pending; then
  say "Up to date: $BRANCH is on $LOCAL and the container is running."
  exit 0
fi
[ "$(git rev-parse --short HEAD)" != "$REMOTE" ] && git pull --ff-only --quiet origin "$BRANCH"
export DLP_CHECK_BUILD_COMMIT="$(git rev-parse --short HEAD)" DLP_CHECK_BUILD_BRANCH="$BRANCH"
say "Building $BRANCH at $DLP_CHECK_BUILD_COMMIT (was $LOCAL) and restarting the container…"
docker compose build 2>&1 | tee -a "$LOG" || { say "The build failed; the previous container keeps running. See the lines above (TLS inspection: INSTALL.md, certs folder)."; exit 1; }
# Copy data from before the rename (once), then start the new container.
migrate_old_data || exit $?
docker compose up -d 2>&1 | tee -a "$LOG"
docker image prune -f >/dev/null 2>&1 || true
say "Done. The new UI token and address: docker logs $CONTAINER"
