#!/usr/bin/env bash
# Update the DLP-Check container: pull the latest code for this checkout's
# branch from GitHub and rebuild the container, only when GitHub has
# something new. Run it on the computer that runs Docker, from the folder
# that holds docker-compose.yml (a git clone, not a ZIP).
#
#   ./update_container.sh              update now if GitHub is ahead
#   ./update_container.sh --force      rebuild even when already up to date
#   ./update_container.sh --schedule   also update automatically every day at 03:17
#   ./update_container.sh --unschedule stop the automatic update
#
# Saved data (profiles, deployment records, audit log, uploaded packs) is in
# the dlpcheck-data volume and survives the rebuild. The rebuild restarts
# the app, which prints a new UI token (docker logs dlp-check).
set -euo pipefail
cd "$(dirname "$0")"
DIR="$(pwd)"
LOG="$DIR/update_container.log"
say() { echo "$(date '+%Y-%m-%d %H:%M:%S')  $*" | tee -a "$LOG"; }
MARK="# DLP-Check container auto-update"

case "${1:-}" in
  --schedule)
    command -v crontab >/dev/null || { echo "crontab is not available; schedule '$DIR/update_container.sh' with your system's scheduler instead."; exit 1; }
    ( crontab -l 2>/dev/null | grep -v "$MARK" ; echo "17 3 * * * '$DIR/update_container.sh' >/dev/null 2>&1 $MARK" ) | crontab -
    say "Scheduled: every day at 03:17 this computer runs $DIR/update_container.sh (log: $LOG)."
    ;;
  --unschedule)
    ( crontab -l 2>/dev/null | grep -v "$MARK" ) | crontab - || true
    say "Automatic update removed."
    exit 0
    ;;
  ""|--force) ;;
  *) echo "Unknown option $1. Use --force, --schedule or --unschedule."; exit 2 ;;
esac

command -v git >/dev/null || { say "git is not installed; install it and run this again."; exit 1; }
command -v docker >/dev/null || { say "docker is not installed or not on PATH."; exit 1; }
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  say "This folder is not a git clone (a ZIP download), so it cannot pull updates. Clone it once:"
  say "  git clone https://github.com/berserkerjay/DLP-Check.git && cd DLP-Check && ./update_container.sh --force"
  exit 1
fi
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  say "Stopped: files in this folder were edited by hand and an update would overwrite them:"
  git status --porcelain --untracked-files=no | tee -a "$LOG"
  say "Put settings in .env instead (see INSTALL.md), then run: git checkout -- <file> and this script again."
  exit 1
fi
git fetch --quiet origin "$BRANCH"
LOCAL="$(git rev-parse --short HEAD)"; REMOTE="$(git rev-parse --short "origin/$BRANCH")"
if [ "$LOCAL" = "$REMOTE" ] && [ "${1:-}" != "--force" ] && docker ps --format '{{.Names}}' | grep -qx dlp-check; then
  say "Up to date: $BRANCH is on $LOCAL and the container is running."
  exit 0
fi
[ "$LOCAL" != "$REMOTE" ] && git pull --ff-only --quiet origin "$BRANCH"
export DLP_CHECK_BUILD_COMMIT="$(git rev-parse --short HEAD)" DLP_CHECK_BUILD_BRANCH="$BRANCH"
say "Building $BRANCH at $DLP_CHECK_BUILD_COMMIT (was $LOCAL) and restarting the container…"
docker compose up -d --build 2>&1 | tee -a "$LOG"
docker image prune -f >/dev/null 2>&1 || true
say "Done. The new UI token and address: docker logs dlp-check"
