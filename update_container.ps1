# Update the DLP-Check container on Windows: pull the latest code for this
# checkout's branch from GitHub and rebuild the container, only when GitHub
# has something new. Run it from the folder that holds docker-compose.yml
# (a git clone, not a ZIP):
#
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1              update now if GitHub is ahead
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Branch qa   switch to a branch (main, qa or dev) and update from it
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Force       rebuild even when up to date
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Schedule    also update every day at 03:17
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Unschedule  stop the automatic update
#
# main is what customers run; qa and dev carry changes before they are
# promoted (dev -> qa -> main). The branch chosen stays checked out, so
# later runs and the daily schedule keep updating from it.
#
# Saved data is in the dlpcheck-data volume and survives the rebuild. The
# rebuild restarts the app, which prints a new UI token (docker logs dlp-check).
param([switch]$Force, [switch]$Schedule, [switch]$Unschedule,
      [ValidateSet('main', 'qa', 'dev', 'DLP-CHECK-QA')][string]$Branch = '')
# PowerShell names are case-insensitive: $Branch is $branch, which is set
# to the checked-out branch below, so keep the requested one apart first.
$want = if (-not $Branch) { '' } elseif ($Branch -ieq 'DLP-CHECK-QA') { 'qa' } else { $Branch.ToLower() }   # QA's old name; git names are case-sensitive
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$Log = Join-Path $PSScriptRoot 'update_container.log'
$TaskName = 'DLP-Check container update'
function Say($m) { $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m"; Write-Host $line; Add-Content -LiteralPath $Log -Value $line }

if ($Unschedule) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Say 'Automatic update removed.'; exit 0
}
if ($Schedule) {
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -WorkingDirectory $PSScriptRoot
  $trigger = New-ScheduledTaskTrigger -Daily -At '03:17'
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description 'Pulls DLP-Check from GitHub and rebuilds its container when there is an update.' -Force | Out-Null
  Say "Scheduled: every day at 03:17 (and at the next start if the computer was off) Windows runs $PSCommandPath, updating from the branch checked out then. Log: $Log"
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Say 'git is not installed; install Git for Windows and run this again.'; exit 1 }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Say 'docker is not installed or not on PATH; start Docker Desktop and run this again.'; exit 1 }
git rev-parse --is-inside-work-tree 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  Say 'This folder is not a git clone (a ZIP download), so it cannot pull updates. Clone it once:'
  Say '  git clone https://github.com/berserkerjay/DLP-Check.git; cd DLP-Check; powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Force'
  exit 1
}
$dirty = git status --porcelain --untracked-files=no
if ($dirty) {
  Say 'Stopped: files in this folder were edited by hand and an update would overwrite them:'
  $dirty | ForEach-Object { Say "  $_" }
  Say 'Put settings in .env instead (see INSTALL.md), then run: git checkout -- <file> and this script again.'
  exit 1
}
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
$before = (git rev-parse --short HEAD).Trim()
if ($want -and $want -ne $branch) {
  git fetch --quiet origin $want
  if ($LASTEXITCODE -ne 0) { Say "Could not fetch $want from GitHub; nothing was changed."; exit 1 }
  git show-ref --verify --quiet "refs/heads/$want"
  if ($LASTEXITCODE -eq 0) { git checkout --quiet $want } else { git checkout --quiet -b $want --track "origin/$want" }
  if ($LASTEXITCODE -ne 0) { Say "Could not switch to $want; nothing was changed."; exit 1 }
  Say "Switched from $branch to $want; later runs and the schedule update from $want."
  $branch = $want; $Force = [switch]$true   # a different branch is always rebuilt
}
git fetch --quiet origin $branch
if ($LASTEXITCODE -ne 0) { Say "Could not reach GitHub (git fetch failed). Check the network or TLS inspection, then run this again."; exit 1 }
$local = (git rev-parse --short HEAD).Trim(); $remote = (git rev-parse --short "origin/$branch").Trim()
$running = (docker ps --format '{{.Names}}') -contains 'dlp-check'
if ($local -eq $remote -and -not $Force -and $running) { Say "Up to date: $branch is on $local and the container is running."; exit 0 }
if ($local -ne $remote) { git pull --ff-only --quiet origin $branch; if ($LASTEXITCODE -ne 0) { Say 'git pull failed; nothing was changed.'; exit 1 } }
$env:DLP_CHECK_BUILD_COMMIT = (git rev-parse --short HEAD).Trim(); $env:DLP_CHECK_BUILD_BRANCH = $branch
Say "Building $branch at $($env:DLP_CHECK_BUILD_COMMIT) (was $before) and restarting the container..."
docker compose up -d --build 2>&1 | ForEach-Object { Add-Content -LiteralPath $Log -Value "$_"; Write-Host $_ }
if ($LASTEXITCODE -ne 0) { Say 'The build failed; the previous container keeps running. See the lines above (TLS inspection: INSTALL.md, certs folder).'; exit 1 }
docker image prune -f 2>$null | Out-Null
Say 'Done. The new UI token and address: docker logs dlp-check'
