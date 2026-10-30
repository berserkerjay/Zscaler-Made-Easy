# Update the Zscaler Made Easy container on Windows: pull the latest code for this
# checkout's branch from GitHub and rebuild the container, only when GitHub
# has something new. Run it from the folder that holds docker-compose.yml
# (a git clone, not a ZIP):
#
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1              update now if GitHub is ahead
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Branch qa   switch to a branch (main, qa or dev) and update from it
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Force       rebuild even when up to date
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Schedule    also update every day at 03:17
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Unschedule  stop the automatic update
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -OldVolume NAME  which old data volume to copy, when there are several
#   powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -MigrateOnly     only copy the old data across (the image must be built)
#
# main is what customers run; qa and dev carry changes before they are
# promoted (dev -> qa -> main). The branch chosen stays checked out, so
# later runs and the daily schedule keep updating from it.
#
# Saved data is in the zscaler-made-easy-data volume and survives the
# rebuild. The rebuild restarts the app, which prints a new UI token
# (docker logs zscaler-made-easy).
#
# Moving to the new name: before the rename the container was dlp-check and
# the data was on a volume called dlpcheck-data or <folder>_dlpcheck-data.
# The first run after the rename COPIES that volume into
# zscaler-made-easy-data (it never moves or deletes it), then removes the old
# container so port 8001 is free. Later runs copy nothing. With more than one
# old volume it asks which one: -OldVolume NAME or $env:ZME_OLD_VOLUME.
param([switch]$Force, [switch]$Schedule, [switch]$Unschedule, [switch]$MigrateOnly,
      [string]$OldVolume = $env:ZME_OLD_VOLUME,
      [ValidateSet('main', 'qa', 'dev', 'DLP-CHECK-QA')][string]$Branch = '')
# PowerShell names are case-insensitive: $Branch is $branch, which is set
# to the checked-out branch below, so keep the requested one apart first.
$want = if (-not $Branch) { '' } elseif ($Branch -ieq 'DLP-CHECK-QA') { 'qa' } else { $Branch.ToLower() }   # QA's old name; git names are case-sensitive
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$Log = Join-Path $PSScriptRoot 'update_container.log'
$TaskName = 'Zscaler Made Easy container update'
function Say($m) { $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m"; Write-Host $line; Add-Content -LiteralPath $Log -Value $line }

# ── Moving to the new name ────────────────────────────────────────────────
$NewVolume = 'zscaler-made-easy-data'
$Image = 'zscaler-made-easy:local'
$Container = 'zscaler-made-easy'
$OldVolumeRe = '^(dlpcheck-data|.+_dlpcheck-data)$'     # docker run -v dlpcheck-data, or compose's <project>_dlpcheck-data
$OldContainerRe = '^(dlp-check|.+-dlp-check-.+)$'       # container_name dlp-check, or compose's <project>-dlp-check-1
# The image's own Python checks the copy: every file and folder arrived with
# the same size, mode and owner. Single quotes only, so the line passes
# through Windows PowerShell's argument quoting unchanged.
$VerifyPy = "import os,sys;st=lambda r:{(os.path.relpath(os.path.join(d,n),r),s.st_mode,s.st_uid,s.st_gid,0 if os.path.isdir(os.path.join(d,n)) else s.st_size) for d,ds,fs in os.walk(r) for n in ds+fs for s in [os.lstat(os.path.join(d,n))]};sys.exit(0 if st('/from')==st('/to') else 1)"

function Invoke-Docker([string[]]$DockerArgs) {
  # docker writes progress to stderr; judge it by its exit code only.
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { docker @DockerArgs 2>&1 | ForEach-Object { Add-Content -LiteralPath $Log -Value "$_"; Write-Host "$_" } }
  finally { $ErrorActionPreference = $eap }
  return $LASTEXITCODE
}
function Test-Volume([string]$name) { $ErrorActionPreference = 'Continue'; docker volume inspect $name 2>$null | Out-Null; return ($LASTEXITCODE -eq 0) }
# Written into the new volume once the copy is verified: what tells a later
# run the move is done (a new volume without it may be one an older update
# script created empty). The checks are Python in the image, single quotes only.
$Marker = '.zscaler-made-easy-moved-from'
$HasMarkerPy = "import os,sys;sys.exit(0 if os.path.exists('/to/$Marker') else 1)"
$IsEmptyPy = "import os,sys;sys.exit(0 if not os.listdir('/to') else 1)"
$MarkPy = "import os;open('/to/$Marker','w').write(os.environ['ZME_FROM']+chr(10))"
# Run one check on the new volume, read-only, as the image's own user:
# 0 yes, 1 no, 125 or more: Docker could not run it.
function Test-NewVolume([string]$py) {
  $ErrorActionPreference = 'Continue'
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true -v "${NewVolume}:/to:ro" --entrypoint python $Image -c $py 2>$null | Out-Null
  return $LASTEXITCODE
}
function Get-OldVolumes { $ErrorActionPreference = 'Continue'; return @(docker volume ls -q 2>$null | Where-Object { $_ -match $OldVolumeRe }) }
# True while data from before the rename is still to be copied.
function Test-MigrationPending {
  if ((Get-OldVolumes).Count -eq 0) { return $false }
  if (-not (Test-Volume $NewVolume)) { return $true }
  return ((Test-NewVolume $HasMarkerPy) -ne 0)
}

# Returns 0 when the new container may start, else the exit code to stop with.
function Move-OldData {
  # docker's messages on stderr are not fatal here; every step is judged by
  # its exit code. (A local setting: the rest of the script keeps 'Stop'.)
  $ErrorActionPreference = 'Continue'
  $olds = @(docker ps -a --format '{{.Names}}' 2>$null | Where-Object { $_ -match $OldContainerRe })
  $cands = @(Get-OldVolumes)   # @() keeps one name a list (a function returns a single item unwrapped)
  $old = $script:OldVolume
  $copy = $false; $refill = $false
  if ($old -and -not (Test-Volume $old)) { Say "Stopped: there is no volume called $old; nothing was changed."; return 2 }
  if ($cands.Count -gt 0 -or $old) {
    docker image inspect $Image 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Say "Stopped: the image $Image is not built yet, so the old data cannot be copied. Run this script with -Force first."; return 1 }
    if (-not (Test-Volume $NewVolume)) {
      $copy = $true
    } else {
      $rc = Test-NewVolume $HasMarkerPy
      if ($rc -ge 125) { Say "Stopped: could not read the volume $NewVolume; nothing was changed."; return 1 }
      if ($rc -ne 0) {
        # No marker: an older update script may have created it empty.
        $rc = Test-NewVolume $IsEmptyPy
        if ($rc -ge 125) { Say "Stopped: could not read the volume $NewVolume; nothing was changed."; return 1 }
        if ($rc -ne 0) {
          $which = (@($cands) + @($old) | Where-Object { $_ } | Sort-Object -Unique) -join ' '
          Say "Stopped: both the old data ($which) and $NewVolume hold files, and this script did not fill $NewVolume, so it copies nothing rather than overwrite anything. Nothing was changed."
          Say '  If the app on the new volume shows your data (you copied it yourself), keep it and remove the old volume:  docker volume rm <old volume>'
          Say "  If it holds only what a first start wrote (no profiles), remove it and run this again:  docker rm -f $Container; docker volume rm $NewVolume"
          return 1
        }
        $copy = $true; $refill = $true
      }
    }
    if ($copy -and -not $old) {
      if ($cands.Count -gt 1) {
        Say 'Stopped: more than one volume holds data from before the rename, and this script will not guess which one is yours:'
        $cands | ForEach-Object { Say "    $_" }
        Say 'Run it again naming the one to copy:  powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -OldVolume <name>   (or set ZME_OLD_VOLUME=<name>). Nothing was changed.'
        return 2
      }
      $old = $cands[0]
    }
  }
  if ($copy) {
    Say "Moving to the new name: copying volume $old into $NewVolume (the old volume is kept)..."
    if ($refill) {
      # The empty volume an older script made, and the never-used container
      # on it, go first (the container holds no data; the volume is empty).
      docker rm -f $Container 2>$null | Out-Null
      docker volume rm $NewVolume 2>$null | Out-Null
      if ($LASTEXITCODE -ne 0) { Say "Stopped: could not replace the empty volume $NewVolume; nothing was copied."; return 1 }
    }
    # Stop the old app first, so nothing writes to the old volume during the copy.
    foreach ($c in $olds) { docker stop $c 2>$null | Out-Null }
    docker volume create --label com.docker.compose.project=zscaler-made-easy --label com.docker.compose.volume=zscaler-made-easy-data $NewVolume 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
      foreach ($c in $olds) { docker start $c 2>$null | Out-Null }
      Say "Stopped: could not create the volume $NewVolume; nothing was copied and the old container runs as before."; return 1
    }
    # One short-lived container from the image just built (nothing is
    # pulled). It runs as root only because the image's user cannot write
    # into a new, empty volume or keep other owners; it keeps only the
    # capabilities cp -a needs, has no network, a read-only root, and the
    # old volume mounted read-only. The app's own container is unchanged.
    $copied = Invoke-Docker @('run', '--rm', '--network', 'none', '--read-only', '--user', '0',
      '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER', '--cap-add', 'FSETID',
      '--security-opt', 'no-new-privileges:true', '-v', "${old}:/from:ro", '-v', "${NewVolume}:/to",
      '--entrypoint', 'sh', $Image, '-c', 'cp -a /from/. /to/')
    if ($copied -eq 0) {
      $copied = Invoke-Docker @('run', '--rm', '--network', 'none', '--read-only', '--user', '0', '--cap-drop', 'ALL', '--cap-add', 'DAC_OVERRIDE',
        '--security-opt', 'no-new-privileges:true', '-v', "${old}:/from:ro", '-v', "${NewVolume}:/to:ro",
        '--entrypoint', 'python', $Image, '-c', $VerifyPy)
    }
    if ($copied -eq 0) {
      $copied = Invoke-Docker @('run', '--rm', '--network', 'none', '--read-only', '--user', '0', '--cap-drop', 'ALL', '--cap-add', 'DAC_OVERRIDE',
        '--security-opt', 'no-new-privileges:true', '-e', "ZME_FROM=$old", '-v', "${NewVolume}:/to",
        '--entrypoint', 'python', $Image, '-c', $MarkPy)
    }
    if ($copied -ne 0) {
      # Remove only the half-filled volume this run created, so the next run
      # copies afresh; start the old app again so nothing is lost or down.
      docker volume rm $NewVolume 2>$null | Out-Null
      foreach ($c in $olds) { docker start $c 2>$null | Out-Null }
      Say "Stopped: copying $old into $NewVolume failed (see the lines above). The new container was NOT started; the old data is untouched and the old container runs as before."
      return 1
    }
    Say "Copied $old into $NewVolume; every file arrived with the same size, mode and owner."
  }
  # The old container would hold port 8001: remove it (its volume stays).
  foreach ($c in $olds) {
    docker rm -f $c 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Say "Removed the old container $c (its data volume is kept)." }
  }
  foreach ($c in (Get-OldVolumes)) {
    Say "The old volume $c is kept as a backup; once the app works with your data, remove it with:  docker volume rm $c"
  }
  return 0
}

if ($MigrateOnly) {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Say 'docker is not installed or not on PATH; start Docker Desktop and run this again.'; exit 1 }
  exit (Move-OldData | Select-Object -Last 1)
}

if ($Unschedule) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Say 'Automatic update removed.'; exit 0
}
if ($Schedule) {
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -WorkingDirectory $PSScriptRoot
  $trigger = New-ScheduledTaskTrigger -Daily -At '03:17'
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description 'Pulls Zscaler Made Easy from GitHub and rebuilds its container when there is an update.' -Force | Out-Null
  Say "Scheduled: every day at 03:17 (and at the next start if the computer was off) Windows runs $PSCommandPath, updating from the branch checked out then. Log: $Log"
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Say 'git is not installed; install Git for Windows and run this again.'; exit 1 }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Say 'docker is not installed or not on PATH; start Docker Desktop and run this again.'; exit 1 }
git rev-parse --is-inside-work-tree 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  Say 'This folder is not a git clone (a ZIP download), so it cannot pull updates. Clone it once:'
  Say '  git clone https://github.com/berserkerjay/Zscaler-Made-Easy.git; cd Zscaler-Made-Easy; powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Force'
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
$running = (docker ps --format '{{.Names}}') -contains $Container
if ($local -eq $remote -and -not $Force -and $running -and -not (Test-MigrationPending)) { Say "Up to date: $branch is on $local and the container is running."; exit 0 }
if ($local -ne $remote) { git pull --ff-only --quiet origin $branch; if ($LASTEXITCODE -ne 0) { Say 'git pull failed; nothing was changed.'; exit 1 } }
$env:DLP_CHECK_BUILD_COMMIT = (git rev-parse --short HEAD).Trim(); $env:DLP_CHECK_BUILD_BRANCH = $branch
Say "Building $branch at $($env:DLP_CHECK_BUILD_COMMIT) (was $before) and restarting the container..."
# docker writes its build progress to stderr. Windows PowerShell 5.1 turns
# each such line into an error record, which 'Stop' makes fatal: the script
# died on the first progress line. Relax it for this one call and judge the
# build by docker's exit code instead.
$ErrorActionPreference = 'Continue'
docker compose build 2>&1 | ForEach-Object { Add-Content -LiteralPath $Log -Value "$_"; Write-Host "$_" }
$buildExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($buildExit -ne 0) { Say 'The build failed; the previous container keeps running. See the lines above (TLS inspection: INSTALL.md, certs folder).'; exit 1 }
# Copy data from before the rename (once), then start the new container.
$moved = Move-OldData | Select-Object -Last 1
if ($moved -ne 0) { exit $moved }
$ErrorActionPreference = 'Continue'
docker compose up -d 2>&1 | ForEach-Object { Add-Content -LiteralPath $Log -Value "$_"; Write-Host "$_" }
$upExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($upExit -ne 0) { Say 'Starting the container failed; see the lines above.'; exit 1 }
docker image prune -f 2>$null | Out-Null
Say "Done. The new UI token and address: docker logs $Container"
