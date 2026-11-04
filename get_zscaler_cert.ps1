# Copy this computer's Zscaler Root CA into certs\ so the container build
# (pip) and the running app trust Zscaler's TLS inspection.
# Usage: powershell -ExecutionPolicy Bypass -File .\get_zscaler_cert.ps1   (then update_container.ps1)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$name = if ($env:ZSCALER_CA_NAME) { $env:ZSCALER_CA_NAME } else { 'Zscaler Root CA' }
$out = Join-Path 'certs' 'zscaler-root.crt'
New-Item -ItemType Directory -Force -Path 'certs' | Out-Null
$c = Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*$name*" } | Select-Object -First 1
if (-not $c) { Write-Host "$name not found on this computer. Ask IT for the root certificate as a Base-64 .crt file and save it as $out."; exit 1 }
"-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n" | Set-Content -Encoding ascii -NoNewline $out
Write-Host "Saved $out. Now run update_container.ps1"
