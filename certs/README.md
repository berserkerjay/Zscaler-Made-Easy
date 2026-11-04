# Extra root certificates for the container build

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Only needed on a network with TLS inspection (Zscaler or another proxy),
where `docker compose up --build` fails with `CERTIFICATE_VERIFY_FAILED`.

Put your organisation's root certificate here as a Base-64 (PEM) file
ending in `.crt`, `.pem` or `.cer`, then build again (`./update_container.sh`,
`update_container.ps1`, or `docker compose up -d --build`). The build log
says `extra root certificates added: 1`; the image's trust store (pip,
Python, the Zscaler SDK and the app) then trusts it at build and at run time.

Easiest: from the app folder run `./get_zscaler_cert.sh` (Mac/Linux) or
`powershell -ExecutionPolicy Bypass -File .\get_zscaler_cert.ps1` (Windows).
Or export the Zscaler Root CA into this folder by hand:

- **Mac:** `security find-certificate -c "Zscaler Root CA" -p > certs/zscaler-root.crt`
- **Windows (PowerShell):**

  ```powershell
  $c = Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*Zscaler Root CA*" } | Select-Object -First 1
  if (-not $c) { "Zscaler Root CA not found: ask IT for the root certificate as a Base-64 .crt file and save it in the certs folder" } else { "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n" | Set-Content -Encoding ascii -NoNewline certs\zscaler-root.crt; "Saved certs\zscaler-root.crt" }
  ```

- **Linux / another inspection product:** copy the Base-64 root
  certificate IT gave you here, ending in `.crt`.

Or ask IT to exempt `pypi.org` and `files.pythonhosted.org` from inspection.

Certificate files here are git-ignored, so they stay on this machine.
