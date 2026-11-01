# Extra root certificates for the container build

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Only needed on a network with TLS inspection (Zscaler or another proxy),
where `docker compose up --build` fails with `CERTIFICATE_VERIFY_FAILED`.

Put your organisation's root certificate here as a Base-64 (PEM) file
ending in `.crt`, `.pem` or `.cer`, then build again. INSTALL.md, section
"Run it in a container instead", has a one-line PowerShell command that
exports the Zscaler root certificate into this folder.

Certificate files here are git-ignored, so they stay on this machine.
