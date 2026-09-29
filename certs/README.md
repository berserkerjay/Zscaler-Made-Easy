# Extra root certificates for the container build

Only needed on a network with TLS inspection (Zscaler or another proxy),
where `docker compose up --build` fails with `CERTIFICATE_VERIFY_FAILED`.

Put your organisation's root certificate here as a Base-64 (PEM) file
ending in `.crt`, `.pem` or `.cer`, then build again. INSTALL.md, section
"Run it in a container instead", has a one-line PowerShell command that
exports the Zscaler root certificate into this folder.

Certificate files here are git-ignored, so they stay on this machine.
