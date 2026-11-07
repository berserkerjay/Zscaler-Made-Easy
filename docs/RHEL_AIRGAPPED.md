# RHEL service and air-gapped install

Neither script below is run by the app. An operator runs them.

## Run as a service (RHEL and compatible)
1. `./install.sh` in the app folder (makes `.venv`).
2. `sudo deploy/rhel/install_service.sh --now`

The unit (`deploy/rhel/zscaler-made-easy.service`) runs as the unprivileged
user `zscaler-made-easy`, listens on `127.0.0.1:8000` only, keeps its data in
`/var/lib/zscaler-made-easy` (mode 0700) and is sandboxed (no new privileges,
read-only system, no home access). Tenant writes stay refused. Settings such as a
proxy come from `local_settings.env` in the app folder.

## Air-gapped install
On a machine with internet: `deploy/rhel/build_wheelhouse.sh /path/wheelhouse`
(add `--with-delivery` for the optional SFTP/SMB packages). It downloads every
dependency pinned by hash in `requirements.lock`, then writes `SHA256SUMS`.
Copy the app folder and the wheelhouse to the offline host, check
`sha256sum -c SHA256SUMS`, then:

    python3 -m venv .venv
    .venv/bin/python -m pip install --no-index --find-links wheelhouse/wheels \
        --require-hashes --no-deps -r wheelhouse/requirements.lock
    .venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e .

Then `sudo deploy/rhel/install_service.sh --now`. The log pipeline (watched
folder, syslog listener, `log_pipeline_cli.py`) works fully offline.
