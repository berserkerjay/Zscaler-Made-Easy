# DLP-Check in a container: pinned base, hash-pinned dependencies, no root,
# read-only filesystem, loopback publish. Build:  docker build -t dlp-check .
# Run (see docker-compose.yml for the full set of flags):
#   docker run --rm -p 127.0.0.1:8001:8000 -e DLP_CHECK_HOST_PORT=8001 -v dlpcheck-data:/data --read-only --tmpfs /tmp dlp-check
# The UI token is printed on the container's console (docker logs) and
# written to /data/ui_token.txt; open http://localhost:8001/?token=<it>.
# Extra root certificates for TLS inspection (see below): the certs/ folder
# of the build context. A build straight from the GitHub URL has no local
# certs/ folder, so it hands one in instead:
#   docker build --build-context certs=<folder with the .crt> ...
FROM scratch AS certs
COPY certs/ /

FROM python:3.11-slim-trixie AS base

# The floating 3.11 tag picks up the current Debian and Python security
# releases on every build (the image scan in CI fails on a stale base).
# To pin exactly for a reproducible build, replace the tag with the digest:
#   docker pull python:3.11-slim-trixie && docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim-trixie
# Debian 13 (trixie), not 12: bookworm's perl, util-linux, openssl and
# zlib carry critical and high CVEs Debian will not fix there.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Debian security updates for the packages the base image ships (openssl, perl, ...).
RUN apt-get update && apt-get -y --no-install-recommends upgrade && rm -rf /var/lib/apt/lists/*

RUN groupadd --system dlpcheck && useradd --system --gid dlpcheck --home-dir /app --shell /usr/sbin/nologin dlpcheck

WORKDIR /app

# Networks with TLS inspection (Zscaler or another proxy) re-sign HTTPS
# with the organisation's own root certificate, which this image does not
# trust: pip then fails with CERTIFICATE_VERIFY_FAILED on pypi.org, and the
# app fails the same way on the Zscaler API. Put that root certificate in
# certs/ as a Base-64 (PEM) file before building (INSTALL.md says how);
# it is added to the image's trust store, and pip, requests and Python's
# own ssl all use that store. With certs/ empty nothing changes. A build
# from the GitHub URL passes the folder as --build-context certs=<folder>.
COPY --from=certs / /tmp/extra-ca/
RUN set -e; n=0; \
    for f in /tmp/extra-ca/*.crt /tmp/extra-ca/*.pem /tmp/extra-ca/*.cer; do \
      [ -f "$f" ] || continue; \
      grep -q "BEGIN CERTIFICATE" "$f" || { echo "certs/$(basename "$f") is not a Base-64 (PEM) certificate; export it as Base-64 and build again" >&2; exit 1; }; \
      n=$((n+1)); cp "$f" "/usr/local/share/ca-certificates/extra-ca-$n.crt"; \
    done; \
    rm -rf /tmp/extra-ca; update-ca-certificates >/dev/null; echo "extra root certificates added: $n"
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

COPY requirements.lock requirements.txt ./
# Hash-pinned install: every wheel must match requirements.lock. Build
# tools (setuptools, wheel) are not needed at runtime and carry their own
# CVEs (pip also vendors old copies of msgpack and setuptools that image
# scanners flag), so pip, setuptools, wheel and the bundled ensurepip wheels
# are removed afterwards: nothing can install packages into the running
# image. The build fails if a copy of either survives.
RUN python -m pip install --require-hashes --no-deps -r requirements.lock \
 && python -m pip install --upgrade pip \
 && python -m pip uninstall -y setuptools wheel \
 && python -m pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3.11/ensurepip /usr/local/lib/python3.11/site-packages/pip* /usr/local/bin/pip* \
 && ! python -c "import setuptools" 2>/dev/null \
 && ! python -c "import pip" 2>/dev/null

# The commit and branch the image is built from (update_container.sh / .ps1
# pass them), so Update app can say whether GitHub has a newer build.
ARG DLP_CHECK_BUILD_COMMIT=unknown
ARG DLP_CHECK_BUILD_BRANCH=main
ENV DLP_CHECK_BUILD_COMMIT=$DLP_CHECK_BUILD_COMMIT \
    DLP_CHECK_BUILD_BRANCH=$DLP_CHECK_BUILD_BRANCH

COPY --chown=dlpcheck:dlpcheck . .
RUN rm -rf .git tests *.zip && mkdir -p /data && chown dlpcheck:dlpcheck /data

# The app runs Python and nothing else: it never calls perl, tar, mount,
# apt or the login tools, and does not use sqlite. Remove those packages
# (and the libraries only they need), so their CVEs are not in the image at
# all; nothing can install packages into the running image either. What
# stays is what Python needs to run: glibc, OpenSSL's library, zlib, and
# dash/coreutils for the shell. Last root step: the build fails if one of
# them is still installed, or if the app no longer imports.
RUN set -e; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt; \
    dpkg --purge --force-remove-essential --force-remove-protected --force-depends \
      apt libapt-pkg7.0 \
      perl-base tar diffutils \
      util-linux bsdutils mount login libblkid1 libmount1 libsmartcols1 libuuid1 liblastlog2-2 \
      passwd login.defs \
      libsystemd0 libudev1 \
      libsqlite3-0 \
      openssl openssl-provider-legacy; \
    for p in apt perl-base tar util-linux passwd libsystemd0 libsqlite3-0 openssl; do \
      ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || { echo "$p is still installed" >&2; exit 1; }; \
    done; \
    python -c "import ssl, zlib, hashlib, uuid, fastapi, uvicorn, requests, zscaler; ssl.create_default_context(); print('image trimmed; Python and its libraries still load')"

# Everything the app writes goes to /data (mount a volume there); the
# application directory itself stays read-only.
ENV ZSCALER_BIND_HOST=0.0.0.0 \
    ZSCALER_PORT=8000 \
    DLP_CHECK_PROFILES=/data/tenant_profiles.json \
    DLP_CHECK_DEPLOYMENTS=/data/deployments.json \
    DLP_CHECK_ZIA_RATE_STATE=/data/zia_rate.json \
    DLP_CHECK_AUDIT=/data/audit.log \
    DLP_CHECK_UI_TOKEN_DIR=/data \
    DLP_CHECK_DIGESTS=/data/digests \
    DLPCHECK_PROPOSALS_FILE=/data/proposals.json \
    DLP_CHECK_GUIDANCE_STATE=/data/guidance_state.json \
    DLP_CHECK_SAAS_MATRIX=/data/saas_apps.local.json \
    DLP_CHECK_BEACON_STATE=/data/beacon_state.json \
    DLP_CHECK_CHECKS_CONFIG=/data/checks_config.json \
    XDG_CACHE_HOME=/data/cache \
    DLP_CHECK_IN_CONTAINER=1

USER dlpcheck
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/ping', timeout=4).status == 200 else 1)"
CMD ["python", "dlp_api_server.py"]
