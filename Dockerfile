# DLP-Check in a container: pinned base, hash-pinned dependencies, no root,
# read-only filesystem, loopback publish. Build:  docker build -t dlp-check .
# Run (see docker-compose.yml for the full set of flags):
#   docker run --rm -p 127.0.0.1:8000:8000 -v dlpcheck-data:/data --read-only --tmpfs /tmp dlp-check
# The UI token is printed on the container's console (docker logs) and
# written to /data/ui_token.txt; open http://localhost:8000/?token=<it>.
FROM python:3.11-slim-bookworm AS base

# The floating 3.11 tag picks up the current Debian and Python security
# releases on every build (the image scan in CI fails on a stale base).
# To pin exactly for a reproducible build, replace the tag with the digest:
#   docker pull python:3.11-slim-bookworm && docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Debian security updates for the packages the base image ships (openssl, perl, ...).
RUN apt-get update && apt-get -y --no-install-recommends upgrade && rm -rf /var/lib/apt/lists/*

RUN groupadd --system dlpcheck && useradd --system --gid dlpcheck --home-dir /app --shell /usr/sbin/nologin dlpcheck

WORKDIR /app
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

COPY --chown=dlpcheck:dlpcheck . .
RUN rm -rf .git tests *.zip && mkdir -p /data && chown dlpcheck:dlpcheck /data

# Everything the app writes goes to /data (mount a volume there); the
# application directory itself stays read-only.
ENV ZSCALER_BIND_HOST=0.0.0.0 \
    ZSCALER_PORT=8000 \
    DLP_CHECK_PROFILES=/data/tenant_profiles.json \
    DLP_CHECK_DEPLOYMENTS=/data/deployments.json \
    DLP_CHECK_AUDIT=/data/audit.log \
    DLP_CHECK_UI_TOKEN_DIR=/data \
    DLP_CHECK_DIGESTS=/data/digests \
    DLPCHECK_PROPOSALS_FILE=/data/proposals.json \
    DLP_CHECK_GUIDANCE_STATE=/data/guidance_state.json \
    DLP_CHECK_SAAS_MATRIX=/data/saas_apps.local.json \
    DLP_CHECK_IN_CONTAINER=1

USER dlpcheck
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/ping', timeout=4).status == 200 else 1)"
CMD ["python", "dlp_api_server.py"]
