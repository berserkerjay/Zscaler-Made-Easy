# DLP-Check in a container: pinned base, hash-pinned dependencies, no root,
# read-only filesystem, loopback publish. Build:  docker build -t dlp-check .
# Run (see docker-compose.yml for the full set of flags):
#   docker run --rm -p 127.0.0.1:8000:8000 -v dlpcheck-data:/data --read-only --tmpfs /tmp dlp-check
# The UI token is printed on the container's console (docker logs) and
# written to /data/ui_token.txt; open http://localhost:8000/?token=<it>.
FROM python:3.11.9-slim-bookworm AS base

# Pin the base image by digest for a reproducible build:
#   docker pull python:3.11.9-slim-bookworm && docker inspect --format='{{index .RepoDigests 0}}' python:3.11.9-slim-bookworm
# then replace the tag above with python@sha256:<digest>.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system dlpcheck && useradd --system --gid dlpcheck --home-dir /app --shell /usr/sbin/nologin dlpcheck

WORKDIR /app
COPY requirements.lock requirements.txt ./
# Hash-pinned install: every wheel must match requirements.lock.
RUN python -m pip install --require-hashes --no-deps -r requirements.lock

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
    DLP_CHECK_IN_CONTAINER=1

USER dlpcheck
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/ping', timeout=4).status == 200 else 1)"
CMD ["python", "dlp_api_server.py"]
