# One set of targets for both delivery modes; both build from this tree.
#   make install    local install (.venv + hash-pinned dependencies + dlp-check command)
#   make run        start the web app locally
#   make test       the test suite
#   make check      compile, lint (pyflakes), pack conventions, Terraform freshness: what CI runs
#   make docker     build the container image
#   make docker-run start the container (loopback publish, read-only, non-root)
PY ?= .venv/bin/python

.PHONY: install dev run stop test check docker docker-run lock

install:
	./install.sh

# Test and lint tools into the same environment (pytest, pyflakes, httpx).
dev: install
	$(PY) -m pip install --quiet --disable-pip-version-check -e ".[dev]"

run:
	./start.sh

stop:
	./stop.sh

test:
	$(PY) -m pytest -q tests

check:
	$(PY) -m py_compile $$(git ls-files '*.py')
	$(PY) -m pyflakes $$(git ls-files '*.py' | grep -v '^tests/') || true
	$(PY) tools/fan_out_channels.py --check
	$(PY) pack_terraform.py --out terraform && git diff --exit-code -- terraform

docker:
	docker build -t dlp-check .

docker-run:
	docker compose up --build

# Re-pin the dependencies (after editing requirements.txt / pyproject.toml, or
# when CI reports the lock stale). --upgrade is what makes pip-compile refresh
# existing pins to what the index offers now, the way CI's fresh compile does.
lock:
	$(PY) -m pip install --quiet pip-tools
	$(PY) -m piptools compile --upgrade --generate-hashes --allow-unsafe --output-file=requirements.lock requirements.txt
