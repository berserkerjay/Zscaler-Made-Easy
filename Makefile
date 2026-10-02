# One set of targets for both delivery modes; both build from this tree.
#   make install    local install (.venv + hash-pinned dependencies + dlp-check command)
#   make run        start the web app locally
#   make test       the test suite
#   make check      compile, lint (pyflakes), pack conventions, Terraform freshness: what CI runs
#   make docker     build the container image
#   make docker-run start the container (loopback publish, read-only, non-root)
PY ?= .venv/bin/python

.PHONY: install dev run stop test check docker docker-run lock sbom upstream

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
	$(PY) pack_terraform.py --out terraform && git diff --exit-code -- terraform && test -z "$$(git status --porcelain -- terraform)"
	@if command -v terraform >/dev/null 2>&1; then $(PY) tools/terraform_samples.py /tmp/dlp_check_tf_samples && terraform fmt -check -recursive terraform /tmp/dlp_check_tf_samples/vendor_hcl /tmp/dlp_check_tf_samples/containment /tmp/dlp_check_tf_samples/endpoint; else echo "terraform not installed: fmt check skipped here (CI runs it)"; fi
	$(PY) upstream_check.py --offline --quiet

# The daily upstream check (also .github/workflows/upstream_check.yml): the
# installed SDK against PyPI's latest release and the 2.x prerelease's ZIA
# service definition, the Terraform provider pin and schema against the
# registry and the generator's output, Zscaler's API reference.
upstream:
	$(PY) upstream_check.py --md upstream_report.md

docker:
	docker build -t dlp-check .

docker-run:
	docker compose up --build

# Re-pin the dependencies (after editing requirements.txt / pyproject.toml, or
# when CI reports the lock stale). The lock is resolved for every platform at
# once (--universal), so it also pins the Windows-only dependencies (pywin32,
# colorama) behind sys_platform markers; pip-compile resolves only for the
# machine it runs on and drops them, and every installer uses --no-deps, so a
# dependency missing from the lock is never installed. --upgrade refreshes
# existing pins to what the index offers now.
lock:
	$(PY) -m pip install --quiet uv
	$(PY) -m uv pip compile --universal --python-version 3.11 --generate-hashes --upgrade --output-file requirements.lock requirements.txt

# Rebuild docs/sbom.cdx.json and THIRD_PARTY_NOTICES.md (docs/SBOM.md); run
# after make lock or a Terraform provider upgrade. CI fails when they are stale.
sbom:
	$(PY) -m pip install --quiet cyclonedx-bom==7.5.0
	$(PY) -m cyclonedx_py requirements --pyproject pyproject.toml --mc-type application --output-reproducible --of JSON -o docs/sbom.cdx.json requirements.lock
	$(PY) tools/sbom_enrich.py docs/sbom.cdx.json
