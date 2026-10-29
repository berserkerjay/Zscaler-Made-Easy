# Software bill of materials

`docs/sbom.cdx.json` is a CycloneDX 1.6 JSON SBOM of Zscaler Made Easy's own
dependencies, the Python packages and the Terraform provider:

- every Python package pinned in `requirements.lock`, with its exact version,
  package URL, the wheel hashes the installers verify and its SPDX licence.
  It covers every platform the lock covers, so the Windows-only `pywin32` and
  `colorama` are listed too, as are `keyring` (the credential store for
  remembered profile secrets, pinned for Windows and macOS) and the packages
  it pulls in (`pywin32-ctypes`, the `jaraco` packages, `more-itertools`);
- the Terraform provider the policy packs use (`zscaler/zia`, pinned in
  `terraform/*/.terraform.lock.hcl`), with its licence (MPL-2.0);
- Zscaler Made Easy itself as the root component (`LicenseRef-DLP-Check-Internal`,
  the terms in `LICENSE`).

It holds the dependency graph too. The root depends on the packages
`requirements.txt` asks for and on the Terraform provider, and each package
depends on the packages that pulled it in, as the lock's `# via` comments
record. So any component can be traced back to a direct dependency: for
example, jwcrypto (LGPL) is there because of zscaler-sdk-python. Each Python
component's `bom-ref` is its package URL (`pkg:pypi/<name>@<version>`).

## What it does not cover: the container image's base

The container image is built on `python:3.11-slim-trixie` (see the
`Dockerfile`). Its CPython 3.11 runtime and the Debian packages the
Dockerfile keeps (glibc, OpenSSL's library, zlib, dash, coreutils and the
libraries they need) are not in `docs/sbom.cdx.json`. The base tag floats so
that each build picks up Debian and Python security releases, so a committed
inventory of it would go stale on the next build. Instead, the `container`
job in CI builds the image and writes a CycloneDX SBOM of it with Trivy,
listing every OS package and Python package in the image with its licence.
It uploads that SBOM as the `image-sbom` artifact. To produce the same file
for a local image:

```sh
docker build -t dlp-check:local .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/out" \
  aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa image --format cyclonedx --output /out/image-sbom.cdx.json dlp-check:local
```

`THIRD_PARTY_NOTICES.md` ends with a "Container image" section that names
the base image and the licences of the main components it keeps: PSF-2.0 for
CPython, LGPL-2.1-or-later for glibc, Apache-2.0 for OpenSSL, Zlib for zlib,
and GPL for dash and coreutils. It also gives the path of each component's
licence text inside the image.

`THIRD_PARTY_NOTICES.md` is the same inventory as a readable table, and
`third_party_licenses/` holds the full texts of the copyleft licences in it
(LGPL-3.0 and GPL-3.0 for jwcrypto, MPL-2.0 for certifi and the provider,
LGPL-2.1 for the adodbapi part of pywin32). CI rebuilds both on every push
(the `supply-chain` job), fails when the committed files differ, and uploads
the SBOM as the `sbom` artifact.

## Regenerate it

Do this whenever `requirements.lock` changes (after `make lock`) or a
Terraform provider is upgraded. `make sbom` runs the same commands:

```sh
python -m pip install --require-hashes --no-deps -r requirements-ci.lock   # cyclonedx-bom, hash-pinned
cyclonedx-py requirements --pyproject pyproject.toml --mc-type application \
  --output-reproducible --of JSON -o docs/sbom.cdx.json requirements.lock
python tools/sbom_enrich.py docs/sbom.cdx.json
```

`cyclonedx-py requirements` reads only the lock, which holds no licence data
and no Terraform provider, and it leaves the dependency graph flat, with
lock line numbers as references. `tools/sbom_enrich.py` adds each component's
licence from `tools/third_party_licenses.json` and the Terraform providers
from the lockfiles. It also replaces the references with package URLs, builds
the graph from the lock's `# via` comments, and rewrites
`THIRD_PARTY_NOTICES.md`. It stops with an
error naming any package that has no licence recorded there: add the
package's SPDX licence (its `License-Expression` metadata, or its LICENSE
file) to that JSON file, and, if the licence is copyleft, add its text to
`third_party_licenses/` and to `LICENCE_TEXTS` in the script.

`--output-reproducible` leaves out the timestamp and the random serial number,
so the file only changes when the pins change. `tests/test_lock_platforms.py`
fails when the SBOM and the lock list different packages or versions, and
`tests/test_sbom_licences.py` fails when a component has no licence, the
provider is missing, or the SBOM and notices are not what the script produces.
`tests/test_sbom_graph.py` fails when a component is not reachable from the
root, when an edge does not match the lock, or when the base-image coverage
described here is no longer true.

## Re-locking

`make lock` resolves the lock for every platform at once
(`uv pip compile --universal --python-version 3.11 --generate-hashes --upgrade`).
Platform-only dependencies are kept with their `sys_platform` markers, so the
`--no-deps` installs on Windows, Linux, macOS and in the container all get a
complete set. After re-locking, run `pip-audit -r requirements.lock --disable-pip --strict`
and `make sbom`. CI audits every lock (`requirements.lock`, `requirements-dev.lock`
and the CI tools' `requirements-ci.lock` and `requirements-pip.lock`) on Linux,
and the first three again on Windows, where the Windows-only pins are resolved.
The tools CI runs (pip, uv, pip-audit, cyclonedx-bom, and PyInstaller for the
standalone builds) are installed from those two hash-pinned locks too
(`make lock-ci` re-pins them). The standalone edition embeds the packages of
`requirements.lock` and the CPython it was built with; each release build
carries signed SLSA build provenance (`.github/workflows/release-standalone.yml`).
