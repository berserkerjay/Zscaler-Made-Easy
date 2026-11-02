# Third-party notices

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Zscaler Made Easy itself is under the Apache License 2.0 ([LICENSE](LICENSE), with
its [NOTICE](NOTICE)). It runs with the
third-party components below, each under its own licence. This file is
generated from the SBOM ([docs/sbom.cdx.json](docs/sbom.cdx.json)) by
`python tools/sbom_enrich.py docs/sbom.cdx.json`; see [docs/SBOM.md](docs/SBOM.md).

Each Python package's own licence file, with its copyright notice, is
installed with it (in the package's `*.dist-info` folder). The full texts
of the copyleft licences are kept in [third_party_licenses/](third_party_licenses/):

- **LGPL-2.1-or-later** (pywin32 312): [LGPL-2.1.txt](third_party_licenses/LGPL-2.1.txt)
- **LGPL-3.0-or-later** (jwcrypto 1.6.0): [LGPL-3.0.txt](third_party_licenses/LGPL-3.0.txt) and [GPL-3.0.txt](third_party_licenses/GPL-3.0.txt)
- **MPL-2.0** (certifi 2026.10.23, zscaler/terraform-provider-zia 4.8.8): [MPL-2.0.txt](third_party_licenses/MPL-2.0.txt)

These components are used unmodified; their source is available from the
distribution links in the SBOM.

| Component | Version | Licence (SPDX) |
|---|---|---|
| aenum | 3.1.17 | BSD-3-Clause |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| arrow | 1.4.0 | Apache-2.0 |
| attrs | 26.1.0 | MIT |
| backports-tarfile | 1.2.0 | MIT |
| cbor2 | 6.1.5 | MIT |
| certifi | 2026.10.23 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD-3-Clause |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| defusedxml | 0.7.1 | PSF-2.0 |
| fastapi | 0.141.1 | MIT |
| h11 | 0.16.0 | MIT |
| httpcore2 | 2.13.0 | BSD-3-Clause |
| httpx2 | 2.13.0 | BSD-3-Clause |
| httpx2-jsfetch | 1.0 | BSD-3-Clause |
| idna | 3.19 | BSD-3-Clause |
| importlib-metadata | 9.0.1 | Apache-2.0 |
| jaraco-classes | 3.4.0 | MIT |
| jaraco-context | 6.1.2 | MIT |
| jaraco-functools | 4.6.0 | MIT |
| jmespath | 1.1.0 | MIT |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| jwcrypto | 1.6.0 | LGPL-3.0-or-later |
| keyring | 25.7.0 | MIT |
| lxml | 6.1.3 | BSD-3-Clause |
| markdown-it-py | 4.2.0 | MIT |
| mcp | 2.2.0 | MIT |
| mcp-types | 2.2.0 | MIT |
| mdurl | 0.1.2 | MIT |
| more-itertools | 11.1.0 | MIT |
| msgpack | 1.2.3 | Apache-2.0 |
| opentelemetry-api | 1.45.1 | Apache-2.0 |
| pyasn1 | 0.6.5 | BSD-2-Clause |
| pyasn1-modules | 0.4.2 | BSD-2-Clause |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| pydash | 8.1.0 | MIT |
| pygments | 2.21.0 | BSD-2-Clause |
| pyjwt | 2.15.0 | MIT |
| pyopenssl | 26.4.0 | Apache-2.0 |
| python-box | 7.4.1 | MIT |
| python-dateutil | 2.9.0.post0 | Apache-2.0 AND BSD-3-Clause |
| python-docx | 1.2.0 | MIT |
| python-dotenv | 1.2.3 | BSD-3-Clause |
| python-multipart | 0.0.32 | Apache-2.0 |
| pytz | 2026.3.post1 | MIT |
| pywin32 | 312 | BSD-3-Clause AND LGPL-2.1-or-later AND PSF-2.0 AND HPND AND MIT |
| pywin32-ctypes | 0.2.3 | BSD-3-Clause |
| pyyaml | 6.0.3 | MIT |
| referencing | 0.37.0 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| rich | 15.0.0 | MIT |
| rpds-py | 2026.6.3 | MIT |
| setuptools | 84.2.1 | MIT |
| shellingham | 1.5.4 | ISC |
| signxml | 5.2.0 | Apache-2.0 |
| six | 1.17.0 | MIT |
| sse-starlette | 3.4.11 | BSD-3-Clause |
| starlette | 1.6.0 | BSD-3-Clause |
| truststore | 0.10.4 | MIT |
| typer | 0.27.2 | MIT |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| tzdata | 2026.4 | Apache-2.0 |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.53.0 | BSD-3-Clause |
| webauthn | 3.0.1 | BSD-3-Clause |
| zipp | 4.1.0 | MIT |
| zscaler-sdk-python | 1.11.3 | MIT |
| zscaler/terraform-provider-zia | 4.8.8 | MPL-2.0 |

## Container image

The container image is built on `python:3.11-slim-trixie@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e` (Debian 13 with CPython 3.11).
The components of that base image are not in the SBOM above, which covers
the Python packages and the Terraform provider only; CI builds a CycloneDX
SBOM of the built image (every Debian package and its licence) as the
`image-sbom` artifact. The Dockerfile removes the base packages the app
does not need; what stays includes the components below, used unmodified.
Each one's licence text and copyright notice are in the image at the path
shown, and the Debian licence texts are in `/usr/share/common-licenses/`.

| Component | Licence text in the image | Licence (SPDX) |
|---|---|---|
| CPython 3.11 | `/usr/local/lib/python3.11/LICENSE.txt` | PSF-2.0 |
| glibc (libc6) | `/usr/share/doc/libc6/copyright` | LGPL-2.1-or-later |
| OpenSSL library (libssl3t64) | `/usr/share/doc/libssl3t64/copyright` | Apache-2.0 |
| zlib (zlib1g) | `/usr/share/doc/zlib1g/copyright` | Zlib |
| dash | `/usr/share/doc/dash/copyright` | BSD-3-Clause AND GPL-2.0-or-later |
| coreutils | `/usr/share/doc/coreutils/copyright` | GPL-3.0-or-later |

## What these licences mean for redistributing Zscaler Made Easy

Zscaler Made Easy's own code is under the Apache License 2.0. None of it is copied
from a GPL or LGPL work, and every third-party component is used unmodified, as
its own package or program. The GPL and LGPL components, and how they are used:

- **jwcrypto (LGPL-3.0-or-later).** The app's own code does not import it; the
  Zscaler SDK (zscaler-sdk-python) imports it for OneAPI sign-in. So it is installed
  on every platform: in a local install's virtual environment, in the container
  image (the Dockerfile installs requirements.lock) and frozen into the standalone
  (no-install) edition by PyInstaller. The LGPL lets a work that only uses the
  library keep its own licence, so the app stays under Apache-2.0. Whoever passes
  on a build that contains jwcrypto passes on the LGPL-3.0 and GPL-3.0 texts (the
  LGPL-3.0 is a set of extra permissions on top of the GPL-3.0, which is the only
  reason GPL-3.0.txt is here), says where jwcrypto's source is (its unmodified PyPI
  release) and leaves the recipient able to use a changed jwcrypto: it is a separate
  package folder in a local install and in the container, and the app's full source
  and build script (tools/build_standalone.py) let anyone rebuild the standalone
  edition with another jwcrypto.
- **pywin32 (partly LGPL-2.1-or-later).** Windows only. The LGPL-2.1 part is its
  adodbapi module, which nothing in the app imports; the rest of pywin32 is under
  BSD-3-Clause, PSF-2.0, HPND and MIT. It is not in the container image (Linux). A
  local Windows install has it, unmodified, in the virtual environment; PyInstaller
  freezes only modules that something imports, so adodbapi is not expected in the
  Windows standalone edition.
- **The container image's base: dash (GPL-2.0-or-later), coreutils
  (GPL-3.0-or-later) and glibc (LGPL-2.1-or-later).** Debian packages of the base
  image, unmodified. dash and coreutils are separate programs beside the app in
  the same image (an aggregate, which the GPL allows next to software under other
  licences); the app does not link to them. CPython links to glibc dynamically,
  which the LGPL allows. Whoever passes on the image passes on their licence texts
  (in the image, at the paths above) and offers their source (Debian publishes it
  for each package version). The standalone edition does not carry them.

The Apache License 2.0 is compatible with the GPL-3.0 in one direction only:
Apache-2.0 code may become part of a GPL-3.0 work (the combined work is then
passed on under the GPL-3.0), but GPL-3.0 code may not become part of an
Apache-2.0 work. So Zscaler Made Easy may be passed on under Apache-2.0 with the
components above used as they are, and someone may build it into a GPL-3.0
project; copying GPL or LGPL source code into this repository, instead of using
those libraries and programs unmodified, would put the result under those
licences, so it is not done. This summary is not legal advice.
