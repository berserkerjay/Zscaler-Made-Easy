# Third-party notices

DLP-Check itself is under the terms in [LICENSE](LICENSE). It runs with the
third-party components below, each under its own licence. This file is
generated from the SBOM ([docs/sbom.cdx.json](docs/sbom.cdx.json)) by
`python tools/sbom_enrich.py docs/sbom.cdx.json`; see [docs/SBOM.md](docs/SBOM.md).

Each Python package's own licence file, with its copyright notice, is
installed with it (in the package's `*.dist-info` folder). The full texts
of the copyleft licences are kept in [third_party_licenses/](third_party_licenses/):

- **LGPL-2.1-or-later** (pywin32 312): [LGPL-2.1.txt](third_party_licenses/LGPL-2.1.txt)
- **LGPL-3.0-or-later** (jwcrypto 1.6.0): [LGPL-3.0.txt](third_party_licenses/LGPL-3.0.txt) and [GPL-3.0.txt](third_party_licenses/GPL-3.0.txt)
- **MPL-2.0** (certifi 2026.7.22, zscaler/terraform-provider-zia 4.8.8): [MPL-2.0.txt](third_party_licenses/MPL-2.0.txt)

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
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD-3-Clause |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| fastapi | 0.141.1 | MIT |
| h11 | 0.16.0 | MIT |
| httpcore2 | 2.13.0 | BSD-3-Clause |
| httpx2 | 2.13.0 | BSD-3-Clause |
| httpx2-jsfetch | 1.0 | BSD-3-Clause |
| idna | 3.19 | BSD-3-Clause |
| jmespath | 1.1.0 | MIT |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| jwcrypto | 1.6.0 | LGPL-3.0-or-later |
| lxml | 6.1.3 | BSD-3-Clause |
| markdown-it-py | 4.2.0 | MIT |
| mcp | 2.2.0 | MIT |
| mcp-types | 2.2.0 | MIT |
| mdurl | 0.1.2 | MIT |
| msgpack | 1.2.2 | Apache-2.0 |
| opentelemetry-api | 1.44.0 | Apache-2.0 |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| pydash | 8.1.0 | MIT |
| pygments | 2.21.0 | BSD-2-Clause |
| pyjwt | 2.15.0 | MIT |
| python-box | 7.4.1 | MIT |
| python-dateutil | 2.9.0.post0 | Apache-2.0 AND BSD-3-Clause |
| python-docx | 1.2.0 | MIT |
| python-dotenv | 1.2.3 | BSD-3-Clause |
| python-multipart | 0.0.32 | Apache-2.0 |
| pytz | 2026.3.post1 | MIT |
| pywin32 | 312 | BSD-3-Clause AND LGPL-2.1-or-later AND PSF-2.0 AND HPND AND MIT |
| pyyaml | 6.0.3 | MIT |
| referencing | 0.37.0 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| rich | 15.0.0 | MIT |
| rpds-py | 2026.6.3 | MIT |
| setuptools | 84.0.0 | MIT |
| shellingham | 1.5.4 | ISC |
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
| zscaler-sdk-python | 1.9.44 | MIT |
| zscaler/terraform-provider-zia | 4.8.8 | MPL-2.0 |

## Container image

The container image is built on `python:3.11-slim-trixie` (Debian 13 with CPython 3.11).
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
