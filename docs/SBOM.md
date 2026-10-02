# Software bill of materials

`docs/sbom.cdx.json` is a CycloneDX 1.6 JSON SBOM of everything DLP-Check
runs with:

- every Python package pinned in `requirements.lock`, with its exact version,
  package URL, the wheel hashes the installers verify and its SPDX licence.
  It covers every platform the lock covers, so the Windows-only `pywin32` and
  `colorama` are listed too;
- the Terraform provider the policy packs use (`zscaler/zia`, pinned in
  `terraform/*/.terraform.lock.hcl`), with its licence (MPL-2.0);
- DLP-Check itself as the root component (`LicenseRef-DLP-Check-Internal`,
  the terms in `LICENSE`).

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
python -m pip install cyclonedx-bom==7.5.0
cyclonedx-py requirements --pyproject pyproject.toml --mc-type application \
  --output-reproducible --of JSON -o docs/sbom.cdx.json requirements.lock
python tools/sbom_enrich.py docs/sbom.cdx.json
```

`cyclonedx-py requirements` reads only the lock, which holds no licence data
and no Terraform provider. `tools/sbom_enrich.py` adds each component's
licence from `tools/third_party_licenses.json`, adds the Terraform providers
from the lockfiles, and rewrites `THIRD_PARTY_NOTICES.md`. It stops with an
error naming any package that has no licence recorded there: add the
package's SPDX licence (its `License-Expression` metadata, or its LICENSE
file) to that JSON file, and, if the licence is copyleft, add its text to
`third_party_licenses/` and to `LICENCE_TEXTS` in the script.

`--output-reproducible` leaves out the timestamp and the random serial number,
so the file only changes when the pins change. `tests/test_lock_platforms.py`
fails when the SBOM and the lock list different packages or versions, and
`tests/test_sbom_licences.py` fails when a component has no licence, the
provider is missing, or the SBOM and notices are not what the script produces.

## Re-locking

`make lock` resolves the lock for every platform at once
(`uv pip compile --universal --python-version 3.11 --generate-hashes --upgrade`).
Platform-only dependencies are kept with their `sys_platform` markers, so the
`--no-deps` installs on Windows, Linux, macOS and in the container all get a
complete set. After re-locking, run `pip-audit -r requirements.lock --strict`
and `make sbom`. CI audits the lock on Linux and again on Windows, where the
Windows-only pins are resolved.
