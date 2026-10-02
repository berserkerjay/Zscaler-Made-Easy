# Software bill of materials

`docs/sbom.cdx.json` is a CycloneDX 1.6 JSON SBOM of the runtime
dependencies pinned in `requirements.lock`: every package, its exact version,
its package URL and the wheel hashes the installers verify. It covers all
platforms the lock covers, so the Windows-only `pywin32` and `colorama` are
listed too. CI builds the same file on every push (the `supply-chain` job,
uploaded as the `sbom` artifact).

## Regenerate it

Do this whenever `requirements.lock` changes (after `make lock`):

```sh
python -m pip install cyclonedx-bom
cyclonedx-py requirements --pyproject pyproject.toml --mc-type application \
  --output-reproducible --of JSON -o docs/sbom.cdx.json requirements.lock
```

`--output-reproducible` leaves out the timestamp and the random serial number,
so the file only changes when the pins change. `tests/test_lock_platforms.py`
fails when the SBOM and the lock list different packages or versions.

## Re-locking

`make lock` resolves the lock for every platform at once
(`uv pip compile --universal --python-version 3.11 --generate-hashes --upgrade`).
Platform-only dependencies are kept with their `sys_platform` markers, so the
`--no-deps` installs on Windows, Linux, macOS and in the container all get a
complete set. After re-locking, run `pip-audit -r requirements.lock --strict`
and regenerate the SBOM.
