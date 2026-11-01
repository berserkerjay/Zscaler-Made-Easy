# Stage 5 — Release: prove every way it runs, then promote

**One job:** validate the integrated code in every hosting mode this machine can run, and promote it through the branches. You don't change code; a defect goes back to stage 1.

## Inputs
- `_config/token-efficiency.md` (always).
- `output/<run>/integrate.md` (the green integration branch and its counts).
- `_config/git.md` (branch flow, PR and attribution rules), `_config/testing.md` (runners).
- `INSTALL.md`, `docker-compose.yml`, `update_container.sh`, `.github/workflows/` (what each hosting mode does).

## Process
1. **Docker:** build as `update_container.sh` does, run hardened, check the UI and a sample-tenant assessment, and rehearse an upgrade from the previous container and volume.
2. **Native install:** run `tools/verify_native_install.py` the way the native-install workflow does.
3. **No-install edition:** build and smoke-test it as the release workflow does (no publishing, no signing).
4. Record what this machine cannot check (macOS and Windows, PowerShell, real tenants) for CI or a real machine.
5. Only after the owner's go-ahead: open and merge the pull requests integration → dev (squash) → qa → main (merge commits), then sync the session branch.

## Outputs
- `output/<run>/release.md`: a table of each check (pass / fail / not possible here, with evidence), the PRs and commits, and the update command for the owner.

## Review gate
The owner approves the promotion to `main`.
