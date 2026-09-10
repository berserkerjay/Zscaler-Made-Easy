# Changelog

The app shows its build (git commit) in the guide's *Build* badge and at
`GET /api/health`. Updates are fast-forwards of `main`; this file lists
what each batch of changes did, newest first.

## 2026-09-10

### Security
- Web UI and API require a per-process UI token (cookie set by the launcher's URL, or `X-DLP-Check-Token` / Bearer header). `ZSCALER_UI_AUTH=0` disables it.
- Audit log (`audit.log`, owner-only) of every non-GET API call with a redacted body, plus write-mode toggles.
- MCP server binds 127.0.0.1 by default; pack upload is localhost-only; Word exports use private temp files removed after download.
- Hash-pinned `requirements.lock`; installer and updater install from it with `--require-hashes`.
- Container image (non-root, read-only filesystem, loopback publish) with `docker-compose.yml`; CI adds pip-audit, an SBOM and an image scan; Dependabot for pip, actions and Docker.
- `SECURITY.md` (disclosure policy), `LICENSE`, this changelog.

### Features
- Advanced settings tab: add your own policy packs from a JSON bundle, the three pack files, Terraform for the zscaler/zia provider or a ZIP; they are validated, kept in `user_packs/` (the `/data` volume in the container) and offered everywhere the app offers a pack. Download any pack as one JSON file.
- Detection validation harness (`tools/validate_detection.py`) and reviewer report; predefined dictionaries resolve by API or display name.
- Assessment runs checks in parallel, streams results first, reports a stuck check instead of hanging, and measures the journey afterwards.
- Partial scans: checks, report sections and plan items the API client cannot read are marked as not permitted; results say what a full scan or a configuration change needs.
- Best Practices & Benchmarks card: best-practice alignment grade per area, DLP programme stages, frameworks incl. NIST CSF 2.0 and GLBA.
- Data Flow Map: the exact path a transaction takes through Client Connector app and forwarding profiles, PAC, SSL, URL filtering, app control, file type control and DLP, per policy pack.
- Source Code to AI pack rebuilt from the v4.14 pattern library (13 languages, Anchor AND Signal); rebuild from the tenant's own dictionaries.
- Global Banking Baseline pack; Deploy Policy Packs flow diagram in its own tab; assessment results in their own tab; SSL Inspection Flow shows Client Connector bypasses.
- Every report section opens by default; the compliance card shows all frameworks when none is ticked.

## Earlier
- Deploy Policy Packs with channel choice and undo, tenant profiles, Terraform hand-off, app update from the UI, SSL Inspection Flow, Bypass report, DLP efficacy, Best Practices library, healthcare / CUI / CJIS / Fed / ZBP packs.
