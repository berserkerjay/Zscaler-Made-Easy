# Zscaler DLP Assessment Automation Engine

**Full-auto tenant assessment against the DLP Assessment Checklist v3.0.**
Zero manual checks. 150+ automated checks via Zscaler OneAPI. Scored maturity report in 90 seconds.

---

## Architecture

```
┌─────────────────┐     POST /api/assess      ┌──────────────────┐     OAuth2 + GET      ┌─────────────────┐
│   React UI      │ ──── SSE stream ─────────▶ │  FastAPI Server  │ ──────────────────▶   │  Zscaler OneAPI  │
│   (browser)     │ ◀─── real-time results ─── │  dlp_api_server  │ ◀── JSON responses ── │  api.zsapi.net   │
└─────────────────┘                            └──────────────────┘                       └─────────────────┘
                                                       │
                                                       ▼
                                               ┌──────────────────┐
                                               │  Assessment      │
                                               │  Engine          │
                                               │  150+ checks     │
                                               │  Zero manual     │
                                               └──────────────────┘
```

## Quick Start

```bash
# 1. Install
pip install requests fastapi uvicorn

# 2. Discover real API paths on the tenant (first time only)
python src/discover_endpoints.py --config config/tenant.json

# 3. Start API server
cd src && uvicorn dlp_api_server:app --host 0.0.0.0 --port 8000

# 4. Run assessment
curl -X POST http://localhost:8000/api/assess/json \
  -H "Content-Type: application/json" \
  -d @config/tenant.json | python -m json.tool > report.json
```

Or run directly without the server:
```bash
python src/dlp_assessment_full_auto.py --config config/tenant.json --output report.json
```

## File Structure

```
├── src/
│   ├── dlp_assessment_full_auto.py    # Assessment engine — 150+ check functions
│   ├── dlp_api_server.py              # FastAPI server with SSE streaming
│   └── discover_endpoints.py          # One-time endpoint discovery tool
├── config/
│   └── tenant_config_sample.json      # Template — fill in customer creds
├── docs/
│   ├── DLP_Assessment_Step_by_Step_Guide.docx
│   └── DLP_Assessment_Checklist_v3.docx
├── requirements.txt
├── .gitignore
└── README.md
```

## Prerequisites

### Your Machine
- Python 3.9+
- `pip install requests fastapi uvicorn`

### Customer's Zscaler Tenant
1. OneAPI + ZIdentity enabled (contact Zscaler account team if not)
2. Read-only API Role created in ZIA Admin Portal
3. API Client created in ZIdentity with Client Secret auth
4. Client ID, Client Secret, Vanity Domain, and Cloud noted

See `docs/DLP_Assessment_Step_by_Step_Guide.docx` for the complete walkthrough.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/assess` | SSE streaming assessment (React frontend) |
| `POST` | `/api/assess/json` | Full JSON response (cURL/Postman) |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/checks` | List all check IDs and labels |
| `POST` | `/api/report/bypass` | Bypass / non-inspected traffic inventory (opens at `/report/bypass?id=`) |
| `POST` | `/api/report/ssl-flow` | SSL Inspection Flow: per traffic class, which SSL rule decides and whether inline DLP can see it (opens at `/report/sslflow?id=`; exports via `/api/report/ssl-flow/export/{id}`) |
| `GET` | `/report/flow` | Deployment Flow tab: the Deploy Policy Packs dependency diagram (templates → dictionaries → engines → rules) full width, with a details panel; fed live by the assessment tab |
| `POST` | `/api/report/data-flow` | Data Flow Map: how ZIA processes a policy from the device to incident management, and per traffic class and network context the exact path through Client Connector app/forwarding profiles, PAC, then ZIA's request order (Browser & FTP Control, Cloud App Control before URL Filtering, URL filtering, SSL, threat protection, File Type Control, Bandwidth Control, Web DLP, Firewall & DNS Control) and the logs → Incident Receiver → Workflow Automation hop, the endpoint/SaaS/email channels and each pack's coverage (opens at `/report/dataflow?id=`; `/{id}/trace` traces any app, category or hostname; exports via `/api/report/data-flow/export/{id}`) |
| `GET` | `/api/pack-library` | Policy pack library: built-in and uploaded packs with counts, where uploads live and whether adding is allowed (`/report/advanced` is the tab) |
| `POST` | `/api/pack-library/preview` · `/upload` · `/{id}/remove` · `GET /{id}/bundle` | Check an upload (JSON bundle, the three pack files, Terraform or a ZIP) without saving, add it to the library, remove an uploaded pack, download any pack as one JSON file |
| `POST` | `/api/benchmarks` | Best-practice alignment per area (deviations with guidance and article), DLP programme stages, framework rows (incl. NIST CSF 2.0, GLBA) and journey, from an assessment report; `/api/benchmarks/export?format=markdown|json` downloads it |
| `POST` | `/api/dlp-packs/{pack_id}/from-tenant` | Rebuild a pack from the tenant's own Anchor/Signal dictionaries (paired by name, one engine per language); preview unless `confirm` is true; writing is localhost-only |

### Request Body

```json
{
  "org_name": "Acme Corporation",
  "assessor": "Jason",
  "cloud": "zscloud",
  "vanity_domain": "acme",
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_secret": "your-secret"
}
```

### Response

```json
{
  "score": 67,
  "maturity": "Developing",
  "sections": {
    "1 — CC Portal": { "total": 14, "pass": 10, "fail": 2, "warn": 2, "pct": 71 },
    "4 — SSL Policy": { "total": 13, "pass": 11, "fail": 1, "warn": 1, "pct": 85 }
  },
  "critical": [
    { "id": "1.8", "label": "Strict Enforcement", "detail": "Strict mode OFF on: Default" }
  ],
  "checks": [ ... ]
}
```

## Checklist Coverage

The engine covers every section of the DLP Assessment Checklist v3.0:

| Section | Checks | Method |
|---------|--------|--------|
| 1 — CC Portal & Bypass Review | 14 | ZCC App Profiles, Forwarding Profiles |
| 2 — Bypass Inventory | 8 | App Profiles aggregation + domain matching |
| 3 — App Profile | 8 | ZCC App Profiles, Isolation Profiles |
| 4 — SSL Policy | 13 | ZIA SSL Inspection Rules, Cloud App Rules |
| 5 — Endpoint DLP Policy | 22 | ZIA DLP Rules, Dictionaries, URL Filtering |
| Multi-Channel Coverage | 12 | DLP Rules, CASB, Email, Isolation, GraphQL |
| 6 — Versions & Hygiene | 7 | ZCC Devices, App Profiles |
| 7 — SSL Alignment | 3 | SSL Rules, Devices |
| 8 — Pilot Tests | 12 | Rule-existence + ICAP validation |
| 9 — Troubleshooting | 4 | SSL Rules, Devices |
| 10 — macOS | 4 | Devices, App Profiles |
| 11 — Rollback | 3 | Config inference |
| 12 — Incident Management | 14 | ICAP, NSS Feeds, Workflows, Admin Roles |
| Ch.A — Inline Web DLP | 16 | DLP Rules, SSL, Cloud App Control |
| Ch.B — Endpoint DLP | 16 | Endpoint Rules, Devices, Workflows |
| Ch.E — GenAI DLP | 15 | URL Categories, DLP Rules, Dictionaries |

## First-Time Setup: Endpoint Discovery

Zscaler's OneAPI paths may vary by cloud version. Run the discovery tool once:

```bash
python src/discover_endpoints.py --config config/tenant.json
```

This probes ~80 path variations and outputs `discovery.json` showing:
- Which paths return 200 (use these)
- Which return 403 (need more API resources in ZIdentity)
- Which return 404 (not available on OneAPI)
- The actual JSON field names for each endpoint

Update `src/dlp_assessment_full_auto.py` with any paths that differ from the defaults.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy and the full posture. In short:

- **Read-only by default.** The assessment, reports, preflight and journey checks only read. Writing to a tenant (Deploy Policy Packs, undo, migration, remediation) is refused until write mode is enabled for the session with a typed confirmation phrase on a localhost-bound server, or the server is started with `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`. Every deploy is a plan you approve first (bound to a plan hash), every rule ships DISABLED, and every deployment is recorded for undo.
- **Machine identity only.** OAuth2 client-credentials against ZIdentity; no human login is proxied. Use a least-privilege API client and revoke it when the engagement ends.
- **Secrets stay local.** Credentials come from the form, `ZSCALER_*` environment variables, `local_settings.bat`, or a saved tenant profile (secret stored only when you tick *remember*, in an owner-only file). Secrets are never returned by the API and are masked in every error. All of those files are git-ignored.
- **Loopback bound, token guarded.** The web server and the MCP server bind to 127.0.0.1 unless you set `ZSCALER_BIND_HOST` / `ZSCALER_MCP_BIND_HOST`. Every API call needs the per-process UI token (the launcher opens the browser with it; `ui_token.txt` holds it); CORS and origin checks allow only localhost origins; security headers, a body-size cap and a rate limit are always on. Every write call is audited in `audit.log`.
- **Pinned and scanned.** `requirements.lock` pins every wheel by hash and the installer, updater and container install with `--require-hashes`; CI runs pip-audit, publishes an SBOM and scans the image. `docker compose up --build` runs it as a non-root, read-only container published on loopback.
- **Reports are confidential.** JSON, Markdown and Word exports contain tenant configuration; temp files are removed once sent.

## License

Internal tooling. Not for redistribution.

## Policy Packs and the Data-Governance Journey

Beyond assessment, DLP-Check deploys **policy packs** (dictionaries → engines → rules across
Web, Endpoint, SaaS Security API and Email DLP, plus Cloud App Control, File Type Control,
URL Filtering and SSL Inspection) through a guided preflight → approve → apply flow, into an
empty tenant (greenfield) or on top of an existing one (brownfield). Whatever the customer
already has is kept exactly as it is; only what is missing is created, every rule DISABLED.

**Tenant profiles** keep one record per customer (details, scopes, applicable policy packs, optional
remembered secret) with a history of every assessment, so a consultant can switch tenants and show
movement between visits. A **policy pack** is the reference a tenant is measured against. After deployment the assessment
places every policy pack object (missing, deployed, monitoring, enforcing, customized) and reports
where the tenant is on the journey — Foundation → Policies deployed → Visibility → Containment
→ Enforcement — with the exact rules to enable or harden next. Every pack can also be owned by
Terraform state using the official
[zscaler/zia](https://registry.terraform.io/providers/zscaler/zia/latest/docs) provider:
`terraform/<pack>/` holds a generated workspace per pack, and *Export Terraform* after a
preflight produces a gap-mode workspace whose first `terraform plan` is exactly the difference
between the tenant and the pack.
See `POLICY_PACKS.md` sections 6, 11 and 12.
