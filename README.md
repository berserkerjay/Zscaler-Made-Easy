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

- All API calls are **read-only GET requests** — the engine cannot modify tenant config
- OAuth2 Client Credentials flow — no human user auth involved
- Credentials stay in `config/tenant.json` — delete after engagement
- Revoke the API Client in ZIdentity when done
- JSON report may contain config details — treat as confidential

## License

Internal tooling. Not for redistribution.

## Policy Packs, Baselines and the Data-Governance Journey

Beyond assessment, DLP-Check deploys **policy packs** (dictionaries → engines → rules across
Web, Endpoint, SaaS Security API and Email DLP, plus Cloud App Control, File Type Control,
URL Filtering and SSL Inspection) through a guided preflight → approve → apply flow, into an
empty tenant (greenfield) or on top of an existing one (brownfield). Whatever the customer
already has is kept exactly as it is; only what is missing is created, every rule DISABLED.

**Tenant profiles** keep one record per customer (details, scopes, applicable baselines, optional
remembered secret) with a history of every assessment, so a consultant can switch tenants and show
movement between visits. A **baseline** is the reference a tenant is measured against. After deployment the assessment
places every baseline object (missing, deployed, monitoring, enforcing, customized) and reports
where the tenant is on the journey — Foundation → Policies deployed → Visibility → Containment
→ Enforcement — with the exact rules to enable or harden next. Every pack can also be owned by
Terraform state using the official
[zscaler/zia](https://registry.terraform.io/providers/zscaler/zia/latest/docs) provider:
`terraform/<pack>/` holds a generated workspace per pack, and *Export Terraform* after a
preflight produces a gap-mode workspace whose first `terraform plan` is exactly the difference
between the tenant and the pack.
See `POLICY_PACKS.md` sections 6, 11 and 12.
