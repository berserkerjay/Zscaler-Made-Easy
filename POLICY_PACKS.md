# DLP Policy Packs — Authoring Guide

A **policy pack** is a directory of JSON files that define DLP dictionaries, engines, and policies to deploy against a ZIA tenant. Any directory placed in the project root that follows the layout below is auto-discovered and appears in the **📦 DLP Policy Packs** modal.

Use `fed_policy_pack/` as the canonical reference while authoring your own.

---

## Directory Layout

```
my_pack_name/
├── pack.json                      (optional — metadata + confidence tweaks)
└── configs/
    ├── dlp_dictionaries.json      (optional)
    ├── dlp_engines.json           (optional)
    └── dlp_policies.json          (optional)
```

**Rules:**
- Directory name → pack ID (lowercase, underscores; no spaces)
- All three JSON files are optional. You can ship dictionaries only, policies only, etc.
- Flat layout (JSON files directly in the pack dir, no `configs/` sub-folder) is also supported.

---

## 1. `pack.json` — Metadata

```json
{
  "name": "Healthcare HIPAA Pack",
  "version": "1.0",
  "description": "HIPAA-focused DLP for US healthcare tenants",
  "confidence_tweaks": [
    {
      "name": "MEDICAL",
      "target_confidence": "CONFIDENCE_LEVEL_LOW",
      "label": "Medical → Low (reduce FPs)"
    },
    {
      "name_patterns": ["Financial Document", "FINANCIAL"],
      "target_confidence": "CONFIDENCE_LEVEL_HIGH",
      "label": "Financial → High"
    }
  ]
}
```

`confidence_tweaks` runs during **Phase 4** of import and adjusts confidence levels on matching dictionaries after they are created. Use `name` for an exact match or `name_patterns` for multiple candidates.

---

## 2. `configs/dlp_dictionaries.json` — Dictionaries

A JSON array. Each entry is either a **custom** dictionary (with patterns/phrases) or a **clone** of a Zscaler-predefined dictionary.

### Custom dictionary

```json
{
  "name": "HIPAA Medical Record Numbers",
  "description": "Custom regex for MRN formats",
  "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
  "confidence_threshold": "CONFIDENCE_LEVEL_HIGH",
  "proximity": 250,
  "patterns": [
    { "action": "PATTERN_COUNT_TYPE_ALL", "pattern": "\\bMRN[-:\\s]?\\d{7,10}\\b" }
  ],
  "phrases": [
    { "action": "PHRASE_COUNT_TYPE_UNIQUE", "phrase": "medical record number" }
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Must be unique in tenant |
| `custom_phrase_match_type` | yes | `MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY` or `MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY` |
| `patterns` or `phrases` | at least one | Empty dicts are skipped |
| `description` | no | Shown in ZIA admin UI |
| `confidence_threshold` | no | `CONFIDENCE_LEVEL_LOW` / `MEDIUM` / `HIGH` |
| `proximity` | no | 0 = disabled. Typical values: 100–500 (character window) |
| `include_bin_numbers` | no | `true` for PCI-style BIN validation |
| `include_ssn_numbers` | no | `true` for SSN validation |

**Pattern actions:** `PATTERN_COUNT_TYPE_ALL` (every match counts), `PATTERN_COUNT_TYPE_UNIQUE` (duplicates count once).
**Phrase actions:** `PHRASE_COUNT_TYPE_ALL`, `PHRASE_COUNT_TYPE_UNIQUE`.

### Clone of a predefined dictionary

```json
{
  "name": "Social Security Numbers (US) - High",
  "description": "Clone of predefined SSN dict with high confidence",
  "predefined_clone": true,
  "dict_template_name": "Social Security Numbers (US)",
  "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
  "confidence_level_for_predefined_dict": "CONFIDENCE_LEVEL_HIGH",
  "proximity": 500
}
```

| Field | Required | Notes |
|---|---|---|
| `predefined_clone` | yes | Must be `true` |
| `dict_template_name` | yes* | Name of the predefined dict to clone. *Or supply `dict_template_id` directly. |
| `confidence_level_for_predefined_dict` | no | Override the clone's confidence level |

Clones inherit patterns/phrases from the template but can override `proximity`, confidence, and add their own `hierarchical_identifiers`, `include_bin_numbers`, `include_ssn_numbers`.

---

## 3. `configs/dlp_engines.json` — Engines

An engine is a boolean expression over dictionaries. The importer resolves `D:<name>` symbolic references to `D<id>.S` at import time by looking up dictionary IDs in the target tenant (matches both custom dicts from this pack and predefined dicts already in ZIA).

```json
[
  {
    "name": "HIPAA PHI Engine",
    "description": "MRN and ICD-10 together",
    "expression": "(D:HIPAA Medical Record Numbers AND D:ICD-10 Codes - High)"
  },
  {
    "name": "SSN + DOB Engine",
    "description": "SSN within 500 chars of DOB",
    "expression": "(D:Social Security Numbers (US) - High > D:Date of Birth - High)"
  }
]
```

**Expression operators:**

| Operator | Meaning |
|---|---|
| `AND` | Both dictionaries must match |
| `OR` | Either dictionary matches |
| `>` | Proximity — first matches within window of second |
| `(` `)` | Grouping |
| `D:<dict name>` | Symbolic reference; resolved to dictionary ID at import |

**Gotchas:**
- Dict names with spaces work fine inside `D:...`; the parser handles them.
- If a `D:<name>` can't be resolved (name not found in tenant), import logs a warning but still creates the engine with the raw placeholder — you'll see it in the Verify output.
- Put longer/more-specific dictionary names first if two names share a prefix — the importer already sorts by length descending to avoid that class of bug.

---

## 4. `configs/dlp_policies.json` — Policies (DLP Web Rules)

An array of DLP web rules. Each policy points to one or more engines by **name** — the importer resolves those to engine IDs at import.

```json
[
  {
    "name": "Z-HIPAA PHI Monitor",
    "description": "Monitor HIPAA PHI egress",
    "action": "ALLOW",
    "state": "ENABLED",
    "rank": 7,
    "engines": ["HIPAA PHI Engine"],
    "protocols": ["HTTP_RULE", "HTTPS_RULE"],
    "severity": "RULE_SEVERITY_HIGH",
    "min_size": 0,
    "file_types": [],
    "cloud_applications": [],
    "locations": [],
    "groups": [],
    "departments": [],
    "users": [],
    "url_categories": [],
    "labels": [],
    "match_only": false,
    "without_content_inspection": false
  }
]
```

| Field | Required | Default | Notes |
|---|---|---|---|
| `name` | yes | — | Starts with `Z-` by convention (groups visually in ZIA UI) |
| `action` | no | `ALLOW` | What the rule is designed to do. **Every pack ships monitor-only**: at load time DLP-Check turns `BLOCK` / `CONFIRM` into `target_action` and creates the rule with the channel's monitor action (`ALLOW`; `OFLCASB_DLP_REPORT_INCIDENT` on SaaS). |
| `target_action` | no | — | Only for packs you upload with `BLOCK` / `CONFIRM` rules: the app keeps the designed action here and creates the rule monitor-only. The shipped packs carry none: every rule simply monitors, and enforcing is the customer's decision in the portal. |
| `state` | no | `DISABLED` | **Every pack ships `DISABLED`**; an `ENABLED` value is kept as `target_state` and the rule is still created disabled. |
| `rank` | no | 7 | 0 = highest priority (use Rank 0 import button for conflict resolution) |
| `engines` | yes | — | Exactly **one** engine name per rule (pack convention: one rule per engine, so each detection has its own incident count and can be enabled, tuned or hardened on its own; every engine gets a rule, and `tools/fan_out_channels.py` mirrors each Web rule onto Endpoint, SaaS and Email so every channel carries the same rules) |
| `protocols` | no | `["ANY_RULE"]` | `HTTP_RULE`, `HTTPS_RULE`, `FTP_RULE`, `NATIVE_FTP_RULE` |
| `severity` | no | — | `RULE_SEVERITY_INFO` / `LOW` / `MEDIUM` / `HIGH` |
| `file_types` | no | all | e.g. `["FTCATEGORY_MS_EXCEL", "FTCATEGORY_PDF_DOCUMENT"]` |
| `locations` / `groups` / `departments` / `users` | no | all | Restrict rule to scope |

Set `match_only: true` to use match-only semantics (first-match-wins on a match without continuing rule evaluation). `without_content_inspection: true` matches on metadata (file name, MIME type) without opening the payload.

### 4.1 Channels — Endpoint, SaaS Security API (CASB) and Email DLP

A policy's `channel` decides which ZIA policy it lands in. Everything else about the pack stays the same: the rule references the pack's engines by name, engines reference dictionaries, and Deploy Studio resolves the whole chain before writing.

| `channel` | ZIA policy | API (zscaler-sdk-python) | Monitor action | Enforcing actions |
|---|---|---|---|---|
| `web` (default) | Data Loss Prevention › Web DLP rules | `zia.dlp_web_rules` | `ALLOW` | `BLOCK`, `CONFIRM`, `ICAP_RESPONSE` |
| `endpoint` | Endpoint DLP rules | `zia.endpoint_dlp_rules` | `ALLOW` | `BLOCK`, `CONFIRM` |
| `saas` | SaaS Security API › DLP rules | `zia.casb_dlp_rules` | `OFLCASB_DLP_REPORT_INCIDENT` | anything else (`OFLCASB_DLP_QUARANTINE`, `OFLCASB_DLP_REMOVE_PUBLIC_LINK_SHARE`, `OFLCASB_DLP_BLOCK`, …) |
| `email` | Email DLP rules | `zia.outbound_email_dlp_rules` | `ALLOW` | `BLOCK`, `CUSTOMHEADERINSERTION` |

**Endpoint DLP**

```json
{
  "name": "Z-CJIS Endpoint-Monitor",
  "channel": "endpoint",
  "action": "ALLOW",
  "engines": ["CJIS Any-Signal Engine"],
  "severity": "RULE_SEVERITY_HIGH",
  "device_trust_levels": ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"],
  "file_types": [],
  "user_risk_score_levels": [],
  "notification_template": "DLP Notice",
  "labels": []
}
```

`device_trust_levels` defaults to all four levels. `notification_template` and `labels` are **names**; they must already exist in the tenant. `data_transfer_method` / `network_type` / `min_size` pass through when set.

**SaaS Security API (CASB)**

```json
{
  "name": "Z-CJIS SaaS File-Monitor",
  "channel": "saas",
  "saas_type": "OFLCASB_DLP_FILE",
  "action": "OFLCASB_DLP_REPORT_INCIDENT",
  "engines": ["CJIS Any-Signal Engine"],
  "tenants": "any",
  "collaboration_scope": ["ANY"],
  "components": [],
  "file_types": []
}
```

`saas_type` is required: `OFLCASB_DLP_FILE` (Box, Google Drive, OneDrive, SharePoint…), `OFLCASB_DLP_EMAIL`, `OFLCASB_DLP_COLLAB` (Slack, Teams, Webex), `OFLCASB_DLP_CRM`, `OFLCASB_DLP_ITSM`, `OFLCASB_DLP_REPO`, `OFLCASB_DLP_STORAGE`, `OFLCASB_DLP_GENAI`. `tenants` is `"any"` (every onboarded SaaS tenant whose application matches the rule type) or a list of onboarded tenant **names** to pin. `components` and `content_location` pass through for collaboration/email/ITSM types.

**Email DLP**

```json
{
  "name": "Z-CJIS Email-Monitor",
  "channel": "email",
  "action": "ALLOW",
  "engines": ["CJIS Any-Signal Engine"],
  "tenants": "any",
  "severity": "RULE_SEVERITY_HIGH",
  "notification_template": "DLP Notice"
}
```

`tenants` works as for SaaS but matches email applications (Microsoft 365 / Gmail) onboarded under SaaS Security. Email rules have no `rank`.

**Dependencies per channel.** Preflight resolves every prerequisite against the live tenant and lists them under *Tenant prerequisites* in Deploy Studio (and in the `dependencies` array of `/api/dlp-packs/preflight`). A rule whose prerequisites are missing is skipped with the reason; the other channels still deploy.

| Channel | Needs from the tenant | How it is checked |
|---|---|---|
| all | the dictionaries and engines the rule references (pack or tenant) | resolved per item; blocked items cascade |
| `web` | fewer than 127 web DLP rules after the deployment | rule count vs. API cap |
| `endpoint` | Endpoint DLP licensed (rule API answers); Zscaler Client Connector with Endpoint DLP enabled in the app profile | rule API read; ZCC rollout cannot be verified through the API and is listed as a note |
| `saas` | SaaS Security API licensed; at least one onboarded SaaS application tenant matching `saas_type` (Administration › SaaS Application Tenants) | tenant list read and matched by application |
| `email` | Email DLP licensed; an onboarded Microsoft 365 / Gmail tenant | tenant list read and matched to email applications |
| any | `notification_template` / `labels` named in the rule | looked up by name in DLP Notification Templates / Rule Labels |

Deploy Studio shows the resolved SaaS tenants a rule will be scoped to before you approve, and the post-deploy verification re-reads every channel's rule list to confirm each rule now exists.

---

### 4.2 Endpoint DLP extras — transfer methods, application groups, sub-rules

Endpoint rules (`"channel": "endpoint"`) accept these fields on top of the
shared ones:

| Field | What to enter | Sample |
|---|---|---|
| `data_transfer_method` | One of `REMOVABLE_DRIVE_TRANSFER`, `NETWORK_DRIVE_TRANSFER`, `APPLICATION_FILE_ACCESS`, `PRINTING`, `CLOUD_SYNC`, `ANY` | `"REMOVABLE_DRIVE_TRANSFER"` |
| `user_risk_score_levels` | Explicit values (the API rejects ANY) | `["LOW", "MEDIUM", "HIGH", "CRITICAL"]` |
| `eun_enabled` | Show the end-user notification | `false` |
| `endpoint_application_groups` | Names of groups from `configs/endpoint_application_groups.json` or already in the tenant | `["zbp-GenAI Applications"]` |
| `sub_rules` | Exceptions evaluated under this rule, in order; same fields as a rule, no `channel` | see below |

```json
{
  "name": "zbp-Sensitive Data to USB", "channel": "endpoint", "action": "BLOCK", "state": "DISABLED",
  "engines": ["PCI - High", "PCI - Medium", "PCI - Low"], "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER",
  "sub_rules": [
    {"name": "zbp-PCI High USB Block", "action": "BLOCK",   "engines": ["PCI - High"],   "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER"},
    {"name": "zbp-PCI Medium USB",     "action": "CONFIRM", "engines": ["PCI - Medium"], "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER"},
    {"name": "zbp-PCI Low USB",        "action": "ALLOW",   "engines": ["PCI - Low"],    "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER"}
  ]
}
```

`configs/endpoint_application_groups.json` lists groups of desktop
applications by Zscaler catalogue ID (`zappId`, portable across tenants):

```json
[{"name": "zbp-GenAI Applications", "description": "ChatGPT and Claude desktop apps",
  "resources": ["500000603", "500000605", "600000601", "600000605"],
  "applications": [{"applicationName": "ChatGPT", "osType": "WINDOWS_OS", "zappId": "500000603"}]}]
```

Groups are created before the rules that reference them (or reused by
name), sub-rules are created under their parent after it exists, and
Terraform emits `zia_endpoint_dlp_application_group` and
`zia_endpoint_dlp_sub_rules`. A `CONFIRM` sub-rule needs the tenant's
Endpoint DLP user confirmation template; without one the API rejects that
sub-rule and the rest deploys.

## 5. Validate Locally Before Import

```bash
# JSON is parseable
python3 -c "
import json
for f in ['dlp_dictionaries', 'dlp_engines', 'dlp_policies']:
    with open(f'my_pack_name/configs/{f}.json') as fh:
        data = json.load(fh)
    print(f'{f}: {len(data)} entries OK')
"

# Pack is discovered
python3 -c "
import dlp_importer
for p in dlp_importer.discover_packs():
    print(p['id'], '→', p['name'], f\"({p['dictionaries']}d, {p['engines']}e, {p['policies']}p)\")
"
```

---

## 6. Deploy — Three Ways

### Web UI: Deploy Studio (recommended)

1. Drop the pack directory in the project root.
2. Start the server with **`START_Zscaler_Assessment_WRITES_ENABLED.bat`** (deploying writes to the tenant, so it is gated behind `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`). Hard-refresh the browser (Ctrl+Shift+R).
3. Enter the tenant credentials at the top of the page, then click **📦 Deploy Policy Packs**.
4. **Select** — toggle any number of packs. Options: *Apply confidence tweaks* and *Rank 0*.
5. **Preflight** — the tenant is read and every item is cross-referenced. Nothing is written. You get a status (Ready / Review / Blocked) and, per dictionary, engine, policy and tweak:

   | Status | Meaning |
   |---|---|
   | Will create | New object; will be created. |
   | Will modify | A confidence tweak will change an **existing** tenant dictionary. |
   | Already present | Exists with identical content — nothing to do. |
   | Kept as-is | Exists with **different** content. The tenant's version is kept and everything below binds to it; the pack's version is not applied. |
   | Conflict | Defined differently in two selected packs — skipped, with its dependents. |
   | Skipped | A dependency (dictionary, engine, predefined template) is missing or blocked. |

   Plus an **Impact** panel: rule-order shift (new rules go to order 1), the 127-rule API cap, enforcing vs monitor-only actions, rank-0 mode, and the activation reminder.
6. **Approve** — the exact list of writes and every warning, restated. Deployment stays disabled until you tick the consent box. The plan hash shown is what the server will require.
7. **Deploy** — dictionaries → engines → policies → tweaks → verification. Each item is isolated: a failure is reported and its dependents are skipped, never created half-wired. If the tenant changed since you approved, nothing is written and you are asked to re-run preflight.

### Web UI: Advanced settings (bring your own pack)

The **Advanced settings** tab adds a pack from a single JSON bundle
(`{"name", "description", "dictionaries", "engines", "policies"}`), from the
three files in this document, from Terraform for the zscaler/zia provider,
or from a ZIP of any of them. The upload is validated (section 5's checks)
and stored under `user_packs/<id>/` in exactly the layout above, so it is
an ordinary pack from then on. *Download JSON* on any pack gives you its
bundle to copy from. See `GETTING_STARTED.md` section 5f.

### API (for scripting / CI)

```bash
# List packs / preview one
curl http://localhost:8080/api/dlp-packs
curl http://localhost:8080/api/dlp-packs/my_pack_name

# 1) Preflight — read-only plan for one or more packs. Credentials may be
#    omitted to fall back to ZSCALER_* env vars, then tenant_config.json.
curl -X POST http://localhost:8080/api/dlp-packs/preflight \
  -H 'Content-Type: application/json' \
  -d '{"pack_ids": ["fed_policy_pack", "cjis_policy_pack"],
       "use_rank_0": false, "apply_tweaks": true,
       "cloud": "production", "vanity_domain": "acme",
       "client_id": "...", "client_secret": "..."}'
# → {"status": "ready|warnings|blocked", "items": [...], "warnings": [...],
#    "blockers": [...], "impacts": [...], "plan_hash": "<sha256>", ...}

# 2) Apply — requires confirm=true and the plan_hash from step 1.
#    409 {"status":"plan_changed"} if the tenant/selection drifted; nothing written.
#    403 if the server was not started with writes enabled.
curl -X POST http://localhost:8080/api/dlp-packs/apply \
  -H 'Content-Type: application/json' \
  -d '{"pack_ids": ["fed_policy_pack", "cjis_policy_pack"],
       "plan_hash": "<sha256 from preflight>", "confirm": true,
       "use_rank_0": false, "apply_tweaks": true, "verify": true,
       "cloud": "production", "vanity_domain": "acme",
       "client_id": "...", "client_secret": "..."}'

# Single-pack legacy import (no cross-pack checks, no approval step)
curl -X POST http://localhost:8080/api/dlp-packs/my_pack_name/import \
  -H 'Content-Type: application/json' \
  -d '{"use_rank_0": false, "apply_tweaks": true, "verify": true}'

# Verify a pack against the tenant (read-only)
curl -X POST http://localhost:8080/api/dlp-packs/my_pack_name/verify
```

The planner lives in `pack_deploy.py` (`preflight()` / `apply()`); `tests/test_pack_deploy.py` exercises it against a fake tenant — run `python3 -m pytest tests/`.

### Standalone CLI (no server running)

```bash
cd my_pack_name
python3 ../fed_policy_pack/dlp_stand_alone_import.py
```

The standalone script reads from `configs/` in the current working directory.

---

## 7. Import Pipeline — 5 Phases

1. **Dictionaries** — create missing (skip if exists by name).
2. **Engines** — resolve `D:<name>` → `D<id>.S`, create missing.
3. **Policies** — resolve engine names → IDs, create missing web rules.
4. **Confidence tweaks** — apply `pack.json` → `confidence_tweaks`, or built-in defaults (Medical→Low, Financial→High).
5. **Verify** — diff tenant against JSON; report missing or mismatched items.

All phases are idempotent: re-running against a tenant that already has the pack is safe (no duplicates).

---

## 8. Deployment Tips

- **First deploy is always monitor-only.** Whatever a pack says, every DLP rule is created `ALLOW` (report on SaaS) and `DISABLED`; the designed action is kept as `target_action`. Enable in the portal, let it run a week, review the incidents, tune dictionaries, then flip the rule to its target action. The journey card lists exactly which rules still need that.
- **Rank 0 mode**: only use when a conflicting rule already exists at a higher priority. Rank 0 beats everything, including other Rank 0s, on a first-match basis — don't leave policies here long-term.
- **Naming**: prefix policy names with `Z-` (or your own convention) so they group in the ZIA admin UI. Keep dictionary names short enough that engine expressions stay readable.
- **Proximity**: start at `500` for SSN/DOB/MRN pairings; drop to `250` if you see bleed-over false positives.
- **Version your pack**: bump `pack.json` `version` on any change and commit it to source control so tenant drift is debuggable.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| Pack doesn't appear in UI | `configs/` dir missing or no `dlp_*.json` inside. Restart server. |
| `Cannot clone: No template ID` | `dict_template_name` doesn't exist in the target tenant (Zscaler may have renamed it). Check the ZIA admin UI's Predefined Dictionaries list and use the exact name. |
| `Unresolved dictionary references` warning on engine import | Your engine expression uses `D:<name>` but that dictionary isn't in the pack OR the tenant. Check spelling. |
| Engine imports but policy fails with "No valid engines found" | Policy's `engines` array references an engine name that wasn't created. Look at Phase 2 output for the root failure. |
| Verify shows "Pattern content mismatch" | Someone edited the dictionary in the ZIA UI after import. Either re-import (won't overwrite — it skips by name) or delete in UI first. |

---

## 10. Example — Minimal Starter Pack

```
starter_pack/
├── pack.json
└── configs/
    ├── dlp_dictionaries.json
    ├── dlp_engines.json
    └── dlp_policies.json
```

**`pack.json`**:
```json
{ "name": "Starter Pack", "version": "0.1", "description": "Minimal example" }
```

**`configs/dlp_dictionaries.json`**:
```json
[
  {
    "name": "API Keys - Example",
    "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
    "confidence_threshold": "CONFIDENCE_LEVEL_HIGH",
    "patterns": [
      { "action": "PATTERN_COUNT_TYPE_UNIQUE", "pattern": "sk-[A-Za-z0-9]{32,}" }
    ]
  }
]
```

**`configs/dlp_engines.json`**:
```json
[
  {
    "name": "API Key Leak Engine",
    "expression": "D:API Keys - Example"
  }
]
```

**`configs/dlp_policies.json`**:
```json
[
  {
    "name": "Z-Starter-API-Key-Monitor",
    "action": "ALLOW",
    "state": "ENABLED",
    "engines": ["API Key Leak Engine"],
    "protocols": ["HTTP_RULE", "HTTPS_RULE"],
    "severity": "RULE_SEVERITY_HIGH"
  }
]
```

Drop this at the project root, restart the server, and you have a working pack.

## 11. Policy packs and the Data-Governance Journey

A pack can declare itself a **policy pack**: the reference a tenant is
measured against. Add a `baseline` section to `pack.json`:

```json
{
  "name": "ZBP Enterprise Policy pack",
  "version": "1.0",
  "baseline": { "prefix": "ZBP-", "version": "1.0" }
}
```

A policy pack is deployed **greenfield** (an empty tenant: everything is
created) or **brownfield** (an existing tenant: whatever already exists is
kept exactly as the customer has it, only what is missing is created).
Nothing is ever overwritten by default. An enabled rule, an action
hardened from ALLOW to BLOCK, a tuned dictionary — those are the
customer's progress, not drift to revert.

| Tenant state of a policy pack object | Plan status | What apply does |
|---|---|---|
| Missing | `create` | Creates it, DISABLED, with a provenance tag |
| Exists as the policy pack defines it | `reuse` | Nothing |
| Exists, changed by the customer | `reuse_differs` (customized) | Nothing; the customer's version is kept |
| Same name as a predefined Zscaler dictionary | `conflict` | Nothing; rename the policy pack object |

Preflight adds a **Greenfield** or **Brownfield** impact card per policy pack
saying how many objects exist, how many are customized, and how many will
be created. Objects the policy pack does not define are never touched.

**Converge mode (explicit, off by default).** `restore_drift: true` on
`/preflight` and `/apply` turns customized objects into `restore`
(overwrite with the policy pack definition, a rule keeps its position). It is
an API option only; Deploy Studio never selects it. Use it when the
customer has asked for the tenant to be reset to the reference.

### Where is this tenant on the journey?

After deployment the same comparison places every policy pack object:

| Position | Meaning |
|---|---|
| `missing` | Not in the tenant |
| `deployed` | Present as the policy pack defines it; rule still DISABLED |
| `monitoring` | Rule ENABLED with a non-enforcing action (ALLOW, report) |
| `enforcing` | Rule ENABLED with an enforcing action (BLOCK, DECRYPT, CAUTION…) |
| `customized` | Present but content differs (kept) |
| `relaxed` | The policy pack ships it enabled, the tenant disabled it |
| `blocked` | Cannot be created (missing prerequisite, conflict) |

and rolls them up into five stages. A stage is reached when every object
it needs is at or beyond the required position; the tenant's stage is the
highest one with all earlier stages reached.

| Stage | Reached when |
|---|---|
| 1 Foundation | every dictionary and engine exists |
| 2 Policies deployed | every rule exists (disabled is fine) |
| 3 Visibility | SSL Inspection rules and DLP rules are enabled |
| 4 Containment | Cloud App Control, File Type Control and URL Filtering rules are enabled |
| 5 Enforcement | DLP rules use an enforcing action |

The score is the share of required objects in place, averaged over the
stages. The **assessment** runs this for every policy pack and shows a
*Data governance journey* card; each policy pack card in Deploy Studio has a
*Where is this tenant?* action; and the API exposes the same thing:

```bash
curl -s -X POST http://localhost:8000/api/dlp-packs/journey \
  -H "Content-Type: application/json" \
  -d '{"pack_ids": ["healthcare_phi_baseline"], "cloud": "production", "vanity_domain": "acme",
       "client_id": "...", "client_secret": "..."}'
# → {"status": "not_started|in_progress|governed|blocked", "stage": 3, "score": 72,
#    "baselines": [{"id", "version", "stage", "stage_name", "score", "state",
#                   "missing", "deployed", "monitoring", "enforcing", "customized", "relaxed", "blocked",
#                   "stages": [{"n","name","what","required","met","done","todo"}...],
#                   "next_steps": ["Enable rule 'R_PHI_SSL_...' in Policy > SSL Inspection after reviewing its scope.", ...],
#                   "objects": [{"kind","name","position","channel","drift","action","state"}...]}], ...}
```

It runs without the write gate (nothing is written). `next_steps` names
the exact rules to enable or harden, and where in the ZIA Admin Portal.
Every object a policy pack creates carries a provenance tag in its
description (`[DLP-Check baseline <pack> v<version>]`), so admins can see
which policy pack version it came from.

**Dynamic application scope.** A web rule may carry
`"cloud_app_classes": ["AI_ML"]` instead of a fixed `cloud_applications`
list. Preflight resolves the class against the tenant's current cloud
application catalogue, lists the count as a prerequisite, blocks the rule
if the class resolves to nothing, and applies the resolved list. Newly
classified applications are picked up on the next deploy.

**Shipped policy packs.**

| Pack | Contents | Source |
|---|---|---|
| `zbp_enterprise_baseline` | 31 dictionaries, 9 engines, 6 monitor-only web DLP rules (US PII, US PHI, financial, ITAR, TLP markings, private keys), `ZBP-` prefix | Converted from `mkoyfman/zbp-automation` (`zbp-enterprise-zia`) with `tools/pack_from_terraform.py` |
| `zbp_source_code_baseline` | 3 dictionaries, 3 engines, 1 **BLOCK** rule for Python/JavaScript/shell source uploads to AI/ML applications, scope resolved from the `AI_ML` class at deploy time | `zbp-source-code-dlp-zia` |

**Converting a Terraform template.** `tools/pack_from_terraform.py` turns
a `.tf.json` with `zia_dlp_dictionaries` / `zia_dlp_engines` /
`zia_dlp_web_rules` resources into a pack:

```bash
python tools/pack_from_terraform.py template.tf.json my_baseline \
  --name "My Policy pack" --version 1.0 --prefix ZBP- --baseline --enable-rules
```

### Shipped policy packs

| Pack | Policy pack | Who it is for |
|---|---|---|
| `zbp_enterprise_baseline` | yes | Any enterprise: Zscaler's best-practice DLP set |
| `zbp_source_code_baseline` | yes | Engineering organisations: source code to AI apps. 13 languages from the v4.14 pattern library, each an Anchor dictionary (one fingerprint) AND a Signal dictionary (eight counted patterns) in one engine; regenerate from a new library document with `tools/pack_from_pattern_doc.py`, or from the tenant's own Anchor/Signal dictionaries with `pack_from_tenant.py` (also the *Rebuild from tenant dictionaries* button on the pack card) |
| `healthcare_phi_baseline` | yes | Covered entities, business associates and their vendors: the PHI / HIPAA six-engine build, predefined-first (Names, SSN, NPI, licences, TIN, Medical Information / Document / Imaging, Diseases, Drugs, Treatments, NDC, Insurance Document, Self-Harm, Illegal Drugs, Credit Cards) plus seven custom dictionaries (MRN, DOB, sensitive condition markers, health-plan member id, insurance billing, clinical narrative, address); engines HIPAA Critical, Narrative / Low Volume, Identity Trifecta, Sensitive Subcategory, Pharmacy / Claims / Billing and Bulk PHI in three tiers; eight rules on every channel; see `healthcare_phi_baseline/PHI_HIPAA_BUILD.md`. Detection only; 3.0 |
| `global_banking_baseline` | yes | Banks, card issuers, payment processors: PCI, bank account and payment instructions (ABA, EU and global IBAN, SWIFT/BIC), customer PII across jurisdictions, KYC/AML and lending files, MNPI, confidentiality markings; premised on Zscaler's predefined dictionaries cloned at high confidence, reusing the ZBP Enterprise engines; web, endpoint, SaaS, email and containment rules; see the pack's README |
| `cjis_policy_pack` | no | Law enforcement: CJIS content categories |
| `fed_policy_pack` | no | Federal agencies, the defense industrial base and federal contractors: Zscaler's Fed Policy Pack V1.1 (FOUO, Atomic Energy Act, Standard Forms, US PII/PHI, financial, ITAR, TLP, private keys) plus CUI by its markings (31 dictionaries in seven tiers behind block, caution and monitor rules; see `fed_policy_pack/CUI_MARKINGS.md` for the tier table). Superset of ZBP Enterprise; do not deploy both |

### From a design file to a pack

A DLP engineer's design usually arrives as the ZIA `dlpDictionaries` JSON
with `_`-prefixed build metadata (`_tier`, `_intended_action`,
`_min_match_count`, `_notes`, `_VERIFY`). Keep that file as
`<pack>/design.json` and generate the configs from it:

```bash
python tools/pack_from_design.py my_pack
```

A hand-authored pack can also carry one or more designs next to its own
objects: list them in `pack.json` as
`"designs": [{"file": "cui_design.json", "prefix": "CUI", "owns": ["CUI-", "Legacy-"], "notes": "CUI_MARKINGS.md"}]`
and the same command regenerates only the dictionaries and engines each
design owns (by name prefix), leaving the rest of the pack untouched. That
is how the Fed Policy Pack carries the CUI marking design
(`python tools/pack_from_design.py fed_policy_pack`).

It writes `configs/dlp_dictionaries.json` and `dlp_engines.json` (the
designed engines plus derived `<Prefix>-Detect-Block-Grade` and
`<Prefix>-Detect-Caution-Grade` engines built from each dictionary's
intended action and minimum count, with every Exclude dictionary as
`AND NOT`), and the README tier table. It refuses designs outside the
documented ZIA limits (8 patterns per dictionary, 256 bytes per pattern,
proximity 0-10000, no lookaround, 255-byte descriptions); preflight
enforces the same limits on every pack and blocks only the offending
dictionary. Policies and `pack.json` are authored by hand.

## 12. Terraform — Own a Pack with State

Every pack (policy packs included) can be deployed with the official
[`zscaler/zia`](https://registry.terraform.io/providers/zscaler/zia/latest/docs)
provider instead of the in-app executor. DLP-Check generates the workspace;
Terraform owns the lifecycle: `plan` shows the diff, `apply` converges,
`destroy` removes exactly what the pack created.

**Committed workspaces.** `terraform/<pack_id>/` holds a generated workspace
for every pack in the repo. Regenerate after editing a pack (CI fails if
they are stale):

```bash
python pack_terraform.py --out terraform          # all packs
python pack_terraform.py zbp_enterprise_baseline --out terraform
```

**Gap mode (assess, then close the gap with Terraform).** From Deploy
Studio, run preflight and click *Export Terraform*, or call the API with
tenant credentials:

```bash
curl -s -X POST http://localhost:8000/api/dlp-packs/terraform \
  -H "Content-Type: application/json" -o tf.zip \
  -d '{"pack_ids": ["zbp_enterprise_baseline"], "cloud": "production", "vanity_domain": "acme",
       "client_id": "...", "client_secret": "..."}'
```

The workspace then contains `imports.tf` with an `import {}` block (Terraform
1.5+) for every object that already exists in the tenant, so the first
`terraform plan` is exactly the gap: in-sync objects import with no change,
customized objects import and would be updated in place (delete their
import block to keep the customer's version), missing objects are
created, blocked objects are listed as comments with their reason. Existing
rules keep their current order; new rules start at `rule_starting_order`.
Without credentials the endpoint (and the *Terraform* link on each pack
card) returns the static workspace.

**What is generated.**

| File | Contents |
|---|---|
| `versions.tf` | `zscaler/zia ~> 4.8`, Terraform `>= 1.5`, commented S3 backend |
| `provider.tf` | provider from variables or `ZSCALER_*` environment variables |
| `variables.tf` | credentials (sensitive), `rule_starting_order`, `policy_rank`, `activate`, SaaS tenant ID lists when not resolved |
| `dictionaries.tf` | `data "zia_dlp_dictionaries"` for predefined templates and referenced predefined dictionaries; one resource per pack dictionary |
| `engines.tf` | expressions rewritten to `D${zia_dlp_dictionaries.x.id}.S` |
| `rules.tf` | `zia_dlp_web_rules` / `zia_endpoint_dlp_rules` / `zia_casb_dlp_rules` / `zia_outbound_email_dlp`; `cloud_app_classes` become a `data "zia_cloud_applications"` lookup with a precondition |
| `activation.tf` | `zia_activation_status` after every rule (`activate = false` to skip) |
| `imports.tf` | gap mode only |

Every object carries a `[DLP-Check baseline|pack <id> v<ver>] Terraform-managed.`
description tag. CI regenerates the committed workspaces and runs
`terraform init` + `validate` against the real provider schema.

**Shipping convention.** Every rule in every shipped pack is delivered
`"state": "DISABLED"` with `"severity": "RULE_SEVERITY_INFO"`, the same way
Zscaler delivers its Fed pack. Deploying creates the dictionaries, engines
and rules without changing what users experience; you enable each rule and
raise its severity in the portal (or in the pack) once it is tuned. Actions
are authored as intended (ALLOW to monitor, BLOCK to enforce), so enabling a
rule never changes its meaning. For a policy pack, enabling a rule in the
portal is exactly the expected next step: the journey check reports it as
*monitoring* or *enforcing*, never as drift, and nothing reverts it.

## 13. Containment Rules — Cloud App Control, File Type Control, URL Filtering, SSL Inspection

DLP inspects **content**. These four rule types restrict the **channel**
and the **payload** and run **before** DLP in ZIA's policy order, so a
block here stops a transaction whether or not DLP would have matched. A
pack lists them in `configs/dlp_policies.json` alongside DLP rules; they
have no `engines`. Every field below names the ZIA value to enter and
shows a sample. Anything not listed is passed through untouched.

### Fields shared by all four

| Field | Enter | Sample |
|---|---|---|
| `name` | Rule name as it will appear in the ZIA portal (max 31 chars for SSL rules) | `"R_PHI_CAC_FILE_SHARE_NO_UPLOAD"` |
| `channel` | `cloud_app`, `file_type`, `url` or `ssl` | `"cloud_app"` |
| `description` | Free text; the tool appends a provenance tag | `"Block upload to personal storage"` |
| `state` | `ENABLED` or `DISABLED` (packs ship DISABLED) | `"DISABLED"` |
| `rank` | Admin rank 0–7; 7 is normal | `7` |
| `cloud_app_classes` | Application classes resolved from the tenant catalogue at deploy time. Values match the Cloud App Control types below | `["FILE_SHARE", "WEBMAIL"]` |
| `applications` | Explicit application identifiers instead of classes | `["BOX", "DROPBOX", "GOOGLE_DRIVE"]` |
| `device_trust_levels` | Which ZCC trust levels the rule applies to | `["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]` |

### `cloud_app` — Cloud App Control

| Field | Enter | Sample |
|---|---|---|
| `type` | The application category: `AI_ML`, `BUSINESS_PRODUCTIVITY`, `CONSUMER`, `CUSTOM_CAPP`, `DNS_OVER_HTTPS`, `ENTERPRISE_COLLABORATION`, `FILE_SHARE`, `FINANCE`, `HEALTH_CARE`, `HOSTING_PROVIDER`, `HUMAN_RESOURCES`, `INSTANT_MESSAGING`, `IT_SERVICES`, `LEGAL`, `SALES_AND_MARKETING`, `SOCIAL_NETWORKING`, `STREAMING_MEDIA`, `SYSTEM_AND_DEVELOPMENT`, `WEBMAIL` | `"FILE_SHARE"` |
| `actions_by_verb` | What to do per action family. Keys are the end of the action name (`UPLOAD`, `SHARE`, `SEND`, `ATTACHMENT_SEND`, `VIEW`, `DOWNLOAD`, `CREATE`, `EDIT`...); `*` is the default. Preflight reads the tenant's available actions for the type and applications and picks the matching `ALLOW_`/`BLOCK_` variant, so the exact enums never have to be typed | `{"UPLOAD": "BLOCK", "SHARE": "BLOCK", "*": "ALLOW"}` |
| `actions` | Explicit action enums instead of `actions_by_verb` (use `list_available_actions` or the portal to see them) | `["BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"]` |
| `user_agent_types` | Optional browsers | `["CHROME", "FIREFOX", "MSEDGE", "SAFARI"]` |

```json
{
  "name": "R_PHI_CAC_FILE_SHARE_NO_UPLOAD",
  "channel": "cloud_app",
  "type": "FILE_SHARE",
  "cloud_app_classes": ["FILE_SHARE"],
  "actions_by_verb": {"UPLOAD": "BLOCK", "SHARE": "BLOCK", "*": "ALLOW"},
  "state": "DISABLED",
  "rank": 7
}
```

### `file_type` — File Type Control

| Field | Enter | Sample |
|---|---|---|
| `filtering_action` | `ALLOW`, `CAUTION` (warn, then allow) or `BLOCK` | `"BLOCK"` |
| `operation` | `UPLOAD`, `DOWNLOAD` or `UPLOAD_DOWNLOAD` | `"UPLOAD"` |
| `file_types` | File type categories as ZIA names them (Administration > File Type Control) | `["FTCATEGORY_MS_EXCEL", "FTCATEGORY_ZIP", "FTCATEGORY_RAR", "FTCATEGORY_ACCDB"]` |
| `protocols` | `HTTP_RULE`, `HTTPS_RULE`, `FTP_RULE`, `FOHTTP_RULE` or `ANY_RULE` | `["HTTP_RULE", "HTTPS_RULE"]` |
| `url_categories` | Optional URL categories to scope to | `["OTHER_MISCELLANEOUS"]` |
| `min_size` / `max_size` | Optional size bounds in KB (0–409600) | `10` |
| `active_content` / `unscannable` | Optional booleans | `true` |

```json
{
  "name": "R_PHI_FTC_BLOCK_BULK_EXPORT_UPLOAD",
  "channel": "file_type",
  "filtering_action": "BLOCK",
  "operation": "UPLOAD",
  "file_types": ["FTCATEGORY_MS_EXCEL", "FTCATEGORY_ZIP", "FTCATEGORY_RAR", "FTCATEGORY_TAR", "FTCATEGORY_GZIP"],
  "protocols": ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE"],
  "cloud_app_classes": ["FILE_SHARE"],
  "state": "DISABLED",
  "rank": 7
}
```

### `url` — URL Filtering

| Field | Enter | Sample |
|---|---|---|
| `action` | `ALLOW`, `CAUTION`, `BLOCK`, `ISOLATE` (needs a CBI profile) or `ICAP_RESPONSE` | `"BLOCK"` |
| `url_categories` | ZIA URL category names, or `["ANY"]` | `["OTHER_MISCELLANEOUS", "GAMBLING"]` |
| `protocols` | `HTTP_RULE`, `HTTPS_RULE`, `FTP_RULE`, `WEBSOCKET_RULE`, `WEBSOCKETSSL_RULE`, `ANY_RULE`... | `["HTTP_RULE", "HTTPS_RULE"]` |
| `request_methods` | Optional HTTP methods; `POST` and `PUT` are uploads | `["POST", "PUT"]` |
| `user_agent_types`, `user_risk_score_levels` | Optional | `["HIGH", "CRITICAL"]` |
| `end_user_notification_url`, `block_override` | Optional | `"https://caution.acme.com"` |

```json
{
  "name": "R_PHI_URL_BLOCK_POST_TO_UNKNOWN",
  "channel": "url",
  "action": "BLOCK",
  "url_categories": ["OTHER_MISCELLANEOUS", "GAMBLING"],
  "protocols": ["HTTP_RULE", "HTTPS_RULE"],
  "request_methods": ["POST", "PUT"],
  "state": "DISABLED",
  "rank": 7
}
```

### `ssl` — SSL Inspection

| Field | Enter | Sample |
|---|---|---|
| `action.type` | `DECRYPT`, `DO_NOT_DECRYPT` or `BLOCK` | `"DECRYPT"` |
| `action.ssl_interception_cert.id` | Certificate to sign with; `1` is the tenant's default Zscaler intermediate CA | `{"id": 1, "default_certificate": true}` |
| `action.decrypt_sub_actions` | For DECRYPT: `server_certificates` (`ALLOW`/`BLOCK`/`PASS_THRU`), `ocsp_check`, `block_ssl_traffic_with_no_sni_enabled`, `min_client_tls_version` (`CLIENT_TLS_1_2`...), `min_server_tls_version` (`SERVER_TLS_1_2`...), `block_undecrypt`, `http2_enabled` | see below |
| `action.do_not_decrypt_sub_actions` | For DO_NOT_DECRYPT: `bypass_other_policies`, `server_certificates`, `ocsp_check`, `block_ssl_traffic_with_no_sni_enabled`, `min_tls_version` | `{"bypass_other_policies": false}` |
| `platforms` | Device platforms: `SCAN_WINDOWS`, `SCAN_MACOS`, `SCAN_LINUX`, `SCAN_IOS`, `SCAN_ANDROID`, `NO_CLIENT_CONNECTOR` | all six |
| `road_warrior_for_kerberos` | Apply to remote users with PAC/Kerberos | `true` |
| `cloud_app_classes` / `url_categories` | Scope; classes are resolved against the SSL application catalogue | `["FILE_SHARE", "WEBMAIL", "AI_ML"]` |

```json
{
  "name": "R_PHI_SSL_DECRYPT_FILE_SHARE_WEBMAIL_AI",
  "channel": "ssl",
  "action": {
    "type": "DECRYPT",
    "ssl_interception_cert": {"id": 1, "default_certificate": true},
    "decrypt_sub_actions": {"server_certificates": "ALLOW", "ocsp_check": true, "min_client_tls_version": "CLIENT_TLS_1_2", "min_server_tls_version": "SERVER_TLS_1_2", "http2_enabled": true}
  },
  "cloud_app_classes": ["FILE_SHARE", "WEBMAIL", "AI_ML"],
  "platforms": ["SCAN_WINDOWS", "SCAN_MACOS", "SCAN_LINUX", "SCAN_IOS", "SCAN_ANDROID", "NO_CLIENT_CONNECTOR"],
  "road_warrior_for_kerberos": true,
  "state": "DISABLED",
  "rank": 7
}
```

Preflight lists each channel's API reachability under *Tenant
prerequisites*, resolves application classes and Cloud App Control actions
against the live tenant, blocks only the rules whose prerequisites are
missing, and adds an impact card reminding that containment rules run
before DLP. The journey check compares action, state, applications, URL
categories, file types and operation and reports customized rules without
reverting them. Terraform export emits
`zia_cloud_app_control_rule` (actions via the
`zia_cloud_app_control_rule_actions` data source), `zia_file_type_control_rules`,
`zia_url_filtering_rules` and `zia_ssl_inspection_rules`.
