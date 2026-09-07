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
| `action` | no | `ALLOW` | `ALLOW` (monitor only) or `BLOCK` (enforce) |
| `state` | no | `ENABLED` | `ENABLED` / `DISABLED` |
| `rank` | no | 7 | 0 = highest priority (use Rank 0 import button for conflict resolution) |
| `engines` | yes | — | Array of engine **names** from this pack or pre-existing in tenant |
| `protocols` | no | `["ANY_RULE"]` | `HTTP_RULE`, `HTTPS_RULE`, `FTP_RULE`, `NATIVE_FTP_RULE` |
| `severity` | no | — | `RULE_SEVERITY_INFO` / `LOW` / `MEDIUM` / `HIGH` |
| `file_types` | no | all | e.g. `["FTCATEGORY_MS_EXCEL", "FTCATEGORY_PDF_DOCUMENT"]` |
| `locations` / `groups` / `departments` / `users` | no | all | Restrict rule to scope |

Set `match_only: true` to use match-only semantics (first-match-wins on a match without continuing rule evaluation). `without_content_inspection: true` matches on metadata (file name, MIME type) without opening the payload.

---

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

## 6. Import — Three Ways

### Web UI (recommended)

1. Drop the pack directory in the project root.
2. Restart the server; hard-refresh browser (Ctrl+Shift+R).
3. Click **📦 DLP Policy Packs** → your pack → **▶ Import to Tenant**.
4. Click **Verify Deployment** to diff tenant state vs pack JSON.

### API (for scripting / CI)

```bash
# List packs
curl http://localhost:8080/api/dlp-packs

# Preview a pack's contents
curl http://localhost:8080/api/dlp-packs/my_pack_name

# Run import
curl -X POST http://localhost:8080/api/dlp-packs/my_pack_name/import \
  -H 'Content-Type: application/json' \
  -d '{"use_rank_0": false, "apply_tweaks": true, "verify": true}'

# Verify
curl -X POST http://localhost:8080/api/dlp-packs/my_pack_name/verify
```

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

- **First deploy**: set `action: "ALLOW"` on every policy — this monitors without blocking. Let it run a week, review triggers, tune dictionaries, then flip to `BLOCK`.
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
