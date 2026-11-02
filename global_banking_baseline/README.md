# Global Banking Baseline

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

DLP baseline for global and regional banks, card issuers, payment
processors and wealth managers. It is **premised on Zscaler's predefined
dictionaries**: the identification dictionaries are cloned at
`CONFIDENCE_LEVEL_HIGH` (each with a 500-byte proximity twin), the
hierarchical EU IBAN and EU / Asia-Pacific passport dictionaries and the
corporate-finance, financial-statement and tax ML dictionaries are
referenced directly, and a small set of custom dictionaries adds what
Zscaler does not ship (global IBAN, SWIFT/BIC, wire vocabulary, KYC/AML,
lending, MNPI, confidentiality markings, non-US national IDs).

It **reuses the ZBP Enterprise Baseline engines** (`ZBP-US PII`,
`ZBP-Financial Information`, `ZBP-Private Keys`) and their dictionaries
under the same names, so deploying both packs creates each shared object
once.

## What it detects

| Engine | Built from | Fires when |
|---|---|---|
| `Bank-Payment Card Data` | `CREDIT_CARD` clones (High, Prox 500, BIN numbers on), magnetic-track regex, card-security phrases | 5+ distinct high-confidence PANs, 2+ PANs near card phrases, any track data, or one PAN beside 2+ CVV/PIN/expiry fields |
| `Bank-Payment Card Data - Bulk` | same | 25+ distinct PANs or 5+ track records (block-grade) |
| `Bank-Account and Payment Instructions` | `ABA_LEAKAGE` clones, `EUIBAN_LEAKAGE`, global IBAN regex, SWIFT/BIC regex, wire vocabulary | several account identifiers, or one identifier with wire-instruction vocabulary |
| `Bank-Customer Financial Records` | statement vocabulary + any account / card / DOB / national-ID | 5+ statement terms beside an identifier |
| `Bank-Customer PII (Global)` | `SSN` and `USITIN_LEAKAGE` clones, `USDL_LEAKAGE` clone, `PPEU_LEAKAGE`, `ASPP_LEAKAGE`, US passport, DOB, UK/CA/AU/ZA and IN/SG/HK national-ID regexes, PII field labels | US identifiers at high confidence or in proximity, 2+ national IDs or passports, DOB with a US licence, or 4+ PII labels beside any identifier |
| `Bank-Customer PII - Bulk` | same | 25+ distinct identifiers of one kind or 50+ dates of birth (block-grade) |
| `Bank-KYC and AML Files` | KYC/AML vocabulary + identifier or PII labels | 4+ KYC terms beside personal data |
| `Bank-Credit and Loan Applications` | lending vocabulary + identifier or PII labels | 5+ lending terms beside personal data |
| `Bank-MNPI and Deal Information` | deal vocabulary, `ML_CORPORATE_FINANCE_LEAKAGE`, `FINANCIAL` + markings | 4+ deal terms, the ML dictionary, or a financial statement stamped confidential |
| `Bank-Confidential Markings` | marking phrases | any bank confidentiality marking |
| `ZBP-US PII`, `ZBP-Financial Information`, `ZBP-Private Keys` | ZBP Enterprise Baseline, verbatim | as in that pack (tax forms, US identifiers, private keys) |

## Rules (all ship DISABLED at INFO)

| Channel | Rule | Action |
|---|---|---|
| Inline Web | `Bank-Payment Card Data-Monitor`, `Bank-Payment Instructions-Monitor`, `Bank-Customer PII-Monitor`, `Bank-Customer Records-Monitor`, `Bank-MNPI-Monitor`, `Bank-Confidential Markings-Monitor`, `Bank-Credentials-Monitor` | ALLOW (monitor), OCR on |
| Inline Web | `Bank-Payment Card Data-Bulk-Block`, `Bank-Customer PII-Bulk-Block` | BLOCK |
| Endpoint | `Bank-Endpoint-Monitor` | ALLOW |
| Endpoint | `Bank-Endpoint-Bulk-Block-USB` | BLOCK, removable drives only |
| SaaS Security API | `Bank-SaaS File-Monitor` | report incident, every onboarded file tenant |
| Outbound Email | `Bank-Email-Monitor` | ALLOW |
| SSL Inspection | `Bank-SSL-Decrypt-File-Share-Webmail-AI` | decrypt file-share, webmail and AI apps |
| Cloud App Control | `Bank-CAC-File-Share-No-Upload`, `Bank-CAC-Webmail-No-Send`, `Bank-CAC-AI-No-Upload` | block upload / send |
| File Type Control | `Bank-FTC-Block-Bulk-Export-Upload` | block spreadsheets, databases, archives to file shares |
| URL Filtering | `Bank-URL-Block-Post-To-Unknown` | block POST/PUT to uncategorised sites |

Enable order that works for most banks: confidentiality markings first
(almost no false positives), then card data, then payment instructions and
customer PII. Watch incidents for a week before touching the bulk BLOCK
rules.

## Tenant prerequisites

Preflight lists these under *Tenant prerequisites*:

- Predefined dictionaries `CREDIT_CARD`, `ABA_LEAKAGE`, `SSN`,
  `USITIN_LEAKAGE`, `USDL_LEAKAGE`, `CRED_LEAKAGE` (cloned) and
  `EUIBAN_LEAKAGE`, `PPEU_LEAKAGE`, `ASPP_LEAKAGE`, `FINANCIAL`,
  `ML_CORPORATE_FINANCE_LEAKAGE`, `ML_TAX_LEAKAGE` (referenced). A tenant
  that lacks one skips only the engines that need it.
- Endpoint DLP, SaaS Security API and Email DLP licences for their rules;
  an onboarded file-storage tenant and an onboarded Microsoft 365 / Gmail
  tenant.
- Each predefined dictionary allows 4 clones. The pack uses 2 per
  template; the ZBP Enterprise pack uses the same 2, not 2 more.

## Tuning notes

- `EUIBAN_LEAKAGE`, `PPEU_LEAKAGE` and `ASPP_LEAKAGE` are hierarchical
  (per-country). They are referenced at the tenant's default confidence
  rather than cloned, because a clone must name the country identifiers
  your tenant exposes (`GET /dlpDictionaries/{id}/predefinedIdentifiers`).
  To tighten, clone in the portal at high confidence with the countries
  you serve, point the engines at the clone, and update
  `configs/dlp_engines.json` so the baseline does not report drift.
- The national-ID regexes carry no checksum. Zscaler ships predefined
  dictionaries for many of these countries; if your tenant has them,
  swap the custom dictionary for the predefined name in the engines.
- Bulk thresholds (25 distinct matches) are a starting point. A sanctioned
  statement run legitimately carries hundreds of account numbers; scope
  that channel (SaaS tenant, rule order) rather than raising the threshold.
- `Bank-SWIFT BIC Code` only matches within 300 bytes of a SWIFT/BIC
  phrase because the bare pattern matches ordinary 8-letter uppercase words.

## Regenerating

The configs are authored from a generator to keep the ZBP objects byte
identical; edit `configs/*.json` directly for tuning, and re-run
`python pack_terraform.py global_banking_baseline --out terraform` so the
committed Terraform workspace matches.
