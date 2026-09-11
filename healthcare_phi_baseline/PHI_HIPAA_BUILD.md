# Healthcare PHI Policy Pack 3.1 — PHI / HIPAA DLP Build

Predefined-first dictionary and engine reference for Zscaler ZIA, six-engine architecture plus the Fed pack's US PII and US PHI engines. Built from the customer's build document; the pack configs carry the API fields only. Every rule ships DISABLED, monitor-only (ALLOW) at INFO severity and is mirrored one-for-one onto Endpoint DLP, SaaS Security API and Outbound Email DLP (11 × 4 rules).

Engine names use only the characters ZIA accepts (letters, digits, underscore, hyphen, dot, parentheses and space): "Narrative - Low Volume", "Pharmacy - Claims - Billing", "Strong Signature and Clinical Document". The long engine descriptions in this pack are documentation; the deploy clamps what it sends to ZIA's 255-character limit.

## What is PHI (and what the engines test for)

PHI (45 CFR § 160.103) needs both components: one or more of the 18 HIPAA identifiers (45 CFR § 164.514(b)(2)(i)) **and** health information (condition, care, or payment for care). Every engine below requires an identifier beside a clinical, pharmacy or billing signal, except Engine 3 (identity trifecta, reportable under state breach law on its own) and Engine 6 (bulk identifiers).

## 18-identifier coverage map

| # | Identifier | Covered by |
|---|---|---|
| 1 | Names | Names (US), predefined |
| 2 | Geographic subdivisions smaller than a state | Custom-Address-ZIP (not wired into an engine by default: ZIP alone is very noisy) |
| 3 | Dates (DOB, admission, discharge, death) | Custom-Date-of-Birth |
| 4, 5 | Telephone and fax numbers | Not in this build; add a Custom-Phone-US dictionary if in scope |
| 6 | E-mail addresses | Not in this build; transport-layer detection (Email DLP) covers mail |
| 7 | Social Security Numbers | Social Security Numbers (US), predefined; HC- clones at high confidence and 500-byte proximity (Engines 7-9) |
| 8 | Medical record numbers | Custom-Medical-Record-Number (MRN, chart, encounter, visit, account, EMPI) |
| 9 | Health plan beneficiary numbers | Custom-Health-Plan-Member-Identifier (member, subscriber, policy, group, Medicare MBI, HICN, Medicaid, pharmacy BIN/PCN) |
| 10 | Account numbers | Custom-Health-Plan-Member-Identifier; Credit Cards (predefined) on claim documents |
| 11 | Certificate / licence numbers | National Provider Identifier, Driver's License (United States), Enhanced Driver's License (United States), predefined |
| 12, 13 | Vehicle and device identifiers | Out of scope (environment-specific) |
| 14 | URLs | URL Filtering policy, not DLP |
| 15 | IP addresses | Not in this build; add a regex dictionary if in scope |
| 16, 17 | Biometrics, full-face photographs | Not text-detectable; access controls, image classification |
| 18 | Other unique identifiers | Tax Identification Number (US), predefined |

Clinical data: Diseases Information (ICD-10 and condition names), Treatments Information (CPT/HCPCS and procedures), Drugs Information and NDC Number (Package / Product), Medical Document and Medical Imaging classifiers, Medical Information (general terminology), Insurance Document, plus Custom-Clinical-Narrative and Custom-Insurance-Billing.

Tenants created before April 4, 2025 may need Zscaler Support to enable the medical dictionary bundle. Predefined dictionaries are referenced by their portal display names; the deploy resolves them by API code, display name or description, and prunes (with a warning) any the tenant does not expose.

## Custom dictionaries

| Dictionary | Match | Proximity | Content |
|---|---|---|---|
| Custom-Medical-Record-Number | any pattern near any phrase | 50 | MRN / chart / encounter / account labels beside a 6–10 digit number (optional 1–3 letter prefix) |
| Custom-Date-of-Birth | any pattern near any phrase | 50 | birth-date labels beside US, ISO or long-form dates (1920–2026) |
| Custom-Sensitive-Condition-Markers | any | — | SUD and MAT terms, mental-health, HIV, genetic (incl. gene names BRCA1/2, APOE, MTHFR, CFTR, HLA, MLH1, MSH2/6, PMS2, TP53, PTEN, APC, VHL, RET, JAK2, FLT3, EGFR, ALK, KRAS, NRAS, BRAF, HER2) and reproductive-health markers |
| Custom-Health-Plan-Member-Identifier | any pattern near any phrase | 50 | member / subscriber / policy / group / Medicare labels beside an MBI or a 2–3 letter + 6–12 digit id |
| Custom-Insurance-Billing | phrases | — | major payers, EDI transactions (837/835/271, HL7, FHIR, X12), billing terms (EOB, remittance, copay, prior authorization) |
| Custom-Clinical-Narrative | phrases | — | structural markers of clinical documents (chief complaint, HPI, ROS, discharge, progress and operative notes, provider roles, admission/discharge dates) |
| Custom-Address-ZIP | any pattern near any phrase | 50 | address labels beside ZIP+4 or a street address |

Documented ZIA limits: 8 patterns per dictionary, 256 bytes per pattern, proximity 0–10000 bytes, PCRE without lookaround, phrases 3–128 bytes and up to 256 per dictionary; phrases match case-insensitively and ignore punctuation. A proximity window is accepted only on the *Match any Patterns and any Phrases* type (`MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE`: a number counts when a label sits within the window); the tenant rejects proximity on the *Match All* and *Match Any* types, so the four structured-identifier dictionaries use it.

## Engines

| # | Engine | Reporting tier | Logic |
|---|---|---|---|
| 1 | HIPAA Critical (Strong Signature and Clinical Document) | single record reportable, high priority | Any of: Medical Document or Medical Imaging + identifier; Medical Information + clinical density (Drugs > 4, Diseases > 2, Treatments > 4, or NDC) + identifier; Custom-Clinical-Narrative > 3 + clinical content + identifier. Identifier = SSN, DOB, MRN or name |
| 2 | HIPAA Narrative - Low Volume | single record reportable | clinical terms > 2 (diseases, drugs or treatments) AND a name AND SSN, DOB, MRN or member id |
| 3 | HIPAA Identity Trifecta | single record + state breach law, critical | SSN + DOB + name, OR name + DOB + (driver's licence, enhanced driver's licence or TIN). Without a DOB the expanded branch never fires |
| 4 | HIPAA Sensitive Subcategory | single record + 42 CFR Part 2 / GINA, critical (elevated) | (sensitive markers, Diseases Information, Self-Harm & Cyberbullying or Illegal Drugs) AND (name, SSN, DOB, MRN or member id). Route to a restricted reviewer queue |
| 5 | HIPAA Pharmacy - Claims - Billing | single record reportable | pharmacy: (Drugs > 2 or NDC) + identifier + (NPI or clinical narrative); claims: (billing phrases > 2 or Insurance Document) + (diseases or treatments) + identifier incl. Credit Cards |
| 6 | HIPAA Bulk PHI — Small / Significant / Major | > 1 / > 50 / > 500 identifiers | Sum of the matches of SSN, MRN, member id, NPI, TIN, driver's licence and enhanced driver's licence (the Engine Builder's Sum operator, `((D1.S + D2.S + …) > n)` in the API). One design engine, three thresholds: three engines behind three rules, because a rule has no match-count condition of its own |
| 7 | HIPAA US PII | identity data, no clinical context | From the Fed pack's US PII engine, plus passports: SSN, TIN, alien registration or passport > 4 at high confidence, or any one within 500 bytes of its label, or a date of birth with driver's licences > 4. Covers the patient, member and staff identity data a covered entity holds that state breach law reaches even without a diagnosis |
| 8 | HIPAA US PHI — Medium Confidence | single record, second opinion | From the Fed pack: Medical Document, or Medical Information with Drugs > 9 or Diseases > 9, AND one identifier (SSN, passport, alien number, or DOB beside a driver's licence). Independent of Engine 1's custom dictionaries; the two should agree on real records |
| 9 | HIPAA US PHI — High Confidence | patient-record sets | From the Fed pack: Medical Document, or Medical Information with Drugs > 14 or Diseases > 14, AND identifiers > 4 at high confidence (or DOB > 1 beside licences > 1), or any identifier within 500 bytes of its label |

### Fed-derived PII dictionaries (HC- prefix)

Twelve dictionaries copied from the Fed pack's US PII set and renamed with an `HC-` prefix so the two packs can share a tenant. Three clones, each in a *High* (confidence) and a *Prox 500* (proximity) variant: Social Security Numbers (US), Tax Identification Number (US) and Drivers License (United States); the template is resolved per tenant by name, and a tenant that does not expose one has the clone skipped and the engine created without that term (the plan names it). Three custom pairs: Alien Registration Number, Date of Birth and US Passport, each as a High Confidence and a Prox 500 variant on the *Match any Patterns and any Phrases* type.

## Rules and reporting tiers

| Rule | Engine | Action | Handling |
|---|---|---|---|
| HC-HIPAA Critical-Monitor | 1 | Monitor (ALLOW), DISABLED | immediate investigation; likely reportable if exfiltrated unsecured |
| HC-HIPAA Narrative Low Volume-Monitor | 2 | Monitor (ALLOW), DISABLED | immediate investigation; member id + diagnosis triggers state breach law |
| HC-HIPAA Identity Trifecta-Monitor | 3 | Monitor (ALLOW), DISABLED | immediate investigation; often reportable under state law |
| HC-HIPAA Sensitive Subcategory-Monitor | 4 | Monitor (ALLOW), DISABLED | restricted reviewer queue; elevated SLA; separate notification template and auditor |
| HC-HIPAA Pharmacy Claims Billing-Monitor | 5 | Monitor (ALLOW), DISABLED | immediate investigation; watch the false-positive rate of the merged pathways |
| HC-HIPAA Bulk PHI Major-Monitor | 6, > 500 | Monitor (ALLOW), DISABLED | CRITICAL: bypass tier-2 review; Privacy Officer, legal counsel, executive incident response, forensics; breach risk assessment within 1 hour |
| HC-HIPAA Bulk PHI Significant-Monitor | 6, > 50 | Monitor (ALLOW), DISABLED | HIGH: executive escalation, immediate forensic investigation |
| HC-HIPAA Bulk PHI Small-Monitor | 6, > 1 | Monitor (ALLOW), DISABLED | MEDIUM: standard tier-2 review; document for the annual HHS log |
| HC-US PII-Monitor | 7 | Monitor (ALLOW), DISABLED | identity data without clinical context: state breach law review; often HR, billing or member-services traffic |
| HC-US PHI Medium Confidence-Monitor | 8 | Monitor (ALLOW), DISABLED | second PHI opinion: compare with Engine 1's incidents during tuning; investigate where only this rule fired |
| HC-US PHI High Confidence-Monitor | 9 | Monitor (ALLOW), DISABLED | immediate investigation; a set of patient records is leaving |

Under Rule Order, enable the Bulk rules ordered Major, Significant, Small so a transaction lands in exactly one tier; under Evaluate All Rules every matching tier logs its own incident. Every rule ships DISABLED, at INFO and in monitor (ALLOW): enable, review the incidents, raise the severity per the tier. Every rule in every pack monitors; if the customer later decides to enforce a tier, that is their change in the portal, and the journey card records it as progress.

## From a DLP incident to a breach decision

1. Engine fires; incident generated (Incident Receiver, Workflow Automation).
2. Does the exposed data meet the PHI definition (identifier + health information)?
3. Was the PHI unsecured at the point of egress? Encryption at rest in the source system does not help once the data was decrypted before exfiltration.
4. Four-factor risk assessment (45 CFR § 164.402): nature and extent of the PHI; who received it; whether it was actually acquired or viewed; how far the risk is mitigated. A documented low probability of compromise means no notification, and the assessment is retained for six years.
5. Breach confirmed: count the affected individuals.
6. Notify: individuals within 60 calendar days of discovery (45 CFR § 164.404); HHS immediately for 500+ or in the annual log for fewer (§ 164.408); prominent media when 500+ in one state or jurisdiction (§ 164.406); state attorneys general per state law. Business associates notify the covered entity within 60 days, and usually far sooner under the BAA (§ 164.410).
7. Document the whole response and keep it six years (45 CFR § 164.530(j)).

42 CFR Part 2 (substance use disorder records) follows the same breach notification rule since February 16, 2026, with the extra protection that Part 2 records cannot be used in legal proceedings without consent or a court order. Civil penalty tiers run from "did not know" to "willful neglect, not corrected" (45 CFR § 160.404), each with an annual cap per identical violation; criminal penalties reach $250,000 and ten years for intent to sell or use PHI for gain.

## Implementation sequence

1. Verify the predefined dictionaries exist in the tenant (preflight lists any it prunes); open a support ticket for the medical bundle if needed. Validate them on a test corpus (the app's local corpus test shows which predefined dictionaries and engines would fire).
2. Deploy; everything arrives disabled. Enable Engine 1's rule in monitor mode, validate hit and false-positive rates across its three pathways for one to two weeks, then enforce.
3. Enable Engines 2, 3 and 5 in monitor mode; tune thresholds on incident volume; watch Engine 5 (Insurance Document, Credit Cards) and Engine 3's expanded branch (if it exceeds 25 % of Engine 3's volume, tighten the DOB proximity). Enforce after two weeks.
4. Enable Engine 4 and the three Bulk tiers; configure the restricted reviewer routing for Engine 4 and the executive routing for the Major tier.

## Tuning notes

- Predefined precedence: Diseases and Treatments Information carry the ICD-10 and CPT/HCPCS coverage; no custom code regexes to maintain.
- Proximity: 50 bytes for structured identifiers (MRN, DOB, member id, address); the sensitive markers match on any phrase or gene name instead.
- Names (US) action: conservative accumulation for Engine 3, permissive for Engines 1, 2 and 4 where other dictionaries gate the trigger.
- Custom-Health-Plan-Member-Identifier is intentionally loose (payers vary); rely on the proximity phrase to filter.
- Custom-Address-ZIP: use only beside insurance/billing context.
- Engine 4 hits that come solely from Self-Harm & Cyberbullying (informal language in patient communications, chat, intake notes) go to the same restricted queue but should be flagged separately for review-pattern analysis.
- The Detection Health tab measures each rule's false-positive rate from Workflow Automation verdicts and proposes the tuning (raise a threshold, exclude the clearing house, promote a monitor rule) with the evidence.

This summary is operational reference, not legal advice; the Privacy Officer and counsel own the breach determination.
