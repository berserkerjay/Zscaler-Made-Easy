# Canada DLP Policy Pack (research candidate v0.1.0)

**Status: STAGING / REVIEW REQUIRED.** This is an original Canada-specific extension to Zscaler Made Easy's existing JSON DLP pack format. The pack defines 53 dictionaries, 18 engines and 72 DISABLED monitor-only INFO rules (18 for each of Web, Endpoint, SaaS and Email). The generator `pack_terraform.py` converts the **same** configuration into a Terraform workspace; avoid a second, divergent HCL implementation.

## Coverage and caveats

- Canadian SIN fallback: 1 format + context dictionary. **Does not validate Luhn**. Zscaler's native predefined Social Insurance Numbers (Canada) dictionary is preferable. A tenant-specific test/lookup is required before substituting it into the engine.
- Canada passports: new (2023+) and legacy candidates, both contextual.
- Federal identity and IRCC: UCI, COPR, PR Card, citizenship, landing document, status-registration and birth registration formats. Contextual; no document validity check.
- Healthcare: separate, contextual dictionaries for **13** provinces and territories. Formats are based on the CIHI 2026 identifier reference. Generic eight-/nine-/ten-digit sequences can collide with business data; checksum/issuer validation is **not implemented**.
- Drivers' licences: **13 provisional** province/territory rules based on a community catalog; source is MIT licensed. These are candidate formats, **not verified legal issuer specs**. Particularly short digit sequences require QA before any rule is enabled.
- Banking: institution/transit, EFT and customer account candidates; **not bank-account verification**. Use Zscaler EDM to match validated customer account data where possible.
- CRA federal BN and RT/RP/RC account, Québec NEQ/QST, postal/phone, birth date, tax/payroll, health, educational and insurance context.
- English and French evidence phrases are provided throughout. This is not a compliance certification for PIPEDA, PHIPA, Québec Law 25, or other privacy regimes.

**False-positive guardrails:** A number-shaped string alone is rarely sufficient. Numeric dictionaries require proximity to narrow contextual phrases; each policy is disabled. Check actual incidents, calibrate context, and test with synthetic positive/negative examples. The source metadata is in `sources.json`. No compiled proprietary Microsoft, Trellix, Netskope, or Broadcom rule definitions are redistributed.

## Architecture

```
canada_dlp_baseline/
  pack.json
  sources.json
  configs/
    dlp_dictionaries.json
    dlp_engines.json
    dlp_policies.json
```

- Each engine is a logical combination of symbolic `D:CA-...` references, resolved by existing ZBP import/deploy tooling.
- Every engine has exactly one Web, Endpoint, SaaS and Email rule. This follows the repository-wide pack convention.
- All 72 rules have `DISABLED` state and monitor actions. Enabling after testing is a **separate operator decision**.
- `baseline.immutable` follows existing ZBP convention, but **do not apply to live tenant until reviewed**, as pack convergence may correct drift in existing objects with matching names.

## Review and validation

```bash
python -m pytest -q tests/test_canada_dlp_pack.py
python -m pytest -q tests/test_pack_conventions.py tests/test_pack_terraform.py
```

Use the existing `pack_terraform.generate` integration / UI to create an official `zscaler/zia` Terraform workspace. The generated README describes variables, provider auth, import/gap planning and safe apply. Run `terraform fmt -check`, `terraform init -backend=false`, `terraform validate`, and `terraform plan` **against a non-production tenant first**. No live apply or ZIA activation was performed by this change.

## Source and rights

- [CIHI Canadian 2026 healthcare identifier formats](https://www.cihi.ca/sites/default/files/document/acute-ambulatory-care-data-content-standard-2026-en.pdf) — factual structure reference; linked, **not copied as a document**. Review CIHI terms before redistributing excerpts.
- [IRCC Canadian identity/document help](https://ircc.canada.ca/english/helpcentre/answer.asp?qnum=1446)
- [CRA business number / program accounts](https://www.canada.ca/en/revenue-agency/services/forms-publications/publications/2-1/required-registration.html)
- [dlpscan community patterns](https://github.com/oxide11/dlpscan/blob/main/PATTERNS.md) — MIT license; copyright 2026 Moussa Noun. Preserve license terms when reusing.
- [Zscaler DLP predefined dictionary documentation](https://help.zscaler.com/zia/understanding-predefined-dlp-dictionaries)
- [Microsoft Purview sensitive information definitions](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions)

## Follow-up hardening

1. Verify each driver format with actual issuer examples; remove/disable false-positive-heavy detectors rather than silently trusting community formats.
2. Add test fixtures with synthetic identifiers that follow *actual* check-digit algorithms, and negative samples for incidental numeric matches.
3. Validate the ZIA supported regex dialect on the target tenant (Python regex acceptance is not equivalent to ZIA acceptance).
4. Confirm exact Zscaler native Canadian SIN dictionary name/code via tenant lookup and replace the fallback engine term; preserve source naming.
5. Inspect generated plan for collisions with other packs, missing CASB/Email tenants, and feature availability; deploy by channel, inspect, then enable.
