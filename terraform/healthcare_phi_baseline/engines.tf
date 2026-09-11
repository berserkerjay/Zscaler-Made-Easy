# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "hipaa_critical_strong_signature_and_clinical_document" {
  name                         = "HIPAA Critical (Strong Signature and Clinical Document)"
  description                  = "Engine 1. High-confidence PHI with a strong identity anchor; single record reportable. Three pathways: (1) Medical Document or Medical Imaging classifier + identifier; (2) Medical Information context with clinical density (Drugs > 4, Diseases > 2, Treatments > 4, or an NDC code) + identifier; (3) clinical-narrative structure (> 3 markers) with clinical content + identifier. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((((D${data.zia_dlp_dictionaries.medical_document.id}.S > 0) OR (D${data.zia_dlp_dictionaries.medical_imaging.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${data.zia_dlp_dictionaries.names_us.id}.S > 0))) OR ((D${data.zia_dlp_dictionaries.medical_information.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_information.id}.S > 4) OR (D${data.zia_dlp_dictionaries.diseases_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 4) OR (D${data.zia_dlp_dictionaries.ndc_number_package.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ndc_number_product.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${data.zia_dlp_dictionaries.names_us.id}.S > 0))) OR ((D${zia_dlp_dictionaries.custom_clinical_narrative.id}.S > 3) AND ((D${data.zia_dlp_dictionaries.diseases_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.drugs_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${data.zia_dlp_dictionaries.names_us.id}.S > 0))))"
}

resource "zia_dlp_engines" "hipaa_narrative_low_volume" {
  name                         = "HIPAA Narrative - Low Volume"
  description                  = "Engine 2. Short-form clinical content (referral letters, prior authorizations, prescription notes) that will not reach Engine 1's density: clinical terms > 2 with a name and a second identifier (SSN, DOB, MRN or member id). [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.diseases_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.drugs_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 2)) AND (D${data.zia_dlp_dictionaries.names_us.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0)))"
}

resource "zia_dlp_engines" "hipaa_identity_trifecta" {
  name                         = "HIPAA Identity Trifecta"
  description                  = "Engine 3. Identity-theft-grade combinations independent of clinical content, reportable under most state breach laws: strict trifecta (SSN + DOB + name) or the expanded branch (name + DOB + driver's licence, enhanced driver's licence or TIN). Without a DOB the expanded branch never fires. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) AND (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) AND (D${data.zia_dlp_dictionaries.names_us.id}.S > 0)) OR ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) AND (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S > 0) OR (D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S > 0) OR (D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S > 0))))"
}

resource "zia_dlp_engines" "hipaa_sensitive_subcategory" {
  name                         = "HIPAA Sensitive Subcategory"
  description                  = "Engine 4. Mental health, substance use disorder (42 CFR Part 2), HIV, genetic (GINA) and reproductive PHI beside an identifier: elevated handling, restricted reviewer queue. Terms and gene names from the custom markers, ICD-10 codes from Diseases Information, informal language from Self-Harm & Cyberbullying and Illegal Drugs. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.custom_sensitive_condition_markers.id}.S > 0) OR (D${data.zia_dlp_dictionaries.diseases_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.self_harm_cyberbullying.id}.S > 0) OR (D${data.zia_dlp_dictionaries.illegal_drugs.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0)))"
}

resource "zia_dlp_engines" "hipaa_pharmacy_claims_billing" {
  name                         = "HIPAA Pharmacy - Claims - Billing"
  description                  = "Engine 5. Pharmacy pathway: drug evidence (Drugs > 2 or an NDC code) + identifier + a provider or narrative anchor (NPI or clinical narrative). Claims pathway: billing density (> 2 billing phrases) or the Insurance Document classifier + clinical evidence + identifier (including a card number on a claim document; the clinical gate keeps pure payments out). [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((((D${data.zia_dlp_dictionaries.drugs_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.ndc_number_package.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ndc_number_product.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_clinical_narrative.id}.S > 0))) OR (((D${zia_dlp_dictionaries.custom_insurance_billing.id}.S > 2) OR (D${data.zia_dlp_dictionaries.insurance_document.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.diseases_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0) OR (D${data.zia_dlp_dictionaries.credit_cards.id}.S > 0))))"
}

resource "zia_dlp_engines" "hipaa_bulk_phi_small" {
  name                         = "HIPAA Bulk PHI - Small"
  description                  = "Engine 6, small tier: the Sum of identifier matches (SSN, MRN, member id, NPI, TIN, driver's licence, enhanced driver's licence) above 1, i.e. any multi-record exposure. The Engine Builder's Sum operator, as the build specifies; the tiers differ only in the threshold. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S + D${zia_dlp_dictionaries.custom_medical_record_number.id}.S + D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S + D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S + D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S + D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S + D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S) > 1)"
}

resource "zia_dlp_engines" "hipaa_bulk_phi_significant" {
  name                         = "HIPAA Bulk PHI - Significant"
  description                  = "Engine 6, significant tier: the same Sum of identifier matches above 50. Executive escalation; still under the 500-individual notification threshold. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S + D${zia_dlp_dictionaries.custom_medical_record_number.id}.S + D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S + D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S + D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S + D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S + D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S) > 50)"
}

resource "zia_dlp_engines" "hipaa_bulk_phi_major" {
  name                         = "HIPAA Bulk PHI - Major"
  description                  = "Engine 6, MAJOR tier: the same Sum of identifier matches above 500, a potential 500+ individual breach; routes straight to the Privacy Officer, legal counsel and executive incident response. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S + D${zia_dlp_dictionaries.custom_medical_record_number.id}.S + D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S + D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S + D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S + D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S + D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S) > 500)"
}

resource "zia_dlp_engines" "hipaa_us_pii" {
  name                         = "HIPAA US PII"
  description                  = "Engine 7 (from the Fed pack's US PII engine, plus passports). Personally identifiable information outside a clinical context: five or more SSNs, TINs, alien registration or passport numbers, any one of them within 500 bytes of its label, or a date of birth with five or more driver's licence numbers. Catches the identity data a covered entity holds on patients, members and staff that is reportable under state breach law even when no diagnosis travels with it. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.hc_social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.hc_social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.hc_tax_identification_number_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.hc_tax_identification_number_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.hc_alien_registration_number_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.hc_alien_registration_number_prox_500.id}.S > 0) OR ((D${zia_dlp_dictionaries.hc_date_of_birth_high_confidence.id}.S > 1) AND (D${zia_dlp_dictionaries.hc_drivers_license_united_states_high.id}.S > 4)) OR (D${zia_dlp_dictionaries.hc_us_passport_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.hc_us_passport_prox_500.id}.S > 0))"
}

resource "zia_dlp_engines" "hipaa_us_phi_medium_confidence" {
  name                         = "HIPAA US PHI - Medium Confidence"
  description                  = "Engine 8 (from the Fed pack's US PHI - Medium Confidence). Medical content (Medical Document, or Medical Information with ten or more drug or disease terms) together with one identifier: an SSN, passport or alien number, or a date of birth beside a driver's licence. A second, independent PHI opinion beside Engine 1; the two are expected to overlap on real records and disagree on edge cases, which is what the tuning phase measures. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.medical_document.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical_information.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_information.id}.S > 9) OR (D${data.zia_dlp_dictionaries.diseases_information.id}.S > 9)))) AND ((D${zia_dlp_dictionaries.hc_social_security_numbers_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.hc_us_passport_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.hc_alien_registration_number_high_confidence.id}.S > 0) OR ((D${zia_dlp_dictionaries.hc_date_of_birth_high_confidence.id}.S > 0) AND (D${zia_dlp_dictionaries.hc_drivers_license_united_states_prox_500.id}.S > 0))))"
}

resource "zia_dlp_engines" "hipaa_us_phi_high_confidence" {
  name                         = "HIPAA US PHI - High Confidence"
  description                  = "Engine 9 (from the Fed pack's US PHI - High Confidence). Denser medical content (fifteen or more drug or disease terms) together with five or more identifiers, or any identifier within 500 bytes of its label. Fires on documents that are unmistakably a set of patient records. [DLP-Check baseline healthcare_phi_baseline v3.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.medical_document.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical_information.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_information.id}.S > 14) OR (D${data.zia_dlp_dictionaries.diseases_information.id}.S > 14)))) AND ((D${zia_dlp_dictionaries.hc_social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.hc_us_passport_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.hc_alien_registration_number_high_confidence.id}.S > 4) OR ((D${zia_dlp_dictionaries.hc_date_of_birth_prox_500.id}.S > 1) AND (D${zia_dlp_dictionaries.hc_drivers_license_united_states_prox_500.id}.S > 1)) OR (D${zia_dlp_dictionaries.hc_social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.hc_us_passport_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.hc_alien_registration_number_prox_500.id}.S > 0)))"
}

