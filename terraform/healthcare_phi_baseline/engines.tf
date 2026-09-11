# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "hipaa_critical_strong_signature_clinical_document" {
  name                         = "HIPAA Critical (Strong Signature + Clinical Document)"
  description                  = "Engine 1. High-confidence PHI with a strong identity anchor; single record reportable. Three pathways: (1) Medical Document or Medical Imaging classifier + identifier; (2) Medical Information context with clinical density (Drugs > 4, Diseases > 2, Treatments > 4, or an NDC code) + identifier; (3) clinical-narrative structure (> 3 markers) with clinical content + identifier. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((((D${data.zia_dlp_dictionaries.medical_document.id}.S > 0) OR (D${data.zia_dlp_dictionaries.medical_imaging.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${data.zia_dlp_dictionaries.names_us.id}.S > 0))) OR ((D${data.zia_dlp_dictionaries.medical_information.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_information.id}.S > 4) OR (D${data.zia_dlp_dictionaries.diseases_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 4) OR (D${data.zia_dlp_dictionaries.ndc_number_package.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ndc_number_product.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${data.zia_dlp_dictionaries.names_us.id}.S > 0))) OR ((D${zia_dlp_dictionaries.custom_clinical_narrative.id}.S > 3) AND ((D${data.zia_dlp_dictionaries.diseases_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.drugs_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${data.zia_dlp_dictionaries.names_us.id}.S > 0))))"
}

resource "zia_dlp_engines" "hipaa_narrative_low_volume" {
  name                         = "HIPAA Narrative / Low Volume"
  description                  = "Engine 2. Short-form clinical content (referral letters, prior authorizations, prescription notes) that will not reach Engine 1's density: clinical terms > 2 with a name and a second identifier (SSN, DOB, MRN or member id). [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.diseases_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.drugs_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 2)) AND (D${data.zia_dlp_dictionaries.names_us.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0)))"
}

resource "zia_dlp_engines" "hipaa_identity_trifecta" {
  name                         = "HIPAA Identity Trifecta"
  description                  = "Engine 3. Identity-theft-grade combinations independent of clinical content, reportable under most state breach laws: strict trifecta (SSN + DOB + name) or the expanded branch (name + DOB + driver's licence, enhanced driver's licence or TIN). Without a DOB the expanded branch never fires. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) AND (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) AND (D${data.zia_dlp_dictionaries.names_us.id}.S > 0)) OR ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) AND (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S > 0) OR (D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S > 0) OR (D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S > 0))))"
}

resource "zia_dlp_engines" "hipaa_sensitive_subcategory" {
  name                         = "HIPAA Sensitive Subcategory"
  description                  = "Engine 4. Mental health, substance use disorder (42 CFR Part 2), HIV, genetic (GINA) and reproductive PHI beside an identifier: elevated handling, restricted reviewer queue. Terms and gene names from the custom markers, ICD-10 codes from Diseases Information, informal language from Self-Harm & Cyberbullying and Illegal Drugs. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.custom_sensitive_condition_markers.id}.S > 0) OR (D${data.zia_dlp_dictionaries.diseases_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.self_harm_cyberbullying.id}.S > 0) OR (D${data.zia_dlp_dictionaries.illegal_drugs.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0)))"
}

resource "zia_dlp_engines" "hipaa_pharmacy_claims_billing" {
  name                         = "HIPAA Pharmacy / Claims / Billing"
  description                  = "Engine 5. Pharmacy pathway: drug evidence (Drugs > 2 or an NDC code) + identifier + a provider or narrative anchor (NPI or clinical narrative). Claims pathway: billing density (> 2 billing phrases) or the Insurance Document classifier + clinical evidence + identifier (including a card number on a claim document; the clinical gate keeps pure payments out). [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((((D${data.zia_dlp_dictionaries.drugs_information.id}.S > 2) OR (D${data.zia_dlp_dictionaries.ndc_number_package.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ndc_number_product.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_clinical_narrative.id}.S > 0))) OR (((D${zia_dlp_dictionaries.custom_insurance_billing.id}.S > 2) OR (D${data.zia_dlp_dictionaries.insurance_document.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.diseases_information.id}.S > 0) OR (D${data.zia_dlp_dictionaries.treatments_information.id}.S > 0)) AND ((D${data.zia_dlp_dictionaries.names_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_date_of_birth.id}.S > 0) OR (D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 0) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 0) OR (D${data.zia_dlp_dictionaries.credit_cards.id}.S > 0))))"
}

resource "zia_dlp_engines" "hipaa_bulk_phi_small" {
  name                         = "HIPAA Bulk PHI - Small"
  description                  = "Engine 6, small tier (> 1 identifiers): any multi-record exposure of SSN, MRN, member id, NPI, TIN, driver's licence or enhanced driver's licence. The API has no Sum operator, so the tier is expressed per dictionary; a transaction with 2 or more of one identifier kind matches. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 1) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 1) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 1) OR (D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S > 1) OR (D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S > 1) OR (D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S > 1) OR (D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S > 1))"
}

resource "zia_dlp_engines" "hipaa_bulk_phi_significant" {
  name                         = "HIPAA Bulk PHI - Significant"
  description                  = "Engine 6, significant tier (> 50 identifiers of one kind): executive escalation, still under the 500-individual notification threshold. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 50) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 50) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 50) OR (D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S > 50) OR (D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S > 50) OR (D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S > 50) OR (D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S > 50))"
}

resource "zia_dlp_engines" "hipaa_bulk_phi_major" {
  name                         = "HIPAA Bulk PHI - Major"
  description                  = "Engine 6, MAJOR tier (> 500 identifiers of one kind): a potential 500+ individual breach; routes straight to the Privacy Officer, legal counsel and executive incident response. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${data.zia_dlp_dictionaries.social_security_numbers_us.id}.S > 500) OR (D${zia_dlp_dictionaries.custom_medical_record_number.id}.S > 500) OR (D${zia_dlp_dictionaries.custom_health_plan_member_identifier.id}.S > 500) OR (D${data.zia_dlp_dictionaries.national_provider_identifier.id}.S > 500) OR (D${data.zia_dlp_dictionaries.tax_identification_number_us.id}.S > 500) OR (D${data.zia_dlp_dictionaries.driver_s_license_united_states.id}.S > 500) OR (D${data.zia_dlp_dictionaries.enhanced_driver_s_license_united_states.id}.S > 500))"
}

