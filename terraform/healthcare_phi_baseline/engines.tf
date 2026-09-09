# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "e_healthcare_phi" {
  name                         = "E_HEALTHCARE_PHI"
  description                  = "Presence-based PHI. Branch A: clinical context (predefined MEDICAL (Medical Information) or ML_MEDICAL_DOC_LEAKAGE (Medical Document), or the custom clinical phrases) AND at least one strong identifier. Branch B: two distinct strong identifiers. Branch C: the legal-sex booster beside a strong identifier. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((((D${data.zia_dlp_dictionaries.medical.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_medical_doc_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.d_clinical_phrases.id}.S > 0)) AND ((D${zia_dlp_dictionaries.d_mrn.id}.S > 0) OR (D${zia_dlp_dictionaries.d_acct.id}.S > 0) OR (D${zia_dlp_dictionaries.d_dob.id}.S > 0))) OR (((D${zia_dlp_dictionaries.d_mrn.id}.S > 0) AND (D${zia_dlp_dictionaries.d_acct.id}.S > 0)) OR ((D${zia_dlp_dictionaries.d_mrn.id}.S > 0) AND (D${zia_dlp_dictionaries.d_dob.id}.S > 0)) OR ((D${zia_dlp_dictionaries.d_acct.id}.S > 0) AND (D${zia_dlp_dictionaries.d_dob.id}.S > 0))) OR ((D${zia_dlp_dictionaries.d_legal_sex.id}.S > 0) AND ((D${zia_dlp_dictionaries.d_mrn.id}.S > 0) OR (D${zia_dlp_dictionaries.d_acct.id}.S > 0) OR (D${zia_dlp_dictionaries.d_dob.id}.S > 0))))"
}

resource "zia_dlp_engines" "e_phi_bulk_export" {
  name                         = "E_PHI_BULK_EXPORT"
  description                  = "Volume-based PHI for mass exposure: any strong identifier appearing 10 or more times in one transaction (a record dump or spreadsheet). Tune the threshold to your export sizes. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.d_mrn.id}.S > 9) OR (D${zia_dlp_dictionaries.d_acct.id}.S > 9) OR (D${zia_dlp_dictionaries.d_dob.id}.S > 9))"
}

