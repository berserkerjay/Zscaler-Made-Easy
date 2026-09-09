output "dictionaries" {
  value = { for k, r in {
    d_mrn = zia_dlp_dictionaries.d_mrn
    d_acct = zia_dlp_dictionaries.d_acct
    d_dob = zia_dlp_dictionaries.d_dob
    d_legal_sex = zia_dlp_dictionaries.d_legal_sex
    d_clinical_phrases = zia_dlp_dictionaries.d_clinical_phrases
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    e_healthcare_phi = zia_dlp_engines.e_healthcare_phi
    e_phi_bulk_export = zia_dlp_engines.e_phi_bulk_export
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.r_healthcare_phi_mrn_acct_dob.name,
  ]
}
