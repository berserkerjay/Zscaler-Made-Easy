output "dictionaries" {
  value = { for k, r in {
    custom_medical_record_number = zia_dlp_dictionaries.custom_medical_record_number
    custom_date_of_birth = zia_dlp_dictionaries.custom_date_of_birth
    custom_sensitive_condition_markers = zia_dlp_dictionaries.custom_sensitive_condition_markers
    custom_health_plan_member_identifier = zia_dlp_dictionaries.custom_health_plan_member_identifier
    custom_insurance_billing = zia_dlp_dictionaries.custom_insurance_billing
    custom_clinical_narrative = zia_dlp_dictionaries.custom_clinical_narrative
    custom_address_zip = zia_dlp_dictionaries.custom_address_zip
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    hipaa_critical_strong_signature_clinical_document = zia_dlp_engines.hipaa_critical_strong_signature_clinical_document
    hipaa_narrative_low_volume = zia_dlp_engines.hipaa_narrative_low_volume
    hipaa_identity_trifecta = zia_dlp_engines.hipaa_identity_trifecta
    hipaa_sensitive_subcategory = zia_dlp_engines.hipaa_sensitive_subcategory
    hipaa_pharmacy_claims_billing = zia_dlp_engines.hipaa_pharmacy_claims_billing
    hipaa_bulk_phi_small = zia_dlp_engines.hipaa_bulk_phi_small
    hipaa_bulk_phi_significant = zia_dlp_engines.hipaa_bulk_phi_significant
    hipaa_bulk_phi_major = zia_dlp_engines.hipaa_bulk_phi_major
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.hc_hipaa_critical_block.name,
    zia_dlp_web_rules.hc_hipaa_narrative_low_volume_monitor.name,
    zia_dlp_web_rules.hc_hipaa_identity_trifecta_block.name,
    zia_dlp_web_rules.hc_hipaa_sensitive_subcategory_block.name,
    zia_dlp_web_rules.hc_hipaa_pharmacy_claims_billing_monitor.name,
    zia_dlp_web_rules.hc_hipaa_bulk_phi_major_block.name,
    zia_dlp_web_rules.hc_hipaa_bulk_phi_significant_block.name,
    zia_dlp_web_rules.hc_hipaa_bulk_phi_small_monitor.name,
    zia_endpoint_dlp_rules.hc_hipaa_critical_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_critical_saas.name,
    zia_outbound_email_dlp.hc_hipaa_critical_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_narrative_low_volume_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_narrative_low_volume_saas.name,
    zia_outbound_email_dlp.hc_hipaa_narrative_low_volume_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_identity_trifecta_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_identity_trifecta_saas.name,
    zia_outbound_email_dlp.hc_hipaa_identity_trifecta_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_sensitive_subcategory_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_sensitive_subcategory_saas.name,
    zia_outbound_email_dlp.hc_hipaa_sensitive_subcategory_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_pharmacy_claims_billing_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_pharmacy_claims_billing_saas.name,
    zia_outbound_email_dlp.hc_hipaa_pharmacy_claims_billing_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_bulk_phi_major_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_bulk_phi_major_saas.name,
    zia_outbound_email_dlp.hc_hipaa_bulk_phi_major_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_bulk_phi_significant_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_bulk_phi_significant_saas.name,
    zia_outbound_email_dlp.hc_hipaa_bulk_phi_significant_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_bulk_phi_small_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_bulk_phi_small_saas.name,
    zia_outbound_email_dlp.hc_hipaa_bulk_phi_small_email.name,
  ]
}
