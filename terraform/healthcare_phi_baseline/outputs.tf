output "dictionaries" {
  value = { for k, r in {
    custom_medical_record_number = zia_dlp_dictionaries.custom_medical_record_number
    custom_date_of_birth = zia_dlp_dictionaries.custom_date_of_birth
    custom_sensitive_condition_markers = zia_dlp_dictionaries.custom_sensitive_condition_markers
    custom_health_plan_member_identifier = zia_dlp_dictionaries.custom_health_plan_member_identifier
    custom_insurance_billing = zia_dlp_dictionaries.custom_insurance_billing
    custom_clinical_narrative = zia_dlp_dictionaries.custom_clinical_narrative
    custom_address_zip = zia_dlp_dictionaries.custom_address_zip
    hc_social_security_numbers_us_high = zia_dlp_dictionaries.hc_social_security_numbers_us_high
    hc_social_security_numbers_us_prox_500 = zia_dlp_dictionaries.hc_social_security_numbers_us_prox_500
    hc_tax_identification_number_us_high = zia_dlp_dictionaries.hc_tax_identification_number_us_high
    hc_tax_identification_number_us_prox_500 = zia_dlp_dictionaries.hc_tax_identification_number_us_prox_500
    hc_drivers_license_united_states_high = zia_dlp_dictionaries.hc_drivers_license_united_states_high
    hc_drivers_license_united_states_prox_500 = zia_dlp_dictionaries.hc_drivers_license_united_states_prox_500
    hc_alien_registration_number_high_confidence = zia_dlp_dictionaries.hc_alien_registration_number_high_confidence
    hc_alien_registration_number_prox_500 = zia_dlp_dictionaries.hc_alien_registration_number_prox_500
    hc_date_of_birth_high_confidence = zia_dlp_dictionaries.hc_date_of_birth_high_confidence
    hc_date_of_birth_prox_500 = zia_dlp_dictionaries.hc_date_of_birth_prox_500
    hc_us_passport_high_confidence = zia_dlp_dictionaries.hc_us_passport_high_confidence
    hc_us_passport_prox_500 = zia_dlp_dictionaries.hc_us_passport_prox_500
    hc_aba_bank_routing_number_prox_500 = zia_dlp_dictionaries.hc_aba_bank_routing_number_prox_500
    hc_form_1040_and_related_schedules = zia_dlp_dictionaries.hc_form_1040_and_related_schedules
    hc_aba_bank_routing_number_high = zia_dlp_dictionaries.hc_aba_bank_routing_number_high
    hc_credit_card_magnetic_tracks = zia_dlp_dictionaries.hc_credit_card_magnetic_tracks
    hc_form_1099_misc_and_1099_nec = zia_dlp_dictionaries.hc_form_1099_misc_and_1099_nec
    hc_credit_cards_prox_500 = zia_dlp_dictionaries.hc_credit_cards_prox_500
    hc_w2_or_w4_or_w9_forms = zia_dlp_dictionaries.hc_w2_or_w4_or_w9_forms
    hc_credit_cards_high = zia_dlp_dictionaries.hc_credit_cards_high
    hc_form_k_1 = zia_dlp_dictionaries.hc_form_k_1
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    hipaa_critical_strong_signature_and_clinical_document = zia_dlp_engines.hipaa_critical_strong_signature_and_clinical_document
    hipaa_narrative_low_volume = zia_dlp_engines.hipaa_narrative_low_volume
    hipaa_identity_trifecta = zia_dlp_engines.hipaa_identity_trifecta
    hipaa_sensitive_subcategory = zia_dlp_engines.hipaa_sensitive_subcategory
    hipaa_pharmacy_claims_billing = zia_dlp_engines.hipaa_pharmacy_claims_billing
    hipaa_bulk_phi_small = zia_dlp_engines.hipaa_bulk_phi_small
    hipaa_bulk_phi_significant = zia_dlp_engines.hipaa_bulk_phi_significant
    hipaa_bulk_phi_major = zia_dlp_engines.hipaa_bulk_phi_major
    hipaa_us_pii = zia_dlp_engines.hipaa_us_pii
    hipaa_us_phi_medium_confidence = zia_dlp_engines.hipaa_us_phi_medium_confidence
    hipaa_us_phi_high_confidence = zia_dlp_engines.hipaa_us_phi_high_confidence
    hipaa_financial_information = zia_dlp_engines.hipaa_financial_information
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.hc_hipaa_critical_monitor.name,
    zia_dlp_web_rules.hc_hipaa_narrative_low_volume_monitor.name,
    zia_dlp_web_rules.hc_hipaa_identity_trifecta_monitor.name,
    zia_dlp_web_rules.hc_hipaa_sensitive_subcategory_monitor.name,
    zia_dlp_web_rules.hc_hipaa_pharmacy_claims_billing_monitor.name,
    zia_dlp_web_rules.hc_hipaa_bulk_phi_major_monitor.name,
    zia_dlp_web_rules.hc_hipaa_bulk_phi_significant_monitor.name,
    zia_dlp_web_rules.hc_hipaa_bulk_phi_small_monitor.name,
    zia_dlp_web_rules.hc_us_pii_monitor.name,
    zia_dlp_web_rules.hc_us_phi_medium_confidence_monitor.name,
    zia_dlp_web_rules.hc_us_phi_high_confidence_monitor.name,
    zia_dlp_web_rules.hc_financial_information_monitor.name,
    zia_endpoint_dlp_rules.hc_hipaa_critical_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_critical_saas.name,
    zia_outbound_email_dlp.hc_hipaa_critical_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_narrative_low_volume_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_narrative_low_saas.name,
    zia_outbound_email_dlp.hc_hipaa_narrative_low_volume_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_identity_trifecta_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_identity_saas.name,
    zia_outbound_email_dlp.hc_hipaa_identity_trifecta_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_sensitive_subcategory_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_sensitive_saas.name,
    zia_outbound_email_dlp.hc_hipaa_sensitive_subcategory_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_pharmacy_claims_billing_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_pharmacy_saas.name,
    zia_outbound_email_dlp.hc_hipaa_pharmacy_claims_billing_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_bulk_phi_major_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_bulk_phi_major_saas.name,
    zia_outbound_email_dlp.hc_hipaa_bulk_phi_major_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_bulk_phi_significant_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_bulk_phi_saas.name,
    zia_outbound_email_dlp.hc_hipaa_bulk_phi_significant_email.name,
    zia_endpoint_dlp_rules.hc_hipaa_bulk_phi_small_endpoint.name,
    zia_casb_dlp_rules.hc_hipaa_bulk_phi_small_saas.name,
    zia_outbound_email_dlp.hc_hipaa_bulk_phi_small_email.name,
    zia_endpoint_dlp_rules.hc_us_pii_endpoint.name,
    zia_casb_dlp_rules.hc_us_pii_saas.name,
    zia_outbound_email_dlp.hc_us_pii_email.name,
    zia_endpoint_dlp_rules.hc_us_phi_medium_confidence_endpoint.name,
    zia_casb_dlp_rules.hc_us_phi_medium_saas.name,
    zia_outbound_email_dlp.hc_us_phi_medium_confidence_email.name,
    zia_endpoint_dlp_rules.hc_us_phi_high_confidence_endpoint.name,
    zia_casb_dlp_rules.hc_us_phi_high_saas.name,
    zia_outbound_email_dlp.hc_us_phi_high_confidence_email.name,
    zia_endpoint_dlp_rules.hc_financial_information_endpoint.name,
    zia_casb_dlp_rules.hc_financial_information_saas.name,
    zia_outbound_email_dlp.hc_financial_information_email.name,
  ]
}
