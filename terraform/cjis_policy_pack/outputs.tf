output "dictionaries" {
  value = { for k, r in {
    cjis_marking_pattern_high_confidence = zia_dlp_dictionaries.cjis_marking_pattern_high_confidence
    cjis_marking_pattern_medium_confidence = zia_dlp_dictionaries.cjis_marking_pattern_medium_confidence
    law_enforcement_sensitive_les_markings = zia_dlp_dictionaries.law_enforcement_sensitive_les_markings
    ncic_ori_pattern = zia_dlp_dictionaries.ncic_ori_pattern
    fbi_ucn_universal_control_number = zia_dlp_dictionaries.fbi_ucn_universal_control_number
    state_id_number_sid_reference = zia_dlp_dictionaries.state_id_number_sid_reference
    ncic_purpose_code_pattern = zia_dlp_dictionaries.ncic_purpose_code_pattern
    criminal_history_rap_sheet_phrases = zia_dlp_dictionaries.criminal_history_rap_sheet_phrases
    ncic_iii_query_terminology = zia_dlp_dictionaries.ncic_iii_query_terminology
    warrant_wanted_person_phrases = zia_dlp_dictionaries.warrant_wanted_person_phrases
    biometric_afis_terminology = zia_dlp_dictionaries.biometric_afis_terminology
    nics_firearms_background_check_phrases = zia_dlp_dictionaries.nics_firearms_background_check_phrases
    n_dex_criminal_justice_info_sharing = zia_dlp_dictionaries.n_dex_criminal_justice_info_sharing
    social_security_numbers_us_cjis_prox_500 = zia_dlp_dictionaries.social_security_numbers_us_cjis_prox_500
    drivers_license_us_cjis_prox_500 = zia_dlp_dictionaries.drivers_license_us_cjis_prox_500
    date_of_birth_cjis_prox_500 = zia_dlp_dictionaries.date_of_birth_cjis_prox_500
    cjis_alien_registration_number_high_confidence = zia_dlp_dictionaries.cjis_alien_registration_number_high_confidence
    cjis_alien_registration_number_prox_500 = zia_dlp_dictionaries.cjis_alien_registration_number_prox_500
    cjis_date_of_birth_high_confidence = zia_dlp_dictionaries.cjis_date_of_birth_high_confidence
    cjis_tlp_red = zia_dlp_dictionaries.cjis_tlp_red
    cjis_tlp_amber_strict = zia_dlp_dictionaries.cjis_tlp_amber_strict
    cjis_tlp_amber = zia_dlp_dictionaries.cjis_tlp_amber
    cjis_social_security_numbers_us_high = zia_dlp_dictionaries.cjis_social_security_numbers_us_high
    cjis_tax_identification_number_us_high = zia_dlp_dictionaries.cjis_tax_identification_number_us_high
    cjis_tax_identification_number_us_prox_500 = zia_dlp_dictionaries.cjis_tax_identification_number_us_prox_500
    cjis_drivers_license_united_states_high = zia_dlp_dictionaries.cjis_drivers_license_united_states_high
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    cjis_markings_high_confidence = zia_dlp_engines.cjis_markings_high_confidence
    cjis_markings_medium_confidence = zia_dlp_engines.cjis_markings_medium_confidence
    cjis_identifier_engine = zia_dlp_engines.cjis_identifier_engine
    criminal_history_rap_sheet_engine = zia_dlp_engines.criminal_history_rap_sheet_engine
    ncic_iii_data_engine = zia_dlp_engines.ncic_iii_data_engine
    warrant_wanted_person_engine = zia_dlp_engines.warrant_wanted_person_engine
    biometric_cji_engine = zia_dlp_engines.biometric_cji_engine
    nics_firearms_background_engine = zia_dlp_engines.nics_firearms_background_engine
    info_sharing_portal_engine = zia_dlp_engines.info_sharing_portal_engine
    cjis_any_signal_engine = zia_dlp_engines.cjis_any_signal_engine
    cjis_us_pii = zia_dlp_engines.cjis_us_pii
    cjis_tlp_red = zia_dlp_engines.cjis_tlp_red
    cjis_tlp_amber_strict = zia_dlp_engines.cjis_tlp_amber_strict
    cjis_tlp_amber = zia_dlp_engines.cjis_tlp_amber
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.z_cjis_markings_monitor.name,
    zia_dlp_web_rules.z_cjis_identifier_monitor.name,
    zia_dlp_web_rules.z_cjis_criminal_history_monitor.name,
    zia_dlp_web_rules.z_cjis_ncic_iii_data_monitor.name,
    zia_dlp_web_rules.z_cjis_warrants_monitor.name,
    zia_dlp_web_rules.z_cjis_biometric_monitor.name,
    zia_dlp_web_rules.z_cjis_nics_firearms_monitor.name,
    zia_dlp_web_rules.z_cjis_info_sharing_monitor.name,
    zia_dlp_web_rules.z_cjis_any_signal_monitor.name,
    zia_dlp_web_rules.z_cjis_markings_medium_confidence_monitor.name,
    zia_dlp_web_rules.z_cjis_us_pii_monitor.name,
    zia_dlp_web_rules.z_cjis_tlp_red_monitor.name,
    zia_dlp_web_rules.z_cjis_tlp_amber_strict_monitor.name,
    zia_dlp_web_rules.z_cjis_tlp_amber_monitor.name,
    zia_endpoint_dlp_rules.z_cjis_markings_endpoint.name,
    zia_casb_dlp_rules.z_cjis_markings_saas.name,
    zia_outbound_email_dlp.z_cjis_markings_email.name,
    zia_endpoint_dlp_rules.z_cjis_identifier_endpoint.name,
    zia_casb_dlp_rules.z_cjis_identifier_saas.name,
    zia_outbound_email_dlp.z_cjis_identifier_email.name,
    zia_endpoint_dlp_rules.z_cjis_criminal_history_endpoint.name,
    zia_casb_dlp_rules.z_cjis_criminal_history_saas.name,
    zia_outbound_email_dlp.z_cjis_criminal_history_email.name,
    zia_endpoint_dlp_rules.z_cjis_ncic_iii_data_endpoint.name,
    zia_casb_dlp_rules.z_cjis_ncic_iii_data_saas.name,
    zia_outbound_email_dlp.z_cjis_ncic_iii_data_email.name,
    zia_endpoint_dlp_rules.z_cjis_warrants_endpoint.name,
    zia_casb_dlp_rules.z_cjis_warrants_saas.name,
    zia_outbound_email_dlp.z_cjis_warrants_email.name,
    zia_endpoint_dlp_rules.z_cjis_biometric_endpoint.name,
    zia_casb_dlp_rules.z_cjis_biometric_saas.name,
    zia_outbound_email_dlp.z_cjis_biometric_email.name,
    zia_endpoint_dlp_rules.z_cjis_nics_firearms_endpoint.name,
    zia_casb_dlp_rules.z_cjis_nics_firearms_saas.name,
    zia_outbound_email_dlp.z_cjis_nics_firearms_email.name,
    zia_endpoint_dlp_rules.z_cjis_info_sharing_endpoint.name,
    zia_casb_dlp_rules.z_cjis_info_sharing_saas.name,
    zia_outbound_email_dlp.z_cjis_info_sharing_email.name,
    zia_endpoint_dlp_rules.z_cjis_any_signal_endpoint.name,
    zia_casb_dlp_rules.z_cjis_any_signal_saas.name,
    zia_outbound_email_dlp.z_cjis_any_signal_email.name,
    zia_endpoint_dlp_rules.z_cjis_markings_medium_confidence_endpoint.name,
    zia_casb_dlp_rules.z_cjis_markings_medium_confidence_saas.name,
    zia_outbound_email_dlp.z_cjis_markings_medium_confidence_email.name,
    zia_endpoint_dlp_rules.z_cjis_us_pii_endpoint.name,
    zia_casb_dlp_rules.z_cjis_us_pii_saas.name,
    zia_outbound_email_dlp.z_cjis_us_pii_email.name,
    zia_endpoint_dlp_rules.z_cjis_tlp_red_endpoint.name,
    zia_casb_dlp_rules.z_cjis_tlp_red_saas.name,
    zia_outbound_email_dlp.z_cjis_tlp_red_email.name,
    zia_endpoint_dlp_rules.z_cjis_tlp_amber_strict_endpoint.name,
    zia_casb_dlp_rules.z_cjis_tlp_amber_strict_saas.name,
    zia_outbound_email_dlp.z_cjis_tlp_amber_strict_email.name,
    zia_endpoint_dlp_rules.z_cjis_tlp_amber_endpoint.name,
    zia_casb_dlp_rules.z_cjis_tlp_amber_saas.name,
    zia_outbound_email_dlp.z_cjis_tlp_amber_email.name,
  ]
}
