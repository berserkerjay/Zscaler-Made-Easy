output "dictionaries" {
  value = { for k, r in {
    zbp_us_passport_high_confidence = zia_dlp_dictionaries.zbp_us_passport_high_confidence
    zbp_us_passport_prox_500 = zia_dlp_dictionaries.zbp_us_passport_prox_500
    zbp_alien_registration_number_prox_500 = zia_dlp_dictionaries.zbp_alien_registration_number_prox_500
    zbp_alien_registration_number_high_confidence = zia_dlp_dictionaries.zbp_alien_registration_number_high_confidence
    zbp_date_of_birth_high_confidence = zia_dlp_dictionaries.zbp_date_of_birth_high_confidence
    zbp_date_of_birth_prox_500 = zia_dlp_dictionaries.zbp_date_of_birth_prox_500
    zbp_social_security_numbers_us_high = zia_dlp_dictionaries.zbp_social_security_numbers_us_high
    zbp_social_security_numbers_us_prox_500 = zia_dlp_dictionaries.zbp_social_security_numbers_us_prox_500
    zbp_tax_identification_number_us_high = zia_dlp_dictionaries.zbp_tax_identification_number_us_high
    zbp_tax_identification_number_us_prox_500 = zia_dlp_dictionaries.zbp_tax_identification_number_us_prox_500
    zbp_drivers_license_united_states_prox_500 = zia_dlp_dictionaries.zbp_drivers_license_united_states_prox_500
    zbp_drivers_license_united_states_high = zia_dlp_dictionaries.zbp_drivers_license_united_states_high
    zbp_private_keys_plaintext_regex = zia_dlp_dictionaries.zbp_private_keys_plaintext_regex
    zbp_jwk_private_key = zia_dlp_dictionaries.zbp_jwk_private_key
    zbp_private_key = zia_dlp_dictionaries.zbp_private_key
    zbp_encrypted_or_ascii_armored_pgp_keys = zia_dlp_dictionaries.zbp_encrypted_or_ascii_armored_pgp_keys
    zbp_encrypted_bouncy_castle_key_exports = zia_dlp_dictionaries.zbp_encrypted_bouncy_castle_key_exports
    zbp_form_k_1 = zia_dlp_dictionaries.zbp_form_k_1
    zbp_form_1099_misc_and_1099_nec = zia_dlp_dictionaries.zbp_form_1099_misc_and_1099_nec
    zbp_w2_or_w4_or_w9_forms = zia_dlp_dictionaries.zbp_w2_or_w4_or_w9_forms
    zbp_form_1040_and_related_schedules = zia_dlp_dictionaries.zbp_form_1040_and_related_schedules
    zbp_aba_bank_routing_number_high = zia_dlp_dictionaries.zbp_aba_bank_routing_number_high
    zbp_aba_bank_routing_number_prox_500 = zia_dlp_dictionaries.zbp_aba_bank_routing_number_prox_500
    zbp_credit_cards_high = zia_dlp_dictionaries.zbp_credit_cards_high
    zbp_credit_cards_prox_500 = zia_dlp_dictionaries.zbp_credit_cards_prox_500
    zbp_credit_card_magnetic_tracks = zia_dlp_dictionaries.zbp_credit_card_magnetic_tracks
    zbp_itar_phrase = zia_dlp_dictionaries.zbp_itar_phrase
    zbp_itar_pattern = zia_dlp_dictionaries.zbp_itar_pattern
    zbp_tlp_red = zia_dlp_dictionaries.zbp_tlp_red
    zbp_tlp_amber_strict = zia_dlp_dictionaries.zbp_tlp_amber_strict
    zbp_tlp_amber = zia_dlp_dictionaries.zbp_tlp_amber
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    zbp_us_pii = zia_dlp_engines.zbp_us_pii
    zbp_private_keys = zia_dlp_engines.zbp_private_keys
    zbp_financial_information = zia_dlp_engines.zbp_financial_information
    zbp_us_phi_medium_confidence = zia_dlp_engines.zbp_us_phi_medium_confidence
    zbp_us_phi_high_confidence = zia_dlp_engines.zbp_us_phi_high_confidence
    zbp_itar_phrases = zia_dlp_engines.zbp_itar_phrases
    zbp_tlp_red = zia_dlp_engines.zbp_tlp_red
    zbp_tlp_amber_strict = zia_dlp_engines.zbp_tlp_amber_strict
    zbp_tlp_amber = zia_dlp_engines.zbp_tlp_amber
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.zbp_financial_information_monitor.name,
    zia_dlp_web_rules.zbp_itar_international_traffic_in_arms_regulations_monitor.name,
    zia_dlp_web_rules.zbp_traffic_light_protocol_monitor.name,
    zia_dlp_web_rules.zbp_us_pii_monitor.name,
    zia_dlp_web_rules.zbp_us_phi_monitor.name,
    zia_dlp_web_rules.zbp_private_keys_monitor.name,
    zia_endpoint_dlp_rules.zbp_financial_information_endpoint.name,
    zia_casb_dlp_rules.zbp_financial_information_saas.name,
    zia_outbound_email_dlp.zbp_financial_information_email.name,
    zia_endpoint_dlp_rules.zbp_itar_international_traffic_in_arms_regulations_endpoint.name,
    zia_casb_dlp_rules.zbp_itar_international_traffic_in_arms_regulations_saas.name,
    zia_outbound_email_dlp.zbp_itar_international_traffic_in_arms_regulations_email.name,
    zia_endpoint_dlp_rules.zbp_traffic_light_protocol_endpoint.name,
    zia_casb_dlp_rules.zbp_traffic_light_protocol_saas.name,
    zia_outbound_email_dlp.zbp_traffic_light_protocol_email.name,
    zia_endpoint_dlp_rules.zbp_us_pii_endpoint.name,
    zia_casb_dlp_rules.zbp_us_pii_saas.name,
    zia_outbound_email_dlp.zbp_us_pii_email.name,
    zia_endpoint_dlp_rules.zbp_us_phi_endpoint.name,
    zia_casb_dlp_rules.zbp_us_phi_saas.name,
    zia_outbound_email_dlp.zbp_us_phi_email.name,
    zia_endpoint_dlp_rules.zbp_private_keys_endpoint.name,
    zia_casb_dlp_rules.zbp_private_keys_saas.name,
    zia_outbound_email_dlp.zbp_private_keys_email.name,
    zia_endpoint_dlp_rules.zbp_financial_information_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_itar_phrases_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_tlp_red_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_tlp_amber_strict_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_tlp_amber_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_us_pii_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_us_phi_medium_confidence_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_us_phi_high_confidence_endpoint_removable_media.name,
    zia_endpoint_dlp_rules.zbp_private_keys_endpoint_removable_media.name,
  ]
}
