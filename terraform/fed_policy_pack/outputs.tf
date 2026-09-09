output "dictionaries" {
  value = { for k, r in {
    fouo_markings_high_confidence = zia_dlp_dictionaries.fouo_markings_high_confidence
    fouo_markings_medium_confidence = zia_dlp_dictionaries.fouo_markings_medium_confidence
    aea_rd_frd_admonishment_phrase = zia_dlp_dictionaries.aea_rd_frd_admonishment_phrase
    aea_rd_frd_literal_phrase = zia_dlp_dictionaries.aea_rd_frd_literal_phrase
    aea_rd_frd_contextual_phrase = zia_dlp_dictionaries.aea_rd_frd_contextual_phrase
    aea_rd_frd_pattern_high_confidence = zia_dlp_dictionaries.aea_rd_frd_pattern_high_confidence
    aea_rd_frd_pattern_medium_confidence = zia_dlp_dictionaries.aea_rd_frd_pattern_medium_confidence
    aea_rd_frd_portion_marking_pattern_high_confidence = zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_high_confidence
    aea_rd_frd_portion_marking_pattern_medium_confidence = zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_medium_confidence
    standard_forms = zia_dlp_dictionaries.standard_forms
    us_passport_high_confidence = zia_dlp_dictionaries.us_passport_high_confidence
    us_passport_prox_500 = zia_dlp_dictionaries.us_passport_prox_500
    alien_registration_number_prox_500 = zia_dlp_dictionaries.alien_registration_number_prox_500
    alien_registration_number_high_confidence = zia_dlp_dictionaries.alien_registration_number_high_confidence
    date_of_birth_high_confidence = zia_dlp_dictionaries.date_of_birth_high_confidence
    date_of_birth_prox_500 = zia_dlp_dictionaries.date_of_birth_prox_500
    social_security_numbers_us_high = zia_dlp_dictionaries.social_security_numbers_us_high
    social_security_numbers_us_prox_500 = zia_dlp_dictionaries.social_security_numbers_us_prox_500
    tax_identification_number_us_high = zia_dlp_dictionaries.tax_identification_number_us_high
    tax_identification_number_us_prox_500 = zia_dlp_dictionaries.tax_identification_number_us_prox_500
    drivers_license_united_states_prox_500 = zia_dlp_dictionaries.drivers_license_united_states_prox_500
    drivers_license_united_states_high = zia_dlp_dictionaries.drivers_license_united_states_high
    private_keys_plaintext_regex = zia_dlp_dictionaries.private_keys_plaintext_regex
    jwk_private_key = zia_dlp_dictionaries.jwk_private_key
    private_key = zia_dlp_dictionaries.private_key
    encrypted_or_ascii_armored_pgp_keys = zia_dlp_dictionaries.encrypted_or_ascii_armored_pgp_keys
    encrypted_bouncy_castle_key_exports = zia_dlp_dictionaries.encrypted_bouncy_castle_key_exports
    form_k_1 = zia_dlp_dictionaries.form_k_1
    form_1099_misc_and_1099_nec = zia_dlp_dictionaries.form_1099_misc_and_1099_nec
    w2_or_w4_or_w9_forms = zia_dlp_dictionaries.w2_or_w4_or_w9_forms
    form_1040_and_related_schedules = zia_dlp_dictionaries.form_1040_and_related_schedules
    aba_bank_routing_number_high = zia_dlp_dictionaries.aba_bank_routing_number_high
    aba_bank_routing_number_prox_500 = zia_dlp_dictionaries.aba_bank_routing_number_prox_500
    credit_cards_high = zia_dlp_dictionaries.credit_cards_high
    credit_cards_prox_500 = zia_dlp_dictionaries.credit_cards_prox_500
    credit_card_magnetic_tracks = zia_dlp_dictionaries.credit_card_magnetic_tracks
    itar_phrase = zia_dlp_dictionaries.itar_phrase
    itar_pattern = zia_dlp_dictionaries.itar_pattern
    tlp_red = zia_dlp_dictionaries.tlp_red
    tlp_amber_strict = zia_dlp_dictionaries.tlp_amber_strict
    tlp_amber = zia_dlp_dictionaries.tlp_amber
    cui_registry_marking_pattern_high_confidence = zia_dlp_dictionaries.cui_registry_marking_pattern_high_confidence
    cui_registry_marking_pattern_medium_confidence = zia_dlp_dictionaries.cui_registry_marking_pattern_medium_confidence
    cui_portion_marking_pattern_high_confidence = zia_dlp_dictionaries.cui_portion_marking_pattern_high_confidence
    cui_portion_marking_pattern_medium_confidence = zia_dlp_dictionaries.cui_portion_marking_pattern_medium_confidence
    declassify_date_pattern_high_confidence = zia_dlp_dictionaries.declassify_date_pattern_high_confidence
    declassify_date_pattern_medium_confidence = zia_dlp_dictionaries.declassify_date_pattern_medium_confidence
    cui_contextual_phrases = zia_dlp_dictionaries.cui_contextual_phrases
    cui_category_phrase = zia_dlp_dictionaries.cui_category_phrase
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    fouo_markings_high_confidence = zia_dlp_engines.fouo_markings_high_confidence
    fouo_markings_medium_confidence = zia_dlp_engines.fouo_markings_medium_confidence
    aea_high_confidence = zia_dlp_engines.aea_high_confidence
    aea_medium_confidence = zia_dlp_engines.aea_medium_confidence
    standard_forms = zia_dlp_engines.standard_forms
    us_pii = zia_dlp_engines.us_pii
    private_keys = zia_dlp_engines.private_keys
    financial_information = zia_dlp_engines.financial_information
    us_phi_medium_confidence = zia_dlp_engines.us_phi_medium_confidence
    us_phi_high_confidence = zia_dlp_engines.us_phi_high_confidence
    itar_phrases = zia_dlp_engines.itar_phrases
    tlp_red = zia_dlp_engines.tlp_red
    tlp_amber_strict = zia_dlp_engines.tlp_amber_strict
    tlp_amber = zia_dlp_engines.tlp_amber
    cui_engine_high_confidence = zia_dlp_engines.cui_engine_high_confidence
    cui_engine_medium_confidence = zia_dlp_engines.cui_engine_medium_confidence
    cui_engine_low_confidence = zia_dlp_engines.cui_engine_low_confidence
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.z_atomic_energy_act_monitor.name,
    zia_dlp_web_rules.z_financial_information_monitor.name,
    zia_dlp_web_rules.z_for_official_use_only_markings_monitor.name,
    zia_dlp_web_rules.z_itar_international_traffic_in_arms_regulations_monitor.name,
    zia_dlp_web_rules.z_standard_forms_monitor.name,
    zia_dlp_web_rules.z_traffic_light_protocol_monitor.name,
    zia_dlp_web_rules.z_us_pii_monitor.name,
    zia_dlp_web_rules.z_us_phi_monitor.name,
    zia_dlp_web_rules.z_controlled_unclassified_information_monitor.name,
    zia_dlp_web_rules.z_private_keys_monitor.name,
    zia_endpoint_dlp_rules.z_fed_endpoint_monitor.name,
    zia_casb_dlp_rules.z_fed_saas_file_monitor.name,
    zia_outbound_email_dlp.z_fed_email_monitor.name,
  ]
}
