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
    private_key_medium_confidence = zia_dlp_dictionaries.private_key_medium_confidence
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
    cui_banner_structural = zia_dlp_dictionaries.cui_banner_structural
    cui_banner_ldc = zia_dlp_dictionaries.cui_banner_ldc
    cui_portionmark_structural = zia_dlp_dictionaries.cui_portionmark_structural
    cui_basic_bare = zia_dlp_dictionaries.cui_basic_bare
    cui_ldc_standalone = zia_dlp_dictionaries.cui_ldc_standalone
    cui_code_cti = zia_dlp_dictionaries.cui_code_cti
    cui_code_prvcy = zia_dlp_dictionaries.cui_code_prvcy
    cui_code_propin = zia_dlp_dictionaries.cui_code_propin
    cui_code_ssel = zia_dlp_dictionaries.cui_code_ssel
    cui_code_isvi = zia_dlp_dictionaries.cui_code_isvi
    cui_code_opsec = zia_dlp_dictionaries.cui_code_opsec
    cui_code_nnpi = zia_dlp_dictionaries.cui_code_nnpi
    cui_code_pcii = zia_dlp_dictionaries.cui_code_pcii
    cui_code_cvi = zia_dlp_dictionaries.cui_code_cvi
    cui_prox_expt = zia_dlp_dictionaries.cui_prox_expt
    cui_prox_tax = zia_dlp_dictionaries.cui_prox_tax
    cui_prox_lei = zia_dlp_dictionaries.cui_prox_lei
    cui_prox_crit = zia_dlp_dictionaries.cui_prox_crit
    cui_prox_nuc = zia_dlp_dictionaries.cui_prox_nuc
    cui_prox_intel = zia_dlp_dictionaries.cui_prox_intel
    cui_prox_legal = zia_dlp_dictionaries.cui_prox_legal
    cui_prox_procure = zia_dlp_dictionaries.cui_prox_procure
    legacy_fouo = zia_dlp_dictionaries.legacy_fouo
    legacy_les = zia_dlp_dictionaries.legacy_les
    legacy_sbu = zia_dlp_dictionaries.legacy_sbu
    legacy_distribution_statements = zia_dlp_dictionaries.legacy_distribution_statements
    cui_designation_indicator = zia_dlp_dictionaries.cui_designation_indicator
    cui_decontrol_context = zia_dlp_dictionaries.cui_decontrol_context
    cui_declassify_date = zia_dlp_dictionaries.cui_declassify_date
    cui_contextual_phrases = zia_dlp_dictionaries.cui_contextual_phrases
    cui_category_phrases = zia_dlp_dictionaries.cui_category_phrases
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    fouo_markings_high_confidence = zia_dlp_engines.fouo_markings_high_confidence
    fouo_markings_medium_confidence = zia_dlp_engines.fouo_markings_medium_confidence
    aea_high_confidence = zia_dlp_engines.aea_high_confidence
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
    cui_detect_all = zia_dlp_engines.cui_detect_all
    cui_detect_contextual = zia_dlp_engines.cui_detect_contextual
    cui_detect_block_grade = zia_dlp_engines.cui_detect_block_grade
    cui_detect_caution_grade = zia_dlp_engines.cui_detect_caution_grade
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.z_atomic_energy_act_monitor.name,
    zia_dlp_web_rules.z_financial_information_monitor.name,
    zia_dlp_web_rules.z_fouo_markings_high_confidence_monitor.name,
    zia_dlp_web_rules.z_fouo_markings_medium_confidence_monitor.name,
    zia_dlp_web_rules.z_itar_international_traffic_in_arms_regulations_monitor.name,
    zia_dlp_web_rules.z_standard_forms_monitor.name,
    zia_dlp_web_rules.z_tlp_red_monitor.name,
    zia_dlp_web_rules.z_tlp_amber_strict_monitor.name,
    zia_dlp_web_rules.z_tlp_amber_monitor.name,
    zia_dlp_web_rules.z_us_pii_monitor.name,
    zia_dlp_web_rules.z_us_phi_medium_confidence_monitor.name,
    zia_dlp_web_rules.z_us_phi_high_confidence_monitor.name,
    zia_dlp_web_rules.z_private_keys_monitor.name,
    zia_dlp_web_rules.cui_monitor_marked_documents.name,
    zia_dlp_web_rules.cui_monitor_weak_markings.name,
    zia_dlp_web_rules.cui_monitor_all.name,
    zia_dlp_web_rules.cui_monitor_contextual.name,
    zia_endpoint_dlp_rules.z_atomic_energy_act_endpoint.name,
    zia_casb_dlp_rules.z_atomic_energy_act_saas.name,
    zia_outbound_email_dlp.z_atomic_energy_act_email.name,
    zia_endpoint_dlp_rules.z_financial_information_endpoint.name,
    zia_casb_dlp_rules.z_financial_information_saas.name,
    zia_outbound_email_dlp.z_financial_information_email.name,
    zia_endpoint_dlp_rules.z_fouo_markings_high_confidence_endpoint.name,
    zia_casb_dlp_rules.z_fouo_markings_high_saas.name,
    zia_outbound_email_dlp.z_fouo_markings_high_confidence_email.name,
    zia_endpoint_dlp_rules.z_fouo_markings_medium_confidence_endpoint.name,
    zia_casb_dlp_rules.z_fouo_markings_medium_saas.name,
    zia_outbound_email_dlp.z_fouo_markings_medium_confidence_email.name,
    zia_endpoint_dlp_rules.z_itar_international_traffic_in_arms_regulations_endpoint.name,
    zia_casb_dlp_rules.z_itar_international_saas.name,
    zia_outbound_email_dlp.z_itar_international_traffic_in_arms_regulations_email.name,
    zia_endpoint_dlp_rules.z_standard_forms_endpoint.name,
    zia_casb_dlp_rules.z_standard_forms_saas.name,
    zia_outbound_email_dlp.z_standard_forms_email.name,
    zia_endpoint_dlp_rules.z_tlp_red_endpoint.name,
    zia_casb_dlp_rules.z_tlp_red_saas.name,
    zia_outbound_email_dlp.z_tlp_red_email.name,
    zia_endpoint_dlp_rules.z_tlp_amber_strict_endpoint.name,
    zia_casb_dlp_rules.z_tlp_amber_strict_saas.name,
    zia_outbound_email_dlp.z_tlp_amber_strict_email.name,
    zia_endpoint_dlp_rules.z_tlp_amber_endpoint.name,
    zia_casb_dlp_rules.z_tlp_amber_saas.name,
    zia_outbound_email_dlp.z_tlp_amber_email.name,
    zia_endpoint_dlp_rules.z_us_pii_endpoint.name,
    zia_casb_dlp_rules.z_us_pii_saas.name,
    zia_outbound_email_dlp.z_us_pii_email.name,
    zia_endpoint_dlp_rules.z_us_phi_medium_confidence_endpoint.name,
    zia_casb_dlp_rules.z_us_phi_medium_saas.name,
    zia_outbound_email_dlp.z_us_phi_medium_confidence_email.name,
    zia_endpoint_dlp_rules.z_us_phi_high_confidence_endpoint.name,
    zia_casb_dlp_rules.z_us_phi_high_saas.name,
    zia_outbound_email_dlp.z_us_phi_high_confidence_email.name,
    zia_endpoint_dlp_rules.z_private_keys_endpoint.name,
    zia_casb_dlp_rules.z_private_keys_saas.name,
    zia_outbound_email_dlp.z_private_keys_email.name,
    zia_endpoint_dlp_rules.cui_monitor_marked_documents_endpoint.name,
    zia_casb_dlp_rules.cui_monitor_marked_saas.name,
    zia_outbound_email_dlp.cui_monitor_marked_documents_email.name,
    zia_endpoint_dlp_rules.cui_monitor_weak_markings_endpoint.name,
    zia_casb_dlp_rules.cui_monitor_weak_saas.name,
    zia_outbound_email_dlp.cui_monitor_weak_markings_email.name,
    zia_endpoint_dlp_rules.cui_monitor_all_endpoint.name,
    zia_casb_dlp_rules.cui_monitor_all_saas.name,
    zia_outbound_email_dlp.cui_monitor_all_email.name,
    zia_endpoint_dlp_rules.cui_monitor_contextual_endpoint.name,
    zia_casb_dlp_rules.cui_monitor_contextual_saas.name,
    zia_outbound_email_dlp.cui_monitor_contextual_email.name,
  ]
}
