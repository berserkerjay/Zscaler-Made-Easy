output "dictionaries" {
  value = { for k, r in {
    zbp_us_passport_high_confidence = zia_dlp_dictionaries.zbp_us_passport_high_confidence
    zbp_us_passport_prox_500 = zia_dlp_dictionaries.zbp_us_passport_prox_500
    zbp_alien_registration_number_prox_500 = zia_dlp_dictionaries.zbp_alien_registration_number_prox_500
    zbp_alien_registration_number_high_confidence = zia_dlp_dictionaries.zbp_alien_registration_number_high_confidence
    zbp_date_of_birth_high_confidence = zia_dlp_dictionaries.zbp_date_of_birth_high_confidence
    zbp_social_security_numbers_us_high = zia_dlp_dictionaries.zbp_social_security_numbers_us_high
    zbp_social_security_numbers_us_prox_500 = zia_dlp_dictionaries.zbp_social_security_numbers_us_prox_500
    zbp_tax_identification_number_us_high = zia_dlp_dictionaries.zbp_tax_identification_number_us_high
    zbp_tax_identification_number_us_prox_500 = zia_dlp_dictionaries.zbp_tax_identification_number_us_prox_500
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
    bank_iban_global = zia_dlp_dictionaries.bank_iban_global
    bank_swift_bic_code = zia_dlp_dictionaries.bank_swift_bic_code
    bank_wire_transfer_instructions = zia_dlp_dictionaries.bank_wire_transfer_instructions
    bank_card_security_data = zia_dlp_dictionaries.bank_card_security_data
    bank_customer_account_statement = zia_dlp_dictionaries.bank_customer_account_statement
    bank_kyc_and_aml = zia_dlp_dictionaries.bank_kyc_and_aml
    bank_loan_and_credit_application = zia_dlp_dictionaries.bank_loan_and_credit_application
    bank_mnpi_and_deal_information = zia_dlp_dictionaries.bank_mnpi_and_deal_information
    bank_confidentiality_markings = zia_dlp_dictionaries.bank_confidentiality_markings
    bank_customer_pii_context = zia_dlp_dictionaries.bank_customer_pii_context
    bank_national_id_uk_canada_australia_south_africa = zia_dlp_dictionaries.bank_national_id_uk_canada_australia_south_africa
    bank_national_id_india_singapore_hong_kong = zia_dlp_dictionaries.bank_national_id_india_singapore_hong_kong
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    bank_payment_card_data = zia_dlp_engines.bank_payment_card_data
    bank_payment_card_data_bulk = zia_dlp_engines.bank_payment_card_data_bulk
    bank_account_and_payment_instructions = zia_dlp_engines.bank_account_and_payment_instructions
    bank_customer_financial_records = zia_dlp_engines.bank_customer_financial_records
    bank_customer_pii_global = zia_dlp_engines.bank_customer_pii_global
    bank_customer_pii_bulk = zia_dlp_engines.bank_customer_pii_bulk
    bank_kyc_and_aml_files = zia_dlp_engines.bank_kyc_and_aml_files
    bank_credit_and_loan_applications = zia_dlp_engines.bank_credit_and_loan_applications
    bank_mnpi_and_deal_information = zia_dlp_engines.bank_mnpi_and_deal_information
    bank_confidential_markings = zia_dlp_engines.bank_confidential_markings
    zbp_us_pii = zia_dlp_engines.zbp_us_pii
    zbp_financial_information = zia_dlp_engines.zbp_financial_information
    zbp_private_keys = zia_dlp_engines.zbp_private_keys
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.bank_payment_card_data_monitor.name,
    zia_dlp_web_rules.bank_payment_card_data_bulk_block.name,
    zia_dlp_web_rules.bank_payment_instructions_monitor.name,
    zia_dlp_web_rules.bank_customer_pii_monitor.name,
    zia_dlp_web_rules.bank_customer_pii_bulk_block.name,
    zia_dlp_web_rules.bank_customer_records_monitor.name,
    zia_dlp_web_rules.bank_mnpi_monitor.name,
    zia_dlp_web_rules.bank_confidential_markings_monitor.name,
    zia_dlp_web_rules.bank_credentials_monitor.name,
    zia_endpoint_dlp_rules.bank_endpoint_monitor.name,
    zia_endpoint_dlp_rules.bank_endpoint_bulk_block_usb.name,
    zia_casb_dlp_rules.bank_saas_file_monitor.name,
    zia_outbound_email_dlp.bank_email_monitor.name,
  ]
}
