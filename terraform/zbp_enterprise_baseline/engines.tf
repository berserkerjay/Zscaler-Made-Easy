# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "zbp_us_pii" {
  name                         = "ZBP-US PII"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_alien_registration_number_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_alien_registration_number_prox_500.id}.S > 0) OR ((D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 1) AND (D${zia_dlp_dictionaries.zbp_drivers_license_united_states_high.id}.S > 4)))"
}

resource "zia_dlp_engines" "zbp_private_keys" {
  name                         = "ZBP-Private Keys"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_private_keys_plaintext_regex.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_jwk_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_encrypted_or_ascii_armored_pgp_keys.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_encrypted_bouncy_castle_key_exports.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_financial_information" {
  name                         = "ZBP-Financial Information"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.zbp_credit_cards_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_credit_cards_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.zbp_credit_card_magnetic_tracks.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_tax_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_form_k_1.id}.S > 3) OR (D${zia_dlp_dictionaries.zbp_form_1099_misc_and_1099_nec.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_w2_or_w4_or_w9_forms.id}.S > 3) OR (D${zia_dlp_dictionaries.zbp_form_1040_and_related_schedules.id}.S > 3) OR (D${data.zia_dlp_dictionaries.financial.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_corporate_finance_leakage.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_us_phi_medium_confidence" {
  name                         = "ZBP-US PHI - Medium Confidence"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.ml_medical_doc_leakage.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_leakage.id}.S > 9) OR (D${data.zia_dlp_dictionaries.diseases_leakage.id}.S > 9)))) AND ((D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_us_passport_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_alien_registration_number_high_confidence.id}.S > 0) OR ((D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 0) AND (D${zia_dlp_dictionaries.zbp_drivers_license_united_states_prox_500.id}.S > 0))))"
}

resource "zia_dlp_engines" "zbp_us_phi_high_confidence" {
  name                         = "ZBP-US PHI - High Confidence"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.ml_medical_doc_leakage.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_leakage.id}.S > 14) OR (D${data.zia_dlp_dictionaries.diseases_leakage.id}.S > 14)))) AND ((D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_us_passport_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_alien_registration_number_high_confidence.id}.S > 4) OR ((D${zia_dlp_dictionaries.zbp_date_of_birth_prox_500.id}.S > 1) AND (D${zia_dlp_dictionaries.zbp_drivers_license_united_states_prox_500.id}.S > 1)) OR (D${zia_dlp_dictionaries.zbp_social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_us_passport_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_alien_registration_number_prox_500.id}.S > 0)))"
}

resource "zia_dlp_engines" "zbp_itar_phrases" {
  name                         = "ZBP-ITAR Phrases"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_itar_pattern.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_itar_phrase.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_tlp_red" {
  name                         = "ZBP-TLP Red"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_tlp_red.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_tlp_amber_strict" {
  name                         = "ZBP-TLP Amber Strict"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_tlp_amber_strict.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_tlp_amber" {
  name                         = "ZBP-TLP Amber"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_tlp_amber.id}.S > 0))"
}

