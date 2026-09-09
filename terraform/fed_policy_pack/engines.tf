# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "fouo_markings_high_confidence" {
  name                         = "FOUO Markings High Confidence"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.fouo_markings_high_confidence.id}.S > 0))"
}

resource "zia_dlp_engines" "fouo_markings_medium_confidence" {
  name                         = "FOUO Markings Medium Confidence"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.fouo_markings_medium_confidence.id}.S > 0))"
}

resource "zia_dlp_engines" "aea_high_confidence" {
  name                         = "AEA High Confidence"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.aea_rd_frd_admonishment_phrase.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_literal_phrase.id}.S > 1)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_literal_phrase.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_contextual_phrase.id}.S > 0)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_high_confidence.id}.S > 2) AND (D${zia_dlp_dictionaries.aea_rd_frd_pattern_high_confidence.id}.S > 0)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_high_confidence.id}.S > 2) AND (D${zia_dlp_dictionaries.aea_rd_frd_contextual_phrase.id}.S > 0)))"
}

resource "zia_dlp_engines" "aea_medium_confidence" {
  name                         = "AEA Medium Confidence"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.aea_rd_frd_admonishment_phrase.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_literal_phrase.id}.S > 0)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_literal_phrase.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_high_confidence.id}.S > 0)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_high_confidence.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_pattern_medium_confidence.id}.S > 0)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_medium_confidence.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_contextual_phrase.id}.S > 0)))"
}

resource "zia_dlp_engines" "standard_forms" {
  name                         = "Standard Forms"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.standard_forms.id}.S > 3))"
}

resource "zia_dlp_engines" "us_pii" {
  name                         = "US PII"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.tax_identification_number_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.tax_identification_number_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.alien_registration_number_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.alien_registration_number_prox_500.id}.S > 0) OR ((D${zia_dlp_dictionaries.date_of_birth_high_confidence.id}.S > 1) AND (D${zia_dlp_dictionaries.drivers_license_united_states_high.id}.S > 4)))"
}

resource "zia_dlp_engines" "private_keys" {
  name                         = "Private Keys"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.private_keys_plaintext_regex.id}.S > 0) OR (D${zia_dlp_dictionaries.jwk_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.encrypted_or_ascii_armored_pgp_keys.id}.S > 0) OR (D${zia_dlp_dictionaries.encrypted_bouncy_castle_key_exports.id}.S > 0))"
}

resource "zia_dlp_engines" "financial_information" {
  name                         = "Financial Information"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.aba_bank_routing_number_high.id}.S > 4) OR (D${zia_dlp_dictionaries.aba_bank_routing_number_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.credit_cards_high.id}.S > 4) OR (D${zia_dlp_dictionaries.credit_cards_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.credit_card_magnetic_tracks.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_tax_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.form_k_1.id}.S > 3) OR (D${zia_dlp_dictionaries.form_1099_misc_and_1099_nec.id}.S > 4) OR (D${zia_dlp_dictionaries.w2_or_w4_or_w9_forms.id}.S > 3) OR (D${zia_dlp_dictionaries.form_1040_and_related_schedules.id}.S > 3) OR (D${data.zia_dlp_dictionaries.financial.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_corporate_finance_leakage.id}.S > 0))"
}

resource "zia_dlp_engines" "us_phi_medium_confidence" {
  name                         = "US PHI - Medium Confidence"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.ml_medical_doc_leakage.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_leakage.id}.S > 9) OR (D${data.zia_dlp_dictionaries.diseases_leakage.id}.S > 9)))) AND ((D${zia_dlp_dictionaries.social_security_numbers_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.us_passport_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.alien_registration_number_high_confidence.id}.S > 0) OR ((D${zia_dlp_dictionaries.date_of_birth_high_confidence.id}.S > 0) AND (D${zia_dlp_dictionaries.drivers_license_united_states_prox_500.id}.S > 0))))"
}

resource "zia_dlp_engines" "us_phi_high_confidence" {
  name                         = "US PHI - High Confidence"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.ml_medical_doc_leakage.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_leakage.id}.S > 14) OR (D${data.zia_dlp_dictionaries.diseases_leakage.id}.S > 14)))) AND ((D${zia_dlp_dictionaries.social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.us_passport_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.alien_registration_number_high_confidence.id}.S > 4) OR ((D${zia_dlp_dictionaries.date_of_birth_prox_500.id}.S > 1) AND (D${zia_dlp_dictionaries.drivers_license_united_states_prox_500.id}.S > 1)) OR (D${zia_dlp_dictionaries.social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.us_passport_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.alien_registration_number_prox_500.id}.S > 0)))"
}

resource "zia_dlp_engines" "itar_phrases" {
  name                         = "ITAR Phrases"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.itar_pattern.id}.S > 0) OR (D${zia_dlp_dictionaries.itar_phrase.id}.S > 0))"
}

resource "zia_dlp_engines" "tlp_red" {
  name                         = "TLP Red"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.tlp_red.id}.S > 0))"
}

resource "zia_dlp_engines" "tlp_amber_strict" {
  name                         = "TLP Amber Strict"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.tlp_amber_strict.id}.S > 0))"
}

resource "zia_dlp_engines" "tlp_amber" {
  name                         = "TLP Amber"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.tlp_amber.id}.S > 0))"
}

resource "zia_dlp_engines" "cui_engine_high_confidence" {
  name                         = "CUI Engine (High Confidence)"
  description                  = "Engine created by automated script. [DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.cui_registry_marking_pattern_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_portion_marking_pattern_high_confidence.id}.S > 1) OR (D${zia_dlp_dictionaries.declassify_date_pattern_high_confidence.id}.S > 0))"
}

resource "zia_dlp_engines" "cui_engine_medium_confidence" {
  name                         = "CUI Engine (Medium Confidence)"
  description                  = "Engine created by automated script. [DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.cui_registry_marking_pattern_medium_confidence.id}.S > 0) AND ((D${zia_dlp_dictionaries.cui_portion_marking_pattern_medium_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_contextual_phrases.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_category_phrase.id}.S > 0))) OR ((D${zia_dlp_dictionaries.cui_portion_marking_pattern_medium_confidence.id}.S > 0) AND ((D${zia_dlp_dictionaries.cui_contextual_phrases.id}.S > 2) OR (D${zia_dlp_dictionaries.cui_category_phrase.id}.S > 1))) OR ((D${zia_dlp_dictionaries.declassify_date_pattern_medium_confidence.id}.S > 0) AND ((D${zia_dlp_dictionaries.cui_portion_marking_pattern_medium_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_contextual_phrases.id}.S > 2) OR (D${zia_dlp_dictionaries.cui_category_phrase.id}.S > 1))))"
}

resource "zia_dlp_engines" "cui_engine_low_confidence" {
  name                         = "CUI Engine (Low Confidence)"
  description                  = "Engine created by automated script. [DLP-Check pack fed_policy_pack] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.cui_contextual_phrases.id}.S > 2) AND (D${zia_dlp_dictionaries.cui_category_phrase.id}.S > 0))"
}

