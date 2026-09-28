# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "fouo_markings_high_confidence" {
  name                         = "FOUO Markings High Confidence"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.fouo_markings_high_confidence.id}.S > 0))"
}

resource "zia_dlp_engines" "fouo_markings_medium_confidence" {
  name                         = "FOUO Markings Medium Confidence"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.fouo_markings_medium_confidence.id}.S > 0))"
}

resource "zia_dlp_engines" "aea_high_confidence" {
  name                         = "AEA High Confidence"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.aea_rd_frd_admonishment_phrase.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_literal_phrase.id}.S > 1)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_literal_phrase.id}.S > 0) AND (D${zia_dlp_dictionaries.aea_rd_frd_contextual_phrase.id}.S > 0)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_high_confidence.id}.S > 2) AND (D${zia_dlp_dictionaries.aea_rd_frd_pattern_high_confidence.id}.S > 0)) OR ((D${zia_dlp_dictionaries.aea_rd_frd_portion_marking_pattern_high_confidence.id}.S > 2) AND (D${zia_dlp_dictionaries.aea_rd_frd_contextual_phrase.id}.S > 0)))"
}

resource "zia_dlp_engines" "standard_forms" {
  name                         = "Standard Forms"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.standard_forms.id}.S > 3))"
}

resource "zia_dlp_engines" "us_pii" {
  name                         = "US PII"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.tax_identification_number_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.tax_identification_number_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.alien_registration_number_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.alien_registration_number_prox_500.id}.S > 0) OR ((D${zia_dlp_dictionaries.date_of_birth_high_confidence.id}.S > 1) AND (D${zia_dlp_dictionaries.drivers_license_united_states_high.id}.S > 4)))"
}

resource "zia_dlp_engines" "private_keys" {
  name                         = "Private Keys"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.private_keys_plaintext_regex.id}.S > 0) OR (D${zia_dlp_dictionaries.jwk_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.fed_pack_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.encrypted_or_ascii_armored_pgp_keys.id}.S > 0) OR (D${zia_dlp_dictionaries.encrypted_bouncy_castle_key_exports.id}.S > 0))"
}

resource "zia_dlp_engines" "financial_information" {
  name                         = "Financial Information"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.aba_bank_routing_number_high.id}.S > 4) OR (D${zia_dlp_dictionaries.aba_bank_routing_number_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.credit_cards_high.id}.S > 4) OR (D${zia_dlp_dictionaries.credit_cards_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.credit_card_magnetic_tracks.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_tax_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.form_k_1.id}.S > 3) OR (D${zia_dlp_dictionaries.form_1099_misc_and_1099_nec.id}.S > 4) OR (D${zia_dlp_dictionaries.w2_or_w4_or_w9_forms.id}.S > 3) OR (D${zia_dlp_dictionaries.form_1040_and_related_schedules.id}.S > 3) OR (D${data.zia_dlp_dictionaries.financial.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_corporate_finance_leakage.id}.S > 0))"
}

resource "zia_dlp_engines" "us_phi_medium_confidence" {
  name                         = "US PHI - Medium Confidence"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.ml_medical_doc_leakage.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_leakage.id}.S > 9) OR (D${data.zia_dlp_dictionaries.diseases_leakage.id}.S > 9)))) AND ((D${zia_dlp_dictionaries.social_security_numbers_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.us_passport_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.alien_registration_number_high_confidence.id}.S > 0) OR ((D${zia_dlp_dictionaries.date_of_birth_high_confidence.id}.S > 0) AND (D${zia_dlp_dictionaries.drivers_license_united_states_prox_500.id}.S > 0))))"
}

resource "zia_dlp_engines" "us_phi_high_confidence" {
  name                         = "US PHI - High Confidence"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${data.zia_dlp_dictionaries.ml_medical_doc_leakage.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.medical.id}.S > 0) AND ((D${data.zia_dlp_dictionaries.drugs_leakage.id}.S > 14) OR (D${data.zia_dlp_dictionaries.diseases_leakage.id}.S > 14)))) AND ((D${zia_dlp_dictionaries.social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.us_passport_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.alien_registration_number_high_confidence.id}.S > 4) OR ((D${zia_dlp_dictionaries.date_of_birth_prox_500.id}.S > 1) AND (D${zia_dlp_dictionaries.drivers_license_united_states_prox_500.id}.S > 1)) OR (D${zia_dlp_dictionaries.social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.us_passport_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.alien_registration_number_prox_500.id}.S > 0)))"
}

resource "zia_dlp_engines" "itar_phrases" {
  name                         = "ITAR Phrases"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.itar_pattern.id}.S > 0) OR (D${zia_dlp_dictionaries.itar_phrase.id}.S > 0))"
}

resource "zia_dlp_engines" "tlp_red" {
  name                         = "TLP Red"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.tlp_red.id}.S > 0))"
}

resource "zia_dlp_engines" "tlp_amber_strict" {
  name                         = "TLP Amber Strict"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.tlp_amber_strict.id}.S > 0))"
}

resource "zia_dlp_engines" "tlp_amber" {
  name                         = "TLP Amber"
  description                  = "[DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.tlp_amber.id}.S > 0))"
}

resource "zia_dlp_engines" "cui_detect_all" {
  name                         = "CUI-Detect-All"
  description                  = "Full CUI detection surface: banner grammar, category tokens, legacy markings, malformed-marking proximity, and designation blocks. [DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((((D${zia_dlp_dictionaries.cui_banner_structural.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_banner_ldc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_portionmark_structural.id}.S > 1) OR (D${zia_dlp_dictionaries.cui_code_cti.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_prvcy.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_propin.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_ssel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_isvi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_opsec.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_nnpi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_pcii.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_cvi.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_fouo.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_les.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_sbu.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_distribution_statements.id}.S > 0)) OR ((D${zia_dlp_dictionaries.cui_prox_expt.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_tax.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_lei.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_crit.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_nuc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_intel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_legal.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_procure.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_ldc_standalone.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_designation_indicator.id}.S > 2) OR (D${zia_dlp_dictionaries.cui_basic_bare.id}.S > 2)))) AND NOT (D${zia_dlp_dictionaries.cui_decontrol_context.id}.S > 0)"
}

resource "zia_dlp_engines" "cui_detect_contextual" {
  name                         = "CUI-Detect-Contextual"
  description                  = "Content-based CUI signal: three or more distinct marking-guide phrases together with a Registry category name, minus the decontrol exclusion. Monitor only. [DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.cui_contextual_phrases.id}.S > 2) AND (D${zia_dlp_dictionaries.cui_category_phrases.id}.S > 0))) AND NOT ((D${zia_dlp_dictionaries.cui_decontrol_context.id}.S > 0))"
}

resource "zia_dlp_engines" "cui_detect_block_grade" {
  name                         = "CUI-Detect-Block-Grade"
  description                  = "High-precision signals intended to BLOCK (16 dictionaries with their minimum counts), minus the exclusion dictionaries. [DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.cui_banner_structural.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_banner_ldc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_portionmark_structural.id}.S > 1) OR (D${zia_dlp_dictionaries.cui_code_cti.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_prvcy.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_propin.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_ssel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_isvi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_opsec.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_nnpi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_pcii.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_cvi.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_fouo.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_les.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_sbu.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_distribution_statements.id}.S > 0))) AND NOT ((D${zia_dlp_dictionaries.cui_decontrol_context.id}.S > 0))"
}

resource "zia_dlp_engines" "cui_detect_caution_grade" {
  name                         = "CUI-Detect-Caution-Grade"
  description                  = "Lower-precision signals intended to CAUTION (12 dictionaries with their minimum counts), minus the exclusion dictionaries. Never wire to BLOCK. [DLP-Check pack fed_policy_pack v2.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.cui_basic_bare.id}.S > 2) OR (D${zia_dlp_dictionaries.cui_ldc_standalone.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_expt.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_tax.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_lei.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_crit.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_nuc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_intel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_legal.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_procure.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_designation_indicator.id}.S > 2) OR (D${zia_dlp_dictionaries.cui_declassify_date.id}.S > 0))) AND NOT ((D${zia_dlp_dictionaries.cui_decontrol_context.id}.S > 0))"
}

