# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "bank_payment_card_data" {
  name                         = "Bank-Payment Card Data"
  description                  = "PCI: several high-confidence card numbers, a card number near a card phrase, magnetic-track data, or one card number beside CVV/PIN/expiry fields. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_credit_cards_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_credit_cards_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.zbp_credit_card_magnetic_tracks.id}.S > 0) OR ((D${zia_dlp_dictionaries.zbp_credit_cards_high.id}.S > 0) AND (D${zia_dlp_dictionaries.bank_card_security_data.id}.S > 1)))"
}

resource "zia_dlp_engines" "bank_payment_card_data_bulk" {
  name                         = "Bank-Payment Card Data - Bulk"
  description                  = "PCI bulk export: 25 or more distinct high-confidence card numbers, or 5 or more magnetic-track records. Block-grade. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_credit_cards_high.id}.S > 24) OR (D${zia_dlp_dictionaries.zbp_credit_card_magnetic_tracks.id}.S > 4))"
}

resource "zia_dlp_engines" "bank_account_and_payment_instructions" {
  name                         = "Bank-Account and Payment Instructions"
  description                  = "Bank account identifiers (ABA routing, EU IBAN with checksum, global IBAN, SWIFT/BIC) in payment context: several identifiers, or an identifier with wire-instruction vocabulary. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_prox_500.id}.S > 1) OR (D${data.zia_dlp_dictionaries.euiban_leakage.id}.S > 2) OR (D${zia_dlp_dictionaries.bank_iban_global.id}.S > 1) OR ((D${zia_dlp_dictionaries.bank_swift_bic_code.id}.S > 0) AND (D${zia_dlp_dictionaries.bank_wire_transfer_instructions.id}.S > 2)) OR ((D${zia_dlp_dictionaries.bank_wire_transfer_instructions.id}.S > 4) AND ((D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_high.id}.S > 0) OR (D${data.zia_dlp_dictionaries.euiban_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_iban_global.id}.S > 0))))"
}

resource "zia_dlp_engines" "bank_customer_financial_records" {
  name                         = "Bank-Customer Financial Records"
  description                  = "Account statements and customer records: statement vocabulary beside an account, card or personal identifier. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.bank_customer_account_statement.id}.S > 4) AND (((D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_high.id}.S > 0) OR (D${data.zia_dlp_dictionaries.euiban_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_iban_global.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_credit_cards_high.id}.S > 0)) OR (D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_national_id_uk_canada_australia_south_africa.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_national_id_india_singapore_hong_kong.id}.S > 0)))"
}

resource "zia_dlp_engines" "bank_customer_pii_global" {
  name                         = "Bank-Customer PII (Global)"
  description                  = "Customer personal data across jurisdictions: US SSN/ITIN (high confidence or in proximity), UK/CA/AU/ZA and IN/SG/HK national IDs, EU and Asia-Pacific passports (Zscaler predefined), US passport, US driver licence with date of birth, or PII field labels beside any identifier. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_national_id_uk_canada_australia_south_africa.id}.S > 1) OR (D${zia_dlp_dictionaries.bank_national_id_india_singapore_hong_kong.id}.S > 1) OR (D${data.zia_dlp_dictionaries.ppeu_leakage.id}.S > 1) OR (D${data.zia_dlp_dictionaries.aspp_leakage.id}.S > 1) OR (D${zia_dlp_dictionaries.zbp_us_passport_prox_500.id}.S > 0) OR ((D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 1) AND (D${zia_dlp_dictionaries.zbp_drivers_license_united_states_high.id}.S > 4)) OR ((D${zia_dlp_dictionaries.bank_customer_pii_context.id}.S > 3) AND ((D${zia_dlp_dictionaries.bank_national_id_uk_canada_australia_south_africa.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_national_id_india_singapore_hong_kong.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ppeu_leakage.id}.S > 0) OR (D${data.zia_dlp_dictionaries.aspp_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_us_passport_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 0))))"
}

resource "zia_dlp_engines" "bank_customer_pii_bulk" {
  name                         = "Bank-Customer PII - Bulk"
  description                  = "Customer-data bulk export: 25 or more distinct identifiers of one kind, or 50 or more dates of birth. Block-grade. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 24) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_high.id}.S > 24) OR (D${zia_dlp_dictionaries.bank_national_id_uk_canada_australia_south_africa.id}.S > 24) OR (D${zia_dlp_dictionaries.bank_national_id_india_singapore_hong_kong.id}.S > 24) OR (D${data.zia_dlp_dictionaries.ppeu_leakage.id}.S > 24) OR (D${data.zia_dlp_dictionaries.aspp_leakage.id}.S > 24) OR (D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 49) OR (D${data.zia_dlp_dictionaries.euiban_leakage.id}.S > 24) OR (D${zia_dlp_dictionaries.bank_iban_global.id}.S > 24))"
}

resource "zia_dlp_engines" "bank_kyc_and_aml_files" {
  name                         = "Bank-KYC and AML Files"
  description                  = "Onboarding, due-diligence and AML case files: KYC/AML vocabulary beside a personal identifier or PII field labels. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.bank_kyc_and_aml.id}.S > 3) AND ((D${zia_dlp_dictionaries.bank_customer_pii_context.id}.S > 1) OR ((D${zia_dlp_dictionaries.bank_national_id_uk_canada_australia_south_africa.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_national_id_india_singapore_hong_kong.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ppeu_leakage.id}.S > 0) OR (D${data.zia_dlp_dictionaries.aspp_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_us_passport_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 0))))"
}

resource "zia_dlp_engines" "bank_credit_and_loan_applications" {
  name                         = "Bank-Credit and Loan Applications"
  description                  = "Lending files: loan/credit application vocabulary beside a personal identifier or PII field labels. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.bank_loan_and_credit_application.id}.S > 4) AND ((D${zia_dlp_dictionaries.bank_customer_pii_context.id}.S > 2) OR ((D${zia_dlp_dictionaries.bank_national_id_uk_canada_australia_south_africa.id}.S > 0) OR (D${zia_dlp_dictionaries.bank_national_id_india_singapore_hong_kong.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ppeu_leakage.id}.S > 0) OR (D${data.zia_dlp_dictionaries.aspp_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_us_passport_high_confidence.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_high.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 0))))"
}

resource "zia_dlp_engines" "bank_mnpi_and_deal_information" {
  name                         = "Bank-MNPI and Deal Information"
  description                  = "Material non-public information: deal vocabulary, Zscaler's corporate-finance ML dictionary, or a financial statement carrying a confidentiality marking. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.bank_mnpi_and_deal_information.id}.S > 3) OR (D${data.zia_dlp_dictionaries.ml_corporate_finance_leakage.id}.S > 0) OR ((D${data.zia_dlp_dictionaries.financial.id}.S > 0) AND (D${zia_dlp_dictionaries.bank_confidentiality_markings.id}.S > 0)))"
}

resource "zia_dlp_engines" "bank_confidential_markings" {
  name                         = "Bank-Confidential Markings"
  description                  = "Any bank confidentiality marking. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.bank_confidentiality_markings.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_us_pii" {
  name                         = "ZBP-US PII"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_social_security_numbers_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_social_security_numbers_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_tax_identification_number_us_prox_500.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_alien_registration_number_high_confidence.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_alien_registration_number_prox_500.id}.S > 0) OR ((D${zia_dlp_dictionaries.zbp_date_of_birth_high_confidence.id}.S > 1) AND (D${zia_dlp_dictionaries.zbp_drivers_license_united_states_high.id}.S > 4)))"
}

resource "zia_dlp_engines" "zbp_financial_information" {
  name                         = "ZBP-Financial Information"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_aba_bank_routing_number_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.zbp_credit_cards_high.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_credit_cards_prox_500.id}.S > 1) OR (D${zia_dlp_dictionaries.zbp_credit_card_magnetic_tracks.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_tax_leakage.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_form_k_1.id}.S > 3) OR (D${zia_dlp_dictionaries.zbp_form_1099_misc_and_1099_nec.id}.S > 4) OR (D${zia_dlp_dictionaries.zbp_w2_or_w4_or_w9_forms.id}.S > 3) OR (D${zia_dlp_dictionaries.zbp_form_1040_and_related_schedules.id}.S > 3) OR (D${data.zia_dlp_dictionaries.financial.id}.S > 0) OR (D${data.zia_dlp_dictionaries.ml_corporate_finance_leakage.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_private_keys" {
  name                         = "ZBP-Private Keys"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_private_keys_plaintext_regex.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_jwk_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_encrypted_or_ascii_armored_pgp_keys.id}.S > 0) OR (D${zia_dlp_dictionaries.zbp_encrypted_bouncy_castle_key_exports.id}.S > 0))"
}

