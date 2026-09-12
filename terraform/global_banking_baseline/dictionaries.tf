# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

data "zia_dlp_dictionaries" "ssn" {
  name = "SSN"
}

data "zia_dlp_dictionaries" "usitin_leakage" {
  name = "USITIN_LEAKAGE"
}

data "zia_dlp_dictionaries" "usdl_leakage" {
  name = "USDL_LEAKAGE"
}

data "zia_dlp_dictionaries" "cred_leakage" {
  name = "CRED_LEAKAGE"
}

data "zia_dlp_dictionaries" "aba_leakage" {
  name = "ABA_LEAKAGE"
}

data "zia_dlp_dictionaries" "credit_card" {
  name = "CREDIT_CARD"
}

data "zia_dlp_dictionaries" "euiban_leakage" {
  name = "EUIBAN_LEAKAGE"
}

data "zia_dlp_dictionaries" "aspp_leakage" {
  name = "ASPP_LEAKAGE"
}

data "zia_dlp_dictionaries" "ppeu_leakage" {
  name = "PPEU_LEAKAGE"
}

data "zia_dlp_dictionaries" "ml_corporate_finance_leakage" {
  name = "ML_CORPORATE_FINANCE_LEAKAGE"
}

data "zia_dlp_dictionaries" "financial" {
  name = "FINANCIAL"
}

data "zia_dlp_dictionaries" "ml_tax_leakage" {
  name = "ML_TAX_LEAKAGE"
}

resource "zia_dlp_dictionaries" "zbp_us_passport_high_confidence" {
  name                         = "ZBP-US Passport - High Confidence"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{8,9}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\b[A-Z]\\d{8}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport Number "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport No"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport#"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PassportID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportno"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportnumber "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. du Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. de Pasaporte"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Pasaporte"
  }
}

resource "zia_dlp_dictionaries" "zbp_us_passport_prox_500" {
  name                         = "ZBP-US Passport - Prox 500"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{8,9}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\b[A-Z]\\d{8}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport Number "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport No"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport#"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PassportID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportno"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportnumber "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. du Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. de Pasaporte"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Pasaporte"
  }
}

resource "zia_dlp_dictionaries" "zbp_alien_registration_number_prox_500" {
  name                         = "ZBP-Alien Registration Number - Prox 500"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\bA?[\\-#]?\\d{3}-?\\d{3}-?\\d{1,3}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ARN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Registration"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "'A-Number'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Immigrant data"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "USCIS Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Employment Authorization"
  }
}

resource "zia_dlp_dictionaries" "zbp_alien_registration_number_high_confidence" {
  name                         = "ZBP-Alien Registration Number - High Confidence"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\bA?[\\-#]?\\d{3}-?\\d{3}-?\\d{1,3}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ARN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Registration"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "'A-Number'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Immigrant data"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "USCIS Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Employment Authorization"
  }
}

resource "zia_dlp_dictionaries" "zbp_date_of_birth_high_confidence" {
  name                         = "ZBP-Date of Birth - High Confidence"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b([0-1]?\\d)[\\/.-]([0-3]?\\d)[\\/.-](19|20)?\\d{2}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(19|20)?\\d{2}[\\/.-]([0-1]?\\d)[\\/.-]([0-3]?\\d)\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "year of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "month of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "day of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birthday"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birth year"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birth month"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "dob"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "d.o.b"
  }
}

resource "zia_dlp_dictionaries" "zbp_social_security_numbers_us_high" {
  name                         = "ZBP-Social Security Numbers (US) - High"
  description                  = "Detect leakage of United States Social Security Numbers [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.ssn.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ssn"
  }
}

resource "zia_dlp_dictionaries" "zbp_social_security_numbers_us_prox_500" {
  name                         = "ZBP-Social Security Numbers (US) - Prox 500"
  description                  = "Detect leakage of United States Social Security Numbers [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.ssn.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ssn"
  }
}

resource "zia_dlp_dictionaries" "zbp_tax_identification_number_us_high" {
  name                         = "ZBP-Tax Identification Number (US) - High"
  description                  = "Detect Leakage of US Tax Identification Numbers [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.usitin_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
}

resource "zia_dlp_dictionaries" "zbp_tax_identification_number_us_prox_500" {
  name                         = "ZBP-Tax Identification Number (US) - Prox 500"
  description                  = "Detect Leakage of US Tax Identification Numbers [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.usitin_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
}

resource "zia_dlp_dictionaries" "zbp_drivers_license_united_states_high" {
  name                         = "ZBP-Drivers License (United States) - High"
  description                  = "Detect leakage of United States Driver’s Licenses [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.usdl_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_HIGH"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  hierarchical_identifiers     = ["USDL_AL", "USDL_AK", "USDL_AZ", "USDL_AR", "USDL_CA", "USDL_CO", "USDL_CT", "USDL_DE", "USDL_DC", "USDL_FL", "USDL_GA", "USDL_HI", "USDL_ID", "USDL_IL", "USDL_IN", "USDL_IA", "USDL_KS", "USDL_KY", "USDL_LA", "USDL_ME", "USDL_MD", "USDL_MA", "USDL_MI", "USDL_MN", "USDL_MS", "USDL_MO", "USDL_MT", "USDL_NE", "USDL_NV", "USDL_NH", "USDL_NJ", "USDL_NM", "USDL_NY", "USDL_NC", "USDL_ND", "USDL_OH", "USDL_OK", "USDL_OR", "USDL_PA", "USDL_RI", "USDL_SC", "USDL_SD", "USDL_TN", "USDL_TX", "USDL_VT", "USDL_VA", "USDL_WV", "USDL_WI", "USDL_WY", "USDL_GU"]
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Driver License"
  }
}

resource "zia_dlp_dictionaries" "zbp_private_keys_plaintext_regex" {
  name                         = "ZBP-Private Keys-Plaintext Regex"
  description                  = "Detect Elliptic Curve(EC), Digital Signature Algorithm (DSA), Rivest-Shamir-Adleman (RSA), Secure Shell 2(SSH2), OpenSSH, Pretty Good Privacy(PGP), Gnu Privacy Guard(GPG) Private key... [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "[- ]{4,5}BEGIN (EC|DSA|RSA|SSH2|OPENSSH|PGP|GPG) PRIVA"
  }
}

resource "zia_dlp_dictionaries" "zbp_jwk_private_key" {
  name                         = "ZBP-JWK Private Key"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\"kty\" ?: ?\"(EC|RSA)\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "'\"d\"'"
  }
}

resource "zia_dlp_dictionaries" "zbp_private_key" {
  name                         = "ZBP-Private Key"
  description                  = "Detect leakage of credentials and secrets [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.cred_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_MEDIUM"
  hierarchical_identifiers     = ["CRED_PRIVATE_KEY"]
}

resource "zia_dlp_dictionaries" "zbp_encrypted_or_ascii_armored_pgp_keys" {
  name                         = "ZBP-Encrypted or ASCII Armored PGP Keys"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "-{4,5}BEGIN (PGP|ENCRYPTED) PRIVATE\\b"
  }
}

resource "zia_dlp_dictionaries" "zbp_encrypted_bouncy_castle_key_exports" {
  name                         = "ZBP-Encrypted Bouncy Castle Key Exports"
  description                  = "Bouncy Castle Key Exports triggers against the unique phrase within the exported key indicating it is encrypted [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bProc-Type: 4,ENCRYPTED\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Private Key"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "DEK-Info"
  }
}

resource "zia_dlp_dictionaries" "zbp_form_k_1" {
  name                         = "ZBP-Form K-1"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Schedule K-1 "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0123"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "A Partnership’s employer identification number "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "F Name, address, city, state, and ZIP code for partner entered in"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Partner’s share of liabilities"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Partner’s Share of Current Year Income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "More than one activity for passive activity purposes"
  }
}

resource "zia_dlp_dictionaries" "zbp_form_1099_misc_and_1099_nec" {
  name                         = "ZBP-Form 1099-MISC and 1099-NEC"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "PAYER’S name, street address, city or town, state or province, country, ZIP"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1099-MISC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1099-NEC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Payer made direct sales totaling $5,000 or more of"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Nonqualified deferred compensation"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0115"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Excess golden parachute"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Gross proceeds paid to an"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "PAYER’S TIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "RECIPIENT’S TIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "File with Form 1096."
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0116"
  }
}

resource "zia_dlp_dictionaries" "zbp_w2_or_w4_or_w9_forms" {
  name                         = "ZBP-W2 or W4 or W9 Forms"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "a Employee’s social security number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0008 "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form W-2"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Wage and Tax Statement"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "c Employer’s name, address, and ZIP code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "e Employee’s first name and initial"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "3 Social security wages"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form W-9"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Identification Number and Certification"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Name of entity/individual. An entry is required"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "LLC. Enter the tax classification "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Exemptions (codes apply only to"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 10231X"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "List account number(s) here (optional)"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form W-4"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0074"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Single or Married filing separately"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Other income (not from jobs)."
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "If your total income will be $200,000 or less"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Deductions. If you expect to claim deductions other than the standard deduction "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 10220Q"
  }
}

resource "zia_dlp_dictionaries" "zbp_form_1040_and_related_schedules" {
  name                         = "ZBP-Form 1040 and related schedules"
  description                  = "[DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1040"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0074"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = " or other tax year beginning"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Was born before January 2, 1959"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "If you checked the HOH or QSS box"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "I have examined this return and accompanying schedules and statements, and to the best of my knowledge"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Do you want to allow another person to discuss this return"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 11320B"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "'Schedule 1 (Form 1040)'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Additional Income and Adjustments to Income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Foreign earned income exclusion"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Activity not engaged in for profit income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Nontaxable amount of Medicaid "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 71479F"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "'Schedule 2 (Form 1040)'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Alternative minimum tax. Attach Form"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Social security and Medicare tax on unreported tip income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Additional Medicare Tax. Attach Form 8959"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = " tax due on installment income from the sale of certain residential lots"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = " Cat. No. 71478U"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Recapture of federal mortgage subsidy"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Compensation you received from a nonqualified deferred"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Tax on non-effectively connected income for any part of"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Section 965 net tax liability installment from Form 965-A"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "'Schedule 3 (Form 1040)'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Foreign tax credit. Attach Form 1116 if required"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "General business credit. Attach Form 3800"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Mortgage interest credit. Attach Form 8396"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Credit to holders of tax credit bonds. Attach Form 8912"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Attach to Form 1040, 1040-SR, or 1040-NR"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Excess social security and tier 1 RRTA tax withheld"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Credit for repayment of amounts included in income from earlier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Deferred amount of net 965 tax liability"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Add lines 9 through 12 and 14. Enter here and on Form 1040, 1040-SR, or 1040-NR"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1040-ES"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Disclosure, Privacy Act, and Paperwork Reduction Act Notice"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "File only if you are making a payment of estimated tax by check"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Amount of estimated tax you are paying"
  }
}

resource "zia_dlp_dictionaries" "zbp_aba_bank_routing_number_high" {
  name                         = "ZBP-ABA Bank Routing Number - High"
  description                  = "Detect leakage of ABA Bank Routing Numbers [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.aba_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
}

resource "zia_dlp_dictionaries" "zbp_aba_bank_routing_number_prox_500" {
  name                         = "ZBP-ABA Bank Routing Number - Prox 500"
  description                  = "Detect leakage of ABA Bank Routing Numbers [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.aba_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
}

resource "zia_dlp_dictionaries" "zbp_credit_cards_high" {
  name                         = "ZBP-Credit Cards - High"
  description                  = "Detect leakage of credit card information [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.credit_card.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  include_bin_numbers          = true
}

resource "zia_dlp_dictionaries" "zbp_credit_cards_prox_500" {
  name                         = "ZBP-Credit Cards - Prox 500"
  description                  = "Detect leakage of credit card information [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.credit_card.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  include_bin_numbers          = true
}

resource "zia_dlp_dictionaries" "zbp_credit_card_magnetic_tracks" {
  name                         = "ZBP-Credit Card Magnetic Tracks"
  description                  = "Focuses on track 1 and 2 data, without targeting track 3. As track 3 is less commonly used, and would still be accompanied by track 1 and 2 [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "[%][B]\\d{12,19}[\\^][a-zA-Z\\/\\s.]{2,26}[\\^](\\d{7})([a-zA-Z\\d*]{1,24})[?][a-zA-Z\\d*]?"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "[;]\\d{12,19}[=]([\\dxX])([a-zA-Z\\d*]{1,24})[?][a-zA-Z\\d*]?"
  }
}

resource "zia_dlp_dictionaries" "bank_iban_global" {
  name                         = "Bank-IBAN (Global)"
  description                  = "International Bank Account Numbers of any country (GB, CH, AE, SA, SG, BR, ... as well as the EU) written with or without spaces, only when a bank-account phrase is within 500 bytes.... [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "IBAN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "International Bank Account Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "beneficiary account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account no"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "acct no"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "bank account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "BIC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SWIFT"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "sort code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "branch code"
  }
}

resource "zia_dlp_dictionaries" "bank_swift_bic_code" {
  name                         = "Bank-SWIFT BIC Code"
  description                  = "SWIFT / BIC bank identifier codes (8 or 11 characters) within 300 bytes of a SWIFT, BIC or correspondent-banking phrase. The pattern alone would match any 8-letter word, so the phrase... [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 300
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[A-Z]{4}(?:AE|AR|AT|AU|BE|BR|CA|CH|CN|CZ|DE|DK|ES|FI|FR|GB|HK|ID|IE|IL|IN|IT|JP|KR|LU|MX|MY|NL|NO|NZ|PL|PT|QA|RU|SA|SE|SG|TH|TR|TW|US|ZA)[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SWIFT"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "BIC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SWIFT code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "BIC code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "bank identifier code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SWIFT/BIC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MT103"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MT202"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MT940"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "correspondent bank"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "intermediary bank"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "beneficiary bank"
  }
}

resource "zia_dlp_dictionaries" "bank_wire_transfer_instructions" {
  name                         = "Bank-Wire Transfer Instructions"
  description                  = "Payment-instruction vocabulary: wire, SWIFT MT messages, SEPA, Fedwire, CHIPS, beneficiary and intermediary bank fields. Counted, not matched alone: the engines pair it with an accoun... [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "wire transfer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "wire instructions"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "payment instructions"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "remittance advice"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "remittance information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "beneficiary bank"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "beneficiary name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "beneficiary account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "intermediary bank"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "correspondent bank"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ordering customer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ordering institution"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account with institution"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "value date"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MT103"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MT202"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MT940"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Fedwire"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CHIPS"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SEPA credit transfer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SEPA direct debit"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ACH transfer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "payment order"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "standing order"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "direct debit mandate"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "sort code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "routing number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ABA number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "transit number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "BSB"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "IFSC code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CLABE"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "reference number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "amount to be transferred"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "currency"
  }
}

resource "zia_dlp_dictionaries" "bank_card_security_data" {
  name                         = "Bank-Card Security Data"
  description                  = "PCI DSS sensitive authentication data and cardholder fields: CVV/CVC, PIN, expiry, track data. Paired with a credit-card match in the engine so a lone card number in a receipt is not... [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CVV"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CVV2"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CVC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CVC2"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CAV2"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "card verification"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "card security code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "security code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PIN block"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PIN number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "card PIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PVV"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "expiry date"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "expiration date"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "exp date"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "valid thru"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "cardholder name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "card holder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "primary account number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PAN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "card number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "track data"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "track 1"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "track 2"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "magnetic stripe"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "chip data"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "EMV"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "issuer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "acquirer"
  }
}

resource "zia_dlp_dictionaries" "bank_customer_account_statement" {
  name                         = "Bank-Customer Account Statement"
  description                  = "Account-statement and customer-record vocabulary. Paired in the engine with an account, card or personal identifier. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account statement"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "statement of account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "bank statement"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "statement period"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "opening balance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "closing balance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "available balance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "current balance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ledger balance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "transaction history"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "transaction details"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account holder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account holder name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "customer number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "customer ID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "customer id"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CIF number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "client number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "relationship number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account type"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "savings account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "current account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "checking account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "overdraft"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "direct debit"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "standing order"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "interest accrued"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "interest rate"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "withdrawal"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "deposit"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "debit"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "account summary"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "portfolio statement"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "custody account"
  }
}

resource "zia_dlp_dictionaries" "bank_kyc_and_aml" {
  name                         = "Bank-KYC and AML"
  description                  = "Know-your-customer, due-diligence and anti-money-laundering vocabulary: CDD/EDD files, PEP and sanctions screening, SAR/STR filings, beneficial ownership. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "know your customer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "KYC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "customer due diligence"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CDD"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "enhanced due diligence"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "EDD"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "politically exposed person"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PEP"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "sanctions screening"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "sanctions list"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "OFAC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SDN list"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "suspicious activity report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SAR"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "suspicious transaction report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "STR"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "anti-money laundering"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "AML"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "counter-terrorist financing"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CTF"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "beneficial owner"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ultimate beneficial owner"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "UBO"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "source of funds"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "source of wealth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "FATF"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "FinCEN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "watchlist"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "adverse media"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "risk rating"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "onboarding"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "identity verification"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "proof of address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "proof of identity"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "customer risk assessment"
  }
}

resource "zia_dlp_dictionaries" "bank_loan_and_credit_application" {
  name                         = "Bank-Loan and Credit Application"
  description                  = "Consumer and commercial lending vocabulary: applications, credit bureau reports and scores, income and collateral. Paired in the engine with a personal identifier. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "loan application"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit application"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "mortgage application"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit card application"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit score"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "FICO"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit bureau"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit history"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Equifax"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Experian"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "TransUnion"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Schufa"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "annual income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "gross income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "net income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "monthly income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "debt-to-income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "employment verification"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "employer name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "collateral"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "co-signer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "guarantor"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "APR"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "loan number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "loan amount"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "credit limit"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "repayment schedule"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "amortization"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "underwriting"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "pre-approval"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "declined"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "approved"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "delinquent"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "default"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "charge-off"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "arrears"
  }
}

resource "zia_dlp_dictionaries" "bank_mnpi_and_deal_information" {
  name                         = "Bank-MNPI and Deal Information"
  description                  = "Material non-public information and deal-team vocabulary: M&A, capital markets, research embargoes, restricted lists. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "material non-public information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MNPI"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "material nonpublic information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "insider information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "inside information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "price sensitive information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "deal team"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "confidential information memorandum"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CIM"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "term sheet"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "letter of intent"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "LOI"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "merger"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "acquisition"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "acquisition target"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "takeover"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "tender offer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "due diligence report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "data room"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "pre-announcement"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "earnings release"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "earnings guidance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "pre-release"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "IPO"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "initial public offering"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "bookbuilding"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "syndicate"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Chinese wall"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "information barrier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "restricted list"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "watch list"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "grey list"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "project codename"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "wall crossing"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "wall-crossed"
  }
}

resource "zia_dlp_dictionaries" "bank_confidentiality_markings" {
  name                         = "Bank-Confidentiality Markings"
  description                  = "Classification labels banks stamp on documents. Any single marking is a signal on its own. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Bank Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Strictly Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Highly Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Highly Restricted"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Restricted - Internal"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Internal Use Only"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "For Internal Use Only"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Internal Only"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Client Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Customer Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Confidential - Client"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Do Not Distribute"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Not for Distribution"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Not for External Distribution"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Privileged and Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Attorney-Client Privileged"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Board Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Regulatory Confidential"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Supervisory Information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Confidential Supervisory Information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CSI"
  }
}

resource "zia_dlp_dictionaries" "bank_customer_pii_context" {
  name                         = "Bank-Customer PII Context"
  description                  = "Personal-data field labels found on account-opening forms, KYC files and customer exports. Counted, then paired with a national ID, passport, date of birth or account number. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "customer name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "full name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "first name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "last name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "surname"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "date of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "place of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "nationality"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "citizenship"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "mother's maiden name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "maiden name"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "home address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "residential address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "postal address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "mailing address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "phone number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "mobile number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "telephone"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "email address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "occupation"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "employer"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "marital status"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "gender"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "passport number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "national ID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ID number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "identification number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "tax residency"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "tax identification"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "TIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "FATCA"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "CRS"
  }
}

resource "zia_dlp_dictionaries" "bank_national_id_uk_canada_australia_south_africa" {
  name                         = "Bank-National ID (UK, Canada, Australia, South Africa)"
  description                  = "National identifiers of the UK (National Insurance number), Canada (SIN), Australia (TFN) and South Africa (ID number), within 300 bytes of the identifier's name. Check your tenant fo... [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 300
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[A-CEGHJ-PR-TW-Z]{2} ?\\d{2} ?\\d{2} ?\\d{2} ?[A-D]\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{3}[ -]\\d{3}[ -]\\d{3}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{3} ?\\d{3} ?\\d{3}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{2}[01]\\d[0-3]\\d ?\\d{4} ?[01] ?8 ?\\d\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "National Insurance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "National Insurance number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "NINO"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "NI number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "NI no"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Social Insurance Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Tax File Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "TFN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "South African ID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "SA ID number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "identity number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ID number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "national ID"
  }
}

resource "zia_dlp_dictionaries" "bank_national_id_india_singapore_hong_kong" {
  name                         = "Bank-National ID (India, Singapore, Hong Kong)"
  description                  = "National identifiers of India (PAN, Aadhaar), Singapore (NRIC/FIN) and Hong Kong (HKID), within 300 bytes of the identifier's name. [DLP-Check baseline global_banking_baseline v1.1] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 300
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[A-Z]{3}[ABCFGHLJPT][A-Z]\\d{4}[A-Z]\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[2-9]\\d{3}[ -]?\\d{4}[ -]?\\d{4}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[STFGM]\\d{7}[A-Z]\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[A-Z]{1,2}\\d{6}\\(?[0-9A]\\)?"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PAN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Permanent Account Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PAN card"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Aadhaar"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Aadhar"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "UIDAI"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "NRIC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "FIN number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "NRIC/FIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "HKID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Hong Kong Identity Card"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "identity card"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ID number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "national ID"
  }
}

