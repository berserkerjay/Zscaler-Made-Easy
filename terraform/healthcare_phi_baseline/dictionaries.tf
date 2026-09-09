# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

data "zia_dlp_dictionaries" "ml_medical_doc_leakage" {
  name = "ML_MEDICAL_DOC_LEAKAGE"
}

data "zia_dlp_dictionaries" "medical" {
  name = "MEDICAL"
}

resource "zia_dlp_dictionaries" "d_mrn" {
  name                         = "D_MRN"
  description                  = "Medical record number: the label phrase and a 7-digit number within ~20 bytes of each other. Both the phrase and the pattern must match. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 20
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b\\d{7}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MRN"
  }
}

resource "zia_dlp_dictionaries" "d_acct" {
  name                         = "D_ACCT"
  description                  = "Patient account number: an account label and a 9-digit number within ~25 bytes. Both the phrase and the pattern must match. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 25
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b\\d{9}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Acct"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Account"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient Account"
  }
}

resource "zia_dlp_dictionaries" "d_dob" {
  name                         = "D_DOB"
  description                  = "Date of birth: a DOB label and a US-format date within ~15 bytes. Both the phrase and the pattern must match. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 15
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\\d|3[01])/(?:19|20)\\d{2}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "DOB"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of Birth"
  }
}

resource "zia_dlp_dictionaries" "d_legal_sex" {
  name                         = "D_LEGAL_SEX"
  description                  = "Legal sex booster: the label and a code or word within ~8 bytes. Never sufficient alone; the engine only counts it beside a strong identifier. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 8
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:M|F|Male|Female)\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Legal Sex"
  }
}

resource "zia_dlp_dictionaries" "d_clinical_phrases" {
  name                         = "D_CLINICAL_PHRASES"
  description                  = "Low-confidence clinical context phrases. Supplements the predefined Medical Information / Medical Document dictionaries; never sufficient alone for PHI. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Discharge Summary"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Progress Notes"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MD Prog Notes"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "MD Progress Notes"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Vitals Include:"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of Service"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No notes of this type exist for this encounter"
  }
}

