# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

data "zia_dlp_dictionaries" "social_security_numbers_us" {
  name = "Social Security Numbers (US)"
}

data "zia_dlp_dictionaries" "drivers_license_united_states" {
  name = "Drivers License (United States)"
}

resource "zia_dlp_dictionaries" "cjis_marking_pattern_high_confidence" {
  name                         = "CJIS Marking Pattern (High Confidence)"
  description                  = "Explicit CJIS / CJI / CHRI portion and banner markings (document header/footer or paragraph portion markings). [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:CJIS|CJI|CHRI)\\s*(?:SECURITY\\s+POLICY|INFO(?:RMATION)?|DATA|RECORDS?)?\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\(\\s*(?:CJIS|CJI|CHRI)\\s*\\)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "//(?:CJIS|CJI|CHRI)(?://|\\b)"
  }
}

resource "zia_dlp_dictionaries" "cjis_marking_pattern_medium_confidence" {
  name                         = "CJIS Marking Pattern (Medium Confidence)"
  description                  = "Looser CJIS marking detection — catches 'CJIS' or 'CJI' in running text without requiring banner syntax. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_MEDIUM"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:CJIS|CHRI)\\b"
  }
}

resource "zia_dlp_dictionaries" "law_enforcement_sensitive_les_markings" {
  name                         = "Law Enforcement Sensitive (LES) Markings"
  description                  = "LES banner/portion markings — 'LES', 'Law Enforcement Sensitive', 'FOUO//LES'. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bLAW\\s+ENFORCEMENT\\s+SENSITIVE\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bFOUO\\s*//\\s*LES\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\(\\s*LES\\s*\\)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "//LES(?://|\\b)"
  }
}

resource "zia_dlp_dictionaries" "ncic_ori_pattern" {
  name                         = "NCIC ORI Pattern"
  description                  = "NCIC Originating Agency Identifier — 9-character alphanumeric (2-letter state + 7 alphanum). Used by every criminal-justice agency that queries NCIC. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 250
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bORI[:\\s=]+[A-Z]{2}[A-Z0-9]{7}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b[A-Z]{2}\\d{7}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "originating agency identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "ORI number"
  }
}

resource "zia_dlp_dictionaries" "fbi_ucn_universal_control_number" {
  name                         = "FBI UCN / Universal Control Number"
  description                  = "FBI Universal Control Number (UCN, formerly 'FBI Number') — typically referenced by 'UCN' or 'FBI#' label followed by alphanumeric identifier. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 250
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:UCN|FBI\\s*#|FBI\\s*No\\.?)\\s*[:\\-=]?\\s*[A-Z0-9]{7,12}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "universal control number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "FBI number"
  }
}

resource "zia_dlp_dictionaries" "state_id_number_sid_reference" {
  name                         = "State ID Number (SID) Reference"
  description                  = "State Identification Number — phrase-anchored (state-specific formats vary too widely for a single regex). [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  confidence_threshold         = "CONFIDENCE_LEVEL_MEDIUM"
  proximity                    = 250
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSID[:\\s=]+[A-Z0-9\\-]{5,15}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "state identification number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "SID number"
  }
}

resource "zia_dlp_dictionaries" "ncic_purpose_code_pattern" {
  name                         = "NCIC Purpose Code Pattern"
  description                  = "NCIC query purpose codes — C (criminal justice), J (criminal justice employment), S (national security), F (firearms), X (exigent), etc. Valid codes appearing in message headers indicate a law... [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 250
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bPurpose\\s*Code[:\\s=]+[CJSFXIDHRW]\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bPUR[:\\s=]+[CJSFXIDHRW]\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NCIC purpose code"
  }
}

resource "zia_dlp_dictionaries" "criminal_history_rap_sheet_phrases" {
  name                         = "Criminal History / RAP Sheet Phrases"
  description                  = "Terminology that signals transmission of criminal-history record information — RAP sheets, booking reports, wants/warrants, court dispositions. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "rap sheet"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "criminal history record"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "criminal history information"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "booking record"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "booking photo"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "mugshot"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "arrest record"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "arrest report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "incident report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "offense report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "case file"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "investigation report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "court disposition"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "conviction record"
  }
}

resource "zia_dlp_dictionaries" "ncic_iii_query_terminology" {
  name                         = "NCIC / III Query Terminology"
  description                  = "Phrases indicating an NCIC or Interstate Identification Index (III) query — wanted-person, stolen-property, missing-person, III hit. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NCIC hit"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NCIC query"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NCIC response"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "III query"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "III response"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Interstate Identification Index"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "wanted person"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "stolen property"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "stolen vehicle"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "missing person"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "protection order"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "gang file"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "known or appropriately suspected terrorist"
  }
}

resource "zia_dlp_dictionaries" "warrant_wanted_person_phrases" {
  name                         = "Warrant / Wanted-Person Phrases"
  description                  = "Active-warrant and wanted-person terminology. High-signal when seen alongside subject PII. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "active warrant"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "arrest warrant"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "bench warrant"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "fugitive warrant"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "extradition warrant"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "warrant number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NCIC wanted"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "warrant of arrest"
  }
}

resource "zia_dlp_dictionaries" "biometric_afis_terminology" {
  name                         = "Biometric / AFIS Terminology"
  description                  = "Biometric data referenced in criminal-justice workflows — fingerprints, palm prints, AFIS/IAFIS/NGI identifiers, mugshot booking. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "fingerprint card"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "ten-print"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "palm print"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "latent print"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "AFIS"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "IAFIS"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Next Generation Identification"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NGI"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "biometric identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "booking photo"
  }
}

resource "zia_dlp_dictionaries" "nics_firearms_background_check_phrases" {
  name                         = "NICS / Firearms Background Check Phrases"
  description                  = "National Instant Criminal Background Check System (NICS) and firearms-eligibility terminology. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NICS"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "National Instant Criminal Background"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "firearm denial"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "NICS denial"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "prohibited person"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "ATF Form 4473"
  }
}

resource "zia_dlp_dictionaries" "n_dex_criminal_justice_info_sharing" {
  name                         = "N-DEx / Criminal-Justice Info Sharing"
  description                  = "Law Enforcement National Data Exchange (N-DEx) and related info-sharing system references. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  confidence_threshold         = "CONFIDENCE_LEVEL_MEDIUM"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "N-DEx"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "National Data Exchange"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Law Enforcement Enterprise Portal"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "LEEP portal"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Nlets"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "RISS"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "regional information sharing"
  }
}

resource "zia_dlp_dictionaries" "social_security_numbers_us_cjis_prox_500" {
  name                         = "Social Security Numbers (US) - CJIS Prox 500"
  description                  = "Cloned predefined SSN dictionary with 500-char proximity — intended to be used WITH criminal-history/warrant phrases so only subject SSNs in CJI context trigger. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.social_security_numbers_us.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
}

resource "zia_dlp_dictionaries" "drivers_license_us_cjis_prox_500" {
  name                         = "Drivers License (US) - CJIS Prox 500"
  description                  = "Cloned predefined Driver's License dictionary with 500-char proximity for CJI-context correlation. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.drivers_license_united_states.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
}

resource "zia_dlp_dictionaries" "date_of_birth_cjis_prox_500" {
  name                         = "Date of Birth - CJIS Prox 500"
  description                  = "Date-of-birth detection with 500-char proximity — couples with warrant / RAP-sheet phrases to reduce false positives on non-CJI DOB mentions. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:0?[1-9]|1[0-2])[\\/\\-.](?:0?[1-9]|[12]\\d|3[01])[\\/\\-.](?:19|20)\\d{2}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:19|20)\\d{2}[\\/\\-.](?:0?[1-9]|1[0-2])[\\/\\-.](?:0?[1-9]|[12]\\d|3[01])\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "date of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "DOB"
  }
}

