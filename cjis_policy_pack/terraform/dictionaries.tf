# ──────────────────────────────────────────────────────────────
# CJIS Dictionaries — 14 custom + 2 predefined clones
# ──────────────────────────────────────────────────────────────

# ── CJIS / CHRI / LES Markings ──────────────────────────────

resource "zia_dlp_dictionaries" "cjis_marking_high" {
  name                     = "CJIS Marking Pattern (High Confidence)"
  description              = "Explicit CJIS / CJI / CHRI portion and banner markings."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"

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

resource "zia_dlp_dictionaries" "cjis_marking_medium" {
  name                     = "CJIS Marking Pattern (Medium Confidence)"
  description              = "Looser CJIS keyword match — pairs with content indicators to cut false positives."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_MEDIUM"

  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(?:CJIS|CHRI)\\b"
  }
}

resource "zia_dlp_dictionaries" "les_markings" {
  name                     = "Law Enforcement Sensitive (LES) Markings"
  description              = "LES banner/portion markings — LES, Law Enforcement Sensitive, FOUO//LES."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"

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

# ── Structured Identifiers ──────────────────────────────────

resource "zia_dlp_dictionaries" "ncic_ori" {
  name                     = "NCIC ORI Pattern"
  description              = "NCIC Originating Agency Identifier — 9-char alphanumeric (2-letter state + 7 alphanum)."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 250
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "fbi_ucn" {
  name                     = "FBI UCN / Universal Control Number"
  description              = "FBI Universal Control Number (UCN, formerly FBI Number) — labelled pattern."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 250
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "sid" {
  name                     = "State ID Number (SID) Reference"
  description              = "State Identification Number — phrase-anchored (state-specific formats vary)."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_MEDIUM"
  proximity                = 250
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "ncic_purpose_code" {
  name                     = "NCIC Purpose Code Pattern"
  description              = "NCIC query purpose codes — C, J, S, F, X, etc."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 250
  proximity_length_enabled = true

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

# ── Contextual Phrase Dictionaries ───────────────────────────

resource "zia_dlp_dictionaries" "criminal_history" {
  name                     = "Criminal History / RAP Sheet Phrases"
  description              = "Criminal-history record terminology — RAP sheets, booking reports, court dispositions."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 500
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "ncic_iii" {
  name                     = "NCIC / III Query Terminology"
  description              = "NCIC or Interstate Identification Index query/response terminology."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 500
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "warrants" {
  name                     = "Warrant / Wanted-Person Phrases"
  description              = "Active-warrant and wanted-person terminology."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 500
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "biometric" {
  name                     = "Biometric / AFIS Terminology"
  description              = "Biometric data in criminal-justice workflows — fingerprints, palm, AFIS/IAFIS/NGI."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 500
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "nics" {
  name                     = "NICS / Firearms Background Check Phrases"
  description              = "NICS and firearms-eligibility terminology."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 500
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "ndex" {
  name                     = "N-DEx / Criminal-Justice Info Sharing"
  description              = "Law Enforcement National Data Exchange (N-DEx), LEEP, Nlets, RISS references."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_MEDIUM"
  proximity                = 500
  proximity_length_enabled = true

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

resource "zia_dlp_dictionaries" "dob_cjis" {
  name                     = "Date of Birth - CJIS Prox 500"
  description              = "DOB detection with 500-char proximity for CJIS pairing."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  confidence_threshold     = "CONFIDENCE_LEVEL_HIGH"
  proximity                = 500
  proximity_length_enabled = true

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

# ── Cloned Predefined Dictionaries ───────────────────────────
# Look up the predefined dict by name, then clone it with
# CJIS-specific proximity so it only triggers IN CONTEXT.

data "zia_dlp_dictionaries" "ssn_predefined" {
  name = "Social Security Numbers (US)"
}

resource "zia_dlp_dictionaries" "ssn_cjis" {
  name                     = "Social Security Numbers (US) - CJIS Prox 500"
  description              = "Cloned predefined SSN dictionary with 500-char proximity for CJI context."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  dict_template_id         = data.zia_dlp_dictionaries.ssn_predefined.id
  proximity                = 500
  proximity_length_enabled = true
}

data "zia_dlp_dictionaries" "dl_predefined" {
  name = "Drivers License (United States)"
}

resource "zia_dlp_dictionaries" "dl_cjis" {
  name                     = "Drivers License (US) - CJIS Prox 500"
  description              = "Cloned predefined DL dictionary with 500-char proximity for CJI context."
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "PATTERNS_AND_PHRASES"
  dict_template_id         = data.zia_dlp_dictionaries.dl_predefined.id
  proximity                = 500
  proximity_length_enabled = true
}
