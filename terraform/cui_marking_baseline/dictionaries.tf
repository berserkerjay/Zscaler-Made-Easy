# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

resource "zia_dlp_dictionaries" "cui_banner_structural" {
  name                         = "CUI-Banner-Structural"
  description                  = "Well-formed CUI banner line with category marking (Basic or Specified). Tier 1 structural marking; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI//(SP-)?[A-Z]{2,10}\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_banner_ldc" {
  name                         = "CUI-Banner-LDC"
  description                  = "CUI banner carrying a limited dissemination control segment. Tier 1 structural marking; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI//([A-Z-]{2,12}//)?(NOFORN|FEDCON|NOCON|PROPIN|DISPLAY ONLY|REL TO|FED ONLY|DL ONLY)\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_portionmark_structural" {
  name                         = "CUI-PortionMark-Structural"
  description                  = "CUI portion markings in parenthetical form. Tier 1 structural marking; intended action Block; min matches 2. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\((CUI|CUI//(SP-)?[A-Z]{2,10})\\)"
  }
}

resource "zia_dlp_dictionaries" "cui_basic_bare" {
  name                         = "CUI-Basic-Bare"
  description                  = "Bare CUI designation with no category segment (Basic CUI). Tier 1 structural marking; intended action Caution; min matches 3. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"CONTROLLED UNCLASSIFIED INFORMATION\""
  }
}

resource "zia_dlp_dictionaries" "cui_ldc_standalone" {
  name                         = "CUI-LDC-Standalone"
  description                  = "Dissemination control markings appearing without an intact banner. Tier 1 structural marking; intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "NOFORN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "FEDCON"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"FED ONLY\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "NOCON"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"DL ONLY\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"REL TO\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"DISPLAY ONLY\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PROPIN"
  }
}

resource "zia_dlp_dictionaries" "cui_code_cti" {
  name                         = "CUI-Code-CTI"
  description                  = "CUI category marking token for Controlled Technical Information. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-CTI\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_prvcy" {
  name                         = "CUI-Code-PRVCY"
  description                  = "CUI category marking token for Privacy. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bPRVCY\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_propin" {
  name                         = "CUI-Code-PROPIN"
  description                  = "CUI category marking token for Proprietary Business Information. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bPROPIN\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_ssel" {
  name                         = "CUI-Code-SSEL"
  description                  = "CUI category marking token for Source Selection. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-SSEL\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_isvi" {
  name                         = "CUI-Code-ISVI"
  description                  = "CUI category marking token for Information Systems Vulnerability Information. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-ISVI\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_opsec" {
  name                         = "CUI-Code-OPSEC"
  description                  = "CUI category marking token for Operations Security. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-OPSEC\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_nnpi" {
  name                         = "CUI-Code-NNPI"
  description                  = "CUI category marking token for Naval Nuclear Propulsion Information. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-NNPI\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_pcii" {
  name                         = "CUI-Code-PCII"
  description                  = "CUI category marking token for Protected Critical Infrastructure Information. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-PCII\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_code_cvi" {
  name                         = "CUI-Code-CVI"
  description                  = "CUI category marking token for Chemical-terrorism Vulnerability Information. Tier 2 category token; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-CVI\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_expt" {
  name                         = "CUI-Prox-EXPT"
  description                  = "CUI token co-located with Export Control category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 400
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-EXPT\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_tax" {
  name                         = "CUI-Prox-TAX"
  description                  = "CUI token co-located with Tax category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 400
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-TAX\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_lei" {
  name                         = "CUI-Prox-LEI"
  description                  = "CUI token co-located with Law Enforcement category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 400
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-LEI\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_crit" {
  name                         = "CUI-Prox-CRIT"
  description                  = "CUI token co-located with Critical Infrastructure category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 400
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-CRIT\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_nuc" {
  name                         = "CUI-Prox-NUC"
  description                  = "CUI token co-located with Nuclear category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 400
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-NUC\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_intel" {
  name                         = "CUI-Prox-INTEL"
  description                  = "CUI token co-located with Intelligence category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 400
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-INTEL\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_legal" {
  name                         = "CUI-Prox-LEGAL"
  description                  = "CUI token co-located with Legal category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 300
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-LEGAL\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_prox_procure" {
  name                         = "CUI-Prox-PROCURE"
  description                  = "CUI token co-located with Procurement and Acquisition category code (malformed marking). Tier 3 malformed marking (proximity); intended action Caution; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 400
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bCUI\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSP-PROCURE\\b"
  }
}

resource "zia_dlp_dictionaries" "legacy_fouo" {
  name                         = "Legacy-FOUO"
  description                  = "Pre-CUI For Official Use Only marking. Tier 4 legacy marking; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bFOUO\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"FOR OFFICIAL USE ONLY\""
  }
}

resource "zia_dlp_dictionaries" "legacy_les" {
  name                         = "Legacy-LES"
  description                  = "Law Enforcement Sensitive marking. Tier 4 legacy marking; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bLAW ENFORCEMENT SENSITIVE\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\b(FOUO|LES)//LES\\b"
  }
}

resource "zia_dlp_dictionaries" "legacy_sbu" {
  name                         = "Legacy-SBU"
  description                  = "Sensitive But Unclassified marking. Tier 4 legacy marking; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bSBU\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"SENSITIVE BUT UNCLASSIFIED\""
  }
}

resource "zia_dlp_dictionaries" "legacy_distribution_statements" {
  name                         = "Legacy-Distribution-Statements"
  description                  = "DoW distribution statements B through F on technical documents. Tier 4 legacy marking; intended action Block; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bDISTRIBUTION STATEMENT [B-F]\\b"
  }
}

resource "zia_dlp_dictionaries" "cui_designation_indicator" {
  name                         = "CUI-Designation-Indicator"
  description                  = "CUI designation indicator block field labels in close proximity. Tier 5 designation block; intended action Caution; min matches 3. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 600
  proximity_enabled_for_custom_dictionary = true
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"Controlled by\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"CUI Category\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"Limited Dissemination Control\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"Distribution Statement\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"Controlled By\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "POC"
  }
}

resource "zia_dlp_dictionaries" "cui_decontrol_context" {
  name                         = "CUI-Decontrol-Context"
  description                  = "Decontrol and marking-guidance language used as an engine-level exclusion. Tier 6 exclusion; intended action Exclude; min matches 1. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "DECONTROLLED"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"does not contain CUI\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"no longer controlled\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"CUI Marking Guide\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"sample marking\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "\"for illustrative purposes\""
  }
}

