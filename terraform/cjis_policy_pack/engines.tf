# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "cjis_markings_high_confidence" {
  name                         = "CJIS Markings High Confidence"
  description                  = "Explicit CJIS / CHRI / LES banner or portion markings — high-confidence indicator that the content is CJI regardless of payload. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${data.zia_dlp_dictionaries.cjis_marking_pattern_high_confidence.id}.S) OR D${zia_dlp_dictionaries.law_enforcement_sensitive_les_markings.id}.S)"
}

resource "zia_dlp_engines" "cjis_markings_medium_confidence" {
  name                         = "CJIS Markings Medium Confidence"
  description                  = "Looser CJIS keyword match — pairs with content indicators in other engines to cut false positives from casual mentions. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "D${data.zia_dlp_dictionaries.cjis_marking_pattern_medium_confidence.id}.S)"
}

resource "zia_dlp_engines" "cjis_identifier_engine" {
  name                         = "CJIS Identifier Engine"
  description                  = "Structured CJIS identifiers — NCIC ORI, FBI UCN, State ID, NCIC Purpose Code. Any of these appearing in content is a strong signal. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${zia_dlp_dictionaries.ncic_ori_pattern.id}.S OR D${zia_dlp_dictionaries.fbi_ucn_universal_control_number.id}.S OR D${zia_dlp_dictionaries.state_id_number_sid_reference.id}.S OR D${zia_dlp_dictionaries.ncic_purpose_code_pattern.id}.S)"
}

resource "zia_dlp_engines" "criminal_history_rap_sheet_engine" {
  name                         = "Criminal History / RAP Sheet Engine"
  description                  = "RAP-sheet / criminal-history terminology correlated with subject PII (SSN, DL, or DOB) within 500 chars. Suppresses matches on news articles that casually mention arrests. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${zia_dlp_dictionaries.criminal_history_rap_sheet_phrases.id}.S AND (D${zia_dlp_dictionaries.social_security_numbers_us_cjis_prox_500.id}.S OR D${zia_dlp_dictionaries.drivers_license_us_cjis_prox_500.id}.S OR D${zia_dlp_dictionaries.date_of_birth_cjis_prox_500.id}.S))"
}

resource "zia_dlp_engines" "ncic_iii_data_engine" {
  name                         = "NCIC / III Data Engine"
  description                  = "NCIC or III query/response terminology correlated with subject PII — indicates a live CJI data transfer. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${zia_dlp_dictionaries.ncic_iii_query_terminology.id}.S AND (D${zia_dlp_dictionaries.social_security_numbers_us_cjis_prox_500.id}.S OR D${zia_dlp_dictionaries.drivers_license_us_cjis_prox_500.id}.S OR D${zia_dlp_dictionaries.date_of_birth_cjis_prox_500.id}.S))"
}

resource "zia_dlp_engines" "warrant_wanted_person_engine" {
  name                         = "Warrant / Wanted-Person Engine"
  description                  = "Warrant/wanted terminology near subject PII — extradition, bench, arrest warrants referencing a named subject. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${zia_dlp_dictionaries.warrant_wanted_person_phrases.id}.S AND (D${zia_dlp_dictionaries.social_security_numbers_us_cjis_prox_500.id}.S OR D${zia_dlp_dictionaries.drivers_license_us_cjis_prox_500.id}.S OR D${zia_dlp_dictionaries.date_of_birth_cjis_prox_500.id}.S))"
}

resource "zia_dlp_engines" "biometric_cji_engine" {
  name                         = "Biometric CJI Engine"
  description                  = "Biometric identifiers (fingerprint, palm, AFIS, NGI) with CJIS markings or any structured CJIS identifier — indicates fingerprint card or biometric record. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${zia_dlp_dictionaries.biometric_afis_terminology.id}.S AND (D${data.zia_dlp_dictionaries.cjis_marking_pattern_high_confidence.id}.S) OR D${zia_dlp_dictionaries.ncic_ori_pattern.id}.S OR D${zia_dlp_dictionaries.fbi_ucn_universal_control_number.id}.S))"
}

resource "zia_dlp_engines" "nics_firearms_background_engine" {
  name                         = "NICS Firearms Background Engine"
  description                  = "NICS / firearm background-check terminology — ATF Form 4473, NICS denial, prohibited-person language. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "D${zia_dlp_dictionaries.nics_firearms_background_check_phrases.id}.S"
}

resource "zia_dlp_engines" "info_sharing_portal_engine" {
  name                         = "Info-Sharing Portal Engine"
  description                  = "Exfil of N-DEx, LEEP, or Nlets derived content references — info-sharing-system terminology co-occurring with subject identifiers. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${zia_dlp_dictionaries.n_dex_criminal_justice_info_sharing.id}.S AND (D${zia_dlp_dictionaries.social_security_numbers_us_cjis_prox_500.id}.S OR D${zia_dlp_dictionaries.ncic_ori_pattern.id}.S OR D${zia_dlp_dictionaries.fbi_ucn_universal_control_number.id}.S))"
}

resource "zia_dlp_engines" "cjis_any_signal_engine" {
  name                         = "CJIS Any-Signal Engine"
  description                  = "Any strong CJIS signal — explicit markings, structured identifiers, or RAP/NCIC/warrant content engines. Catch-all for broad monitoring. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${data.zia_dlp_dictionaries.cjis_marking_pattern_high_confidence.id}.S) OR D${zia_dlp_dictionaries.law_enforcement_sensitive_les_markings.id}.S OR D${zia_dlp_dictionaries.ncic_ori_pattern.id}.S OR D${zia_dlp_dictionaries.fbi_ucn_universal_control_number.id}.S OR D${zia_dlp_dictionaries.ncic_purpose_code_pattern.id}.S)"
}

