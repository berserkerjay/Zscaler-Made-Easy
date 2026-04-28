# ──────────────────────────────────────────────────────────────
# CJIS Engines — 10 composite engines
# ──────────────────────────────────────────────────────────────
# Engine expressions reference dictionaries by Terraform resource
# ID (D<id>.S) — no symbolic D:<name> resolution needed because
# Terraform manages the dependency graph.
#
# Locals for PII sub-expression: reused across multiple engines
# to avoid repeating the SSN/DL/DOB OR-chain everywhere.
# ──────────────────────────────────────────────────────────────

locals {
  pii_or = "(D${zia_dlp_dictionaries.ssn_cjis.id}.S OR D${zia_dlp_dictionaries.dl_cjis.id}.S OR D${zia_dlp_dictionaries.dob_cjis.id}.S)"
}

resource "zia_dlp_engines" "markings_high" {
  name              = "CJIS Markings High Confidence"
  description       = "Explicit CJIS / CHRI / LES banner or portion markings."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.cjis_marking_high.id}.S OR D${zia_dlp_dictionaries.les_markings.id}.S)"
}

resource "zia_dlp_engines" "markings_medium" {
  name              = "CJIS Markings Medium Confidence"
  description       = "Looser CJIS keyword match — pairs with content indicators."
  custom_dlp_engine = true
  engine_expression = "D${zia_dlp_dictionaries.cjis_marking_medium.id}.S"
}

resource "zia_dlp_engines" "identifiers" {
  name              = "CJIS Identifier Engine"
  description       = "Structured CJIS identifiers — ORI, FBI UCN, SID, Purpose Code."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.ncic_ori.id}.S OR D${zia_dlp_dictionaries.fbi_ucn.id}.S OR D${zia_dlp_dictionaries.sid.id}.S OR D${zia_dlp_dictionaries.ncic_purpose_code.id}.S)"
}

resource "zia_dlp_engines" "criminal_history" {
  name              = "Criminal History / RAP Sheet Engine"
  description       = "RAP-sheet terminology correlated with subject PII within 500 chars."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.criminal_history.id}.S AND ${local.pii_or})"
}

resource "zia_dlp_engines" "ncic_iii" {
  name              = "NCIC / III Data Engine"
  description       = "NCIC or III query/response terminology correlated with PII."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.ncic_iii.id}.S AND ${local.pii_or})"
}

resource "zia_dlp_engines" "warrants" {
  name              = "Warrant / Wanted-Person Engine"
  description       = "Warrant/wanted terminology near subject PII."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.warrants.id}.S AND ${local.pii_or})"
}

resource "zia_dlp_engines" "biometric" {
  name              = "Biometric CJI Engine"
  description       = "Biometric identifiers with CJIS markings or structured identifiers."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.biometric.id}.S AND (D${zia_dlp_dictionaries.cjis_marking_high.id}.S OR D${zia_dlp_dictionaries.ncic_ori.id}.S OR D${zia_dlp_dictionaries.fbi_ucn.id}.S))"
}

resource "zia_dlp_engines" "nics" {
  name              = "NICS Firearms Background Engine"
  description       = "NICS / firearm background-check terminology."
  custom_dlp_engine = true
  engine_expression = "D${zia_dlp_dictionaries.nics.id}.S"
}

resource "zia_dlp_engines" "info_sharing" {
  name              = "Info-Sharing Portal Engine"
  description       = "N-DEx, LEEP, Nlets content with subject identifiers."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.ndex.id}.S AND (D${zia_dlp_dictionaries.ssn_cjis.id}.S OR D${zia_dlp_dictionaries.ncic_ori.id}.S OR D${zia_dlp_dictionaries.fbi_ucn.id}.S))"
}

resource "zia_dlp_engines" "any_signal" {
  name              = "CJIS Any-Signal Engine"
  description       = "Any strong CJIS signal — markings or structured identifiers. Catch-all."
  custom_dlp_engine = true
  engine_expression = "(D${zia_dlp_dictionaries.cjis_marking_high.id}.S OR D${zia_dlp_dictionaries.les_markings.id}.S OR D${zia_dlp_dictionaries.ncic_ori.id}.S OR D${zia_dlp_dictionaries.fbi_ucn.id}.S OR D${zia_dlp_dictionaries.ncic_purpose_code.id}.S)"
}
