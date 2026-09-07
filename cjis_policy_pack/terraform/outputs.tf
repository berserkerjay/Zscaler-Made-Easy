# ── Resource IDs for downstream consumption ─────────────────

output "dictionary_ids" {
  description = "Map of dictionary resource names to ZIA IDs"
  value = {
    cjis_marking_high  = zia_dlp_dictionaries.cjis_marking_high.id
    cjis_marking_medium = zia_dlp_dictionaries.cjis_marking_medium.id
    les_markings       = zia_dlp_dictionaries.les_markings.id
    ncic_ori           = zia_dlp_dictionaries.ncic_ori.id
    fbi_ucn            = zia_dlp_dictionaries.fbi_ucn.id
    sid                = zia_dlp_dictionaries.sid.id
    ncic_purpose_code  = zia_dlp_dictionaries.ncic_purpose_code.id
    criminal_history   = zia_dlp_dictionaries.criminal_history.id
    ncic_iii           = zia_dlp_dictionaries.ncic_iii.id
    warrants           = zia_dlp_dictionaries.warrants.id
    biometric          = zia_dlp_dictionaries.biometric.id
    nics               = zia_dlp_dictionaries.nics.id
    ndex               = zia_dlp_dictionaries.ndex.id
    dob_cjis           = zia_dlp_dictionaries.dob_cjis.id
    ssn_cjis           = zia_dlp_dictionaries.ssn_cjis.id
    dl_cjis            = zia_dlp_dictionaries.dl_cjis.id
  }
}

output "engine_ids" {
  description = "Map of engine resource names to ZIA IDs"
  value = {
    markings_high   = zia_dlp_engines.markings_high.id
    markings_medium = zia_dlp_engines.markings_medium.id
    identifiers     = zia_dlp_engines.identifiers.id
    criminal_history = zia_dlp_engines.criminal_history.id
    ncic_iii        = zia_dlp_engines.ncic_iii.id
    warrants        = zia_dlp_engines.warrants.id
    biometric       = zia_dlp_engines.biometric.id
    nics            = zia_dlp_engines.nics.id
    info_sharing    = zia_dlp_engines.info_sharing.id
    any_signal      = zia_dlp_engines.any_signal.id
  }
}

output "policy_ids" {
  description = "Map of policy resource names to ZIA IDs"
  value = {
    cjis_markings    = zia_dlp_web_rules.cjis_markings.id
    cjis_identifiers = zia_dlp_web_rules.cjis_identifiers.id
    criminal_history = zia_dlp_web_rules.criminal_history.id
    ncic_iii         = zia_dlp_web_rules.ncic_iii.id
    warrants         = zia_dlp_web_rules.warrants.id
    biometric        = zia_dlp_web_rules.biometric.id
    nics             = zia_dlp_web_rules.nics.id
    info_sharing     = zia_dlp_web_rules.info_sharing.id
    any_signal       = zia_dlp_web_rules.any_signal.id
  }
}

output "policy_action" {
  description = "Current policy action (ALLOW=monitor, BLOCK=enforce)"
  value       = var.policy_action
}
