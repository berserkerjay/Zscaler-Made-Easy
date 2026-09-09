# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.z_cjis_markings_monitor,
    zia_dlp_web_rules.z_cjis_identifier_monitor,
    zia_dlp_web_rules.z_cjis_criminal_history_monitor,
    zia_dlp_web_rules.z_cjis_ncic_iii_data_monitor,
    zia_dlp_web_rules.z_cjis_warrants_monitor,
    zia_dlp_web_rules.z_cjis_biometric_monitor,
    zia_dlp_web_rules.z_cjis_nics_firearms_monitor,
    zia_dlp_web_rules.z_cjis_info_sharing_monitor,
    zia_dlp_web_rules.z_cjis_any_signal_monitor,
    zia_endpoint_dlp_rules.z_cjis_endpoint_monitor,
    zia_casb_dlp_rules.z_cjis_saas_file_monitor,
    zia_casb_dlp_rules.z_cjis_saas_collaboration_monitor,
    zia_outbound_email_dlp.z_cjis_email_monitor,
  ]
}
