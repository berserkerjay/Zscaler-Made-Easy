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
    zia_dlp_web_rules.z_cjis_markings_medium_confidence_monitor,
    zia_endpoint_dlp_rules.z_cjis_markings_endpoint,
    zia_casb_dlp_rules.z_cjis_markings_saas,
    zia_outbound_email_dlp.z_cjis_markings_email,
    zia_endpoint_dlp_rules.z_cjis_identifier_endpoint,
    zia_casb_dlp_rules.z_cjis_identifier_saas,
    zia_outbound_email_dlp.z_cjis_identifier_email,
    zia_endpoint_dlp_rules.z_cjis_criminal_history_endpoint,
    zia_casb_dlp_rules.z_cjis_criminal_history_saas,
    zia_outbound_email_dlp.z_cjis_criminal_history_email,
    zia_endpoint_dlp_rules.z_cjis_ncic_iii_data_endpoint,
    zia_casb_dlp_rules.z_cjis_ncic_iii_data_saas,
    zia_outbound_email_dlp.z_cjis_ncic_iii_data_email,
    zia_endpoint_dlp_rules.z_cjis_warrants_endpoint,
    zia_casb_dlp_rules.z_cjis_warrants_saas,
    zia_outbound_email_dlp.z_cjis_warrants_email,
    zia_endpoint_dlp_rules.z_cjis_biometric_endpoint,
    zia_casb_dlp_rules.z_cjis_biometric_saas,
    zia_outbound_email_dlp.z_cjis_biometric_email,
    zia_endpoint_dlp_rules.z_cjis_nics_firearms_endpoint,
    zia_casb_dlp_rules.z_cjis_nics_firearms_saas,
    zia_outbound_email_dlp.z_cjis_nics_firearms_email,
    zia_endpoint_dlp_rules.z_cjis_info_sharing_endpoint,
    zia_casb_dlp_rules.z_cjis_info_sharing_saas,
    zia_outbound_email_dlp.z_cjis_info_sharing_email,
    zia_endpoint_dlp_rules.z_cjis_any_signal_endpoint,
    zia_casb_dlp_rules.z_cjis_any_signal_saas,
    zia_outbound_email_dlp.z_cjis_any_signal_email,
    zia_endpoint_dlp_rules.z_cjis_markings_medium_confidence_endpoint,
    zia_casb_dlp_rules.z_cjis_markings_medium_confidence_saas,
    zia_outbound_email_dlp.z_cjis_markings_medium_confidence_email,
  ]
}
