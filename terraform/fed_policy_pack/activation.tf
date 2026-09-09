# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.z_atomic_energy_act_monitor,
    zia_dlp_web_rules.z_financial_information_monitor,
    zia_dlp_web_rules.z_for_official_use_only_markings_monitor,
    zia_dlp_web_rules.z_itar_international_traffic_in_arms_regulations_monitor,
    zia_dlp_web_rules.z_standard_forms_monitor,
    zia_dlp_web_rules.z_traffic_light_protocol_monitor,
    zia_dlp_web_rules.z_us_pii_monitor,
    zia_dlp_web_rules.z_us_phi_monitor,
    zia_dlp_web_rules.z_controlled_unclassified_information_monitor,
    zia_dlp_web_rules.z_private_keys_monitor,
    zia_endpoint_dlp_rules.z_fed_endpoint_monitor,
    zia_casb_dlp_rules.z_fed_saas_file_monitor,
    zia_outbound_email_dlp.z_fed_email_monitor,
  ]
}
