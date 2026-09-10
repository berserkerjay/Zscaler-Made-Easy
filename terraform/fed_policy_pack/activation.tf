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
    zia_endpoint_dlp_rules.z_atomic_energy_act_endpoint,
    zia_casb_dlp_rules.z_atomic_energy_act_saas,
    zia_outbound_email_dlp.z_atomic_energy_act_email,
    zia_endpoint_dlp_rules.z_financial_information_endpoint,
    zia_casb_dlp_rules.z_financial_information_saas,
    zia_outbound_email_dlp.z_financial_information_email,
    zia_endpoint_dlp_rules.z_for_official_use_only_markings_endpoint,
    zia_casb_dlp_rules.z_for_official_use_only_markings_saas,
    zia_outbound_email_dlp.z_for_official_use_only_markings_email,
    zia_endpoint_dlp_rules.z_itar_international_traffic_in_arms_regulations_endpoint,
    zia_casb_dlp_rules.z_itar_international_traffic_in_arms_regulations_saas,
    zia_outbound_email_dlp.z_itar_international_traffic_in_arms_regulations_email,
    zia_endpoint_dlp_rules.z_standard_forms_endpoint,
    zia_casb_dlp_rules.z_standard_forms_saas,
    zia_outbound_email_dlp.z_standard_forms_email,
    zia_endpoint_dlp_rules.z_traffic_light_protocol_endpoint,
    zia_casb_dlp_rules.z_traffic_light_protocol_saas,
    zia_outbound_email_dlp.z_traffic_light_protocol_email,
    zia_endpoint_dlp_rules.z_us_pii_endpoint,
    zia_casb_dlp_rules.z_us_pii_saas,
    zia_outbound_email_dlp.z_us_pii_email,
    zia_endpoint_dlp_rules.z_us_phi_endpoint,
    zia_casb_dlp_rules.z_us_phi_saas,
    zia_outbound_email_dlp.z_us_phi_email,
    zia_endpoint_dlp_rules.z_controlled_unclassified_information_endpoint,
    zia_casb_dlp_rules.z_controlled_unclassified_information_saas,
    zia_outbound_email_dlp.z_controlled_unclassified_information_email,
    zia_endpoint_dlp_rules.z_private_keys_endpoint,
    zia_casb_dlp_rules.z_private_keys_saas,
    zia_outbound_email_dlp.z_private_keys_email,
  ]
}
