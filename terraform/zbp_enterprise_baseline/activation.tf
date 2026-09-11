# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.zbp_financial_information_monitor,
    zia_dlp_web_rules.zbp_itar_international_traffic_in_arms_regulations_monitor,
    zia_dlp_web_rules.zbp_traffic_light_protocol_monitor,
    zia_dlp_web_rules.zbp_us_pii_monitor,
    zia_dlp_web_rules.zbp_us_phi_monitor,
    zia_dlp_web_rules.zbp_private_keys_monitor,
    zia_endpoint_dlp_rules.zbp_financial_information_endpoint,
    zia_casb_dlp_rules.zbp_financial_information_saas,
    zia_outbound_email_dlp.zbp_financial_information_email,
    zia_endpoint_dlp_rules.zbp_itar_international_traffic_in_arms_regulations_endpoint,
    zia_casb_dlp_rules.zbp_itar_international_traffic_in_arms_regulations_saas,
    zia_outbound_email_dlp.zbp_itar_international_traffic_in_arms_regulations_email,
    zia_endpoint_dlp_rules.zbp_traffic_light_protocol_endpoint,
    zia_casb_dlp_rules.zbp_traffic_light_protocol_saas,
    zia_outbound_email_dlp.zbp_traffic_light_protocol_email,
    zia_endpoint_dlp_rules.zbp_us_pii_endpoint,
    zia_casb_dlp_rules.zbp_us_pii_saas,
    zia_outbound_email_dlp.zbp_us_pii_email,
    zia_endpoint_dlp_rules.zbp_us_phi_endpoint,
    zia_casb_dlp_rules.zbp_us_phi_saas,
    zia_outbound_email_dlp.zbp_us_phi_email,
    zia_endpoint_dlp_rules.zbp_private_keys_endpoint,
    zia_casb_dlp_rules.zbp_private_keys_saas,
    zia_outbound_email_dlp.zbp_private_keys_email,
    zia_endpoint_dlp_rules.zbp_financial_information_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_itar_phrases_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_tlp_red_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_tlp_amber_strict_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_tlp_amber_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_us_pii_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_us_phi_medium_confidence_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_us_phi_high_confidence_endpoint_removable_media,
    zia_endpoint_dlp_rules.zbp_private_keys_endpoint_removable_media,
  ]
}
