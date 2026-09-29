# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.zbp_financial_information_monitor,
    zia_dlp_web_rules.zbp_itar_international_traffic_in_arms_regulations_monitor,
    zia_dlp_web_rules.zbp_tlp_red_monitor,
    zia_dlp_web_rules.zbp_tlp_amber_strict_monitor,
    zia_dlp_web_rules.zbp_tlp_amber_monitor,
    zia_dlp_web_rules.zbp_us_pii_monitor,
    zia_dlp_web_rules.zbp_us_phi_medium_confidence_monitor,
    zia_dlp_web_rules.zbp_us_phi_high_confidence_monitor,
    zia_dlp_web_rules.zbp_private_keys_monitor,
    zia_endpoint_dlp_rules.zbp_financial_information_endpoint,
    zia_casb_dlp_rules.zbp_financial_informatio_saas,
    zia_outbound_email_dlp.zbp_financial_information_email,
    zia_endpoint_dlp_rules.zbp_itar_international_traffic_in_arms_regulations_endpoint,
    zia_casb_dlp_rules.zbp_itar_international_saas,
    zia_outbound_email_dlp.zbp_itar_international_traffic_in_arms_regulations_email,
    zia_endpoint_dlp_rules.zbp_tlp_red_endpoint,
    zia_casb_dlp_rules.zbp_tlp_red_saas,
    zia_outbound_email_dlp.zbp_tlp_red_email,
    zia_endpoint_dlp_rules.zbp_tlp_amber_strict_endpoint,
    zia_casb_dlp_rules.zbp_tlp_amber_strict_saas,
    zia_outbound_email_dlp.zbp_tlp_amber_strict_email,
    zia_endpoint_dlp_rules.zbp_tlp_amber_endpoint,
    zia_casb_dlp_rules.zbp_tlp_amber_saas,
    zia_outbound_email_dlp.zbp_tlp_amber_email,
    zia_endpoint_dlp_rules.zbp_us_pii_endpoint,
    zia_casb_dlp_rules.zbp_us_pii_saas,
    zia_outbound_email_dlp.zbp_us_pii_email,
    zia_endpoint_dlp_rules.zbp_us_phi_medium_confidence_endpoint,
    zia_casb_dlp_rules.zbp_us_phi_medium_saas,
    zia_outbound_email_dlp.zbp_us_phi_medium_confidence_email,
    zia_endpoint_dlp_rules.zbp_us_phi_high_confidence_endpoint,
    zia_casb_dlp_rules.zbp_us_phi_high_saas,
    zia_outbound_email_dlp.zbp_us_phi_high_confidence_email,
    zia_endpoint_dlp_rules.zbp_private_keys_endpoint,
    zia_casb_dlp_rules.zbp_private_keys_saas,
    zia_outbound_email_dlp.zbp_private_keys_email,
  ]
}
