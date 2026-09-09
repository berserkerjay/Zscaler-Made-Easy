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
    zia_outbound_email_dlp.zbp_email_monitor,
  ]
}
