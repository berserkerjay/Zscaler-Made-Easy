# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_endpoint_dlp_rules.zbp_sensitive_data_to_usb,
    zia_endpoint_dlp_sub_rules.zbp_pci_high_usb_block,
    zia_endpoint_dlp_sub_rules.zbp_pci_medium_usb,
    zia_endpoint_dlp_sub_rules.zbp_pci_low_usb,
    zia_endpoint_dlp_rules.zbp_unapproved_genai_applications,
    zia_endpoint_dlp_sub_rules.zbp_genai_application_block,
    zia_endpoint_dlp_sub_rules.zbp_genai_application_monitor,
    zia_endpoint_dlp_rules.zbp_sensitive_data_private_share,
  ]
}
