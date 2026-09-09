output "dictionaries" {
  value = { for k, r in {
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    pci_high = zia_dlp_engines.pci_high
    pci_medium = zia_dlp_engines.pci_medium
    pci_low = zia_dlp_engines.pci_low
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_endpoint_dlp_rules.zbp_sensitive_data_to_usb.name,
    zia_endpoint_dlp_sub_rules.zbp_pci_high_usb_block.name,
    zia_endpoint_dlp_sub_rules.zbp_pci_medium_usb.name,
    zia_endpoint_dlp_sub_rules.zbp_pci_low_usb.name,
    zia_endpoint_dlp_rules.zbp_unapproved_genai_applications.name,
    zia_endpoint_dlp_sub_rules.zbp_genai_application_block.name,
    zia_endpoint_dlp_sub_rules.zbp_genai_application_monitor.name,
    zia_endpoint_dlp_rules.zbp_sensitive_data_private_share.name,
  ]
}
