# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.bank_payment_card_data_monitor,
    zia_dlp_web_rules.bank_payment_card_data_bulk_block,
    zia_dlp_web_rules.bank_payment_instructions_monitor,
    zia_dlp_web_rules.bank_customer_pii_monitor,
    zia_dlp_web_rules.bank_customer_pii_bulk_block,
    zia_dlp_web_rules.bank_customer_records_monitor,
    zia_dlp_web_rules.bank_mnpi_monitor,
    zia_dlp_web_rules.bank_confidential_markings_monitor,
    zia_dlp_web_rules.bank_credentials_monitor,
    zia_endpoint_dlp_rules.bank_endpoint_monitor,
    zia_endpoint_dlp_rules.bank_endpoint_bulk_block_usb,
    zia_casb_dlp_rules.bank_saas_file_monitor,
    zia_outbound_email_dlp.bank_email_monitor,
  ]
}
