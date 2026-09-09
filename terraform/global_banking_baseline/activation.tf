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
    zia_ssl_inspection_rules.bank_ssl_decrypt_file_share_webmail_ai,
    zia_cloud_app_control_rule.bank_cac_file_share_no_upload,
    zia_cloud_app_control_rule.bank_cac_webmail_no_send,
    zia_cloud_app_control_rule.bank_cac_ai_no_upload,
    zia_file_type_control_rules.bank_ftc_block_bulk_export_upload,
    zia_url_filtering_rules.bank_url_block_post_to_unknown,
  ]
}
