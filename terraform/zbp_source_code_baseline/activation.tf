# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.src_dlp_block_source_code_uploads,
    zia_endpoint_dlp_rules.src_dlp_block_source_code_uploads_endpoint,
    zia_casb_dlp_rules.src_dlp_block_source_code_uploads_saas,
    zia_outbound_email_dlp.src_dlp_block_source_code_uploads_email,
  ]
}
