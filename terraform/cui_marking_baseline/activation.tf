# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.cui_block_marked_documents,
    zia_dlp_web_rules.cui_caution_weak_markings,
    zia_dlp_web_rules.cui_monitor_all,
    zia_ssl_inspection_rules.cui_ssl_decrypt_file_share_webmail_ai,
    zia_cloud_app_control_rule.cui_cac_ai_no_upload,
  ]
}
