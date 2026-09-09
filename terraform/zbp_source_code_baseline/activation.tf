# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.zbp_dlp_block_source_code_uploads,
    zia_cloud_app_control_rule.zbp_cac_ai_apps_block_file_upload,
    zia_ssl_inspection_rules.zbp_ssl_decrypt_ai_apps,
  ]
}
