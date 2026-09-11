# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.src_dlp_block_source_code_uploads,
    zia_endpoint_dlp_rules.src_dlp_block_source_code_uploads_endpoint,
    zia_casb_dlp_rules.src_dlp_block_source_code_uploads_saas,
    zia_outbound_email_dlp.src_dlp_block_source_code_uploads_email,
    zia_endpoint_dlp_rules.src_csharp_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_cplusplus_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_go_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_html_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_java_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_javascript_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_kotlin_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_python_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_rust_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_sql_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_swift_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_typescript_endpoint_removable_media,
    zia_endpoint_dlp_rules.src_vbnet_endpoint_removable_media,
  ]
}
