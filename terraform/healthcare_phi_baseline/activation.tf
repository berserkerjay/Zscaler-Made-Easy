# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.r_healthcare_phi_mrn_acct_dob,
    zia_ssl_inspection_rules.r_phi_ssl_decrypt_file_share_webmail_ai,
    zia_cloud_app_control_rule.r_phi_cac_file_share_no_upload,
    zia_cloud_app_control_rule.r_phi_cac_webmail_no_send,
    zia_cloud_app_control_rule.r_phi_cac_ai_no_upload,
    zia_file_type_control_rules.r_phi_ftc_block_bulk_export_upload,
    zia_file_type_control_rules.r_phi_ftc_caution_image_upload,
    zia_url_filtering_rules.r_phi_url_block_post_to_unknown,
  ]
}
