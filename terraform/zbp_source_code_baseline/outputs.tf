output "dictionaries" {
  value = { for k, r in {
    zbp_python_code_detection = zia_dlp_dictionaries.zbp_python_code_detection
    zbp_javascript_code_detection = zia_dlp_dictionaries.zbp_javascript_code_detection
    zbp_shell_script_detection = zia_dlp_dictionaries.zbp_shell_script_detection
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    zbp_python_code_detection_engine = zia_dlp_engines.zbp_python_code_detection_engine
    zbp_javascript_code_detection_engine = zia_dlp_engines.zbp_javascript_code_detection_engine
    zbp_shell_script_detection_engine = zia_dlp_engines.zbp_shell_script_detection_engine
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.zbp_dlp_block_source_code_uploads.name,
    zia_cloud_app_control_rule.zbp_cac_ai_apps_block_file_upload.name,
    zia_ssl_inspection_rules.zbp_ssl_decrypt_ai_apps.name,
  ]
}
