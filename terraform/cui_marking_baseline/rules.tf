# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

data "zia_cloud_applications" "apps_ssl_file_share" {
  policy_type = "cloud_application_ssl_policy"
  app_class   = ["FILE_SHARE"]
}

data "zia_cloud_applications" "apps_ssl_webmail" {
  policy_type = "cloud_application_ssl_policy"
  app_class   = ["WEBMAIL"]
}

data "zia_cloud_applications" "apps_ssl_ai_ml" {
  policy_type = "cloud_application_ssl_policy"
  app_class   = ["AI_ML"]
}

data "zia_cloud_applications" "apps_ai_ml" {
  policy_type = "cloud_application_policy"
  app_class   = ["AI_ML"]
}

data "zia_cloud_app_control_rule_actions" "cui_cac_ai_no_upload_actions" {
  type       = "AI_ML"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
}

resource "zia_dlp_web_rules" "cui_block_marked_documents" {
  name                         = "CUI-Block-Marked-Documents"
  description                  = "Inline Web DLP: block uploads carrying high-precision CUI markings (banners, category tokens, legacy FOUO/LES/SBU, distribution statements) via CUI-Detect-Block-Grade. Ships DISABLED at INFO; enable after reviewing monitor incidents from CUI-Monitor-All. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
}

resource "zia_dlp_web_rules" "cui_caution_weak_markings" {
  name                         = "CUI-Caution-Weak-Markings"
  description                  = "Inline Web DLP: caution (user must confirm) on lower-precision CUI signals: bare CUI, standalone LDCs, malformed markings, designation blocks, via CUI-Detect-Caution-Grade. Never BLOCK on these. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "CONFIRM"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
}

resource "zia_dlp_web_rules" "cui_monitor_all" {
  name                         = "CUI-Monitor-All"
  description                  = "Inline Web DLP: monitor-only rule over the full CUI-Detect-All surface. Enable this first to size incident volume and tune before enabling the block and caution rules above it. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
}

resource "zia_ssl_inspection_rules" "cui_ssl_decrypt_file_share_webmail_ai" {
  name                         = "CUI-SSL-Decrypt-File-Share-Webmail-AI"
  description                  = "SSL Inspection: decrypt file-sharing, webmail and AI/ML applications so CUI markings inside HTTPS uploads can be inspected. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  platforms                    = ["SCAN_WINDOWS", "SCAN_MACOS", "SCAN_LINUX", "SCAN_IOS", "SCAN_ANDROID", "NO_CLIENT_CONNECTOR"]
  road_warrior_for_kerberos    = true
  cloud_applications           = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ssl_file_share.applications : a.app], [for a in data.zia_cloud_applications.apps_ssl_webmail.applications : a.app], [for a in data.zia_cloud_applications.apps_ssl_ai_ml.applications : a.app])))
  action {
    type                   = "DECRYPT"
    override_default_certificate = false
    ssl_interception_cert {
      id                     = 1
    }
    decrypt_sub_actions {
      server_certificates    = "ALLOW"
      ocsp_check             = true
      block_ssl_traffic_with_no_sni_enabled = false
      min_client_tls_version = "CLIENT_TLS_1_2"
      min_server_tls_version = "SERVER_TLS_1_2"
      block_undecrypt        = false
      http2_enabled          = true
    }
  }
}

resource "zia_cloud_app_control_rule" "cui_cac_ai_no_upload" {
  name                         = "CUI-CAC-AI-No-Upload"
  description                  = "Cloud App Control: on AI & ML applications allow browsing but block upload and file submission, so marked documents cannot be pasted into public models regardless of content inspection. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "AI_ML"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.cui_cac_ai_no_upload_actions.available_actions_without_isolate : a if (anytrue([for v in ["_UPLOAD"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

