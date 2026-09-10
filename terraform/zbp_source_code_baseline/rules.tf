# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

data "zia_cloud_applications" "apps_ai_ml" {
  policy_type = "cloud_application_policy"
  app_class   = ["AI_ML"]
}

data "zia_cloud_app_control_rule_actions" "src_cac_ai_apps_block_file_upload_actions" {
  type       = "AI_ML"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
}

data "zia_cloud_applications" "apps_ssl_ai_ml" {
  policy_type = "cloud_application_ssl_policy"
  app_class   = ["AI_ML"]
}

resource "zia_dlp_web_rules" "src_dlp_block_source_code_uploads" {
  name                         = "SRC-[DLP] Block Source Code Uploads"
  description                  = "Blocks uploads containing Python, JavaScript, or shell-script source code to AI/ML applications. Application scope is resolved from the tenant's AI_ML catalogue at deploy time. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  cloud_applications           = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
  lifecycle {
    precondition {
      condition     = length(sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))) > 0
      error_message = "No cloud applications of class AI_ML resolved on this tenant; set cloud_applications explicitly."
    }
  }
  dlp_engines {
    id = [zia_dlp_engines.src_csharp.id, zia_dlp_engines.src_cplusplus.id, zia_dlp_engines.src_go.id, zia_dlp_engines.src_html.id, zia_dlp_engines.src_java.id, zia_dlp_engines.src_javascript.id, zia_dlp_engines.src_kotlin.id, zia_dlp_engines.src_python.id, zia_dlp_engines.src_rust.id, zia_dlp_engines.src_sql.id, zia_dlp_engines.src_swift.id, zia_dlp_engines.src_typescript.id, zia_dlp_engines.src_vbnet.id]
  }
}

resource "zia_cloud_app_control_rule" "src_cac_ai_apps_block_file_upload" {
  name                         = "SRC-[CAC] AI Apps: Block File Upload"
  description                  = "Cloud App Control: on AI & ML applications, allow browsing and prompts but block file upload regardless of content. The containment layer in front of the DLP rule above. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "AI_ML"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.src_cac_ai_apps_block_file_upload_actions.available_actions_without_isolate : a if (anytrue([for v in ["_UPLOAD"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_ssl_inspection_rules" "src_ssl_decrypt_ai_apps" {
  name                         = "SRC-[SSL] Decrypt AI Apps"
  description                  = "SSL Inspection: decrypt traffic to AI & ML applications so the source-code DLP rule can inspect uploads. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  platforms                    = ["SCAN_WINDOWS", "SCAN_MACOS", "SCAN_LINUX", "SCAN_IOS", "SCAN_ANDROID", "NO_CLIENT_CONNECTOR"]
  road_warrior_for_kerberos    = true
  cloud_applications           = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ssl_ai_ml.applications : a.app])))
  # not in the zscaler/zia provider schema (set in the Admin Portal if needed): action.ssl_interception_cert.default_certificate = true
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

