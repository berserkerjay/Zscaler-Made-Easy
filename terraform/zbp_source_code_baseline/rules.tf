# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

data "zia_cloud_applications" "apps_ai_ml" {
  policy_type = "cloud_application_policy"
  app_class   = ["AI_ML"]
}

resource "zia_dlp_web_rules" "zbp_dlp_block_source_code_uploads" {
  name                         = "ZBP-[DLP] Block Source Code Uploads"
  description                  = "Blocks uploads containing Python, JavaScript, or shell-script source code to AI/ML applications. Application scope is resolved from the tenant's AI_ML catalogue at deploy time. [DLP-Check baseline zbp_source_code_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_javascript_code_detection_engine.id, zia_dlp_engines.zbp_python_code_detection_engine.id, zia_dlp_engines.zbp_shell_script_detection_engine.id]
  }
}

