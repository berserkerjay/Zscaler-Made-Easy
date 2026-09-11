# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

data "zia_cloud_applications" "apps_ai_ml" {
  policy_type = "cloud_application_policy"
  app_class   = ["AI_ML"]
}

resource "zia_dlp_web_rules" "src_dlp_block_source_code_uploads" {
  name                         = "SRC-[DLP] Block Source Code Uploads"
  description                  = "Blocks uploads containing Python, JavaScript, or shell-script source code to AI/ML applications. Application scope is resolved from the tenant's AI_ML catalogue at deploy time. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  # Ships monitor-only; the designed action once incidents are tuned is BLOCK.
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

resource "zia_endpoint_dlp_rules" "src_dlp_block_source_code_uploads_endpoint" {
  name                         = "SRC-[DLP] Block Source Code Uploads [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-[DLP] Block Source Code Uploads\" (SRC-CSharp, SRC-CPlusPlus, SRC-Go, SRC-HTML, SRC-Java, SRC-JavaScript, SRC-Kotlin, SRC-Python, SRC-Rust, SRC-SQL, SRC-Swift, SRC-TypeScript, SRC-VBNet). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_csharp.id, zia_dlp_engines.src_cplusplus.id, zia_dlp_engines.src_go.id, zia_dlp_engines.src_html.id, zia_dlp_engines.src_java.id, zia_dlp_engines.src_javascript.id, zia_dlp_engines.src_kotlin.id, zia_dlp_engines.src_python.id, zia_dlp_engines.src_rust.id, zia_dlp_engines.src_sql.id, zia_dlp_engines.src_swift.id, zia_dlp_engines.src_typescript.id, zia_dlp_engines.src_vbnet.id]
  }
}

resource "zia_casb_dlp_rules" "src_dlp_block_source_code_uploads_saas" {
  name                         = "SRC-[DLP] Block Source Code Uploads [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-[DLP] Block Source Code Uploads\" (SRC-CSharp, SRC-CPlusPlus, SRC-Go, SRC-HTML, SRC-Java, SRC-JavaScript, SRC-Kotlin, SRC-Python, SRC-Rust, SRC-SQL, SRC-Swift, SRC-TypeScript, SRC-VBNet). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_csharp.id, zia_dlp_engines.src_cplusplus.id, zia_dlp_engines.src_go.id, zia_dlp_engines.src_html.id, zia_dlp_engines.src_java.id, zia_dlp_engines.src_javascript.id, zia_dlp_engines.src_kotlin.id, zia_dlp_engines.src_python.id, zia_dlp_engines.src_rust.id, zia_dlp_engines.src_sql.id, zia_dlp_engines.src_swift.id, zia_dlp_engines.src_typescript.id, zia_dlp_engines.src_vbnet.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_dlp_block_source_code_uploads_saas
  }
}

resource "zia_outbound_email_dlp" "src_dlp_block_source_code_uploads_email" {
  name                         = "SRC-[DLP] Block Source Code Uploads [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-[DLP] Block Source Code Uploads\" (SRC-CSharp, SRC-CPlusPlus, SRC-Go, SRC-HTML, SRC-Java, SRC-JavaScript, SRC-Kotlin, SRC-Python, SRC-Rust, SRC-SQL, SRC-Swift, SRC-TypeScript, SRC-VBNet). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_csharp.id, zia_dlp_engines.src_cplusplus.id, zia_dlp_engines.src_go.id, zia_dlp_engines.src_html.id, zia_dlp_engines.src_java.id, zia_dlp_engines.src_javascript.id, zia_dlp_engines.src_kotlin.id, zia_dlp_engines.src_python.id, zia_dlp_engines.src_rust.id, zia_dlp_engines.src_sql.id, zia_dlp_engines.src_swift.id, zia_dlp_engines.src_typescript.id, zia_dlp_engines.src_vbnet.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_dlp_block_source_code_uploads_email
  }
}

