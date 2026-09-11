# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

data "zia_cloud_applications" "apps_ai_ml" {
  policy_type = "cloud_application_policy"
  app_class   = ["AI_ML"]
}

resource "zia_dlp_web_rules" "src_csharp_code_to_ai_block" {
  name                         = "SRC-CSharp Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing C# source code to AI/ML applications (engine SRC-CSharp). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
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
    id = [zia_dlp_engines.src_csharp.id]
  }
}

resource "zia_dlp_web_rules" "src_cplusplus_code_to_ai_block" {
  name                         = "SRC-CPlusPlus Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing C++ source code to AI/ML applications (engine SRC-CPlusPlus). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 1
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
    id = [zia_dlp_engines.src_cplusplus.id]
  }
}

resource "zia_dlp_web_rules" "src_go_code_to_ai_block" {
  name                         = "SRC-Go Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing Go source code to AI/ML applications (engine SRC-Go). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 2
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
    id = [zia_dlp_engines.src_go.id]
  }
}

resource "zia_dlp_web_rules" "src_html_code_to_ai_block" {
  name                         = "SRC-HTML Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing HTML source code to AI/ML applications (engine SRC-HTML). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 3
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
    id = [zia_dlp_engines.src_html.id]
  }
}

resource "zia_dlp_web_rules" "src_java_code_to_ai_block" {
  name                         = "SRC-Java Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing Java source code to AI/ML applications (engine SRC-Java). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 4
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
    id = [zia_dlp_engines.src_java.id]
  }
}

resource "zia_dlp_web_rules" "src_javascript_code_to_ai_block" {
  name                         = "SRC-JavaScript Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing JavaScript source code to AI/ML applications (engine SRC-JavaScript). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 5
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
    id = [zia_dlp_engines.src_javascript.id]
  }
}

resource "zia_dlp_web_rules" "src_kotlin_code_to_ai_block" {
  name                         = "SRC-Kotlin Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing Kotlin source code to AI/ML applications (engine SRC-Kotlin). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 6
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
    id = [zia_dlp_engines.src_kotlin.id]
  }
}

resource "zia_dlp_web_rules" "src_python_code_to_ai_block" {
  name                         = "SRC-Python Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing Python source code to AI/ML applications (engine SRC-Python). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 7
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
    id = [zia_dlp_engines.src_python.id]
  }
}

resource "zia_dlp_web_rules" "src_rust_code_to_ai_block" {
  name                         = "SRC-Rust Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing Rust source code to AI/ML applications (engine SRC-Rust). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 8
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
    id = [zia_dlp_engines.src_rust.id]
  }
}

resource "zia_dlp_web_rules" "src_sql_code_to_ai_block" {
  name                         = "SRC-SQL Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing SQL source code to AI/ML applications (engine SRC-SQL). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 9
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
    id = [zia_dlp_engines.src_sql.id]
  }
}

resource "zia_dlp_web_rules" "src_swift_code_to_ai_block" {
  name                         = "SRC-Swift Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing Swift source code to AI/ML applications (engine SRC-Swift). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 10
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
    id = [zia_dlp_engines.src_swift.id]
  }
}

resource "zia_dlp_web_rules" "src_typescript_code_to_ai_block" {
  name                         = "SRC-TypeScript Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing TypeScript source code to AI/ML applications (engine SRC-TypeScript). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 11
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
    id = [zia_dlp_engines.src_typescript.id]
  }
}

resource "zia_dlp_web_rules" "src_vbnet_code_to_ai_block" {
  name                         = "SRC-VBNet Code to AI-Block"
  description                  = "Inline Web DLP: uploads containing VB.NET source code to AI/ML applications (engine SRC-VBNet). Application scope is resolved from the tenant's AI_ML catalogue at deploy time. One rule per engine so each language has its own incident count and can be enabled, tuned or hardened on its own. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 12
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
    id = [zia_dlp_engines.src_vbnet.id]
  }
}

resource "zia_endpoint_dlp_rules" "src_csharp_code_to_ai_endpoint" {
  name                         = "SRC-CSharp Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-CSharp Code to AI-Block\" (SRC-CSharp). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
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
    id = [zia_dlp_engines.src_csharp.id]
  }
}

resource "zia_casb_dlp_rules" "src_csharp_code_to_ai_saas" {
  name                         = "SRC-CSharp Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-CSharp Code to AI-Block\" (SRC-CSharp). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_csharp.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_csharp_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_csharp_code_to_ai_email" {
  name                         = "SRC-CSharp Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-CSharp Code to AI-Block\" (SRC-CSharp). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_csharp.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_csharp_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_cplusplus_code_to_ai_endpoint" {
  name                         = "SRC-CPlusPlus Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-CPlusPlus Code to AI-Block\" (SRC-CPlusPlus). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_cplusplus.id]
  }
}

resource "zia_casb_dlp_rules" "src_cplusplus_code_to_ai_saas" {
  name                         = "SRC-CPlusPlus Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-CPlusPlus Code to AI-Block\" (SRC-CPlusPlus). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_cplusplus.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_cplusplus_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_cplusplus_code_to_ai_email" {
  name                         = "SRC-CPlusPlus Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-CPlusPlus Code to AI-Block\" (SRC-CPlusPlus). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 1
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_cplusplus.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_cplusplus_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_go_code_to_ai_endpoint" {
  name                         = "SRC-Go Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-Go Code to AI-Block\" (SRC-Go). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_go.id]
  }
}

resource "zia_casb_dlp_rules" "src_go_code_to_ai_saas" {
  name                         = "SRC-Go Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-Go Code to AI-Block\" (SRC-Go). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_go.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_go_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_go_code_to_ai_email" {
  name                         = "SRC-Go Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-Go Code to AI-Block\" (SRC-Go). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_go.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_go_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_html_code_to_ai_endpoint" {
  name                         = "SRC-HTML Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-HTML Code to AI-Block\" (SRC-HTML). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_html.id]
  }
}

resource "zia_casb_dlp_rules" "src_html_code_to_ai_saas" {
  name                         = "SRC-HTML Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-HTML Code to AI-Block\" (SRC-HTML). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_html.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_html_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_html_code_to_ai_email" {
  name                         = "SRC-HTML Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-HTML Code to AI-Block\" (SRC-HTML). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 3
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_html.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_html_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_java_code_to_ai_endpoint" {
  name                         = "SRC-Java Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-Java Code to AI-Block\" (SRC-Java). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_java.id]
  }
}

resource "zia_casb_dlp_rules" "src_java_code_to_ai_saas" {
  name                         = "SRC-Java Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-Java Code to AI-Block\" (SRC-Java). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_java.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_java_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_java_code_to_ai_email" {
  name                         = "SRC-Java Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-Java Code to AI-Block\" (SRC-Java). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 4
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_java.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_java_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_javascript_code_to_ai_endpoint" {
  name                         = "SRC-JavaScript Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-JavaScript Code to AI-Block\" (SRC-JavaScript). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_javascript.id]
  }
}

resource "zia_casb_dlp_rules" "src_javascript_code_to_ai_saas" {
  name                         = "SRC-JavaScript Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-JavaScript Code to AI-Block\" (SRC-JavaScript). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_javascript.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_javascript_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_javascript_code_to_ai_email" {
  name                         = "SRC-JavaScript Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-JavaScript Code to AI-Block\" (SRC-JavaScript). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 5
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_javascript.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_javascript_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_kotlin_code_to_ai_endpoint" {
  name                         = "SRC-Kotlin Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-Kotlin Code to AI-Block\" (SRC-Kotlin). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_kotlin.id]
  }
}

resource "zia_casb_dlp_rules" "src_kotlin_code_to_ai_saas" {
  name                         = "SRC-Kotlin Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-Kotlin Code to AI-Block\" (SRC-Kotlin). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_kotlin.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_kotlin_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_kotlin_code_to_ai_email" {
  name                         = "SRC-Kotlin Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-Kotlin Code to AI-Block\" (SRC-Kotlin). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 6
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_kotlin.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_kotlin_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_python_code_to_ai_endpoint" {
  name                         = "SRC-Python Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-Python Code to AI-Block\" (SRC-Python). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_python.id]
  }
}

resource "zia_casb_dlp_rules" "src_python_code_to_ai_saas" {
  name                         = "SRC-Python Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-Python Code to AI-Block\" (SRC-Python). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_python.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_python_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_python_code_to_ai_email" {
  name                         = "SRC-Python Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-Python Code to AI-Block\" (SRC-Python). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 7
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_python.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_python_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_rust_code_to_ai_endpoint" {
  name                         = "SRC-Rust Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-Rust Code to AI-Block\" (SRC-Rust). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_rust.id]
  }
}

resource "zia_casb_dlp_rules" "src_rust_code_to_ai_saas" {
  name                         = "SRC-Rust Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-Rust Code to AI-Block\" (SRC-Rust). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_rust.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_rust_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_rust_code_to_ai_email" {
  name                         = "SRC-Rust Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-Rust Code to AI-Block\" (SRC-Rust). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_rust.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_rust_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_sql_code_to_ai_endpoint" {
  name                         = "SRC-SQL Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-SQL Code to AI-Block\" (SRC-SQL). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_sql.id]
  }
}

resource "zia_casb_dlp_rules" "src_sql_code_to_ai_saas" {
  name                         = "SRC-SQL Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-SQL Code to AI-Block\" (SRC-SQL). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_sql.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_sql_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_sql_code_to_ai_email" {
  name                         = "SRC-SQL Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-SQL Code to AI-Block\" (SRC-SQL). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 9
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_sql.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_sql_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_swift_code_to_ai_endpoint" {
  name                         = "SRC-Swift Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-Swift Code to AI-Block\" (SRC-Swift). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_swift.id]
  }
}

resource "zia_casb_dlp_rules" "src_swift_code_to_ai_saas" {
  name                         = "SRC-Swift Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-Swift Code to AI-Block\" (SRC-Swift). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_swift.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_swift_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_swift_code_to_ai_email" {
  name                         = "SRC-Swift Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-Swift Code to AI-Block\" (SRC-Swift). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 10
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_swift.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_swift_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_typescript_code_to_ai_endpoint" {
  name                         = "SRC-TypeScript Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-TypeScript Code to AI-Block\" (SRC-TypeScript). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_typescript.id]
  }
}

resource "zia_casb_dlp_rules" "src_typescript_code_to_ai_saas" {
  name                         = "SRC-TypeScript Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-TypeScript Code to AI-Block\" (SRC-TypeScript). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_typescript.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_typescript_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_typescript_code_to_ai_email" {
  name                         = "SRC-TypeScript Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-TypeScript Code to AI-Block\" (SRC-TypeScript). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 11
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_typescript.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_typescript_code_to_ai_email
  }
}

resource "zia_endpoint_dlp_rules" "src_vbnet_code_to_ai_endpoint" {
  name                         = "SRC-VBNet Code to AI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"SRC-VBNet Code to AI-Block\" (SRC-VBNet). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 12
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.src_vbnet.id]
  }
}

resource "zia_casb_dlp_rules" "src_vbnet_code_to_ai_saas" {
  name                         = "SRC-VBNet Code to AI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"SRC-VBNet Code to AI-Block\" (SRC-VBNet). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 12
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.src_vbnet.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_src_vbnet_code_to_ai_saas
  }
}

resource "zia_outbound_email_dlp" "src_vbnet_code_to_ai_email" {
  name                         = "SRC-VBNet Code to AI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"SRC-VBNet Code to AI-Block\" (SRC-VBNet). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_source_code_baseline v4.14] Terraform-managed."
  order                        = var.rule_starting_order + 12
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.src_vbnet.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_src_vbnet_code_to_ai_email
  }
}

