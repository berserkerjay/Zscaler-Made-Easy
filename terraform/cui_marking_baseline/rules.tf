# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

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

resource "zia_endpoint_dlp_rules" "cui_block_marked_documents_endpoint" {
  name                         = "CUI-Block-Marked-Documents [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Block-Marked-Documents\" (CUI-Detect-Block-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
}

resource "zia_casb_dlp_rules" "cui_block_marked_documents_saas" {
  name                         = "CUI-Block-Marked-Documents [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Block-Marked-Documents\" (CUI-Detect-Block-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_block_marked_documents_saas
  }
}

resource "zia_outbound_email_dlp" "cui_block_marked_documents_email" {
  name                         = "CUI-Block-Marked-Documents [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Block-Marked-Documents\" (CUI-Detect-Block-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_block_marked_documents_email
  }
}

resource "zia_endpoint_dlp_rules" "cui_caution_weak_markings_endpoint" {
  name                         = "CUI-Caution-Weak-Markings [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Caution-Weak-Markings\" (CUI-Detect-Caution-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
}

resource "zia_casb_dlp_rules" "cui_caution_weak_markings_saas" {
  name                         = "CUI-Caution-Weak-Markings [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Caution-Weak-Markings\" (CUI-Detect-Caution-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_caution_weak_markings_saas
  }
}

resource "zia_outbound_email_dlp" "cui_caution_weak_markings_email" {
  name                         = "CUI-Caution-Weak-Markings [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Caution-Weak-Markings\" (CUI-Detect-Caution-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_caution_weak_markings_email
  }
}

resource "zia_endpoint_dlp_rules" "cui_monitor_all_endpoint" {
  name                         = "CUI-Monitor-All [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.cui_detect_all.id]
  }
}

resource "zia_casb_dlp_rules" "cui_monitor_all_saas" {
  name                         = "CUI-Monitor-All [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_monitor_all_saas
  }
}

resource "zia_outbound_email_dlp" "cui_monitor_all_email" {
  name                         = "CUI-Monitor-All [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All). Monitor-only; enable after reviewing incidents. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_monitor_all_email
  }
}

