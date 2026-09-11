# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "zbp_financial_information_monitor" {
  name                         = "ZBP-Financial Information-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
}

resource "zia_dlp_web_rules" "zbp_itar_international_traffic_in_arms_regulations_monitor" {
  name                         = "ZBP-ITAR International Traffic in Arms Regulations-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_itar_phrases.id]
  }
}

resource "zia_dlp_web_rules" "zbp_tlp_red_monitor" {
  name                         = "ZBP-TLP Red-Monitor"
  description                  = "One rule per engine: this rule carries ZBP-TLP Red only. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_red.id]
  }
}

resource "zia_dlp_web_rules" "zbp_tlp_amber_strict_monitor" {
  name                         = "ZBP-TLP Amber Strict-Monitor"
  description                  = "One rule per engine: this rule carries ZBP-TLP Amber Strict only. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_amber_strict.id]
  }
}

resource "zia_dlp_web_rules" "zbp_tlp_amber_monitor" {
  name                         = "ZBP-TLP Amber-Monitor"
  description                  = "One rule per engine: this rule carries ZBP-TLP Amber only. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_amber.id]
  }
}

resource "zia_dlp_web_rules" "zbp_us_pii_monitor" {
  name                         = "ZBP-US PII-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
}

resource "zia_dlp_web_rules" "zbp_us_phi_medium_confidence_monitor" {
  name                         = "ZBP-US PHI - Medium Confidence-Monitor"
  description                  = "One rule per engine: this rule carries ZBP-US PHI - Medium Confidence only. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_phi_medium_confidence.id]
  }
}

resource "zia_dlp_web_rules" "zbp_us_phi_high_confidence_monitor" {
  name                         = "ZBP-US PHI - High Confidence-Monitor"
  description                  = "One rule per engine: this rule carries ZBP-US PHI - High Confidence only. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_phi_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "zbp_private_keys_monitor" {
  name                         = "ZBP-Private Keys-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
}

resource "zia_endpoint_dlp_rules" "zbp_financial_information_endpoint" {
  name                         = "ZBP-Financial Information [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-Financial Information-Monitor\" (ZBP-Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_financial_information_saas" {
  name                         = "ZBP-Financial Information [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-Financial Information-Monitor\" (ZBP-Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_financial_information_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_financial_information_email" {
  name                         = "ZBP-Financial Information [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-Financial Information-Monitor\" (ZBP-Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_financial_information_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_itar_international_traffic_in_arms_regulations_endpoint" {
  name                         = "ZBP-ITAR International Traffic in Arms Regulations [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-ITAR International Traffic in Arms Regulations-Monitor\" (ZBP-ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_itar_phrases.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_itar_international_traffic_in_arms_regulations_saas" {
  name                         = "ZBP-ITAR International Traffic in Arms Regulations [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-ITAR International Traffic in Arms Regulations-Monitor\" (ZBP-ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_itar_phrases.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_itar_international_traffic_in_arms_regulations_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_itar_international_traffic_in_arms_regulations_email" {
  name                         = "ZBP-ITAR International Traffic in Arms Regulations [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-ITAR International Traffic in Arms Regulations-Monitor\" (ZBP-ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_itar_phrases.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_itar_international_traffic_in_arms_regulations_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_tlp_red_endpoint" {
  name                         = "ZBP-TLP Red [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-TLP Red-Monitor\" (ZBP-TLP Red). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_tlp_red.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_tlp_red_saas" {
  name                         = "ZBP-TLP Red [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-TLP Red-Monitor\" (ZBP-TLP Red). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_red.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_tlp_red_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_tlp_red_email" {
  name                         = "ZBP-TLP Red [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-TLP Red-Monitor\" (ZBP-TLP Red). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_red.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_tlp_red_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_tlp_amber_strict_endpoint" {
  name                         = "ZBP-TLP Amber Strict [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-TLP Amber Strict-Monitor\" (ZBP-TLP Amber Strict). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_tlp_amber_strict.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_tlp_amber_strict_saas" {
  name                         = "ZBP-TLP Amber Strict [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-TLP Amber Strict-Monitor\" (ZBP-TLP Amber Strict). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_amber_strict.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_tlp_amber_strict_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_tlp_amber_strict_email" {
  name                         = "ZBP-TLP Amber Strict [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-TLP Amber Strict-Monitor\" (ZBP-TLP Amber Strict). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_amber_strict.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_tlp_amber_strict_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_tlp_amber_endpoint" {
  name                         = "ZBP-TLP Amber [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-TLP Amber-Monitor\" (ZBP-TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_tlp_amber.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_tlp_amber_saas" {
  name                         = "ZBP-TLP Amber [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-TLP Amber-Monitor\" (ZBP-TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_amber.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_tlp_amber_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_tlp_amber_email" {
  name                         = "ZBP-TLP Amber [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-TLP Amber-Monitor\" (ZBP-TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_amber.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_tlp_amber_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_us_pii_endpoint" {
  name                         = "ZBP-US PII [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-US PII-Monitor\" (ZBP-US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_us_pii_saas" {
  name                         = "ZBP-US PII [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-US PII-Monitor\" (ZBP-US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_us_pii_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_us_pii_email" {
  name                         = "ZBP-US PII [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-US PII-Monitor\" (ZBP-US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_us_pii_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_us_phi_medium_confidence_endpoint" {
  name                         = "ZBP-US PHI - Medium Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-US PHI - Medium Confidence-Monitor\" (ZBP-US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_us_phi_medium_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_us_phi_medium_confidence_saas" {
  name                         = "ZBP-US PHI - Medium Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-US PHI - Medium Confidence-Monitor\" (ZBP-US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_phi_medium_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_us_phi_medium_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_us_phi_medium_confidence_email" {
  name                         = "ZBP-US PHI - Medium Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-US PHI - Medium Confidence-Monitor\" (ZBP-US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_phi_medium_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_us_phi_medium_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_us_phi_high_confidence_endpoint" {
  name                         = "ZBP-US PHI - High Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-US PHI - High Confidence-Monitor\" (ZBP-US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_us_phi_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_us_phi_high_confidence_saas" {
  name                         = "ZBP-US PHI - High Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-US PHI - High Confidence-Monitor\" (ZBP-US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_phi_high_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_us_phi_high_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_us_phi_high_confidence_email" {
  name                         = "ZBP-US PHI - High Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-US PHI - High Confidence-Monitor\" (ZBP-US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_phi_high_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_us_phi_high_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "zbp_private_keys_endpoint" {
  name                         = "ZBP-Private Keys [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"ZBP-Private Keys-Monitor\" (ZBP-Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
}

resource "zia_casb_dlp_rules" "zbp_private_keys_saas" {
  name                         = "ZBP-Private Keys [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"ZBP-Private Keys-Monitor\" (ZBP-Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_zbp_private_keys_saas
  }
}

resource "zia_outbound_email_dlp" "zbp_private_keys_email" {
  name                         = "ZBP-Private Keys [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"ZBP-Private Keys-Monitor\" (ZBP-Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_zbp_private_keys_email
  }
}

